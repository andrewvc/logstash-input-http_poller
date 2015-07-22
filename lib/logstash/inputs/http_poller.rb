# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/plugin_mixins/http_client"
require "socket" # for Socket.gethostname
require "manticore"
require "securerandom"

# Note. This plugin is a WIP! Things will change and break!
#
# Reads from a list of urls and decodes the body of the response with a codec
# The config should look like this:
#
# input {
#   http_poller {
#     urls => {
#       test1 => "http://localhost:9200"
#       test2 => {
#         # Supports all options supported by ruby's Manticore HTTP client
#         method => get
#         url => "http://localhost:9200/_cluster/health"
#         headers => {
#           Accept => "application/json"
#         }
#         auth => {
#           user => "AzureDiamond"
#           password => "hunter2"
#         }
#       }
#     }
#     request_timeout => 60
#     interval => 60
#     codec => "json"
#     # A hash of request metadata info (timing, response headers, etc.) will be sent here
#     metadata_target => "_http_poller_metadata"
#   }
# }
#
# output {
#   stdout {
#     codec => rubydebug
#   }
# }

class LogStash::Inputs::HTTP_Poller < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient

  # We pass this group of data around a lot
  RequestMeta = Struct.new(:name, :request_spec, :batch_uuid, :batch_started_at, :issued_at)

  config_name "http_poller"

  default :codec, "json"

  # A Hash of urls in this format : "name" => "url"
  # The name and the url will be passed in the outputed event
  #
  config :urls, :validate => :hash, :required => true

  # How often  (in seconds) the urls will be called
  config :interval, :validate => :number, :required => true

  # Define the target field for placing the received data. If this setting is omitted, the data will be stored at the root (top level) of the event.
  config :target, :validate => :string

  # If you'd like to work with the request/response metadata
  # Set this value to the name of the field you'd like to store a nested
  # hash of metadata.
  config :metadata_target, :validate => :string, :default => '@metadata'

  public
  def register
    @host = Socket.gethostname.force_encoding(Encoding::UTF_8)

    @logger.info("Registering http_poller Input", :type => @type,
                 :urls => @urls, :interval => @interval, :timeout => @timeout)

    setup_requests!
  end

  private
  def setup_requests!
    @requests = Hash[@urls.map {|name, url| [name, normalize_request(url)] }]
  end

  private
  def normalize_request(url_or_spec)
    if url_or_spec.is_a?(String)
      res = [:get, url_or_spec]
    elsif url_or_spec.is_a?(Hash)
      # The client will expect keys / values
      spec = Hash[url_or_spec.clone.map {|k,v| [k.to_sym, v] }] # symbolize keys

      # method and url aren't really part of the options, so we pull them out
      method = (spec.delete(:method) || :get).to_sym.downcase
      url = spec.delete(:url)

      # We need these strings to be keywords!
      spec[:auth] = {user: spec[:auth]["user"], pass: spec[:auth]["password"]} if spec[:auth]

      res = [method, url, spec]
    else
      raise LogStash::ConfigurationError, "Invalid URL or request spec: '#{url_or_spec}', expected a String or Hash!"
    end

    validate_request!(url_or_spec, res)
    res
  end

  private
  def validate_request!(url_or_spec, request)
    method, url, spec = request

    raise LogStash::ConfigurationError, "Invalid URL #{url}" unless URI::DEFAULT_PARSER.regexp[:ABS_URI].match(url)

    raise LogStash::ConfigurationError, "No URL provided for request! #{url_or_spec}" unless url
    if spec && spec[:auth]
      if !spec[:auth][:user]
        raise LogStash::ConfigurationError, "Auth was specified, but 'user' was not!"
      end
      if !spec[:auth][:pass]
        raise LogStash::ConfigurationError, "Auth was specified, but 'password' was not!"
      end
    end

    request
  end

  public
  def run(queue)
    Stud.interval(@interval) do
      run_once(queue)
    end
  end

  private
  def run_once(queue)
    batch_started_at = Time.now
    @requests.each do |name, request_spec|
      request_meta = RequestMeta.new(name, request_spec, SecureRandom.uuid, batch_started_at, Time.now)
      request_async(queue, request_meta)
    end

    client.execute!
  end

  private
  def request_async(queue, request_meta)
    @logger.debug? && @logger.debug("Fetching URL",
                                    name => request_meta.name,
                                    :url => request_meta.request)

    method, *request_opts = request_meta.request_spec
    client.async.send(method, *request_opts).
      on_success {|response| handle_success(queue, request_meta, response)}.
      on_failure {|exception| handle_failure(queue, request_meta, exception)
    }
  end

  private
  def handle_success(queue, request_meta, response)
    @codec.decode(response.body) do |decoded|
      event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
      handle_decoded_event(queue, event, request_meta, response)
    end
  end

  private
  def handle_decoded_event(queue, event, request_meta, response)
    queue << event
  rescue StandardError, java.lang.Exception => e
    @logger.error? && @logger.error("Error eventifying response!",
                                    :exception => e,
                                    :exception_message => e.message,
                                    :name => request_meta.name,
                                    :url => request_meta.request_spec,
                                    :response => response
    )
  end

  private
  # Beware, on old versions of manticore some uncommon failures are not handled
  def handle_failure(queue, request_meta, exception)
    event = LogStash::Event.new
    apply_metadata(event, request_meta)

    event.tag("_http_request_failure")

    # This is also in the metadata, but we send it anyone because we want this
    # persisted by default, whereas metadata isn't. People don't like mysterious errors
    event["_http_request_failure"] = {
      "url" => @urls[request_meta.name], # We want the exact parameter they passed in
      "name" => request_meta.name,
      "error" => exception.to_s,
      "backtrace" => exception.backtrace,
      "runtime_seconds" => (Time.now - request_meta.issued_at)
   }

    queue << event
  rescue StandardError, java.lang.Exception => e
      @logger.error? && @logger.error("Cannot read URL or send the error as an event!",
                                      :exception => e,
                                      :exception_message => e.message,
                                      :exception_backtrace => e.backtrace,
                                      :name => request_meta.name,
                                      :url => request
      )
  end

  private
  def apply_metadata(event, request_meta, response=nil)
    return unless @metadata_target
    event[@metadata_target] = event_metadata(request_meta, response)
  end

  private
  def event_metadata(request_meta, response=nil)
    m = {
        "name" => request_meta.name,
        "host" => @host,
        "url" => @urls[request_meta.name],
        "issued_at" => request_meta.issued_at
      }

    m["runtime_seconds"] = Time.now - request_meta.issued_at

    if response
      m["code"] = response.code
      m["response_headers"] = response.headers
      m["response_message"] = response.message
      m["times_retried"] = response.times_retried
    end

    m
  end
end
