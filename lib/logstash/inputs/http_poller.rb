# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/plugin_mixins/http_client"
require "socket" # for Socket.gethostname
require "manticore"

# Note. This plugin is a WIP! Things will change and break!
#
# Reads from a list of urls and decodes the body of the response with a codec
# The config should look like this:
#
# input {
#   http_poller {
#     urls => {
#       test1 => "http://localhost:9200"
#     test2 => {
#       # Supports all options supported by ruby's Manticore HTTP client
#       method => get
#     url => "http://localhost:9200/_cluster/health"
#     headers => {
#       Accept => "application/json"
#     }
#   }
# }
# request_timeout => 60
# interval => 60
# codec => "json"
# # A hash of request metadata info (timing, response headers, etc.) will be sent here
# metadata_target => "_http_poller_metadata"
# }
# }
#
# output {
#   stdout {
#     codec => rubydebug
#   }
# }

class LogStash::Inputs::HTTP_Poller < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient

  config_name "http_poller"

  default :codec, "json"

  # A Hash of urls in this format : "name" => "url"
  # The name and the url will be passed in the outputed event
  #
  config :urls, :validate => :hash, :required => true

  # How often  (in seconds) the urls will be called
  config :interval, :validate => :number, :required => true

  # If you'd like to work with the request/response metadata
  # Set this value to the name of the field you'd like to store a nested
  # hash of metadata.
  config :metadata_target, :validate => :string, :default => '@metadata'

  public
  def register
    @host = Socket.gethostname.force_encoding(Encoding::UTF_8)

    @logger.info("Registering http_poller Input", :type => @type,
                 :urls => @urls, :interval => @interval, :timeout => @timeout)
  end # def register

  private
  def requests
    @requests ||= Hash[@urls.map {|name, url| [name, normalize_request(url)] }]
  end

  private
  def normalize_request(url_or_spec)
    if url_or_spec.is_a?(String)
      [:get, url_or_spec]
    elsif url_or_spec.is_a?(Hash)
      # The client will expect keys / values
      spec = Hash[url_or_spec.clone.map {|k,v| [k.to_sym, v] }] # symbolize keys
      method = (spec.delete(:method) || :get).to_sym.downcase
      url = spec.delete(:url)
      raise ArgumentError, "No URL provided for request! #{url_or_spec}" unless url
      [method, url, spec]
    else
      raise ArgumentError, "Invalid URL or request spec: '#{url_or_spec}', expected a String or Hash!"
    end
  end

  public
  def run(queue)
    Stud.interval(@interval) do
      run_once(queue)
    end
  end

  private
  def run_once(queue)
    requests.each do |name, request|
      request_async(queue, name, request)
    end

    # TODO: Remove this once our patch to manticore is accepted. The real callback should work
    # Some exceptions are only returned here! There is no callback,
    # for example, if there is a bad port number.
    # https://github.com/cheald/manticore/issues/22
    client.execute!.each_with_index do |resp, i|
      if resp.is_a?(java.lang.Exception) || resp.is_a?(StandardError)
        name = requests.keys[i]
        request = requests[name]
        # We can't report the time here because this is as slow as the slowest request
        # This is all temporary code anyway
        handle_failure(queue, name, request, resp, nil)
      end
    end
  end

  private
  def request_async(queue, name, request)
    @logger.debug? && @logger.debug("Fetching URL", :name => name, :url => request)
    started = Time.now

    method, request_opts = request
    client.async.send(method, request_opts).
      on_success {|response| handle_success(queue, name, request, response, Time.now - started)}.
      on_failure {|exception|
      handle_failure(queue, name, request, exception, Time.now - started)
    }
  end

  private
  def handle_success(queue, name, request, response, execution_time)
    @codec.decode(response.body) do |decoded|
      handle_decoded_event(queue, name, request, response, decoded, execution_time)
    end
  end

  private
  def handle_decoded_event(queue, name, request, response, event, execution_time)
    apply_metadata(event, name, request, response, execution_time)
    queue << event
  rescue StandardError, java.lang.Exception => e
    @logger.error? && @logger.error("Error eventifying response!",
                                    :exception => e,
                                    :exception_message => e.message,
                                    :name => name,
                                    :url => request,
                                    :response => response
    )
  end

  private
  def handle_failure(queue, name, request, exception, execution_time)
    event = LogStash::Event.new
    apply_metadata(event, name, request)

    event.tag("_http_request_failure")

    # This is also in the metadata, but we send it anyone because we want this
    # persisted by default, whereas metadata isn't. People don't like mysterious errors
    event["_http_request_failure"] = {
      "url" => @urls[name], # We want the exact parameter they passed in
      "name" => name,
      "error" => exception.to_s,
      "runtime_seconds" => execution_time
   }

    queue << event
  rescue StandardError, java.lang.Exception => e
      @logger.error? && @logger.error("Cannot read URL or send the error as an event!",
                                      :exception => exception,
                                      :exception_message => exception.message,
                                      :name => name,
                                      :url => request
      )
  end

  private
  def apply_metadata(event, name, request, response=nil, execution_time=nil)
    return unless @metadata_target
    event[@metadata_target] = event_metadata(name, request, response, execution_time)
  end

  private
  def event_metadata(name, request, response=nil, execution_time=nil)
    m = {
        "name" => name,
        "host" => @host,
        "url" => @urls[name]
      }

    m["runtime_seconds"] = execution_time

    if response
      m["code"] = response.code
      m["response_headers"] = response.headers
      m["response_message"] = response.message
      m["times_retried"] = response.times_retried
    end

    m
  end
end