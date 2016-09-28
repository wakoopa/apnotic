require 'net-http2'
require 'openssl'

module Apnotic

  APPLE_DEVELOPMENT_SERVER_URL = "https://api.development.push.apple.com:443"
  APPLE_PRODUCTION_SERVER_URL  = "https://api.push.apple.com:443"

  class Connection
    attr_reader :url, :cert_path

    class << self
      def development(options={})
        options.merge!(url: APPLE_DEVELOPMENT_SERVER_URL)
        new(options)
      end
    end

    def initialize(options={})
      @url             = options[:url] || APPLE_PRODUCTION_SERVER_URL
      @cert_path       = options[:cert_path]
      @cert_pass       = options[:cert_pass]
      @connect_timeout = options[:connect_timeout] || 30
      @auth_method     = options[:auth_method] || :cert
      @team_id         = options[:team_id]
      @key_id          = options[:key_id]

      raise "Cert file not found: #{@cert_path}" unless @cert_path && (@cert_path.respond_to?(:read) || File.exist?(@cert_path))

      @client = NetHttp2::Client.new(@url, ssl_context: ssl_context, connect_timeout: @connect_timeout)
    end

    def push(notification, options={})
      request  = Apnotic::Request.new(notification, request_options)
      response = @client.call(:post, request.path,
        body:    request.body,
        headers: request.headers,
        timeout: options[:timeout]
      )
      Apnotic::Response.new(headers: response.headers, body: response.body) if response
    end

    def push_async(push)
      @client.call_async(push.http2_request)
    end

    def prepare_push(notification)
      puts '--------------'
      puts request_options.inspect
      puts '--------------'
      request       = Apnotic::Request.new(notification, request_options)
      http2_request = @client.prepare_request(:post, request.path,
        body:    request.body,
        headers: request.headers
      )
      Apnotic::Push.new(http2_request)
    end

    def close
      @client.close
    end

    def join
      @client.join
    end

    private

    def ssl_context
      @ssl_context ||= begin
        @auth_method == :cert ? build_ssl_context : nil
      end
    end

    def build_ssl_context
      ctx = OpenSSL::SSL::SSLContext.new
      begin
        p12      = OpenSSL::PKCS12.new(certificate, @cert_pass)
        ctx.key  = p12.key
        ctx.cert = p12.certificate
      rescue OpenSSL::PKCS12::PKCS12Error
        ctx.key  = OpenSSL::PKey::RSA.new(certificate, @cert_pass)
        ctx.cert = OpenSSL::X509::Certificate.new(certificate)
      end
      ctx
    end

    def certificate
      @certificate ||= begin
        if @cert_path.respond_to?(:read)
          cert = @cert_path.read
          @cert_path.rewind if @cert_path.respond_to?(:rewind)
        else
          cert = File.read(@cert_path)
        end
        cert
      end
    end

    def request_options
      @request_options ||= begin
        options = {}
        if @auth_method == :token
          token = ProviderToken.new(certificate, @team_id, @key_id).token
          options.merge!(token: token)
        end
        options
      end
    end
  end
end
