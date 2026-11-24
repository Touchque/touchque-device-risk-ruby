# frozen_string_literal: true

require "json"
require "openssl"
require "securerandom"
require "uri"

module Touchque
  module DeviceRisk
    # @api private: small helpers (no third-party gems), as in the main Touchque gem.
    module Util
      module_function

      def sha256_hex(data)
        OpenSSL::Digest::SHA256.hexdigest(data)
      end

      def hmac_hex(key, data)
        OpenSSL::HMAC.hexdigest("SHA256", key, data)
      end

      def random_hex(bytes = 16)
        SecureRandom.hex(bytes)
      end

      def now_ms
        (Time.now.to_f * 1000).to_i
      end

      # A path segment, percent-encoded (encodeURIComponent / rawurlencode).
      def seg(value)
        URI.encode_www_form_component(value.to_s).gsub("+", "%20")
      end

      # JSON text, compact, non-ASCII kept as is (like JSON.stringify).
      def json(value)
        JSON.generate(value)
      end

      def parse_json(text)
        return nil if text.nil? || text.strip.empty?

        JSON.parse(text)
      rescue JSON::ParserError
        nil
      end

      # Keys as strings, deeply (symbol keys from Ruby callers become the API's names).
      def stringify(value)
        case value
        when Hash then value.each_with_object({}) { |(k, v), h| h[k.to_s] = stringify(v) }
        when Array then value.map { |v| stringify(v) }
        when Symbol then value.to_s
        else value
        end
      end

      # https, or http to localhost / loopback only (local development).
      def assert_safe_url!(url, name)
        uri = URI.parse(url.to_s)
        return if uri.scheme == "https"

        if uri.scheme == "http"
          return if %w[localhost 127.0.0.1 ::1 [::1]].include?(uri.host.to_s.downcase)

          raise ConfigError, "Refusing a plaintext http:// #{name} for \"#{uri.host}\". The API key and request signature would be sent in the clear: use https://."
        end
        raise ConfigError, "#{name} must be http(s): #{url}"
      rescue URI::InvalidURIError
        raise ConfigError, "#{name} is not a valid URL: #{url}"
      end
    end
  end
end
