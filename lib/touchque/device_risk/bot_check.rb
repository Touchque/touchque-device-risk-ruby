# frozen_string_literal: true

require "ipaddr"

module Touchque
  module DeviceRisk
    # The bot check (Client#bot_check, Client#bot_check_rack): which bot sent one request your
    # server received. Many bots never run your page's JavaScript, so the page tag never sees them
    # (ChatGPT-User, GPTBot, Meta's crawlers, Grok's fetches, curl, scripts); this check reads the
    # request itself. Touchque decides on its own servers with its own data: the operators'
    # published address lists, Web Bot Auth signatures, reverse DNS checked both ways and its own
    # network data. When a source is unavailable the answer is "cannot tell", never a guess and
    # never a block. Touchque never logs or stores header values and keeps nothing from a check
    # but short-lived keyed-hash counters.
    module BotCheck
      # What Touchque found: a bot it is sure of, signs of one, or none.
      RESULTS = %w[detected suspected not_detected].freeze
      # The kinds of bot. New ones may be added: an answer can carry one that is not listed here.
      CATEGORIES = %w[ai_agent ai_assistant ai_crawler ai_search search_crawler link_preview seo monitoring archiver
                      feed_reader security_scanner http_client headless_browser automation].freeze
      # Is the bot who it says it is? "unverified" is a spoofed name (see Bot#identity).
      IDENTITIES = %w[verified unverified claimed].freeze
      # What proved the identity.
      VERIFIED_BY = %w[signature ip_list reverse_dns asn].freeze
      # How sure Touchque is.
      CONFIDENCES = %w[high medium low].freeze
      # What Touchque would do: advice in shadow, Touchque never enforces it.
      SUGGESTIONS = %w[allow block challenge].freeze
      # The http_version: values ("HTTP/2", "2.0", "h2" or 2 work too).
      HTTP_VERSIONS = %w[1.0 1.1 2 3].freeze
      # Sent with empty values, their names kept for the order (compared without case).
      BLANKED_HEADERS = %w[authorization cookie proxy-authorization x-api-key set-cookie].freeze
      # The API's limits: headers per request, characters per name and per value, bytes per request
      # (32 KB read as 32,000, so a body fits either reading of "KB").
      MAX_HEADERS = 100
      MAX_NAME_LENGTH = 128
      MAX_VALUE_LENGTH = 4096
      MAX_BODY_BYTES = 32_000
      # @api private: a longer URL is left out, never cut (a signature may cover its path).
      MAX_URL_LENGTH = 4096
      # @api private: a longer JA4 is not one.
      MAX_JA4_LENGTH = 128
      # @api private: the methods the API reads.
      METHOD = /\A[A-Za-z]{1,16}\z/
      # @api private: a header name as HTTP allows it (RFC 9110 token).
      TOKEN = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/
      # @api private
      PLAIN_AUTHORITY = /\A([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?)(?::([0-9]{0,5}))?\z/
      # @api private
      DOTTED_QUAD = /\A(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\z/

      # A bot check's answer: a Hash with the API's keys ("bot", "network", "suggestion",
      # "rulesVersion") and a reader for each. Fields Touchque adds later stay in the Hash, and a
      # value this gem does not know yet (a new category) comes through as it is.
      #
      #   r = dr.bot_check_rack(request.env)
      #   r.bot.result     # "detected"
      #   r.bot.name       # "ChatGPT-User" (r.bot.provider: "OpenAI")
      #   r.bot.identity   # "verified"
      #   r.suggestion     # "allow"
      class Result < Hash
        # @api private: Client.parse_bot_check. Never raises: a missing or broken field reads as
        # nothing seen (result "not_detected", suggestion "allow").
        def self.parse(raw)
          raw = {} unless raw.is_a?(Hash)
          new.update(raw).update("bot" => Bot.parse(raw["bot"]), "network" => Network.parse(raw["network"]),
                                 "suggestion" => BotCheck.text(raw["suggestion"]) || "allow",
                                 "rulesVersion" => BotCheck.text(raw["rulesVersion"]))
        end

        # What Touchque found (a Bot). Never nil.
        def bot
          self["bot"]
        end

        # The network the request came from (a Network), or nil when Touchque could not tell.
        def network
          self["network"]
        end

        # What Touchque would do, as advice in shadow: Touchque never enforces it, your code decides.
        # - "allow": a verified bot, a declared crawler, assistant or other bot Touchque cannot check,
        #   or no bot;
        # - "block": a spoofed name (identity "unverified", or a signature that failed);
        # - "challenge": an AI agent that only names itself (it acts for a person: ask that person),
        #   automation that does not say what it is (an HTTP client, a headless browser, a browser
        #   whose claims contradict each other), or a suspected bot.
        # New values may be added (SUGGESTIONS).
        def suggestion
          self["suggestion"]
        end

        # The version of Touchque's rules that answered ("2026.11.25-1"), or nil.
        def rules_version
          self["rulesVersion"]
        end
      end

      # What Touchque found: a Hash with the API's keys ("result", "category", "provider", "name",
      # "identity", "verifiedBy", "confidence", "rule", "reasons") and a reader for each.
      class Bot < Hash
        # @api private: the fields that are a String or nil.
        TEXT_FIELDS = %w[category provider name identity verifiedBy confidence rule].freeze

        # @api private
        def self.parse(raw)
          raw = {} unless raw.is_a?(Hash)
          out = new.update(raw)
          out["result"] = BotCheck.text(raw["result"]) || "not_detected"
          TEXT_FIELDS.each { |key| out[key] = BotCheck.text(raw[key]) }
          out["reasons"] = (raw["reasons"].is_a?(Array) ? raw["reasons"] : []).filter_map { |r| Reason.parse(r) }
          out
        end

        # "detected" (a bot, for sure), "suspected" (signs of one) or "not_detected" (none seen,
        # or Touchque cannot tell).
        def result
          self["result"]
        end

        # The kind of bot, or nil: "ai_agent", "ai_assistant" (fetches a page a person asked an AI
        # about), "ai_crawler", "ai_search", "search_crawler", "link_preview", "seo", "monitoring",
        # "archiver", "feed_reader", "security_scanner", "http_client" (curl, scripts),
        # "headless_browser" or "automation". New kinds may come (CATEGORIES).
        def category
          self["category"]
        end

        # Who runs the bot ("OpenAI"), or nil.
        def provider
          self["provider"]
        end

        # The bot's name ("ChatGPT-User"), or nil.
        def name
          self["name"]
        end

        # Is the bot who it says it is? nil when it names no one.
        # - "verified": its operator's signature, published addresses or reverse DNS proved it;
        # - "unverified": a spoofed name. It uses a name whose operator publishes a way to check,
        #   and that check failed;
        # - "claimed": a name its operator gives no way to check, or one Touchque cannot check right now.
        def identity
          self["identity"]
        end

        # What proved the identity, or nil: "signature" (a Web Bot Auth signature), "ip_list" (the
        # operator's published addresses), "reverse_dns" (its host name, checked both ways) or "asn"
        # (the operator's own network).
        def verified_by
          self["verifiedBy"]
        end

        # How sure Touchque is: "high", "medium" or "low", or nil.
        def confidence
          self["confidence"]
        end

        # The rule that decided, a stable id ("directory.chatgpt_user", "http_client.curl",
        # "browser.chromium_without_client_hints"), or nil.
        def rule
          self["rule"]
        end

        # Every sign Touchque saw (Reason), each with an English sentence for your fraud team. May be empty.
        def reasons
          self["reasons"]
        end
      end

      # One sign Touchque saw: "code" (stable, for your code) and "text" (an English sentence a
      # fraud team reads).
      class Reason < Hash
        # @api private: nil unless it carries a code.
        def self.parse(raw)
          return nil unless raw.is_a?(Hash) && BotCheck.text(raw["code"])

          new.update(raw).update("text" => raw["text"].is_a?(String) ? raw["text"] : "")
        end

        # The sign's stable code.
        def code
          self["code"]
        end

        # What it means, in English ("" when the answer had none).
        def text
          self["text"]
        end
      end

      # The network a request came from, from Touchque's own data: a Hash with the API's keys
      # ("asn", "asnOrg", "countryCode", "hosting") and a reader for each, each nil when unknown.
      class Network < Hash
        # @api private
        def self.parse(raw)
          return nil unless raw.is_a?(Hash)

          new.update(raw).update("asn" => raw["asn"].is_a?(Integer) ? raw["asn"] : nil,
                                 "asnOrg" => BotCheck.text(raw["asnOrg"]), "countryCode" => BotCheck.text(raw["countryCode"]),
                                 "hosting" => [true, false].include?(raw["hosting"]) ? raw["hosting"] : nil)
        end

        # The network's number (8075), or nil.
        def asn
          self["asn"]
        end

        # Who runs the network ("Microsoft Corporation"), or nil.
        def asn_org
          self["asnOrg"]
        end

        # The network's country, two letters ("US"), or nil.
        def country_code
          self["countryCode"]
        end

        # true: a cloud or hosting network (where scripts and many proxies run); false: not one;
        # nil: unknown.
        def hosting
          self["hosting"]
        end
      end

      module_function

      # @api private: +value+ when it is a non-empty String, else nil.
      def text(value)
        value.is_a?(String) && !value.empty? ? value : nil
      end

      # @api private: the request body. Raises ConfigError, before anything is sent, only for what
      # your code passed wrong (no ip or not one address, a wrong shape). What the visitor sent never
      # raises: the first 100 headers stay, names and values are cut to the API's limits, the body is
      # fitted to 32 KB, and "truncated" => true tells Touchque so.
      def request_body(ip:, headers:, method:, url:, http_version:, tls:, where: "bot_check()")
        body = { "ip" => ip_of(ip, where) }
        pairs, ordered, truncated = header_list(headers, where)
        unless method.nil? || method == ""
          raise ConfigError, "#{where}: method must be a String" unless method.is_a?(String)

          m = utf8(method).strip
          body["method"] = m if METHOD.match?(m) # anything but 1 to 16 letters is left out
        end
        unless url.nil? || url == ""
          raise ConfigError, "#{where}: url must be a String" unless url.is_a?(String)

          short = url_of(url)
          body["url"] = short if short
        end
        version = normalize_version(http_version)
        body["httpVersion"] = version if version
        tls = tls_of(tls, where)
        body["tls"] = tls if tls
        fit(body, pairs, ordered, truncated)
      end

      # @api private: the body within 32 KB. The longest values are cut to one length, the longest
      # that fits. Names always fit (100 of 128 characters); only a url or cipher list made long by
      # escaping can crowd them out, so tls goes first, then the url, and the last headers only after.
      def fit(body, pairs, ordered, truncated)
        build = lambda do |count, cap, drop|
          kept = pairs.first(count).map { |name, value| [name, cut(value, cap)] }
          out = { "ip" => body["ip"], "headers" => ordered ? kept : kept.to_h }
          { "method" => 3, "url" => 2, "httpVersion" => 3, "tls" => 1 }.each do |key, kept_below|
            out[key] = body[key] if body.key?(key) && drop < kept_below
          end
          cut_any = kept.each_with_index.any? { |(_, value), i| value.length < pairs[i][1].length }
          out["truncated"] = true if truncated || count < pairs.size || cut_any
          out
        end
        fits = ->(b) { Util.json(b).bytesize <= MAX_BODY_BYTES }
        whole = build.call(pairs.size, MAX_VALUE_LENGTH, 0)
        return whole if fits.call(whole)

        drop = 0
        drop += 1 while drop < 2 && !fits.call(build.call(pairs.size, 0, drop))
        low = 0
        high = MAX_VALUE_LENGTH - 1
        while low < high
          mid = (low + high + 1) / 2
          if fits.call(build.call(pairs.size, mid, drop)) then low = mid else high = mid - 1 end
        end
        count = pairs.size
        out = build.call(count, low, drop)
        out = build.call(count -= 1, 0, drop) while count.positive? && !fits.call(out)
        out
      end

      # @api private: one IPv4 or IPv6 address; a zone is dropped and ::ffff:a.b.c.d goes as a.b.c.d.
      def ip_of(ip, where)
        address = ip.is_a?(String) ? utf8(ip).strip.sub(/%.*\z/m, "") : ""
        parsed = begin
          IPAddr.new(address) if address.match?(/\A[0-9A-Fa-f:.]+\z/)
        rescue IPAddr::Error
          nil
        end
        raise ConfigError, "#{where}: ip is required: the visitor's IPv4 or IPv6 address, as your server saw it" unless parsed

        parsed.ipv4_mapped? ? parsed.native.to_s : address
      end

      # @api private: the headers as they go, whether in the order received, and whether any was
      # left out or cut: HTTP/2 pseudo-headers (method and url carry them, and :path has the query)
      # and a nil value are left out; so is a header HTTP does not allow (a name that is not a
      # token, a line break or NUL in the value), on which the API would refuse the whole check.
      # The first 100 stay; names are cut to 128 characters and values to 4096; secrets go blank.
      def header_list(headers, where)
        list = case headers
               when Array then headers
               when Hash then headers.to_a
               else raise ConfigError, "#{where}: headers must be [[name, value], ...] in the order received ([] for none), or { name => value }"
               end
        truncated = false
        pairs = []
        list.each do |pair|
          raise ConfigError, "#{where}: each header is a [name, value] pair" unless pair.is_a?(Array) && pair.size == 2

          name, value = pair
          name = name.to_s if name.is_a?(Symbol)
          raise ConfigError, "#{where}: a header name is a non-empty String" unless name.is_a?(String) && !name.empty?
          next if value.nil? || name.start_with?(":")

          name = utf8(name)
          value = utf8(value_text(value, where))
          if !TOKEN.match?(name) || value.match?(/[\r\n\0]/)
            truncated = true
            next
          end
          pairs << [name, value]
        end
        truncated ||= pairs.size > MAX_HEADERS # more is not a browser: the rest is left out, never an error
        pairs = pairs.first(MAX_HEADERS).map do |name, value|
          blank = BLANKED_HEADERS.include?(name.downcase)
          sent = blank ? "" : cut(value, MAX_VALUE_LENGTH)
          truncated ||= name.length > MAX_NAME_LENGTH || (!blank && sent.length < value.length)
          [cut(name, MAX_NAME_LENGTH), sent]
        end
        [pairs, !headers.is_a?(Hash), truncated]
      end

      # @api private: several values of one header are joined as HTTP joins them.
      def value_text(value, where)
        case value
        when String then value
        when Symbol, Numeric then value.to_s
        when Array then value.map { |v| value_text(v, where) }.join(", ")
        else raise ConfigError, "#{where}: a header value must be a String"
        end
      end

      # @api private: the host and path only, never the query string or fragment, nor a user:password@.
      # A path, or an http(s) URL (ws and wss read as http and https); a host Touchque could not read
      # goes as the path alone; anything else, or one over 4096 characters, is nil.
      def url_of(url)
        head = utf8(url).strip.sub(/[?#].*\z/m, "")
        out = if head.start_with?("/")
                head
              elsif (m = %r{\A(https?|wss?)://([^/]*)(/.*)?\z}im.match(head))
                scheme = { "ws" => "http", "wss" => "https" }.fetch(m[1].downcase, m[1].downcase)
                authority = m[2].split("@", -1).last.to_s
                path = m[3].to_s
                plain_host?(authority) ? "#{scheme}://#{authority}#{path}" : (path.empty? ? "/" : path)
              end
        out if out && cut(out, MAX_URL_LENGTH) == out
      end

      # @api private: a host Touchque reads as it is: letters, digits, dots, hyphens and underscores,
      # an IPv4 address, a port up to 65535. Anything else (the Host header is the visitor's) goes as
      # the path alone, so an odd Host never makes the API refuse the check.
      def plain_host?(authority)
        m = PLAIN_AUTHORITY.match(authority)
        return false if m.nil? || (!m[2].to_s.empty? && m[2].to_i > 65_535)

        host = m[1].chomp(".")
        labels = host.split(".")
        return false if labels.any? { |label| label.downcase.start_with?("xn--") }

        # A name that ends in a number is read as an IPv4 address: it must be one.
        labels.last.match?(/\A(?:[0-9]+|0x[0-9a-f]*)\z/i) ? DOTTED_QUAD.match?(host) : true
      end

      # @api private: "1.0", "1.1", "2" or "3" from "HTTP/2", "2.0", "h2", 2, 1.1...; nil (left out) for anything else.
      def normalize_version(version)
        version = version.to_s if version.is_a?(Numeric)
        return nil unless version.is_a?(String)

        v = utf8(version).strip.downcase.sub(%r{\Ahttp/}, "")
        { "1.0" => "1.0", "1.1" => "1.1", "2" => "2", "2.0" => "2", "h2" => "2", "h2c" => "2",
          "3" => "3", "3.0" => "3", "h3" => "3" }[v]
      end

      # @api private: what the brand's edge saw of TLS: ciphers (cut to 4096 characters: the list the
      # visitor offered can be long) and ja4 (one over 128 characters is not a JA4: left out).
      def tls_of(tls, where)
        return nil if tls.nil?
        raise ConfigError, "#{where}: tls must be { ciphers:, ja4: }" unless tls.is_a?(Hash)

        out = {}
        tls.each do |key, value|
          key = key.to_s
          raise ConfigError, "#{where}: tls takes ciphers: and ja4: only, not #{key}" unless %w[ciphers ja4].include?(key)
          next if value.nil? || value == ""
          raise ConfigError, "#{where}: tls #{key} must be a String" unless value.is_a?(String)

          value = utf8(value).strip
          next if value.empty?

          if key == "ciphers"
            out[key] = cut(value, MAX_VALUE_LENGTH)
          elsif value.length <= MAX_JA4_LENGTH
            out[key] = value
          end
        end
        out.empty? ? nil : out
      end

      # @api private: what bot_check_rack reads from a Rack env. The headers come in the env's order
      # (servers add them as they arrive), in lower case (Rack keeps no case). No HTTP version: the
      # env's SERVER_PROTOCOL is the connection to this server, behind a proxy the proxy's.
      def rack_request(env)
        headers = []
        env.each do |key, value|
          next unless key.is_a?(String) && value.is_a?(String)

          name = if key.start_with?("HTTP_") then key.delete_prefix("HTTP_")
                 elsif key == "CONTENT_TYPE" || key == "CONTENT_LENGTH" then key
                 end
          # Some servers keep the protocol in HTTP_VERSION: not a header the visitor sent.
          next if name.nil? || (key == "HTTP_VERSION" && protocol?(value))

          headers << [name.downcase.tr("_", "-"), value]
        end
        method = env["rack.methodoverride.original_method"] || env["REQUEST_METHOD"]
        { ip: rack_ip(env), headers: headers, method: method.is_a?(String) ? method : nil, url: rack_url(env) }
      end

      # @api private: "HTTP/1.1" and the like, as a server sets it (a visitor's Version header is not one).
      def protocol?(value)
        value.is_a?(String) && utf8(value).start_with?("HTTP/")
      end

      # @api private: Rails' request.remote_ip, else Rack's request.ip (both read X-Forwarded-For
      # behind trusted proxies), else the TCP peer.
      def rack_ip(env)
        ip = quietly { env["action_dispatch.remote_ip"]&.to_s }
        ip = quietly { ::Rack::Request.new(env).ip } if !text(ip) && defined?(::Rack::Request)
        ip = env["REMOTE_ADDR"] unless text(ip)
        text(ip)
      end

      # @api private: Rails raises on a spoofed Client-Ip header; the next source answers instead.
      def quietly
        yield
      rescue StandardError
        nil
      end

      # @api private
      def rack_url(env)
        host = [env["HTTP_HOST"], env["SERVER_NAME"]].find { |h| text(h) }
        path = utf8(env["SCRIPT_NAME"].to_s) + utf8(env["PATH_INFO"].to_s)
        return text(path) unless host

        scheme = text(env["rack.url_scheme"]) || "http"
        "#{utf8(scheme)}://#{utf8(host)}#{path}"
      end

      # @api private: valid UTF-8 (a header holds bytes; a Rack env's are binary), a bad byte
      # replaced by U+FFFD, so the JSON never fails.
      def utf8(text)
        s = if [Encoding::UTF_8, Encoding::BINARY, Encoding::US_ASCII].include?(text.encoding)
              text.dup.force_encoding(Encoding::UTF_8)
            else
              text.encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
            end
        s.valid_encoding? ? s : s.scrub
      end

      # @api private: at most +max+ UTF-16 code units (what the API counts), never inside a character.
      def cut(text, max)
        return text if text.length * 2 <= max

        units = 0
        text.each_char.with_index do |char, i|
          units += char.ord > 0xFFFF ? 2 : 1
          return text[0, i] if units > max
        end
        text
      end
    end
  end
end
