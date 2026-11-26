# frozen_string_literal: true

module Touchque
  module DeviceRisk
    DEFAULT_BASE_URL = "https://api.touchque.com"

    # Touchque Device Risk (a paid add-on, off until your workspace turns it on): a visitor
    # ID for every browser on your sign-up, password-reset, sign-in or approval page, and
    # what your server saw it do. The page identifies with @touchque/device-risk (the
    # script tag, or identify({ siteKey, purpose }), which gives { visitorId, requestId,
    # confidence }) and sends you the requestId. Never trust the page's copy: read the
    # identification here (get_event) or check it for an account (check). Touchque keeps
    # keyed hashes only, with a key of your workspace alone, and its risk engine decides.
    #
    # Every signal only ever asks for more: "stepUp" means an extra check on this page (an
    # emailed code, a passkey, a number-matched approval), never a refusal. For sign-ins
    # approved on the phone with the main Touchque gem, pass the requestId to its
    # login.request / risk.check as device_risk_request_id: instead. Collect it only on
    # these pages and name it in your privacy notice.
    #
    # With the script tag (device.js), the form arrives with touchque_request_id:
    #
    #   dr = Touchque::DeviceRisk::Client.new   # TQ_API_KEY, TQ_API_SECRET
    #   r = dr.check(params[:touchque_request_id], event: "sign_in", external_username: email)
    #
    # Pass it as it came. Missing, empty, made up or expired, it is still a verdict
    # ("report" missing, unknown, expired; the signal device_identification_missing), never
    # an exception: a page without the tag, or with it blocked, only gets the visitor a
    # step-up.
    #
    # Thread-safe: create one and reuse it.
    class Client
      # @api private: the ConfigError message for a missing key or secret.
      MISSING_KEYS = "Set TQ_API_KEY and TQ_API_SECRET (or pass api_key: and api_secret:)."
      # The pages a device report may come from.
      EVENTS = %w[sign_in sign_up password_reset approval].freeze
      # What the page had sent: ok, replayed, or no usable identification.
      REPORTS = %w[ok replayed missing unknown expired invalid].freeze
      # The marks a visitor's "mark" can hold (nil: none applied).
      MARKS = %w[trusted step_up].freeze
      # How a visitor was recognised (an event's "matchedBy").
      MATCHED_BY = %w[key fpc sid traits new].freeze
      # The kind of network an answer's network["kind"] names (search_events' network_kind:). An open
      # list: new values may be added in minor versions, so an answer can carry one not listed here.
      NETWORK_KINDS = %w[residential mobile_carrier education business public_wifi hosting proxy vpn tor relay unknown].freeze
      # What your server saw the visitor do (activity's type:).
      ACTIVITY_TYPES = %w[payment_attempt login_failed not_found forbidden otp_sent code_failed].freeze
      # payment_attempt: what the payment provider answered.
      ACTIVITY_OUTCOMES = %w[approved declined error].freeze
      # The abuse codes an activity can raise. New codes may be added.
      ACTIVITY_SIGNALS = %w[abuse_card_testing abuse_card_shared abuse_login_failures abuse_probing abuse_otp_pumping abuse_code_guessing].freeze
      # The class of a not_found / forbidden path.
      PATH_CLASSES = %w[admin wordpress secrets source db_admin debug shell other].freeze
      REQUEST_ID = /\Adre_[A-Za-z0-9_-]{22}\z/
      SEARCH_FILTERS = { from: "from", to: "to", signal: "signal", kind: "kind", origin: "origin", ip: "ip", account: "account",
                         visitor_id: "visitorId", request_id: "requestId", network_kind: "networkKind", cursor: "cursor" }.freeze
      CARD_NUMBER = "never send the card number: card: is { bin: 6 to 8 digits, last4: 4 digits }"

      # Anything left nil falls back to the environment: TQ_API_KEY, TQ_API_SECRET and
      # TQ_API_URL (default https://api.touchque.com): the same key and secret as the main
      # Touchque gem. +timeout+ is seconds per request.
      def initialize(api_key: nil, api_secret: nil, base_url: nil, timeout: 10)
        api_key ||= ENV.fetch("TQ_API_KEY", nil)
        api_secret ||= ENV.fetch("TQ_API_SECRET", nil)
        base_url ||= ENV["TQ_API_URL"].to_s.empty? ? DEFAULT_BASE_URL : ENV.fetch("TQ_API_URL")
        raise ConfigError, MISSING_KEYS if api_key.to_s.empty? || api_secret.to_s.empty?
        raise ConfigError, "api_key must start with \"tq_\". Did you accidentally swap api_key and api_secret?" unless api_key.start_with?("tq_")

        Util.assert_safe_url!(base_url, "base_url")
        @http = HTTP.new(api_key: api_key, api_secret: api_secret, base_url: base_url.chomp("/"), timeout: timeout)
      end

      # Never shows the API key or secret.
      def inspect
        "#<#{self.class.name} base_url=#{@http.base_url.inspect}>"
      end

      # Checks the page's identification for an account: binds it (one account per
      # identification, 15 minutes) and asks the risk engine. Pass the form field as it came:
      # nil, empty or made up is still a verdict ("report" missing, unknown), never an
      # exception. 409 device_risk_off until your workspace turns Device risk on.
      # device_risk: instead of request_id, the page's report (collect()).
      #
      #   r = dr.check(params[:touchque_request_id], event: "sign_up", external_username: email, client_ip: request.remote_ip)
      #   ask_for_email_code if r["stepUp"]   # never refuse on it alone
      def check(request_id = nil, event: "sign_in", external_username: nil, client_ip: nil, device_risk: nil)
        raise ConfigError, "check(): event must be one of #{EVENTS.join(", ")}" unless EVENTS.include?(event)

        body = {}
        if request_id.is_a?(String) && !request_id.empty?
          body["requestId"] = request_id[0, 64]
        elsif !device_risk.to_s.empty?
          body["deviceRisk"] = device_risk
        end
        body["event"] = event
        body["externalUsername"] = external_username unless external_username.to_s.empty?
        body["clientIp"] = client_ip unless client_ip.to_s.empty?
        self.class.parse_check(@http.post("/device-risk/check", body))
      end

      # Your workspace's identifications, newest first, one page at a time
      # (GET /device-risk/events): a date range (from:/to: YYYY-MM-DD or ISO times; 7 days by
      # default, at most 90, within your retention) and any of the filters. ip: is an address
      # or a CIDR range and is never returned. Pass "nextCursor" back as cursor: until it is
      # nil; do not page by moving the dates. A search that would read too much is a 422
      # search_too_broad: narrow the range or add a filter. Each event may carry "suspect"
      # (see parse_suspect), "matchedBy" (MATCHED_BY) and "network" (as in parse_check).
      # network_kind: is a network["kind"] (NETWORK_KINDS, sent as networkKind): it matches only
      # identifications classified since network kind exists, never older ones. shared: true keeps
      # the identifications whose own address was shared, false the ones counted and not shared: one
      # that was not counted matches neither. Older servers ignore both and answer as without them.
      # { "events" => [...], "nextCursor" => String | nil, "from" => String, "to" => String }.
      def search_events(step_up: nil, shared: nil, limit: nil, **filters)
        unknown = filters.keys - SEARCH_FILTERS.keys
        raise ConfigError, "search_events() does not know #{unknown.join(', ')}" unless unknown.empty?
        raise ConfigError, "search_events() limit must be 1 to 100" unless limit.nil? || (limit.is_a?(Integer) && limit.between?(1, 100))

        params = {}
        filters.each { |k, v| params[SEARCH_FILTERS[k]] = v if v.is_a?(String) && !v.empty? }
        params["stepUp"] = step_up ? "true" : "false" if [true, false].include?(step_up)
        params["shared"] = shared ? "true" : "false" if [true, false].include?(shared)
        params["limit"] = limit.to_s if limit
        raw = @http.get("/device-risk/events", params) || {}
        cursor = raw["nextCursor"]
        { "events" => raw["events"].is_a?(Array) ? raw["events"] : [],
          "nextCursor" => cursor.is_a?(String) && !cursor.empty? ? cursor : nil,
          "from" => raw["from"].to_s, "to" => raw["to"].to_s }
      end

      # The trusted identification behind a request_id: the visitor, how sure, what the page
      # showed, the risk engine's verdict, "network" and "bot" (as in parse_check), "accountDevice"
      # and "suspect" (read them with parse_account_device / parse_suspect). Read-only.
      # visitor["mark"] is the mark actually applied (see parse_check).
      def get_event(request_id)
        raise ConfigError, "get_event() needs a request_id (dre_...)" unless request_id.is_a?(String) && REQUEST_ID.match?(request_id)

        @http.get("/device-risk/events/#{request_id}")
      end

      # Reports what a visitor did that your server saw (POST /device-risk/activity):
      # payments, failed sign-ins, probing, SMS codes, wrong codes. Touchque counts it per
      # visitor and per network and answers the abuse codes it raised; for 24 hours the
      # visitor's next identifications and checks carry them (shadow: they decide nothing on
      # their own).
      #
      #   a = dr.activity(type: "payment_attempt", request_id: params[:touchque_request_id],
      #                   client_ip: request.remote_ip, outcome: "declined", card: { bin: "411111", last4: "1111" })
      #   stop_taking_cards if a["signals"].include?("abuse_card_testing")
      #
      # Name the visitor with request_id: (the form field as it came), visitor_id: (tqv_…) or
      # client_ip:. outcome: is ACTIVITY_OUTCOMES (payment_attempt), phone: is for otp_sent,
      # path: for not_found / forbidden. Never send a card number: a card that is not exactly
      # { bin: 6-8 digits, last4: 4 digits } raises ConfigError before anything is sent.
      # { "recorded" => Boolean, "visitorId" => String | nil, "signals" => [String] }, plus
      # "pathClass" (PATH_CLASSES) for a path.
      def activity(type:, request_id: nil, visitor_id: nil, client_ip: nil, external_username: nil, outcome: nil, card: nil,
                   phone: nil, path: nil)
        body = self.class.activity_body(type: type, request_id: request_id, visitor_id: visitor_id, client_ip: client_ip,
                                        external_username: external_username, outcome: outcome, card: card, phone: phone, path: path)
        self.class.parse_activity(@http.post("/device-risk/activity", body))
      end

      # @api private: activity's request body, validated.
      def self.activity_body(type:, request_id:, visitor_id:, client_ip:, external_username:, outcome:, card:, phone:, path:)
        raise ConfigError, "activity(): type must be one of #{ACTIVITY_TYPES.join(", ")}" unless ACTIVITY_TYPES.include?(type)

        body = { "type" => type }
        # The form field as it came: anything but a string is no identification.
        body["requestId"] = request_id if request_id.is_a?(String) && !request_id.empty?
        { "visitorId" => visitor_id, "clientIp" => client_ip, "externalUsername" => external_username,
          "phone" => phone, "path" => path }.each do |key, value|
          next if value.nil? || value == ""
          raise ConfigError, "activity(): #{key} must be a String" unless value.is_a?(String)

          body[key] = value
        end
        raise ConfigError, "activity(): name the visitor: request_id, visitor_id or client_ip" unless body.key?("requestId") || body.key?("visitorId") || body.key?("clientIp")
        raise ConfigError, "activity(): external_username is at most 255 characters" if body["externalUsername"].to_s.length > 255
        raise ConfigError, "activity(): path is at most 2048 characters" if body["path"].to_s.length > 2048
        raise ConfigError, "activity(): phone must be 6 to 15 digits, with an optional leading +" if body.key?("phone") && !body["phone"].match?(/\A\+?[0-9]{6,15}\z/)

        unless outcome.nil?
          raise ConfigError, "activity(): outcome must be one of #{ACTIVITY_OUTCOMES.join(", ")}" unless ACTIVITY_OUTCOMES.include?(outcome)

          body["outcome"] = outcome
        end
        body["card"] = card_body(card) unless card.nil?
        body
      end

      # A card as its BIN and last 4 digits only; anything that could be a card number is refused.
      def self.card_body(card)
        raise ConfigError, "activity(): #{CARD_NUMBER}" unless card.is_a?(Hash)

        c = card.transform_keys(&:to_s)
        raise ConfigError, "activity(): #{CARD_NUMBER}" unless c.keys.sort == %w[bin last4]

        bin = c["bin"]
        last4 = c["last4"]
        unless bin.is_a?(String) && last4.is_a?(String) && bin.match?(/\A[0-9]{6,8}\z/) && last4.match?(/\A[0-9]{4}\z/)
          raise ConfigError, "activity(): #{CARD_NUMBER}"
        end

        { "bin" => bin, "last4" => last4 }
      end
      private_class_method :card_body

      # Reads an activity answer: "recorded" only when it says exactly true; unknown path
      # classes are dropped.
      def self.parse_activity(raw)
        body = raw.is_a?(Hash) ? raw : {}
        out = { "recorded" => body["recorded"] == true,
                "visitorId" => body["visitorId"].is_a?(String) ? body["visitorId"] : nil,
                "signals" => body["signals"].is_a?(Array) ? body["signals"].grep(String) : [] }
        out["pathClass"] = body["pathClass"] if PATH_CLASSES.include?(body["pathClass"])
        out
      end

      # Asks which bot sent one request your server received (POST /device-risk/bot-check). Many
      # bots never run your page's JavaScript, so the page tag never sees them: ChatGPT-User,
      # GPTBot, Meta's crawlers, Grok's fetches, curl and scripts. Your server sends the visitor's
      # address and headers; Touchque answers which bot it is, whether that identity is proven and
      # what it would do. Touchque never logs or stores header values and keeps nothing from a
      # check but short-lived keyed-hash counters. In a Rack app (Rails, Sinatra) use
      # bot_check_rack(request.env).
      #
      #   r = dr.bot_check(ip: visitor_ip, headers: [["Host", "shop.example"], ["User-Agent", ua], ["Accept", "*/*"]],
      #                    method: "GET", url: "https://shop.example/login", http_version: "1.1")
      #   r.bot.result     # "detected", "suspected" or "not_detected"
      #   r.bot.identity   # "verified", "unverified" (a spoofed name) or "claimed"
      #   r.suggestion     # "allow", "block" or "challenge": advice in shadow, Touchque never enforces it
      #
      # ip: is the visitor's IPv4 or IPv6 address as your server saw it. headers: is
      # [[name, value], ...] in the order received (the order is a sign too; [] for a request that had
      # none), or { name => value } when the order is unknown. Authorization, Cookie,
      # Proxy-Authorization, X-Api-Key and Set-Cookie go with empty values, their names kept for the
      # order. What the visitor sent never raises: the first 100 headers go, a name is cut to 128
      # characters and a value to 4096, the request is kept under 32 KB, and "truncated" => true tells
      # Touchque so; a header HTTP does not allow, a method other than 1 to 16 letters or a URL
      # Touchque could not read is left out. No ip (or not one address) or a wrong shape raises
      # ConfigError before anything is sent. url: goes without its query string (only the host and
      # path are read). http_version: ("1.0", "1.1", "2" or "3") and tls: ({ ciphers:, ja4: }) only
      # when your edge tells you what the visitor's were, never your server's own protocol. Answers a
      # BotCheck::Result. 400 (APIError code invalid_ip, headers_required, too_large, invalid_body),
      # 409 device_risk_off until your workspace turns Device risk on, 429 (retry_after) past your
      # workspace's bot checks per minute.
      def bot_check(ip:, headers:, method: nil, url: nil, http_version: nil, tls: nil)
        body = BotCheck.request_body(ip: ip, headers: headers, method: method, url: url, http_version: http_version, tls: tls)
        self.class.parse_bot_check(@http.post("/device-risk/bot-check", body))
      end

      # bot_check for the request a Rack app (Rails, Sinatra, Roda, Hanami) is answering: pass its
      # env (request.env; a request object that answers #env works too). It sends the visitor's
      # address (Rails' request.remote_ip, else Rack's request.ip, else REMOTE_ADDR: set your trusted
      # proxies), the headers in the order the server kept them (in lower case: Rack keeps no case),
      # the method and the host and path. It never sends the env's own HTTP version: that is the
      # connection to this server, behind a proxy the proxy's. ip: replaces the env's address;
      # http_version: and tls: are what your edge saw, as for bot_check.
      #
      # Like bot_check, it never raises for what the visitor sent.
      #
      #   r = dr.bot_check_rack(request.env)   # in a Rails controller
      #   head :forbidden if r.suggestion == "block"   # a spoofed bot name; your choice to act on it
      def bot_check_rack(env, ip: nil, http_version: nil, tls: nil)
        env = env.env if !env.is_a?(Hash) && env.respond_to?(:env)
        raise ConfigError, "bot_check_rack(): pass the Rack env (request.env)" unless env.is_a?(Hash)

        req = BotCheck.rack_request(env)
        body = BotCheck.request_body(ip: ip || req[:ip], headers: req[:headers], method: req[:method], url: req[:url],
                                     http_version: http_version, tls: tls, where: "bot_check_rack()")
        self.class.parse_bot_check(@http.post("/device-risk/bot-check", body))
      end

      # Reads a bot check answer (the decoded JSON) into a BotCheck::Result. Never raises: fields
      # and values added later come through as they are, a missing or broken one reads as nothing
      # seen (result "not_detected", suggestion "allow").
      def self.parse_bot_check(raw)
        BotCheck::Result.parse(raw)
      end

      # The suspect score of an answer, event or search row (in shadow: it decides nothing
      # yet), or nil: "score" 0-100, "band" (low | medium | high | critical), "wouldDo"
      # (allow | number_match | passkey | block: what it would ask for), "mode" ("shadow")
      # and "reasons" ("code", "points", "by": server | site | page | brand, "text").
      def self.parse_suspect(raw)
        return nil unless raw.is_a?(Hash) && raw["score"].is_a?(Integer)

        reasons = (raw["reasons"].is_a?(Array) ? raw["reasons"] : []).filter_map do |r|
          next unless r.is_a?(Hash) && r["code"].is_a?(String)

          { "code" => r["code"], "points" => r["points"].is_a?(Integer) ? r["points"] : 0,
            "by" => %w[server site page brand].include?(r["by"]) ? r["by"] : "server",
            "text" => r["text"].is_a?(String) ? r["text"] : "" }
        end
        score = raw["score"].clamp(0, 100)
        band = if %w[low medium high critical].include?(raw["band"]) then raw["band"]
               elsif score >= 80 then "critical"
               elsif score >= 60 then "high"
               elsif score >= 30 then "medium"
               else "low"
               end
        { "score" => score, "band" => band,
          "wouldDo" => %w[allow number_match passkey block].include?(raw["wouldDo"]) ? raw["wouldDo"] : "allow",
          "mode" => "shadow", "reasons" => reasons }
      end

      # Did this account use the device before (once a check names the account), or nil:
      # "status" known | likely | new | first, "visitorId" (likely: the account's visitor it
      # looks like) and "since" (known: the account's first identification on it).
      def self.parse_account_device(raw)
        return nil unless raw.is_a?(Hash) && %w[known likely new first].include?(raw["status"])

        out = { "status" => raw["status"] }
        out["visitorId"] = raw["visitorId"] if raw["visitorId"].is_a?(String)
        out["since"] = raw["since"] if raw["since"].is_a?(String)
        out
      end

      # The visitor as it came; a "mark" other than trusted or step_up reads as nil (no mark applied).
      def self.visitor_of(raw)
        return nil unless raw.is_a?(Hash)
        return raw unless raw.key?("mark")

        raw.merge("mark" => MARKS.include?(raw["mark"]) ? raw["mark"] : nil)
      end

      # Reads an answer, failing toward asking: "stepUp" is true unless it says exactly
      # false; junk signals are dropped. visitor["mark"] is the mark actually applied to the
      # identification: "step_up" always, "trusted" only when the browser matched by its stored
      # key or id (never by traits), else nil; visitor["status"] stays your admin's mark. Absent
      # from older servers.
      def self.parse_check(raw)
        body = raw.is_a?(Hash) ? raw : {}
        signals = (body["signals"].is_a?(Array) ? body["signals"] : []).filter_map do |s|
          next unless s.is_a?(Hash) && s["code"].is_a?(String)

          item = { "code" => s["code"], "text" => s["text"].is_a?(String) ? s["text"] : "",
                   "strength" => %w[passkey none].include?(s["strength"]) ? s["strength"] : "number_match" }
          item["enforced"] = s["enforced"] if [true, false].include?(s["enforced"])
          item["evidence"] = s["evidence"] if s["evidence"].is_a?(Hash)
          item
        end
        out = {
          "report" => REPORTS.include?(body["report"]) ? body["report"] : "invalid",
          "requestId" => body["requestId"].is_a?(String) ? body["requestId"] : nil,
          "visitorId" => body["visitorId"].is_a?(String) ? body["visitorId"] : nil,
          "confidence" => body["confidence"].is_a?(Numeric) ? body["confidence"] : nil,
          "visitor" => visitor_of(body["visitor"]),
          "counts" => body["counts"].is_a?(Hash) ? body["counts"] : nil,
          # "network" is the address as the risk engine saw it (never coordinates), passed through as the API answers
          # it: countryCode, region, city, accuracyKm, timeZone, asn, asnOrg, type (isp | hosting | tor | relay: Apple's
          # iCloud Private Relay | unknown), tor, hosting, hostingProvider, proxy (on a public proxy list in the last 30
          # days: context; absent on older servers; the proxy list includes IP2Proxy LITE data available from
          # https://lite.ip2location.com), timezoneMismatch and, absent on older servers (nil when not classified, as
          # for an identification made before them): kind (NETWORK_KINDS, an open list: new values may be added in minor
          # versions), kindSource (address | network | mixed | network_open | name, the operator's name only: shown,
          # never used for a decision), vpn (a VPN company's own address), shared (many browsers used this address on
          # your pages in the last 24 hours: context only), sharedVisitors24h and sharedAccounts24h (at least 1, 2, 5,
          # 10, 100 or 1000; nil when not counted) and lookAlikeMatching (false: this computer was recognised only by
          # its own key, cookie or stored id; true: look-alike matching was allowed; nil: not decided). The shared
          # fields describe the identification's own address: nil when the answer is about another one.
          "network" => body["network"].is_a?(Hash) ? body["network"] : nil,
          "velocity" => body["velocity"].is_a?(Hash) ? body["velocity"] : nil,
          # "bot" is passed through as the API answers it: result (detected | suspected | not_detected), reasons
          # (detected ones first: webdriver, headless, tool_<name>, agent_verified; then suspected: pointer_synthetic,
          # input_synthetic, agent_pace, zero_window, headless_window, emulator, cdp, cdp_input (a press with no
          # pressure: only the DevTools protocol sends it), input_no_focus (a click or key into a page that was not in
          # front), insert_text_bulk (text that arrived whole, no key pressed), scripted_click (a form sent with no
          # click or key), agent_unverified, agent_claimed; soft_gpu (software graphics) only next to another) and, on
          # servers since 2026-11-24 (absent on older ones): type (ai_agent: an AI agent or bot by its own identity or
          # its marks on the page, or a pause before every step; automation: a driven browser; script: moved or typed
          # like software in a browser that shows no driver; or null), tools (the automation tools and AI agents whose
          # marks were on the page: selenium, playwright, puppeteer, phantomjs, nightmare, headless_chrome and, on
          # servers since 2026-11-25, claude_agent (the Claude app's browser or Claude in Chrome), comet_agent
          # (Perplexity Comet), genspark_agent, browser_use, stagehand, skyvern), agent (null, or provider, name,
          # category ai_agent | ai_crawler | search_crawler, identity verified | unverified | claimed: a Web Bot Auth
          # signature checked against the provider's published keys, or the user agent only) and input
          # (insert_no_keys, uniform_keys, instant_keys, center_press, agent_pace). New tools and reasons may be added.
          "bot" => body["bot"].is_a?(Hash) ? body["bot"] : nil,
          # Did this account use the device before (nil before an account is named); see parse_account_device.
          "accountDevice" => parse_account_device(body["accountDevice"]),
          # The suspect score, in shadow (nil from servers that do not send it); see parse_suspect.
          "suspect" => parse_suspect(body["suspect"]),
          "signals" => signals,
          "stepUp" => body["stepUp"] != false,
          "wouldStepUp" => body["wouldStepUp"] == true,
          "requires" => %w[number_match passkey].include?(body["requires"]) ? body["requires"] : "none",
          "mode" => body["mode"] == "enforce" ? "enforce" : "shadow",
          # The engine's state for this check; "unavailable" when the risk engine could not be reached and the verdict is a safe default.
          "engine" => body["engine"].is_a?(String) ? body["engine"] : nil
        }
        out["caseCode"] = body["caseCode"] if body["caseCode"].is_a?(String)
        out
      end
    end
  end
end
