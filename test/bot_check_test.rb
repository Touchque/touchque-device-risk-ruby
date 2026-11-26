# frozen_string_literal: true

require "test_helper"
require "socket"
require "stringio"

module TestSupport
  # POST /device-risk/bot-check for these tests. The shared fake API (testing/fake-touchque-api.mjs)
  # has no bot-check route yet, so a small local server stands in: like the shared one it checks
  # every request's signature as the real API does, keeps each signed call and answers what the
  # test queued (a "not_detected" answer by default).
  class BotCheckApi
    API_KEY = "tq_test_key"
    API_SECRET = "test_secret"
    NOTHING_SEEN = { "bot" => { "result" => "not_detected", "category" => nil, "provider" => nil, "name" => nil, "identity" => nil,
                                "verifiedBy" => nil, "confidence" => nil, "rule" => nil, "reasons" => [] },
                     "network" => nil, "suggestion" => "allow", "rulesVersion" => "2026.11.25-1" }.freeze

    attr_reader :calls

    def self.instance
      @instance ||= new.tap { |api| Minitest.after_run { api.close } }
    end

    def initialize
      @server = TCPServer.new("127.0.0.1", 0)
      @calls = []
      @answers = []
      @thread = Thread.new do
        loop { serve(@server.accept) }
      rescue IOError, SystemCallError
        nil # closed at the end of the run
      end
    end

    def client
      Touchque::DeviceRisk::Client.new(api_key: API_KEY, api_secret: API_SECRET, base_url: "http://127.0.0.1:#{@server.addr[1]}")
    end

    def reset
      @calls.clear
      @answers.clear
    end

    # The next signed request gets this answer.
    def answer(status, body, headers = {})
      @answers << [status, body, headers]
    end

    def close
      @server.close
    end

    private

    def serve(conn)
      method, target = conn.gets.to_s.split(" ")
      headers = {}
      while (line = conn.gets) && line != "\r\n"
        name, value = line.split(":", 2)
        headers[name.downcase] = value.to_s.strip
      end
      raw = conn.read(headers["content-length"].to_i).to_s
      status, body, extra = signed?(method, target, headers, raw) ? record(method, target, raw) : [401, { "code" => "INVALID_SIGNATURE" }, {}]
      text = JSON.generate(body)
      head = extra.merge("Content-Type" => "application/json", "Content-Length" => text.bytesize.to_s, "Connection" => "close")
      conn.write("HTTP/1.1 #{status} Answer\r\n#{head.map { |k, v| "#{k}: #{v}\r\n" }.join}\r\n#{text}")
    rescue StandardError => e
      warn "fake bot-check API: #{e.class}: #{e.message}"
    ensure
      conn.close
    end

    # As the real API: HMAC-SHA256 of "METHOD:path:timestamp:nonce:sha256(body)" with the API
    # secret, the timestamp at most 5 minutes old and 1 minute ahead.
    def signed?(method, target, headers, raw)
      age = (Time.now.to_f * 1000).to_i - headers["x-timestamp"].to_i
      message = "#{method}:#{target}:#{headers["x-timestamp"]}:#{headers["x-nonce"]}:#{OpenSSL::Digest::SHA256.hexdigest(raw)}"
      headers["x-api-key"] == API_KEY && age.between?(-60_000, 300_000) && headers["x-signature"] == OpenSSL::HMAC.hexdigest("SHA256", API_SECRET, message)
    end

    def record(method, target, raw)
      @calls << { "method" => method, "path" => target, "raw" => raw.dup.force_encoding("UTF-8"), "body" => JSON.parse(raw) }
      @answers.shift || [200, NOTHING_SEEN, {}]
    end
  end
end

# The bot check: the request as the contract has it (the order kept, the secrets blanked, the
# limits kept before anything is sent, never the query string) and the answer as a typed Hash that
# keeps what this gem does not know yet.
class BotCheckTest < Minitest::Test
  C = Touchque::DeviceRisk::Client
  B = Touchque::DeviceRisk::BotCheck
  IP = "203.0.113.7"

  def api
    TestSupport::BotCheckApi.instance
  end

  def dr
    api.client
  end

  def setup
    api.reset
  end

  def last_body
    api.calls.last["body"]
  end

  # assert_equal that also takes nil (left out).
  def expect(want, got, message)
    want.nil? ? assert_nil(got, message) : assert_equal(want, got, message)
  end

  def rack_env(extra = {})
    { "rack.version" => [1, 6], "REQUEST_METHOD" => "POST", "SCRIPT_NAME" => "", "PATH_INFO" => "/session",
      "QUERY_STRING" => "email=ada%40example.com", "SERVER_NAME" => "shop.example", "SERVER_PORT" => "443",
      "SERVER_PROTOCOL" => "HTTP/1.1", "HTTP_VERSION" => "HTTP/1.1", "rack.url_scheme" => "https", "REMOTE_ADDR" => "203.0.113.9",
      "HTTP_HOST" => "shop.example", "HTTP_USER_AGENT" => "curl/8.4.0", "HTTP_ACCEPT" => "*/*", "HTTP_COOKIE" => "sid=s3cret",
      "CONTENT_TYPE" => "application/x-www-form-urlencoded", "CONTENT_LENGTH" => "27", "HTTP_AUTHORIZATION" => "Basic s3cret",
      "rack.input" => StringIO.new("email=ada%40example.com&x=1") }.merge(extra)
  end

  def test_the_request_is_signed_and_carries_the_contract
    r = dr.bot_check(ip: " #{IP} ", headers: [["Host", "shop.example"], ["User-Agent", "curl/8.4.0"], ["Accept", "*/*"]],
                     method: "GET", url: "https://ada:pw@shop.example/login?email=ada@example.com#top", http_version: "HTTP/1.1",
                     tls: { ja4: "t13d1516h2_8daaf6152771_02713d6af862", ciphers: "TLS_AES_128_GCM_SHA256" })
    assert_equal %w[POST /device-risk/bot-check], api.calls.last.values_at("method", "path")
    assert_equal({ "ip" => IP, "headers" => [["Host", "shop.example"], ["User-Agent", "curl/8.4.0"], ["Accept", "*/*"]],
                   "method" => "GET", "url" => "https://shop.example/login", "httpVersion" => "1.1",
                   "tls" => { "ja4" => "t13d1516h2_8daaf6152771_02713d6af862", "ciphers" => "TLS_AES_128_GCM_SHA256" } }, last_body)
    refute_includes api.calls.last["raw"], "email="
    refute_includes api.calls.last["raw"], "pw@"
    assert_equal %w[not_detected allow], [r.bot.result, r.suggestion]
    # Only what was given: the optional fields stay out.
    dr.bot_check(ip: IP, headers: [])
    assert_equal({ "ip" => IP, "headers" => [] }, last_body)
    dr.bot_check(ip: IP, headers: [], http_version: 2)
    assert_equal "2", last_body["httpVersion"]
  end

  def test_secrets_go_as_empty_values_and_the_order_stays
    dr.bot_check(ip: IP, headers: [["Authorization", "Bearer s3cret"], ["user-agent", "Mozilla/5.0"], ["COOKIE", "sid=s3cret"],
                                   ["Proxy-Authorization", "Basic s3cret"], ["x-api-key", "s3cret"], ["Set-Cookie", "a=s3cret"],
                                   [:"Accept-Language", "tr-TR"], ["X-Forwarded-For", ["198.51.100.1", "10.0.0.2"]]])
    assert_equal [["Authorization", ""], ["user-agent", "Mozilla/5.0"], ["COOKIE", ""], ["Proxy-Authorization", ""], ["x-api-key", ""],
                  ["Set-Cookie", ""], ["Accept-Language", "tr-TR"], ["X-Forwarded-For", "198.51.100.1, 10.0.0.2"]], last_body["headers"]
    refute_includes api.calls.last["raw"], "s3cret"
    # A Hash says the order is unknown: it goes as an object, blanked the same way.
    dr.bot_check(ip: IP, headers: { "User-Agent" => "curl/8.4.0", cookie: "sid=s3cret" })
    assert_equal({ "User-Agent" => "curl/8.4.0", "cookie" => "" }, last_body["headers"])
    refute_includes api.calls.last["raw"], "s3cret"
  end

  def test_only_what_your_code_passes_wrong_raises_before_anything_is_sent
    [{ ip: nil, headers: [] }, { ip: " ", headers: [] }, { ip: 42, headers: [] }, { ip: "not-an-ip", headers: [] },
     { ip: "203.0.113.7:443", headers: [] }, { ip: "203.0.113.0/24", headers: [] },
     { ip: IP, headers: nil }, { ip: IP, headers: "User-Agent: curl/8.4.0" }, { ip: IP, headers: [["User-Agent"]] },
     { ip: IP, headers: [["", "x"]] }, { ip: IP, headers: [["X-Thing", Object.new]] },
     { ip: IP, headers: [], method: :get }, { ip: IP, headers: [], url: 7 },
     { ip: IP, headers: [], tls: "t13d" }, { ip: IP, headers: [], tls: { ja3: "x" } }, { ip: IP, headers: [], tls: { ja4: 4 } }].each do |args|
      assert_raises(Touchque::DeviceRisk::ConfigError, args.inspect[0, 120]) { dr.bot_check(**args) }
    end
    assert_empty api.calls
    # A zone means nothing outside your host; a dual-stack server's IPv4 visitor goes as IPv4.
    dr.bot_check(ip: "fe80::1%en0", headers: [])
    assert_equal "fe80::1", last_body["ip"]
    dr.bot_check(ip: "::FFFF:203.0.113.7", headers: [])
    assert_equal IP, last_body["ip"]
  end

  def test_what_the_visitor_sent_is_kept_to_the_limits_and_never_raises
    # Past 100 headers: the first 100 in order, and Touchque is told ("truncated").
    many = Array.new(150) { |i| ["x-h#{i}", "v"] }
    dr.bot_check(ip: IP, headers: many)
    assert_equal [many.first(100), true], last_body.values_at("headers", "truncated")
    # Exactly 100, and a pseudo-header, which never counts: nothing cut.
    dr.bot_check(ip: IP, headers: [[":path", "/?q=1"]] + many.first(100))
    assert_equal [100, false], [last_body["headers"].size, last_body.key?("truncated")]
    # A long value is cut to 4096 characters (UTF-16 units, as the API counts them), a long name to 128;
    # a blanked secret is not a cut.
    headers = Array.new(100) { |i| ["x-h#{i}", "v"] }
    headers[0] = ["User-Agent", "a" * 5000]
    headers[1] = ["X-#{"n" * 200}", "\u{1F600}" * 3000]
    dr.bot_check(ip: IP, headers: headers)
    sent = last_body["headers"]
    assert_equal [100, 4096, 128, true], [sent.size, sent[0][1].length, sent[1][0].length, last_body["truncated"]]
    assert_equal "\u{1F600}" * 2048, sent[1][1]
    dr.bot_check(ip: IP, headers: [["Cookie", "c" * 5000]])
    refute last_body.key?("truncated")
    # Over 32 KB: the long values are cut to one length, the longest that fits; short ones stay whole.
    big = [["User-Agent", "curl/8.4.0"]] + Array.new(20) { |i| ["x-big#{i}", "b" * 4096] }
    dr.bot_check(ip: IP, headers: big)
    call = api.calls.last
    lengths = call["body"]["headers"].drop(1).map { |_, value| value.length }.uniq
    assert_operator call["raw"].bytesize, :<=, B::MAX_BODY_BYTES
    assert_equal [21, ["User-Agent", "curl/8.4.0"], 1, true], [call["body"]["headers"].size, call["body"]["headers"][0], lengths.size, call["body"]["truncated"]]
    assert_operator lengths.first, :<, 4096
    # A long url and cipher list leave less room: every name stays, the values shrink, tls goes before any header.
    names = Array.new(100) { |i| [format("%03d%s", i, "n" * 125), "v" * 100] }
    url = "https://shop.example/#{"\u20AC" * 4000}"
    dr.bot_check(ip: IP, headers: names, url: url, tls: { ciphers: "\u20AC" * 5000 })
    call = api.calls.last
    assert_operator call["raw"].bytesize, :<=, B::MAX_BODY_BYTES
    assert_equal [url, false, names.map(&:first)], [call["body"]["url"], call["body"].key?("tls"), call["body"]["headers"].map(&:first)]
    assert_includes 1...100, call["body"]["headers"][0][1].length
    # A header HTTP does not allow is left out (the API would refuse the whole check), and none at all go as [].
    dr.bot_check(ip: IP, headers: [["X Bad", "1"], ["Caf\u00e9", "2"], ["X-Nul", "a\0b"], ["X-Break", "a\r\nX-Evil: 1"], ["Accept", "*/*"], ["X-None", nil]])
    assert_equal({ "ip" => IP, "headers" => [["Accept", "*/*"]], "truncated" => true }, last_body)
    dr.bot_check(ip: IP, headers: {})
    assert_equal({ "ip" => IP, "headers" => {} }, last_body)
  end

  def test_the_url_method_version_and_tls_go_as_the_api_reads_them
    { "https://Shop.Example:8443/a/b?c=d#e" => "https://Shop.Example:8443/a/b", "https://203.0.113.7/login" => "https://203.0.113.7/login",
      "http://shop.example" => "http://shop.example", "/sign-in?x=1" => "/sign-in",
      "wss://shop.example/socket" => "https://shop.example/socket", "ws://shop.example/socket" => "http://shop.example/socket",
      # The Host header is the visitor's: one the API could not read goes as the path alone.
      "https://exa mple.com/login" => "/login", "https://shop.example.123/login" => "/login", "https://1.2.3.256/login" => "/login",
      "https://shop.example:99999/login" => "/login", "https://[2001:db8::1]/login" => "/login", "https://xn--zz.example/login" => "/login",
      "https://a:b:c/login" => "/login", "https://shop%2eexample/login" => "/login",
      # Anything that is not a path or an http(s) URL is left out, and so is one over 4096 characters (never cut).
      "*" => nil, "ftp://shop.example/x" => nil, "shop.example/x" => nil, "?q=1" => nil,
      "https://shop.example/#{"p" * 4096}" => nil, "/#{"p" * 4095}" => "/#{"p" * 4095}" }.each do |given, sent|
      expect(sent, B.url_of(given), given[0, 60])
    end
    { "GET" => "GET", " post " => "post", "PROPFIND" => "PROPFIND", "M-SEARCH" => nil, "M" * 17 => nil }.each do |given, sent|
      dr.bot_check(ip: IP, headers: [], method: given)
      expect(sent, last_body["method"], given)
    end
    { "1.0" => "1.0", "HTTP/1.1" => "1.1", "HTTP/2.0" => "2", "h2" => "2", 3 => "3", "h3" => "3", "4" => nil, "spdy/3" => nil }.each do |given, sent|
      dr.bot_check(ip: IP, headers: [], http_version: given)
      expect(sent, last_body["httpVersion"], given.to_s)
    end
    dr.bot_check(ip: IP, headers: [], tls: { ciphers: "c" * 5000, ja4: "j" * 129 })
    assert_equal({ "ciphers" => "c" * 4096 }, last_body["tls"])
    dr.bot_check(ip: IP, headers: [], tls: { ja4: "j" * 129 })
    refute last_body.key?("tls")
  end

  def test_the_answer_is_typed_and_keeps_what_this_gem_does_not_know
    api.answer(200, { "bot" => { "result" => "detected", "category" => "ai_assistant", "provider" => "OpenAI", "name" => "ChatGPT-User",
                                 "identity" => "verified", "verifiedBy" => "ip_list", "confidence" => "high", "rule" => "directory.chatgpt_user",
                                 "reasons" => [{ "code" => "ua_token", "text" => "The user agent names ChatGPT-User." },
                                               { "code" => "ip_list", "text" => "The address is in OpenAI's published list.", "weight" => 3 },
                                               "junk", { "text" => "no code" }],
                                 "agentKind" => "assistant" },
                      "network" => { "asn" => 8075, "asnOrg" => "Microsoft Corporation", "countryCode" => "US", "hosting" => true, "type" => "hosting" },
                      "suggestion" => "allow", "rulesVersion" => "2026.11.25-1", "checkedAt" => "2026-11-25T10:00:00.000Z" })
    r = dr.bot_check(ip: "9.129.0.1", headers: [["User-Agent", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"]])
    assert_kind_of B::Result, r
    b = r.bot
    assert_equal ["detected", "ai_assistant", "OpenAI", "ChatGPT-User", "verified", "ip_list", "high", "directory.chatgpt_user"],
                 [b.result, b.category, b.provider, b.name, b.identity, b.verified_by, b.confidence, b.rule]
    assert_equal [%w[ua_token ip_list], ["The user agent names ChatGPT-User.", "The address is in OpenAI's published list."]],
                 [b.reasons.map(&:code), b.reasons.map(&:text)]
    assert_equal [8075, "Microsoft Corporation", "US", true], [r.network.asn, r.network.asn_org, r.network.country_code, r.network.hosting]
    assert_equal %w[allow 2026.11.25-1], [r.suggestion, r.rules_version]
    # Fields added later stay, and it is a Hash with the API's keys too.
    assert_equal [3, "assistant", "hosting", "2026-11-25T10:00:00.000Z"], [b.reasons[1]["weight"], b["agentKind"], r.network["type"], r["checkedAt"]]
    assert_equal "verified", r["bot"]["identity"]
  end

  def test_a_spoofed_name_answers_unverified_and_an_unknown_category_comes_through
    api.answer(200, { "bot" => { "result" => "detected", "category" => "ai_browser", "provider" => "OpenAI", "name" => "GPTBot",
                                 "identity" => "unverified", "verifiedBy" => nil, "confidence" => "high", "rule" => "directory.gptbot",
                                 "reasons" => [{ "code" => "ip_list_mismatch", "text" => "It says GPTBot, but the address is not in OpenAI's list." }] },
                      "network" => nil, "suggestion" => "block", "rulesVersion" => "2026.11.25-1" })
    r = dr.bot_check(ip: IP, headers: [["User-Agent", "Mozilla/5.0 (compatible; GPTBot/1.4; +https://openai.com/gptbot)"]])
    refute_includes B::CATEGORIES, "ai_browser"
    assert_equal ["ai_browser", "unverified", nil, nil, "block"], [r.bot.category, r.bot.identity, r.bot.verified_by, r.network, r.suggestion]
  end

  def test_a_broken_answer_reads_as_nothing_seen
    r = C.parse_bot_check(nil)
    assert_equal ["not_detected", nil, [], nil, "allow", nil], [r.bot.result, r.bot.name, r.bot.reasons, r.network, r.suggestion, r.rules_version]
    r = C.parse_bot_check({ "bot" => { "result" => 7, "identity" => "", "reasons" => "x" }, "network" => { "asn" => "AS8075", "hosting" => "yes" },
                            "suggestion" => 1 })
    assert_equal ["not_detected", nil, [], nil, nil, "allow"], [r.bot.result, r.bot.identity, r.bot.reasons, r.network.asn, r.network.hosting, r.suggestion]
  end

  def test_an_api_error_carries_its_status_and_code
    api.answer(400, { "code" => "invalid_ip", "error" => "ip must be an IPv4 or IPv6 address" })
    err = assert_raises(Touchque::DeviceRisk::APIError) { dr.bot_check(ip: IP, headers: []) }
    assert_equal [400, "invalid_ip", "ip must be an IPv4 or IPv6 address"], [err.status, err.code, err.message]
    api.answer(429, { "code" => "rate_limited", "error" => "Too many bot checks" }, "Retry-After" => "7")
    err = assert_raises(Touchque::DeviceRisk::APIError) { dr.bot_check(ip: IP, headers: []) }
    assert_equal [429, 7], [err.status, err.retry_after]
    api.answer(409, { "code" => "device_risk_off", "error" => "Device risk is off for this workspace" })
    assert_equal "device_risk_off", assert_raises(Touchque::DeviceRisk::APIError) { dr.bot_check(ip: IP, headers: []) }.code
  end

  def test_bot_check_rack_sends_what_the_rack_env_holds
    dr.bot_check_rack(rack_env)
    assert_equal({ "ip" => "203.0.113.9",
                   "headers" => [["host", "shop.example"], ["user-agent", "curl/8.4.0"], ["accept", "*/*"], ["cookie", ""],
                                 ["content-type", "application/x-www-form-urlencoded"], ["content-length", "27"], ["authorization", ""]],
                   "method" => "POST", "url" => "https://shop.example/session" }, last_body)
    # No httpVersion: SERVER_PROTOCOL is the connection to this server (behind a proxy, the proxy's).
    refute_includes api.calls.last["raw"], "s3cret"
    refute_includes api.calls.last["raw"], "email"
    # A request object that answers #env works too; Rack::MethodOverride's original method is the one sent.
    dr.bot_check_rack(Struct.new(:env).new(rack_env("REQUEST_METHOD" => "DELETE", "rack.methodoverride.original_method" => "POST")))
    assert_equal "POST", last_body["method"]
    # An older server keeps the protocol in HTTP_VERSION: not a header; a visitor's own Version header stays one.
    dr.bot_check_rack(rack_env.except("SERVER_PROTOCOL"))
    assert_equal [nil, nil], [last_body["httpVersion"], last_body["headers"].assoc("version")]
    dr.bot_check_rack(rack_env("HTTP_VERSION" => "2").except("SERVER_PROTOCOL"))
    assert_equal [nil, ["version", "2"]], [last_body["httpVersion"], last_body["headers"].assoc("version")]
  end

  def test_bot_check_rack_takes_the_proxy_aware_address_and_leaves_out_the_proxys_http_version
    dr.bot_check_rack(rack_env("REMOTE_ADDR" => "10.0.0.2", "HTTP_X_FORWARDED_FOR" => "198.51.100.23", "action_dispatch.remote_ip" => "198.51.100.23"))
    assert_equal "198.51.100.23", last_body["ip"]
    refute last_body.key?("httpVersion")
    dr.bot_check_rack(rack_env("HTTP_VIA" => "1.1 vegur"), ip: "198.51.100.7", http_version: "HTTP/2")
    assert_equal ["198.51.100.7", "2"], last_body.values_at("ip", "httpVersion")
    # Rails raises on a spoofed Client-Ip header: the check goes on with the next address.
    spoofed = Object.new
    def spoofed.to_s = raise("IP spoofing attack?!")
    dr.bot_check_rack(rack_env("action_dispatch.remote_ip" => spoofed))
    assert_equal "203.0.113.9", last_body["ip"]
    assert_raises(Touchque::DeviceRisk::ConfigError) { dr.bot_check_rack(rack_env("REMOTE_ADDR" => nil)) }
    assert_raises(Touchque::DeviceRisk::ConfigError) { dr.bot_check_rack("not an env") }
  end

  def test_bot_check_rack_asks_rack_for_the_address_when_rack_is_loaded
    skip "Rack itself is loaded" if defined?(::Rack)
    fake = Module.new
    fake.const_set(:Request, Class.new do
      def initialize(env) = (@env = env)
      def ip = @env["HTTP_X_FORWARDED_FOR"].split(",").first.strip
    end)
    Object.const_set(:Rack, fake)
    dr.bot_check_rack(rack_env("REMOTE_ADDR" => "10.0.0.2", "HTTP_X_FORWARDED_FOR" => "198.51.100.40, 10.0.0.2"))
    assert_equal "198.51.100.40", last_body["ip"]
  ensure
    Object.send(:remove_const, :Rack) if fake && defined?(::Rack) && ::Rack.equal?(fake)
  end

  def test_bot_check_rack_never_raises_for_what_the_visitor_sent
    env = { "REQUEST_METHOD" => "GET", "PATH_INFO" => "/", "REMOTE_ADDR" => IP, "HTTP_USER_AGENT" => "caf\xE9 bot".b,
            "HTTP_#{"X" * 200}" => "a long name" }
    20.times { |i| env["HTTP_X_BIG_#{i}"] = "b" * 5000 }
    150.times { |i| env["HTTP_X_PAD_#{i}"] = "p" }
    dr.bot_check_rack(env)
    call = api.calls.last
    sent = call["body"]["headers"]
    assert_operator call["raw"].bytesize, :<=, B::MAX_BODY_BYTES
    assert_equal [["user-agent", "caf� bot"], "x" * 128, "x-big-0", 100, true],
                 [sent[0], sent[1][0], sent[2][0], sent.size, call["body"]["truncated"]]
    assert(sent.all? { |name, value| name.length <= 128 && value.length <= 4096 })
    # The long values shrink to fit 32 KB; the short ones stay whole.
    assert_equal ["p"], sent.select { |name, _| name.start_with?("x-pad") }.map(&:last).uniq
  end
end
