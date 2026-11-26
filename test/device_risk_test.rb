# frozen_string_literal: true

require "test_helper"

# Device risk against the shared fake API: the report goes through untouched and the
# answer fails toward asking. Same scenarios as the Node package's tests.
class DeviceRiskTest < FakeApiTest
  C = Touchque::DeviceRisk::Client

  def test_the_form_field_as_it_came_is_answered_never_raised
    [nil, "", ["x"]].each do |value|
      r = dr.check(value, event: "sign_in", external_username: "ayse@acme.com")
      assert_equal "missing", r["report"]
      assert_nil r["visitorId"]
      assert_equal ["device_identification_missing"], r["signals"].map { |x| x["code"] }
      refute r["stepUp"]
      assert r["wouldStepUp"]
    end
    assert_equal "unknown", dr.check("nope")["report"]
    assert_equal "expired", C.parse_check({ "report" => "expired" })["report"]
  end

  def test_check_sends_the_report_and_reads_the_answer
    r = dr.check("dre_flaggedaaaaaaaaaaaaaaa", event: "sign_up", external_username: "ayse@acme.com", client_ip: "203.0.113.7")
    assert_equal "ok", r["report"]
    assert_equal ["tqv_fakeVisitor00000001", "DRK-2QX", false], [r["visitorId"], r["caseCode"], r["signals"][0]["enforced"]]
    assert_equal "tqv_fakeVisitor00000001", dr.get_event("dre_aaaaaaaaaaaaaaaaaaaaaa")["visitorId"]
    assert_equal [], dr.check(device_risk: "REPORT")["signals"]
    assert_equal ["device_many_accounts"], r["signals"].map { |s| s["code"] }
    assert_equal [false, true, "shadow"], [r["stepUp"], r["wouldStepUp"], r["mode"]]
    assert_nil r["suspect"]
    assert_nil r["accountDevice"]
  end

  def test_bad_input_fails_before_any_request
    assert_raises(Touchque::DeviceRisk::ConfigError) { dr.check(device_risk: "r", event: "tracking") }
    assert_raises(Touchque::DeviceRisk::ConfigError) { dr.get_event("../users") }
    assert_equal [], api.calls
  end

  def test_the_answer_fails_toward_asking
    assert C.parse_check({})["stepUp"]
    refute C.parse_check({ "stepUp" => false })["stepUp"]
    r = C.parse_check({ "signals" => [{ "code" => "device_tampered", "text" => "t" }, nil, { "text" => "x" }], "requires" => "passkey" })
    assert_equal [{ "code" => "device_tampered", "text" => "t", "strength" => "number_match" }], r["signals"]
    assert_equal %w[passkey invalid], [r["requires"], r["report"]]
  end

  def test_engine_unavailable_comes_through_and_a_normal_answer_has_nil
    down = C.parse_check({ "report" => "ok", "signals" => [], "stepUp" => true, "wouldStepUp" => true,
                           "requires" => "number_match", "mode" => "enforce", "engine" => "unavailable" })
    assert_equal ["unavailable", true, "number_match"], [down["engine"], down["stepUp"], down["requires"]]
    normal = C.parse_check({ "report" => "ok", "signals" => [], "stepUp" => false, "requires" => "none", "mode" => "shadow" })
    assert_nil normal["engine"]
    refute normal["stepUp"]
    assert_nil C.parse_check({ "engine" => 42 })["engine"]
  end

  def test_the_address_the_counts_and_a_bot_answer_come_through
    r = C.parse_check({ "report" => "ok", "network" => { "type" => "hosting" }, "velocity" => { "identifications1h" => 2 }, "bot" => { "result" => "suspected" } })
    assert_equal "hosting", r["network"]["type"]
    assert_equal 2, r["velocity"]["identifications1h"]
    assert_equal "suspected", r["bot"]["result"]
    assert_nil C.parse_check({ "network" => "x" })["network"]
  end

  NETWORK_KIND_FIELDS = %w[kind kindSource vpn shared sharedVisitors24h sharedAccounts24h lookAlikeMatching].freeze

  def test_the_network_kind_and_the_shared_fields_come_through_and_an_older_answer_has_none
    network = { "countryCode" => "TR", "asn" => 64_500, "asnOrg" => "Example University", "type" => "isp", "tor" => false,
                "hosting" => false, "hostingProvider" => nil, "proxy" => true, "timezoneMismatch" => false,
                "kind" => "education", "kindSource" => "network", "vpn" => false, "shared" => true,
                "sharedVisitors24h" => 10, "sharedAccounts24h" => 5, "lookAlikeMatching" => false }
    r = C.parse_check({ "report" => "ok", "network" => network, "stepUp" => false })
    assert_equal network, r["network"]
    assert_equal ["education", "network", false, true, 10, 5, false], r["network"].values_at(*NETWORK_KIND_FIELDS)
    assert r["network"]["proxy"]
    # Apple's relay, a VPN company, an open community network and a kind this gem does not list yet (an open
    # list) come through as they are.
    kinds = lambda { |network| C.parse_check({ "network" => network })["network"].values_at("type", "kind", "kindSource", "vpn") }
    assert_equal ["relay", "relay", "address", false], kinds.call({ "type" => "relay", "kind" => "relay", "kindSource" => "address", "vpn" => false })
    assert_equal ["hosting", "vpn", "network", true], kinds.call({ "type" => "hosting", "kind" => "vpn", "kindSource" => "network", "vpn" => true })
    assert_equal ["isp", "public_wifi", "network_open", false], kinds.call({ "type" => "isp", "kind" => "public_wifi", "kindSource" => "network_open", "vpn" => false })
    refute_includes C::NETWORK_KINDS, "satellite"
    assert_equal ["isp", "satellite", "network", false], kinds.call({ "type" => "isp", "kind" => "satellite", "kindSource" => "network", "vpn" => false })
    # An older server sends none of them; one that does sends null for an identification it did not classify or count.
    older = C.parse_check({ "network" => { "countryCode" => "DE", "type" => "isp", "tor" => false, "hosting" => false } })["network"]
    assert_equal [nil] * NETWORK_KIND_FIELDS.size, older.values_at(*NETWORK_KIND_FIELDS)
    not_classified = NETWORK_KIND_FIELDS.to_h { |f| [f, nil] }
    assert_equal not_classified, C.parse_check({ "network" => not_classified })["network"]
    assert_equal %w[residential mobile_carrier education business public_wifi hosting proxy vpn tor relay unknown], C::NETWORK_KINDS
  end

  def test_the_ai_agents_and_the_new_bot_reasons_come_through
    bot = { "result" => "detected", "type" => "ai_agent",
            "reasons" => %w[tool_claude_agent tool_comet_agent tool_genspark_agent tool_browser_use tool_stagehand tool_skyvern
                            pointer_synthetic headless_window emulator cdp cdp_input input_no_focus insert_text_bulk scripted_click soft_gpu],
            "tools" => %w[claude_agent comet_agent genspark_agent browser_use stagehand skyvern],
            "agent" => nil, "input" => %w[insert_no_keys] }
    r = C.parse_check({ "report" => "ok", "bot" => bot })
    assert_equal bot, r["bot"]
    assert_equal r["bot"]["tools"].map { |t| "tool_#{t}" }, r["bot"]["reasons"].grep(/\Atool_/)
    # A tool or reason this gem does not document yet comes through too.
    assert_equal ["tool_new_agent"], C.parse_check({ "bot" => { "result" => "detected", "reasons" => ["tool_new_agent"], "tools" => ["new_agent"] } })["bot"]["reasons"]
  end

  def test_the_suspect_score_and_the_account_device_are_read
    r = C.parse_check({ "report" => "ok",
                        "suspect" => { "score" => 64, "band" => "high", "wouldDo" => "passkey", "mode" => "shadow", "reasons" => [
                          { "code" => "abuse_card_testing", "points" => 40, "by" => "site", "text" => "Cards tested" },
                          { "code" => "known_browser", "points" => -10, "by" => "server", "text" => "Seen before" }, "junk"
                        ] },
                        "accountDevice" => { "status" => "likely", "visitorId" => "tqv_other00000000000000" } })
    s = r["suspect"]
    assert_equal [64, "high", "passkey", "shadow"], [s["score"], s["band"], s["wouldDo"], s["mode"]]
    assert_equal %w[abuse_card_testing known_browser], s["reasons"].map { |x| x["code"] }
    assert_equal %w[site server], s["reasons"].map { |x| x["by"] }
    assert_equal({ "status" => "likely", "visitorId" => "tqv_other00000000000000" }, r["accountDevice"])
    assert_nil C.parse_suspect({ "score" => "x" })
    assert_equal [100, "critical"], C.parse_suspect({ "score" => 130 }).values_at("score", "band")
    assert_nil C.parse_account_device({ "status" => "maybe" })
    assert_includes C::MATCHED_BY, "fpc"
  end

  def test_search_events_pages_with_the_opaque_cursor_and_sends_the_filters
    first = dr.search_events(account: "ada@example.com", step_up: false, ip: "203.0.113.0/24", limit: 1)
    assert_equal({ "account" => "ada@example.com", "stepUp" => "false", "ip" => "203.0.113.0/24", "limit" => "1" }, api.last_device_risk_search)
    assert_equal ["dre_fakeEvent00000000002"], first["events"].map { |e| e["requestId"] }
    assert_nil first["nextCursor"]
    seen = []
    cursor = nil
    loop do
      page = dr.search_events(limit: 1, cursor: cursor)
      seen.concat(page["events"].map { |e| e["requestId"] })
      cursor = page["nextCursor"]
      break unless cursor
    end
    assert_equal %w[dre_fakeEvent00000000003 dre_fakeEvent00000000002 dre_fakeEvent00000000001], seen
    assert_raises(Touchque::DeviceRisk::ConfigError) { dr.search_events(limit: 101) }
    assert_raises(Touchque::DeviceRisk::ConfigError) { dr.search_events(page: 2) }
  end

  def test_search_events_sends_the_network_kind_and_shared
    page = dr.search_events(network_kind: "education", shared: true, account: "ada@example.com")
    assert_equal({ "networkKind" => "education", "shared" => "true", "account" => "ada@example.com" }, api.last_device_risk_search)
    assert_equal %w[dre_fakeEvent00000000003 dre_fakeEvent00000000002], page["events"].map { |e| e["requestId"] }
    dr.search_events(network_kind: "vpn", shared: false, step_up: true)
    assert_equal({ "networkKind" => "vpn", "shared" => "false", "stepUp" => "true" }, api.last_device_risk_search)
    # An open list: a kind this gem does not list yet still goes (the API answers 400 invalid_network_kind for a wrong one).
    dr.search_events(network_kind: "satellite")
    assert_equal({ "networkKind" => "satellite" }, api.last_device_risk_search)
    # Left out, nil or empty: no filter, as before.
    dr.search_events(network_kind: "", shared: nil)
    assert_equal({}, api.last_device_risk_search)
    assert_raises(Touchque::DeviceRisk::ConfigError) { dr.search_events(networkKind: "vpn") }
  end

  def test_feature_refusals_are_typed
    { "feature_not_in_plan" => [Touchque::DeviceRisk::FeatureNotInPlanError, :not_in_plan],
      "feature_read_only" => [Touchque::DeviceRisk::FeatureReadOnlyError, :read_only],
      "feature_off" => [Touchque::DeviceRisk::FeatureOffError, :off] }.each do |code, (klass, reason)|
      api.opts({ featureRefused: code, feature: "device_risk" })
      err = assert_raises(klass) { dr.check("dre_aaaaaaaaaaaaaaaaaaaaaa") }
      assert_kind_of Touchque::DeviceRisk::APIError, err
      assert_equal [403, "device_risk", reason], [err.status, err.feature, err.feature_reason]
    end
  end

  def test_an_api_error_carries_its_status_and_code
    err = assert_raises(Touchque::DeviceRisk::APIError) { dr.get_event("dre_unknownaaaaaaaaaaaaaaa") }
    refute_kind_of Touchque::DeviceRisk::FeatureError, err
    assert_equal [404, "not_found"], [err.status, err.code]
  end

  def test_the_webhook_event_names
    assert_equal "DEVICE_RISK_SIGNAL", Touchque::DeviceRisk::WebhookEvents::DEVICE_RISK_SIGNAL
    assert_equal "DEVICE_RISK_ALERT", Touchque::DeviceRisk::WebhookEvents::DEVICE_RISK_ALERT
  end

  def test_visitor_mark_is_the_mark_applied_step_up_always_trusted_only_on_a_key_or_sid_match
    key_match = "dre_#{"a" * 22}"
    trait_match = "dre_flagged#{"a" * 15}"
    assert_equal ["none", nil], dr.check(key_match)["visitor"].values_at("status", "mark")
    api.opts(deviceMark: "trusted")
    assert_equal %w[trusted trusted key], dr.check(key_match)["visitor"].values_at("status", "mark", "matchedBy")
    assert_equal ["trusted", nil, "traits"], dr.check(trait_match)["visitor"].values_at("status", "mark", "matchedBy")
    assert_equal %w[trusted trusted], dr.get_event(key_match)["visitor"].values_at("status", "mark")
    api.opts(deviceMark: "step_up")
    assert_equal %w[step_up step_up], dr.check(trait_match)["visitor"].values_at("status", "mark")
  end

  def test_an_unknown_visitor_mark_reads_as_nil_and_an_older_answer_has_none
    parse = ->(visitor) { C.parse_check({ "visitor" => visitor })["visitor"] }
    assert_equal({ "status" => "trusted", "mark" => nil }, parse.call({ "status" => "trusted", "mark" => "admin" }))
    assert_equal "step_up", parse.call({ "status" => "step_up", "mark" => "step_up" })["mark"]
    refute parse.call({ "status" => "none" }).key?("mark")
    assert_nil parse.call("x")
  end
end
