# frozen_string_literal: true

require "test_helper"

# activity: what the server saw, against the shared fake Touchque API. A card number never leaves.
class ActivityTest < FakeApiTest
  def test_a_payment_is_sent_and_recorded
    a = dr.activity(type: "payment_attempt", request_id: "dre_aaaaaaaaaaaaaaaaaaaaaa", client_ip: "203.0.113.7",
                    external_username: "ayse@acme.com", outcome: "declined", card: { bin: "411111", last4: "1111" })
    assert_equal({ "recorded" => true, "visitorId" => "tqv_fakeVisitor00000001", "signals" => [] }, a)
    assert_equal({ "type" => "payment_attempt", "requestId" => "dre_aaaaaaaaaaaaaaaaaaaaaa", "clientIp" => "203.0.113.7",
                   "externalUsername" => "ayse@acme.com", "outcome" => "declined", "card" => { "bin" => "411111", "last4" => "1111" } },
                 api.last_device_risk_activity)
  end

  def test_a_flagged_visitor_raises_card_testing
    a = dr.activity(type: "payment_attempt", request_id: "dre_flaggedaaaaaaaaaaaaaaa", outcome: "declined", card: { "bin" => "41111111", "last4" => "0004" })
    assert_equal ["abuse_card_testing"], a["signals"]
    assert a["recorded"]
  end

  def test_a_probed_path_answers_its_class
    a = dr.activity(type: "not_found", client_ip: "203.0.113.7", path: "/.env")
    assert_equal "secrets", a["pathClass"]
    assert_nil a["visitorId"]
    assert_equal [], a["signals"]
  end

  def test_a_card_number_is_refused_before_anything_is_sent
    [{ number: "4111111111111111" }, { bin: "411111", last4: "1111", pan: "4111111111111111" },
     { bin: "4111111111111111", last4: "1111" }, "4111111111111111", 4_111_111_111_111_111,
     { bin: "411111", last4: "111" }, { bin: 411_111, last4: "1111" }].each do |card|
      err = assert_raises(Touchque::DeviceRisk::ConfigError) { dr.activity(type: "payment_attempt", client_ip: "203.0.113.7", card: card) }
      assert_includes err.message, "never send the card number"
    end
    assert_equal({}, api.last_device_risk_activity)
    assert_equal [], api.calls
  end

  def test_wrong_fields_are_refused_before_any_request
    [{ type: "tracking", client_ip: "203.0.113.7" },
     { type: "login_failed" },
     { type: "login_failed", request_id: ["x"] },
     { type: "payment_attempt", client_ip: "203.0.113.7", outcome: "maybe" },
     { type: "otp_sent", client_ip: "203.0.113.7", phone: "call me" },
     { type: "login_failed", client_ip: "203.0.113.7", external_username: "a" * 256 },
     { type: "not_found", client_ip: "203.0.113.7", path: "/#{"a" * 2048}" },
     { type: "login_failed", client_ip: 42 }].each do |activity|
      assert_raises(Touchque::DeviceRisk::ConfigError, activity.inspect) { dr.activity(**activity) }
    end
    assert_raises(ArgumentError) { dr.activity(type: "login_failed", client_ip: "203.0.113.7", card_number: "4111111111111111") }
    assert_equal [], api.calls
  end

  def test_the_answer_is_read_strictly
    assert_equal({ "recorded" => false, "visitorId" => nil, "signals" => [] }, Touchque::DeviceRisk::Client.parse_activity(nil))
    assert_equal({ "recorded" => false, "visitorId" => nil, "signals" => ["abuse_probing"] },
                 Touchque::DeviceRisk::Client.parse_activity({ "recorded" => "yes", "signals" => ["abuse_probing", 7], "pathClass" => "nowhere" }))
  end
end
