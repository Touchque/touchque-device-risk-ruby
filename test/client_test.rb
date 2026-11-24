# frozen_string_literal: true

require "test_helper"
require "socket"

# The client's configuration and transport, as in the main Touchque gem.
class ClientTest < Minitest::Test
  def with_env(vars)
    old = vars.keys.to_h { |k| [k, ENV.fetch(k, nil)] }
    vars.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    yield
  ensure
    old.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end

  def test_keys_come_from_the_arguments_or_the_environment
    with_env("TQ_API_KEY" => nil, "TQ_API_SECRET" => nil, "TQ_API_URL" => nil) do
      assert_raises(Touchque::DeviceRisk::ConfigError) { Touchque::DeviceRisk::Client.new }
      assert_raises(Touchque::DeviceRisk::ConfigError) { Touchque::DeviceRisk::Client.new(api_key: "wrong", api_secret: "s") }
    end
    with_env("TQ_API_KEY" => "tq_env", "TQ_API_SECRET" => "env_secret", "TQ_API_URL" => "https://custom.example.com/") do
      assert_includes Touchque::DeviceRisk::Client.new.inspect, "https://custom.example.com"
    end
  end

  def test_plaintext_http_only_to_loopback
    assert_raises(Touchque::DeviceRisk::ConfigError) { Touchque::DeviceRisk::Client.new(api_key: "tq_x", api_secret: "s", base_url: "http://api.example.com") }
    Touchque::DeviceRisk::Client.new(api_key: "tq_x", api_secret: "s", base_url: "http://127.0.0.1:9999")
    Touchque::DeviceRisk::Client.new(api_key: "tq_x", api_secret: "s", base_url: "http://[::1]:3000")
  end

  def test_the_secret_is_never_shown
    c = Touchque::DeviceRisk::Client.new(api_key: "tq_x", api_secret: "very_secret", base_url: "https://api.example.com")
    refute_includes c.inspect, "very_secret"
    refute_includes c.instance_variable_get(:@http).inspect, "very_secret"
  end

  def test_the_signature_is_the_main_sdks
    sig = Touchque::DeviceRisk::HTTP.sign("secret", "post", "/device-risk/check", "{}", "1700000000000", "abcd")
    expected = OpenSSL::HMAC.hexdigest("SHA256", "secret", "POST:/device-risk/check:1700000000000:abcd:#{OpenSSL::Digest::SHA256.hexdigest("{}")}")
    assert_equal expected, sig
  end

  def test_a_redirect_is_an_error_and_no_server_a_network_error
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    thread = Thread.new do
      conn = server.accept
      while (line = conn.gets) && line != "\r\n"; end
      conn.write("HTTP/1.1 301 Moved\r\nLocation: https://touchque.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
      conn.close
    end
    dr = Touchque::DeviceRisk::Client.new(api_key: "tq_x", api_secret: "s", base_url: "http://127.0.0.1:#{port}")
    err = assert_raises(Touchque::DeviceRisk::APIError) { dr.check("dre_aaaaaaaaaaaaaaaaaaaaaa") }
    assert_equal 301, err.status
    assert_includes err.message, "redirect"
    thread.join
    server.close
    gone = Touchque::DeviceRisk::Client.new(api_key: "tq_x", api_secret: "s", base_url: "http://127.0.0.1:#{port}", timeout: 2)
    assert_raises(Touchque::DeviceRisk::NetworkError) { gone.check(nil) }
  end
end
