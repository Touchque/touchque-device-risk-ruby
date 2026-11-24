# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "touchque/device_risk"
require "minitest/autorun"
require "json"
require "net/http"
require "open3"

module TestSupport
  # Where the shared fake API lives (sdks/ in the monorepo, next to the package in a
  # split repo).
  def self.shared_root
    @shared_root ||= begin
      dir = File.expand_path("..", __dir__)
      dir = File.dirname(dir) until File.exist?(File.join(dir, "testing", "fake-touchque-api.mjs")) || dir == "/"
      raise "testing/fake-touchque-api.mjs not found" if dir == "/"

      dir
    end
  end

  # The shared Node fake Touchque API (sdks/testing/fake-touchque-api.mjs): it verifies
  # this SDK's request signatures exactly like the real API, over a real HTTP round trip.
  class FakeApi
    attr_reader :base_url

    def self.instance
      @instance ||= new.tap do |api|
        Minitest.after_run { api.close }
      end
    end

    def initialize
      @stdin, @stdout, @stderr, @wait = Open3.popen3("node", File.join(TestSupport.shared_root, "testing", "fake-touchque-api.mjs"))
      line = @stdout.gets
      @base_url = "http://127.0.0.1:#{JSON.parse(line)["port"]}"
      Thread.new { @stderr.each_line { |_| nil } }
    end

    def close
      Process.kill("TERM", @wait.pid)
    rescue Errno::ESRCH
      nil
    end

    def client
      Touchque::DeviceRisk::Client.new(api_key: "tq_test_key", api_secret: "test_secret", base_url: @base_url)
    end

    def post(path, body = {})
      uri = URI("#{@base_url}#{path}")
      res = Net::HTTP.post(uri, JSON.generate(body), "Content-Type" => "application/json")
      JSON.parse(res.body)
    end

    def get(path)
      JSON.parse(Net::HTTP.get(URI("#{@base_url}#{path}")))
    end

    def reset = post("/__test/reset")
    def opts(options) = post("/__test/opts", options)
    def calls = get("/__test/calls")
    def last_device_risk_search = get("/__test/last-device-risk-search")
    def last_device_risk_activity = get("/__test/last-device-risk-activity")
  end
end

# Tests against the fake API: one node process for the whole run, state reset per test.
class FakeApiTest < Minitest::Test
  def api
    TestSupport::FakeApi.instance
  end

  def dr
    api.client
  end

  def setup
    api.reset
  end
end
