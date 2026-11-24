# frozen_string_literal: true

require_relative "lib/touchque/device_risk/version"

Gem::Specification.new do |spec|
  spec.name = "touchque-device-risk"
  spec.version = Touchque::DeviceRisk::VERSION
  spec.authors = ["Touchque"]
  spec.email = ["developer@touchque.com"]
  spec.summary = "Official Ruby server SDK for Touchque Device Risk: check a page's device identification, read and search identifications, report abuse activity."
  spec.description = "Server SDK for Touchque Device Risk: a visitor ID for every browser on your sign-up, reset, sign-in or approval page, a risk verdict, and the abuse your server sees."
  spec.homepage = "https://touchque.com"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"
  spec.metadata = {
    "source_code_uri" => "https://github.com/Touchque/touchque-device-risk-ruby",
    "changelog_uri" => "https://github.com/Touchque/touchque-device-risk-ruby/blob/main/CHANGELOG.md",
    "documentation_uri" => "https://support.touchque.com",
    "rubygems_mfa_required" => "true"
  }
  spec.files = Dir["lib/**/*.rb", "README.md", "CHANGELOG.md", "LICENSE"]
  spec.require_paths = ["lib"]
  # Only the standard library (net/http, openssl, json) at run time.
end
