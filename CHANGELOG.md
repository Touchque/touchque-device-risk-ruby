# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] — 2026-11-24

### Added
- **Touchque Device Risk as its own gem.** Device risk leaves the main `touchque` gem (6.0.0 no longer has `tq.device_risk`): `Touchque::DeviceRisk::Client.new(api_key:, api_secret:, base_url:, timeout:)` with its own small client (the same API key and secret, `TQ_API_KEY` / `TQ_API_SECRET` / `TQ_API_URL`, the same request signing, timeout and errors as the main gem, under `Touchque::DeviceRisk`). `require "touchque/device_risk"`.
- `check(request_id, event:, external_username:, client_ip:, device_risk:)` (`POST /device-risk/check`), `get_event(request_id)` (`GET /device-risk/events/{requestId}`), `search_events(...)` (`GET /device-risk/events`) and `Client.parse_check`, as they were on `tq.device_risk`.
- **`activity(type:, ...)`: report what a visitor did that your server saw** (`POST /device-risk/activity`): `type:` (`payment_attempt`, `login_failed`, `not_found`, `forbidden`, `otp_sent`, `code_failed`), `request_id:`, `visitor_id:`, `client_ip:`, `external_username:`, `outcome:` (`approved`, `declined`, `error`), `card:` (`{ bin: 6-8 digits, last4: 4 digits }`), `phone:`, `path:`. Answers `recorded`, `visitorId`, `signals` (`abuse_card_testing`, `abuse_card_shared`, `abuse_login_failures`, `abuse_probing`, `abuse_otp_pumping`, `abuse_code_guessing`) and `pathClass`. A card that is not exactly a BIN and the last 4 digits (a card number, a `number` or `pan` key) raises `ConfigError` before anything is sent.
- `check` answers carry `suspect` (the suspect score in shadow: `score` 0-100, `band`, `wouldDo`, `mode`, `reasons` with `code`, `points`, `by`, `text`) and `accountDevice` (`status` known, likely, new or first, `visitorId`, `since`); `Client.parse_suspect` and `Client.parse_account_device` read them from `get_event` answers and `search_events` rows. `Client::MATCHED_BY` lists `fpc` (the first-party cookie).
- `Touchque::DeviceRisk::WebhookEvents::DEVICE_RISK_SIGNAL` and `DEVICE_RISK_ALERT` (were `Webhook::EVENT_DEVICE_RISK_*` in the main gem).
- The `bot` hash of `check`, `get_event` and each `search_events` item carries `type` (`ai_agent`, `automation`, `script` or nil), `tools`, `agent` and `input` on servers since 2026-11-24; the API can return the signal codes `device_input_synthetic` and `device_ai_agent` (a number-matched step-up only, never a block).
