# touchque-device-risk

The official Ruby server SDK for **Touchque Device Risk**: a visitor ID for every browser on your
sign-up, password-reset, sign-in or approval page, a risk verdict for the account it is used for, and
the abuse your server sees (card testing, failed sign-ins, probing, SMS pumping, code guessing).

Device Risk is a paid add-on: it answers 409 `device_risk_off` until your workspace turns it on in the
[Touchque dashboard](https://dashboard.touchque.com).

Full docs: **[support.touchque.com](https://support.touchque.com)**

## Install

```ruby
# Gemfile
gem "touchque-device-risk"
```

## Setup

The same API key and secret as the main Touchque gem:

```bash
TQ_API_KEY=tq_your_key
TQ_API_SECRET=your_api_secret
```

```ruby
require "touchque/device_risk"

dr = Touchque::DeviceRisk::Client.new                                   # reads the environment
dr = Touchque::DeviceRisk::Client.new(api_key: key, api_secret: secret, timeout: 10) # or explicit (seconds)
```

Every call is signed with your API secret: keep it on your server. Thread-safe: create one and reuse it.

## Check a page's identification

The page identifies the browser with `@touchque/device-risk` (the script tag `device.js` fills a
`touchque_request_id` field in your form, or `identify({ siteKey, purpose })` gives a `requestId`). Never
trust the page's copy: check it on your server.

```ruby
r = dr.check(params[:touchque_request_id], event: "sign_up", external_username: email, client_ip: request.remote_ip)
ask_for_email_code if r["stepUp"]   # a step-up, never a refusal on it alone
```

- Pass the field as it came: missing, empty, made up or expired is still a verdict (`"report"`:
  `missing`, `unknown`, `expired`, `invalid`; the signal `device_identification_missing`), never an exception.
- `event:`: `sign_in` (default), `sign_up`, `password_reset` or `approval` (`Client::EVENTS`).
- The answer: `report`, `requestId`, `visitorId`, `confidence`, `visitor`, `counts`, `network`,
  `velocity`, `bot`, `accountDevice`, `suspect`, `signals`, `stepUp`, `wouldStepUp`, `requires`, `mode`,
  `engine`, `caseCode`. It fails toward asking: `stepUp` is true unless the API says exactly false.
- `suspect` is the suspect score, in shadow (it decides nothing yet): `score` 0-100, `band`
  (low, medium, high, critical), `wouldDo` (allow, number_match, passkey, block) and `reasons`
  (`code`, `points`, `by`: server, site, page or brand, `text`).
- `accountDevice`: did this account use the device before? `status` known, likely, new or first.

For a sign-in approved on the phone with the main Touchque gem, pass the same field as
`device_risk_request_id:` to its `login.request` or `risk.check` instead.

## Read and search identifications

```ruby
event = dr.get_event("dre_...")   # the trusted identification, the verdict, accountDevice, suspect
suspect = Touchque::DeviceRisk::Client.parse_suspect(event["suspect"])

cursor = nil
loop do
  page = dr.search_events(account: "ada@example.com", step_up: true, limit: 50, cursor: cursor)
  page["events"].each { |e| puts e["requestId"] }
  break unless (cursor = page["nextCursor"])
end
```

Filters: `from:`, `to:` (7 days by default, at most 90), `signal:`, `step_up:`, `kind:`, `origin:`, `ip:`
(an address or a CIDR range, never returned), `account:`, `visitor_id:`, `request_id:`, `limit:` (1 to 100)
and the opaque `cursor:`. A search that would read too much is a 422 `search_too_broad`.

## Report what your server saw

```ruby
a = dr.activity(type: "payment_attempt", request_id: params[:touchque_request_id], client_ip: request.remote_ip,
                external_username: email, outcome: "declined", card: { bin: "411111", last4: "1111" })
stop_taking_cards if a["signals"].include?("abuse_card_testing")
```

- `type:`: `payment_attempt`, `login_failed`, `not_found`, `forbidden` (with `path:`), `otp_sent` (with
  `phone:`), `code_failed` (a wrong coupon or gift-card code).
- Name the visitor with `request_id:`, `visitor_id:` or `client_ip:` (a bot that never runs your page
  still counts on its network).
- The answer: `recorded`, `visitorId`, `signals` (`abuse_card_testing`, `abuse_card_shared`,
  `abuse_login_failures`, `abuse_probing`, `abuse_otp_pumping`, `abuse_code_guessing`) and, for a path,
  `pathClass`. For 24 hours the visitor's next checks carry those signals and the suspect score weighs them.
- A card is its BIN (6 to 8 digits) and last 4 digits only. Anything else (a card number, a `number`
  or `pan` key) raises `Touchque::DeviceRisk::ConfigError` before anything is sent.

## Webhooks

Verify Touchque webhooks with the main Touchque gem, then compare `event` with
`Touchque::DeviceRisk::WebhookEvents::DEVICE_RISK_SIGNAL` (a signal that asks for more) or
`DEVICE_RISK_ALERT` (an alert rule of the workspace went off).

## Errors

All under `Touchque::DeviceRisk`, subclasses of `Error`:

- `ConfigError`: a wrong argument or configuration (nothing was sent).
- `APIError`: the API answered an error (`status`, `code`, `retry_after`, `case_code`); a redirect is an error too.
- `FeatureError` (`FeatureNotInPlanError`, `FeatureReadOnlyError`, `FeatureOffError`): Device risk is not
  in your organization's plan, being turned off, or switched off on this deployment.
- `NetworkError`: the request never reached Touchque.

## Tests

```bash
bundle install
bundle exec rake test
```

The tests run against the shared fake Touchque API (`testing/fake-touchque-api.mjs`, Node.js).

## License

MIT
