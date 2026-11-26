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
- `bot`: one answer to "a bot, and what kind?": `result` (detected, suspected, not_detected), `reasons`, `type`
  (ai_agent, automation, script), `tools`, `agent` and `input`. `tools` names the automation tools (`selenium`,
  `playwright`, `puppeteer`, `phantomjs`, `nightmare`, `headless_chrome`) and the AI agents (`claude_agent`: the
  Claude app's browser or Claude in Chrome; `comet_agent`: Perplexity Comet; `genspark_agent`, `browser_use`,
  `stagehand`, `skyvern`) whose marks were on the page, each also a reason `tool_<name>`. Other reasons include
  `cdp_input` (a press with no pressure: only the DevTools protocol sends it), `input_no_focus` (a click or key
  into a page that was not in front), `insert_text_bulk` (text that arrived whole, no key pressed),
  `scripted_click` (a form sent with no click or key), `headless_window` and `emulator`. Plain strings: new tools
  and reasons may be added. Servers before 2026-11-25 send neither the AI agents nor `cdp_input`,
  `input_no_focus`, `insert_text_bulk` or `scripted_click`.

For a sign-in approved on the phone with the main Touchque gem, pass the same field as
`device_risk_request_id:` to its `login.request` or `risk.check` instead.

### The network

`network` (in `check`, `get_event` and each `search_events` item) is the address as the risk engine saw it,
never coordinates: `countryCode`, `city`, `asn`, `asnOrg`, `type` (isp, hosting, tor, relay: Apple's iCloud
Private Relay, or unknown), `proxy` (on a public proxy list in the last 30 days: context, often a home or school
line resold to a proxy network; absent on older servers) and more. Newer servers add these (absent on older
ones; nil when not classified or counted, as for an identification made before them):

- `kind`: `residential`, `mobile_carrier`, `education`, `business`, `public_wifi`, `hosting`, `proxy`, `vpn`,
  `tor`, `relay` or `unknown` (`Client::NETWORK_KINDS`). An open list: new values may be added in minor
  versions. `kindSource` says where it came from (`address`, `network`, `mixed`, `network_open`, `name`).
- `vpn`: a VPN company's own address (the suspect score's `network_vpn`, 10 points).
- `shared`: many browsers used this address on your pages in the last 24 hours (10 or more, or 5 or more accounts
  from 3 or more browsers), usually a school, an office, a café or a mobile operator: context only
  (`network_shared`, 0 points). `sharedVisitors24h` and `sharedAccounts24h` are "at least" counts (1, 2, 5, 10,
  100 or 1000). They describe the identification's own address: nil when the answer is about another one.
- `lookAlikeMatching`: `false` when Touchque recognised this computer only by its own key, cookie or stored id
  (identical computers in use on its address, or a school, company or public Wi-Fi network on Touchque's list;
  `network_look_alike_off`, 0 points), `true` when look-alike matching was allowed, nil when not decided (a
  phone, a tablet or Safari).

Touchque uses the IP2Proxy LITE database for [proxy and VPN detection](https://www.ip2location.com).
This site or product includes IP2Proxy LITE data available from https://lite.ip2location.com.

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

Filters: `from:`, `to:` (7 days by default, at most 90), `signal:`, `step_up:`, `kind:` (the page), `origin:`,
`ip:` (an address or a CIDR range, never returned), `account:`, `visitor_id:`, `request_id:`, `network_kind:`,
`shared:`, `limit:` (1 to 100) and the opaque `cursor:`. A search that would read too much is a 422
`search_too_broad`.

```ruby
page = dr.search_events(network_kind: "education", shared: true)   # school networks, shared addresses only
```

- `network_kind:` is a `network["kind"]` (sent as `networkKind`). It matches only identifications classified
  since network kind exists: older ones never match. An unknown value is a 400 `invalid_network_kind`.
- `shared: true` keeps the identifications whose own address was shared; `shared: false` keeps the ones counted
  and not shared, so an identification that was not counted matches neither.
- Older servers ignore both and answer as without them.

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

## Bot check

Many bots never run your page's JavaScript, so the page tag never sees them: ChatGPT-User, GPTBot,
Meta's crawlers, Grok's fetches, curl and scripts. Send one request's address and headers from your
server, and Touchque answers which bot it is, whether that identity is proven and what it would do. It
decides on its own servers with its own data, and never logs or stores header values.

```ruby
# Rails: in a controller, for the request it is answering
r = dr.bot_check_rack(request.env)
r.bot.result     # "detected", "suspected" or "not_detected"
r.bot.name       # "ChatGPT-User" (r.bot.provider: "OpenAI"), or nil
r.bot.identity   # "verified", "unverified" (a spoofed name) or "claimed"
head :forbidden if r.suggestion == "block"   # advice in shadow: Touchque never enforces it
```

- `bot_check_rack` reads the address (`request.remote_ip`: set your trusted proxies), the headers in the
  order the server kept them, the method, the host and the path (never the query string). It never sends
  the env's own HTTP version: behind a proxy that is the proxy's connection, not the visitor's.
- Outside Rack: `dr.bot_check(ip:, headers: [[name, value], ...], method:, url:)`, the headers in the order
  received (`[]` for a request that had none). Pass `http_version:` and `tls: { ciphers:, ja4: }` (to
  either method) only when your edge tells you what the visitor's were. `Authorization`, `Cookie`,
  `Proxy-Authorization`, `X-Api-Key` and `Set-Cookie` go with empty values.
- What the visitor sent never raises: the first 100 headers go, a name is cut to 128 characters and a value
  to 4096, the request is kept under 32 KB, and `"truncated" => true` tells Touchque so. A header HTTP does
  not allow, a method other than 1 to 16 letters or a URL Touchque could not read is left out. Only no
  `ip` (or one that is not an address) or a wrong shape raises `ConfigError`, before anything is sent.
- The answer is a `BotCheck::Result` (a Hash with a reader per field): `bot` (`result`, `category`,
  `provider`, `name`, `identity`, `verified_by`, `confidence`, `rule`, `reasons` with `code` and `text`),
  `network` (`asn`, `asn_org`, `country_code`, `hosting`) or nil, `suggestion` and `rules_version`. New
  fields and values come through as they are.
- `suggestion`: `allow` (a verified bot, a declared crawler, assistant or other bot Touchque cannot check, or
  no bot), `block` (a spoofed name) or `challenge` (an AI agent that only names itself, since it acts for a
  person; an HTTP client, a headless browser or a browser whose claims contradict each other; or a suspected
  bot).

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

The tests run against the shared fake Touchque API (`testing/fake-touchque-api.mjs`, Node.js); the bot
check tests against a small local fake that checks request signatures the same way (`test/bot_check_test.rb`).

## License

MIT
