# frozen_string_literal: true

require_relative "device_risk/version"
require_relative "device_risk/errors"
require_relative "device_risk/util"
require_relative "device_risk/http"
require_relative "device_risk/client"

module Touchque
  # Touchque Device Risk: a visitor ID for every browser on your sign-up, password-reset,
  # sign-in or approval page, a risk verdict for the account it is used for, and the
  # abuse your server sees.
  #
  #   # TQ_API_KEY=tq_...  TQ_API_SECRET=...
  #   dr = Touchque::DeviceRisk::Client.new
  #   r = dr.check(params[:touchque_request_id], event: "sign_in", external_username: email)
  module DeviceRisk
    # The +event+ values of Device risk's webhook events. Verify the webhook with the
    # main Touchque gem (tq.webhook), then compare its +event+ with these. Ignore types
    # you do not know.
    module WebhookEvents
      # An identification or a check raised a signal that asks for more. Never a trait.
      DEVICE_RISK_SIGNAL = "DEVICE_RISK_SIGNAL"
      # An alert rule of the workspace went off.
      DEVICE_RISK_ALERT = "DEVICE_RISK_ALERT"
    end
  end
end
