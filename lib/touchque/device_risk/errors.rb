# frozen_string_literal: true

module Touchque
  module DeviceRisk
    # Base class of every error this gem raises.
    class Error < StandardError; end

    # Touchque answered with an error (status 400 or more, or a redirect). +status+ is the
    # HTTP status, +code+ the machine-readable code (+device_risk_off+,
    # +card_number_not_allowed+...) and +data+ the decoded JSON body.
    class APIError < Error
      attr_reader :status, :data

      def initialize(status, data = nil, message = nil)
        @status = status
        @data = data.is_a?(Hash) ? data : {}
        super(message || @data["message"] || @data["error"] || "Touchque API error: HTTP #{status}")
      end

      # Machine-readable error code, e.g. "device_risk_off".
      def code
        @data["code"]
      end

      # The API's +error+ field.
      def error
        @data["error"]
      end

      # Seconds to wait before retrying (429).
      def retry_after
        @data["retryAfter"]
      end

      # "Why?" case code of a refusal (+K7P-2QX+): your team opens the decision by it in
      # the dashboard.
      def case_code
        @data["caseCode"].is_a?(String) ? @data["caseCode"] : nil
      end

      # The error for an answer: a FeatureError subclass for the three feature
      # codes, else APIError.
      def self.for(status, data = nil, message = nil)
        klass = data.is_a?(Hash) ? FeatureError::BY_ERROR[data["error"]] : nil
        (klass || APIError).new(status, data, message)
      end
    end

    # The organization behind your workspace cannot use this feature here (HTTP
    # 403). +feature_reason+:
    # - +:not_in_plan+: not in its plan (+feature_not_in_plan+); an owner or admin
    #   adds it in the Touchque dashboard;
    # - +:read_only+: being turned off (+feature_read_only+); reads still work for
    #   14 days, changes are refused;
    # - +:off+: switched off on this Touchque deployment (+feature_off+).
    # +feature+ is the catalog id (+device_risk+). An APIError, so existing +rescue+
    # blocks still catch it; rescue one of the three subclasses to tell them apart.
    class FeatureError < APIError
      REASON = nil

      # The catalog id of the feature, or nil.
      def feature
        @data["feature"].is_a?(String) ? @data["feature"] : nil
      end

      # +:not_in_plan+, +:read_only+ or +:off+.
      def feature_reason
        self.class::REASON
      end
    end

    # +feature_not_in_plan+: the feature is not in the organization's plan.
    class FeatureNotInPlanError < FeatureError
      REASON = :not_in_plan
    end

    # +feature_read_only+: the feature is being turned off; reads work, changes are refused.
    class FeatureReadOnlyError < FeatureError
      REASON = :read_only
    end

    # +feature_off+: the feature is switched off on this Touchque deployment.
    class FeatureOffError < FeatureError
      REASON = :off
    end

    FeatureError::BY_ERROR = {
      "feature_not_in_plan" => FeatureNotInPlanError,
      "feature_read_only" => FeatureReadOnlyError,
      "feature_off" => FeatureOffError,
    }.freeze

    # The request never reached Touchque (DNS, connection refused, timeout). Unlike
    # APIError, generally safe to retry.
    class NetworkError < Error
      def initialize(message)
        super("Touchque: network request failed: #{message}")
      end
    end

    # Missing or invalid configuration, or a wrong argument (raised before any request).
    class ConfigError < Error
      def initialize(message)
        super("Touchque config error: #{message}")
      end
    end
  end
end
