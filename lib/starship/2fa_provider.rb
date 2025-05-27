# frozen_string_literal: true

require_relative "../logging"

module Starship
  class TwoFactorProvider
    def initialize
    end

    def get_code(session_id, scnt)
      raise NotImplementedError, "Subclasses must implement get_code"
    end

    # @return [String] The type of 2FA ("phone", "trusteddevice")
    def two_factor_type
      raise NotImplementedError, "Subclasses must implement two_factor_type"
    end
  end

  # Manual 2FA provider that prompts the user for a code
  class ManualTwoFactorProvider < TwoFactorProvider
    include Logging

    def get_code(session_id, scnt)
      logger.info "Please enter the code you received: "
      code = gets.chomp.strip
      code
    end

    def two_factor_type
      "trusteddevice"
    end
  end
end
