# frozen_string_literal: true

require_relative "../logging"

module Starship
  class TwoFactorProvider
    def initialize
    end

    # Get the 2FA code
    # @param session_id [String] The session ID from Apple
    # @param scnt [String] The scnt value from Apple
    # @return [String] The 2FA code
    def get_code(session_id, scnt)
      raise NotImplementedError, "Subclasses must implement get_code"
    end

    # Verify if this provider can handle the given 2FA type
    # @param type [String] The 2FA type (sms, voice, etc.)
    # @return [Boolean] Whether this provider can handle the given type
    def can_handle?(type)
      raise NotImplementedError, "Subclasses must implement can_handle?"
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

    def can_handle?(type)
      true
    end
  end
end
