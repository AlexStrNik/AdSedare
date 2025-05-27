# frozen_string_literal: true

require "faraday"
require "faraday-cookie_jar"
require "json"
require "base64"
require "digest"
require "fileutils"
require "openssl"
require "securerandom"
require "fastlane-sirp"

require_relative "2fa_provider"
require_relative "../logging"

module Starship
  class Error < StandardError; end

  # AuthHelper handles authentication with Apple's developer portal
  class AuthHelper
    include Logging
    
    @two_factor_provider = Starship::ManualTwoFactorProvider.new
    attr_reader :session, :csrf, :csrf_ts, :session_data

    AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth"
    WIDGET_KEY_URL = "https://appstoreconnect.apple.com/olympus/v1/app/config?hostname=itunesconnect.apple.com"

    def two_factor_provider=(provider)
      @two_factor_provider = provider
      logger.info "Two-factor provider set to #{provider.class.name}"
    end

    def initialize()
      # Create session directory if it doesn't exist
      @session_directory = File.expand_path("~/.starship")
      FileUtils.mkdir_p(@session_directory)

      @widget_key = nil
      @csrf = nil
      @csrf_ts = nil
      @email = nil
      @session_data = {}

      # Initialize Faraday with cookie jar
      @session = Faraday.new do |builder|
        builder.use :cookie_jar, jar: HTTP::CookieJar.new
        builder.adapter Faraday.default_adapter
      end
    end

    # Sign in to Apple Developer Portal
    # @return [Boolean] Whether authentication was successful
    def sign_in
      email = ENV["APPLE_DEVELOPER_USERNAME"]
      password = ENV["APPLE_DEVELOPER_PASSWORD"]

      if !email || !password
        raise Error, "Email and password are required. Set APPLE_ID and APPLE_PASSWORD environment variables."
      end

      @email = email
      @client_id = generate_session_id(email)
      cookie_path, session_path = get_paths(email)

      # Try to load existing session
      if File.exist?(session_path)
        load_session
        if validate_token
          return true
        end
      end

      logger.warn "Session invalid or expired. Starting authentication from scratch..."
      @session_data = { "client_id" => @client_id, "email" => email }

      # Start authentication process
      auth_result = authenticate_with_srp(email, password)

      if auth_result == :two_factor_required
        handle_two_factor_auth
      elsif auth_result
        # After successful authentication, get CSRF tokens
        response = @session.get("https://developer.apple.com/account")
        if response.status == 200
          extract_csrf_tokens(response)

          if @csrf && @csrf_ts
            save_session
            return true
          end
        end
      end

      return auth_result
    end

    # Check if the current session is valid
    # @return [Boolean] Whether the session is valid
    def validate_token
      return false unless @session_data["session_id"] && @session_data["scnt"]

      begin
        headers = {
          "Accept" => "application/json, text/plain, */*",
          "Content-Type" => "application/vnd.api+json",
          "X-Requested-With" => "XMLHttpRequest",
          "X-Apple-ID-Session-Id" => @session_data["session_id"],
          "scnt" => @session_data["scnt"],
        }

        response = @session.get(
          "https://developer.apple.com/services-account/v1/certificates",
          nil,
          headers
        )

        if response.status == 403
          # Fetch CSRF tokens after confirming session is valid
          csrf_response = @session.get("https://developer.apple.com/account/resources/certificates/list")

          if csrf_response.status == 200
            extract_csrf_tokens(csrf_response)

            if @csrf && @csrf_ts
              return true
            else
              logger.error "Failed to retrieve CSRF tokens after validating session."
              return false
            end
          end
          return true
        else
          logger.warn "Session is invalid. Will reauthenticate."
          return false
        end
      rescue => e
        logger.error "Authentication status check failed: #{e.message}"
        return false
      end
    end

    def request(endpoint, method: :get, params: nil, body: nil, headers: nil)
      default_headers = {
        "Accept" => "application/json, text/plain, */*",
        "X-Requested-With" => "XMLHttpRequest",
        "X-HTTP-Method-Override" => "GET",
        "csrf" => @csrf,
        "csrf_ts" => @csrf_ts,
      }

      if headers
        default_headers = default_headers.merge(headers)
      end

      response = case method
        when :get
          @session.get(endpoint, params, default_headers)
        when :post
          @session.post(endpoint, body, default_headers)
        when :put
          @session.put(endpoint, body, default_headers)
        when :delete
          @session.delete(endpoint, default_headers)
        when :patch
          @session.patch(endpoint, body, default_headers)
        end

      if response.status == 401 || response.status == 403
        logger.warn "Session invalid or expired. Starting authentication from scratch..."

        self.sign_in

        response = self.request(endpoint, method: method, params: params, body: body, headers: headers)
      end

      return response
    end

    private

    # Generate a consistent session ID from email
    # @param email [String] The email address
    # @return [String] The session ID
    def generate_session_id(email)
      "auth-#{Digest::SHA256.hexdigest(email)[0...8]}"
    end

    # Get the paths for cookie and session files
    # @param email [String] The email address
    # @return [Array<String>] The cookie path and session path
    def get_paths(email)
      session_id = generate_session_id(email)
      cookie_path = File.join(@session_directory, "#{session_id}.cookies")
      session_path = File.join(@session_directory, "#{session_id}.session")
      [cookie_path, session_path]
    end

    # Get the cookie jar path
    # @return [String] The cookie jar path
    def cookiejar_path
      raise Error, "Email not set" unless @email
      get_paths(@email)[0]
    end

    # Get the session path
    # @return [String] The session path
    def session_path
      raise Error, "Email not set" unless @email
      get_paths(@email)[1]
    end

    # Load session data from file
    # @return [Boolean] Whether the session was loaded successfully
    def load_session
      begin
        @session_data = JSON.parse(File.read(session_path))
        if File.exist?(cookiejar_path)
          begin
            # Create a new cookie jar for Faraday
            jar = HTTP::CookieJar.new
            jar.load(cookiejar_path, format: :cookiestxt)

            # Recreate the Faraday connection with the loaded cookies
            @session = Faraday.new do |builder|
              builder.use :cookie_jar, jar: jar
              builder.adapter Faraday.default_adapter
            end
          rescue => e
            logger.warn "Failed to load cookies from file: #{e.message}"
          end
        end
        return true
      rescue => e
        logger.warn "Failed to load session from file: #{e.message}"
        @session_data = {}
        return false
      end
    end

    # Save session data to file
    def save_session
      logger.info "Saving session to disk at #{session_path}"
      File.write(session_path, JSON.pretty_generate(@session_data))

      # Save cookies
      cookie_path = get_paths(@email)[0]

      # Get the cookie jar from Faraday
      jar = @session.builder.app.instance_variable_get("@jar")
      if jar
        # Save all cookies, even if they're marked as discardable or expired
        jar.save(cookie_path, format: :cookiestxt, session: true)
        logger.info "Cookies saved to #{cookie_path}"
      else
        logger.info "No cookies were found to save."
      end

      logger.info "Session saved successfully."
    end

    # Get the widget key used for authentication
    # @return [String] The widget key
    def widget_key
      unless @widget_key
        response = @session.get(WIDGET_KEY_URL)
        @widget_key = JSON.parse(response.body)["authServiceKey"] || ""
      end
      @widget_key
    end

    # Get a cookie value by name
    # @param name [String] The cookie name
    # @return [String, nil] The cookie value or nil if not found
    def get_cookie_value(name)
      # Access the cookie jar middleware from Faraday
      jar = @session.builder.app.instance_variable_get("@jar")
      return nil unless jar

      # Find the cookie by name
      jar.cookies.find { |cookie| cookie.name == name }&.value
    end

    # Extract CSRF tokens from response
    # @param response [Faraday::Response] The response object
    def extract_csrf_tokens(response)
      # Try cookies first
      @csrf = get_cookie_value("csrf")
      @csrf_ts = get_cookie_value("csrf_ts")

      # If not in cookies, try response headers
      unless @csrf
        @csrf = response.headers["csrf"]
      end
      unless @csrf_ts
        @csrf_ts = response.headers["csrf_ts"]
      end

      # If still not found, try to extract from page content
      if !@csrf || !@csrf_ts
        if response.body =~ /csrf[""]\s*:\s*[""](.*?)[""]/
          @csrf = $1
        end
        if response.body =~ /csrf_ts[""]\s*:\s*[""](.*?)[""]/
          @csrf_ts = $1
        end
      end
    end

    def to_hex(str)
      str.unpack1('H*')
    end

    def to_byte(str)
      [str].pack('H*')
    end

    def pbkdf2(password, salt, iterations, key_length, digest = OpenSSL::Digest::SHA256.new)
      password = OpenSSL::Digest::SHA256.digest(password)
      OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, key_length, digest)
    end

    def fetch_hashcash
      response = @session.get(
        "#{AUTH_ENDPOINT}/signin?widgetKey=#{widget_key}",
      )
      headers = response.headers

      bits = headers["X-Apple-HC-Bits"]
      challenge = headers["X-Apple-HC-Challenge"]

      if bits.nil? || challenge.nil?
        logger.warn "Unable to find 'X-Apple-HC-Bits' and 'X-Apple-HC-Challenge' to make hashcash"
        return nil
      end

      return make_hashcash(bits: bits, challenge: challenge)
    end

    def make_hashcash(bits: nil, challenge: nil)
      version = 1
      date = Time.now.strftime("%Y%m%d%H%M%S")

      counter = 0
      loop do
        hc = [
          version, bits, date, challenge, ":#{counter}"
        ].join(":")

        if Digest::SHA1.digest(hc).unpack1('B*')[0, bits.to_i].to_i == 0
          return hc
        end
        counter += 1
      end
    end

    # Authenticate with Secure Remote Password protocol
    # @param email [String] The email address
    # @param password [String] The password
    # @return [Boolean, Symbol] True if successful, :two_factor_required if 2FA is needed, false otherwise
    def authenticate_with_srp(email, password)
      client = SIRP::Client.new(2048)
	    a = client.start_authentication()

      headers = {
        "Accept" => "application/json, text/javascript",
        "Content-Type" => "application/json",
        "X-Requested-With" => "XMLHttpRequest",
        "X-Apple-Widget-Key" => widget_key,
      }

      federate_data = {
        "accountName" => email,
        "rememberMe" => false,
      }

      response = @session.post(
        "#{AUTH_ENDPOINT}/federate?isRememberMeEnabled=false",
        federate_data.to_json,
        headers
      )

      if @session_data["session_id"]
        headers.update({
          "X-Apple-ID-Session-Id" => @session_data["session_id"],
          "scnt" => @session_data["scnt"],
        })
      end

      init_data = {
        "a": Base64.strict_encode64(to_byte(a)),
        "accountName": email,
        "protocols": ["s2k", "s2k_fo"],
      }

      response = @session.post(
        "#{AUTH_ENDPOINT}/signin/init",
        init_data.to_json,
        headers
      )

      body = JSON.parse(response.body)
      salt = Base64.strict_decode64(body["salt"])
      b = Base64.strict_decode64(body["b"])
      c = body["c"]
      iterations = body["iteration"]
      key_length = 32

      encrypted_password = pbkdf2(password, salt, iterations, key_length)

      m1 = client.process_challenge(
        email,
        to_hex(encrypted_password),
        to_hex(salt),
        to_hex(b),
        is_password_encrypted: true
      )
      m2 = client.H_AMK

      complete_data = {
        "accountName": email,
        "c": c,
        "m1": Base64.encode64(to_byte(m1)).strip,
        "m2": Base64.encode64(to_byte(m2)).strip,
        "rememberMe": false
      }

      hashcash = self.fetch_hashcash
      if hashcash
        headers.update({
          "X-Apple-HC" => hashcash,
        })
      end

      response = @session.post(
        "#{AUTH_ENDPOINT}/signin/complete?isRememberMeEnabled=false",
        complete_data.to_json,
        headers
      )

      # Handle 409 response (2FA required)
      if response.status == 409
        session_id = response.headers["X-Apple-ID-Session-Id"]
        scnt = response.headers["scnt"]

        if session_id && scnt
          @session_data.update({
            "session_id" => session_id,
            "scnt" => scnt,
            "client_id" => @client_id,
            "email" => email,
          })
          save_session
        end

        return :two_factor_required
      end

      # Handle successful authentication
      if response.status == 200 || response.status == 302
        session_id = response.headers["X-Apple-ID-Session-Id"]
        scnt = response.headers["scnt"]

        if session_id && scnt
          @session_data.update({
            "session_id" => session_id,
            "scnt" => scnt,
            "client_id" => @client_id,
            "email" => email,
          })
          save_session
          logger.info "Session data saved after basic authentication."
          return true
        end
      end

      return false
    end

    # Handle two-factor authentication
    # @return [Boolean] Whether 2FA was successful
    def handle_two_factor_auth
      session_id = @session_data["session_id"]
      scnt = @session_data["scnt"]

      unless session_id && scnt
        logger.error "Missing session data. Cannot continue two-factor authentication."
        return false
      end

      begin
        two_factor_type = @two_factor_provider.two_factor_type
        logger.info "Two-factor authentication required. Requesting #{two_factor_type} verification code..."

        auth_options_headers = {
          "Accept" => "application/json, text/javascript",
          "Content-Type" => "application/json",
          "X-Requested-With" => "XMLHttpRequest",
          "X-Apple-ID-Session-Id" => session_id,
          "scnt" => scnt,
          "X-Apple-Widget-Key" => widget_key,
        }

        auth_options_response = @session.get(
          "#{AUTH_ENDPOINT}/auth",
          nil,
          auth_options_headers
        )
        auth_options = JSON.parse(auth_options_response.body)

        trigger_headers = {
          "Accept" => "application/json",
          "Content-Type" => "application/json",
          "X-Requested-With" => "XMLHttpRequest",
          "X-Apple-ID-Session-Id" => session_id,
          "scnt" => scnt,
          "X-Apple-Widget-Key" => widget_key,
        }

        trigger_data = {
        }

        if two_factor_type == "phone"
          phone_number = auth_options["trustedPhoneNumbers"][0]
          trigger_data = {
            "phoneNumber" => {
              "id" => phone_number["id"],
            },
            "mode" => "sms",
          }
          logger.info "Sending SMS to #{phone_number["numberWithDialCode"]}"
        end

        response = @session.put(
          "#{AUTH_ENDPOINT}/verify/#{two_factor_type}",
          trigger_data.to_json,
          trigger_headers
        )

        code = @two_factor_provider.get_code(session_id, scnt)

        logger.info "Received code: #{code}"

        verify_headers = {
          "Accept" => "application/json",
          "Content-Type" => "application/json",
          "X-Requested-With" => "XMLHttpRequest",
          "X-Apple-ID-Session-Id" => session_id,
          "scnt" => scnt,
          "X-Apple-Widget-Key" => widget_key,
        }

        verify_data = { "securityCode" => { "code" => code.strip } }

        if two_factor_type == "phone"
          verify_data["phoneNumber"] = trigger_data["phoneNumber"]
          verify_data["mode"] = trigger_data["mode"]
        end

        # First verify the security code
        verify_response = @session.post(
          "#{AUTH_ENDPOINT}/verify/#{two_factor_type}/securitycode",
          verify_data.to_json,
          verify_headers
        )

        if verify_response.status == 204 || verify_response.status == 200
          logger.info "Two-factor code verified successfully."
          logger.info "Trusting the session after 2FA verification..."

          # Then request trust for the session
          trust_response = @session.get(
            "#{AUTH_ENDPOINT}/2sv/trust",
            nil,
            verify_headers
          )

          if trust_response.status == 204 || trust_response.status == 200
            # Store all relevant session data
            @session_data.update({
              "session_id" => session_id,
              "scnt" => scnt,
              "client_id" => @client_id,
              "email" => @email,
            })
            logger.info "Session trusted and fully authenticated. Saving final session data."
            save_session
            return true
          else
            logger.error "Failed to trust session after 2FA verification."
            return false
          end
        end
      rescue => e
        logger.error "Two-factor verification failed: #{e.message}"
      end

      return false
    end
  end
end
