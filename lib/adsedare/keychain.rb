# frozen_string_literal: true

require "xcodeproj"
require "base64"
require "fileutils"
require "tempfile"

module Adsedare
  APPLE_CERTS = [
    "AppleWWDRCAG2.cer",
    "AppleWWDRCAG3.cer",
    "AppleWWDRCAG4.cer",
    "AppleWWDRCAG5.cer",
    "AppleWWDRCAG6.cer",
    "AppleWWDRCAG7.cer",
    "AppleWWDRCAG8.cer",
    "DeveloperIDG2CA.cer",
  ]
  APPLE_CERTS_URL = "https://www.apple.com/certificateauthority"

  APPLE_WWDRCA = "https://developer.apple.com/certificationauthority/AppleWWDRCA.cer"

  class << self
    # Create a build keychain with all required intermediate certificates
    # Set following environment variables to add project specific certificates:
    #
    # - AD_HOC_CERTIFICATE Path to the ad-hoc certificate
    # - AD_HOC_PRIVATE_KEY Path to the ad-hoc private key
    # - AD_HOC_KEY_PASSWORD Password for the ad-hoc private key
    #
    # @param keychain_path [String] The path to the keychain
    # @param keychain_password [String] The password for the keychain
    # @param make_default [Boolean] Whether to make the keychain the default
    # @return [void]
    def create_keychain(keychain_path = nil, keychain_password = nil, make_default = true)
      raise "Keychain path is not set" unless keychain_path
      raise "Keychain password is not set" unless keychain_password

      keychain_path = File.expand_path(keychain_path)

      logger.info "Creating keychain at '#{keychain_path}'"

      FileUtils.mkdir_p(File.dirname(keychain_path))
      status = system("security create-keychain -p #{keychain_password} #{keychain_path}")
      unless status
        logger.error "Failed to create keychain at '#{keychain_path}'"
        return
      end

      APPLE_CERTS.each do |cert|
        logger.info "Downloading certificate '#{cert}'"

        response = Faraday.get(
          "#{APPLE_CERTS_URL}/#{cert}"
        )
        unless response.status == 200
          logger.error "Failed to download certificate '#{cert}'"
          next
        end

        file = Tempfile.new(cert)
        file.write(response.body)
        file.close

        install_certificate(file.path, keychain_path)

        file.unlink
      end

      logger.info "Downloading certificate 'AppleWWDRCA.cer'"
      response = Faraday.get(
        APPLE_WWDRCA
      )
      unless response.status == 200
        logger.error "Failed to download certificate 'AppleWWDRCA.cer'"
      else
        file = Tempfile.new("AppleWWDRCA.cer")
        file.write(response.body)
        file.close

        install_certificate(file.path, keychain_path)

        file.unlink
      end

      ad_hoc_certificate = ENV["AD_HOC_CERTIFICATE"]
      ad_hoc_private_key = ENV["AD_HOC_PRIVATE_KEY"]
      ad_hoc_key_password = ENV["AD_HOC_KEY_PASSWORD"]

      unless ad_hoc_certificate || ad_hoc_private_key || ad_hoc_key_password
        logger.warn "AD_HOC_CERTIFICATE, AD_HOC_PRIVATE_KEY, or AD_HOC_KEY_PASSWORD is not set"
        return
      end

      install_certificate(ad_hoc_private_key, keychain_path, ad_hoc_key_password, "priv")
      install_certificate(ad_hoc_certificate, keychain_path, "", "cert")

      if make_default
        status = system("security default-keychain -d user -s #{keychain_path}")
        unless status
          logger.warn "Failed to set default keychain"
          return
        end
      end

      status = system("security set-keychain-settings #{keychain_path}")
      unless status
        logger.error "Failed to set keychain settings"
        return
      end

      status = system("security set-key-partition-list -S apple-tool:,apple: -k #{keychain_password} #{keychain_path}")
      unless status
        logger.error "Failed to set keychain partition list"
        return
      end

      status = system("security unlock-keychain -p #{keychain_password} #{keychain_path}")
      unless status
        logger.error "Failed to unlock keychain"
        return
      end

      logger.info "Keychain created at '#{keychain_path}'"
    end

    private

    def install_certificate(certificate_path, keychain_path, certificate_password = "", certificate_type = "cert")
      certificate_name = File.basename(certificate_path)
      logger.info "Installing certificate '#{certificate_name}' to keychain '#{keychain_path}'"

      status = system("security import #{certificate_path} -k #{keychain_path} -t #{certificate_type} -A -P #{certificate_password} -T /usr/bin/codesign -T /usr/bin/security -T /usr/bin/productbuild")
      unless status
        logger.error "Failed to install certificate '#{certificate_name}' to keychain '#{keychain_path}'"
        return
      end

      logger.info "Certificate '#{certificate_name}' installed to keychain '#{keychain_path}'"
    end
  end
end
