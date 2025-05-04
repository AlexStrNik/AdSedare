# frozen_string_literal: true

require "xcodeproj"
require "base64"
require "fileutils"
require "tempfile"
require "plist"

require_relative "adsedare/version"
require_relative "adsedare/capabilities"
require_relative "logging"

require_relative "starship"
require_relative "appstoreconnect"

module Adsedare
  class Error < StandardError; end

  class << self
    include Logging

    def renew_profiles(project_path = nil, team_id = nil, certificate_id = nil)
      raise "Project path is not set" unless project_path
      
      project = Xcodeproj::Project.open(project_path)
      project_dir = File.dirname(project_path)
      
      bundle_entitlements = {}

      project.targets.each do |target|
        target.build_configurations.each do |config|
          bundle_identifier = config.build_settings["PRODUCT_BUNDLE_IDENTIFIER"]
          entitlements_path = config.build_settings["CODE_SIGN_ENTITLEMENTS"]
          
          # If team_id is not set, use the first one from the project
          team_id ||= config.build_settings["DEVELOPMENT_TEAM"]
          
          if entitlements_path
            full_entitlements_path = File.join(project_dir, entitlements_path)
            bundle_entitlements[bundle_identifier] = full_entitlements_path
          end
        end
      end

      bundle_by_identifier = get_bundle_map(team_id)
      profiles_by_bundle = get_profiles_map(team_id)

      bundle_entitlements.each do |bundle_identifier, entitlements_path|
        bundle_id = bundle_by_identifier[bundle_identifier]
        unless bundle_id
          logger.warn "Bundle '#{bundle_identifier}' is missing in Apple Developer portal. Will create."
          bundle_id = Starship::Client.create_bundle(
            bundle_identifier, 
            team_id,
            # You cannot create bundle without this capability
            [ SimpleCapability.new("IN_APP_PURCHASE").to_bundle_capability(nil, nil) ]
          )["data"]["id"]
          bundle_by_identifier[bundle_identifier] = bundle_id
          logger.info "Bundle '#{bundle_identifier}' created with ID '#{bundle_id}'"
        else
          logger.info "Bundle '#{bundle_identifier}' resolved to Bundle ID '#{bundle_id}'"
        end

        renew_bundle_id(bundle_id, team_id, entitlements_path)

        profile = profiles_by_bundle[bundle_id]
        unless profile
          logger.warn "Profile for Bundle ID '#{bundle_id}' is missing in Apple Developer portal. Will create."
          devices = get_devices(team_id)
          profile_id = Starship::Client.create_provisioning_profile(
            team_id,
            bundle_id,
            bundle_identifier,
            certificate_id,
            devices
          )["data"]["id"]
          profiles_by_bundle[bundle_id] = Starship::Client.get_provisioning_profile(profile_id, team_id)
          profile = profiles_by_bundle[bundle_id]
          logger.info "Profile for Bundle ID '#{bundle_id}' created with ID '#{profile_id}'"
        else
          logger.info "Bundle ID '#{bundle_id}' resolved to Profile '#{profile["provisioningProfile"]["name"]}'"
        end

        renew_provisioning_profile(profile, team_id)
      end
    end

    def install_profiles(project_path = nil)
      raise "Project path is not set" unless project_path
      
      project = Xcodeproj::Project.open(project_path)

      project_bundles = project.targets.map do |target|
        target.build_configurations.map do |config|
          config.build_settings["PRODUCT_BUNDLE_IDENTIFIER"]
        end
      end.flatten.uniq

      bundles_with_profiles = AppStoreConnect::Client.get_bundles_with_profiles(project_bundles)
      bundle_by_identifier = {}
      profiles_by_id = {}

      bundles_with_profiles["data"].each do |bundle_id|
        bundle_by_identifier[bundle_id["attributes"]["identifier"]] = bundle_id
      end

      bundles_with_profiles["included"].each do |profile|
        profiles_by_id[profile["id"]] = profile
      end

      project_bundles.each do |bundle_identifier|
        bundle_id = bundle_by_identifier[bundle_identifier]
        unless bundle_id
          logger.warn "Bundle '#{bundle_identifier}' is missing in App Store Connect. Skipping."
          next
        end

        logger.info "Bundle '#{bundle_identifier}' resolved to Bundle ID '#{bundle_id['id']}'"

        profiles = bundle_id["relationships"]["profiles"]["data"]
        unless profiles
          logger.warn "Profile for Bundle ID '#{bundle_id['id']}' is missing in App Store Connect. Skipping."
          next
        end

        ad_hoc_profile = nil
        profiles.each do |profile|
          profile_id = profile["id"]
          profile = profiles_by_id[profile_id]

          if profile["attributes"]["profileType"] == "IOS_APP_ADHOC" && profile["attributes"]["profileState"] == "ACTIVE"
            ad_hoc_profile = profile
            break
          end
        end

        unless ad_hoc_profile
          logger.warn "Profile for Bundle ID '#{bundle_id['id']}' is missing in App Store Connect. Skipping."
          next
        end

        logger.info "Profile for Bundle ID '#{bundle_id['id']}' resolved to Profile '#{ad_hoc_profile['attributes']['name']}'"

        uuid = ad_hoc_profile["attributes"]["uuid"]
        profile_content = Base64.decode64(ad_hoc_profile["attributes"]["profileContent"])
        profile_path = "#{Dir.home}/Library/MobileDevice/Provisioning Profiles/#{uuid}.mobileprovision"

        FileUtils.mkdir_p(File.dirname(profile_path))
        File.write(profile_path, profile_content)

        logger.info "Profile '#{ad_hoc_profile['attributes']['name']}' installed to '#{profile_path}'"
      end
    end

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

      apple_certs = [
        "AppleWWDRCAG2.cer",
        "AppleWWDRCAG3.cer",
        "AppleWWDRCAG4.cer",
        "AppleWWDRCAG5.cer",
        "AppleWWDRCAG6.cer",
        "AppleWWDRCAG7.cer",
        "AppleWWDRCAG8.cer",
        "DeveloperIDG2CA.cer"
      ]

      apple_certs.each do |cert|
        logger.info "Downloading certificate '#{cert}'"

        response = Faraday.get(
          "https://www.apple.com/certificateauthority/#{cert}"
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
        "https://developer.apple.com/certificationauthority/AppleWWDRCA.cer"
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

    def make_export_options(project_path = nil, export_path = nil, team_id = nil, options = {})
      raise "Project path is not set" unless project_path
      raise "Export path is not set" unless export_path

      project = Xcodeproj::Project.open(project_path)
      export_options = {
        "method" => "ad-hoc",
        "destination" => "export",
        "signingStyle" => "manual",
        "provisioningProfiles" => {}
      }.merge(options)

      project_bundles = []

      project.targets.each do |target|
        target.build_configurations.each do |config|
          team_id ||= config.build_settings["DEVELOPMENT_TEAM"]
          project_bundles << config.build_settings["PRODUCT_BUNDLE_IDENTIFIER"]
        end
      end

      export_options["teamID"] = team_id

      logger.info "Fetching bundles with profiles for team ID '#{team_id}'"

      bundles_with_profiles = AppStoreConnect::Client.get_bundles_with_profiles(project_bundles)
      bundle_by_identifier = {}
      profiles_by_id = {}

      bundles_with_profiles["data"].each do |bundle_id|
        bundle_by_identifier[bundle_id["attributes"]["identifier"]] = bundle_id
      end

      bundles_with_profiles["included"].each do |profile|
        profiles_by_id[profile["id"]] = profile
      end

      project_bundles.each do |bundle_identifier|
        bundle_id = bundle_by_identifier[bundle_identifier]
        unless bundle_id
          logger.warn "Bundle '#{bundle_identifier}' is missing in App Store Connect. Skipping."
          next
        end

        logger.info "Bundle '#{bundle_identifier}' resolved to Bundle ID '#{bundle_id['id']}'"

        profiles = bundle_id["relationships"]["profiles"]["data"]
        unless profiles
          logger.warn "Profile for Bundle ID '#{bundle_id['id']}' is missing in App Store Connect. Skipping."
          next
        end

        ad_hoc_profile = nil
        profiles.each do |profile|
          profile_id = profile["id"]
          profile = profiles_by_id[profile_id]

          if profile["attributes"]["profileType"] == "IOS_APP_ADHOC" && profile["attributes"]["profileState"] == "ACTIVE"
            ad_hoc_profile = profile
            break
          end
        end

        unless ad_hoc_profile
          logger.warn "Profile for Bundle ID '#{bundle_id['id']}' is missing in App Store Connect. Skipping."
          next
        end

        logger.info "Profile for Bundle ID '#{bundle_id['id']}' resolved to Profile '#{ad_hoc_profile['attributes']['name']}'"

        profile_name = ad_hoc_profile["attributes"]["name"]
        
        export_options["provisioningProfiles"][bundle_identifier] = profile_name
      end

      options_plist = Plist::Emit.dump(export_options)
      File.write(export_path, options_plist)

      return export_options
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

    def get_devices(team_id)
      Starship::Client.get_devices(team_id)
    end

    def get_profiles_map(team_id)
      logger.info "Fetching profiles for team ID '#{team_id}'"

      registered_profiles = Starship::Client.get_profiles(team_id)
      profiles = {}

      registered_profiles.each do |profile|
        provisioning_profile = Starship::Client::get_provisioning_profile(profile["id"], team_id)
        app_id = provisioning_profile["provisioningProfile"]["appIdId"]

        profiles[app_id] = provisioning_profile
      end

      return profiles
    end

    def get_bundle_map(team_id)
      logger.info "Fetching bundle IDs for team ID '#{team_id}'"

      registered_bundles = Starship::Client.get_bundle_ids(team_id)
      bundle_ids = {}

      registered_bundles.each do |bundle|
        bundle_ids[bundle["attributes"]["identifier"]] = bundle["id"]
      end

      return bundle_ids
    end

    def renew_provisioning_profile(profile, team_id)
      devices = get_devices(team_id)
      deviceIds = devices.map { |device| device["id"] }

      need_update = false

      profile["provisioningProfile"]["devices"].each do |device|
        if !deviceIds.include?(device["deviceId"])
          need_update = true
          break
        end
      end

      logger.info "Profile '#{profile["provisioningProfile"]["name"]}' status: '#{profile["provisioningProfile"]["status"]}'"

      if profile["provisioningProfile"]["status"] != "Active"
        need_update = true
      end

      if need_update
        logger.warn "Profile '#{profile["provisioningProfile"]["name"]}' is missing one or more devices."
        
        Starship::Client.regen_provisioning_profile(profile, team_id, deviceIds)

        logger.info "Profile '#{profile["provisioningProfile"]["name"]}' updated."
      else
        logger.info "Profile '#{profile["provisioningProfile"]["name"]}' is up to date."
      end
    end

    def renew_bundle_id(bundle_id, team_id, entitlements_path)
      bundle_info = Starship::Client.get_bundle_info(bundle_id, team_id)
      bundle_identifier = bundle_info["data"]["attributes"]["identifier"]

      logger.info "Checking capabilities for bundle '#{bundle_identifier}'"

      capabilities = parse_entitlements(entitlements_path)
      
      need_update = false

      capabilities.each do |capability|
        if capability.check?(bundle_info)
        else
          need_update = true
        end
      end

      if need_update
        logger.warn "Bundle '#{bundle_identifier}' is missing one or more capabilities."
        new_capabilities = (
          # You can't remove IN_APP_PURCHASE capability for some reason
          capabilities + [ SimpleCapability.new("IN_APP_PURCHASE") ]
        ).map { |capability| capability.to_bundle_capability(bundle_info, team_id) }
        
        Starship::Client.patch_bundle(bundle_info, team_id, new_capabilities)

        logger.info "Bundle '#{bundle_identifier}' capabilities updated."
      else
        logger.info "Bundle '#{bundle_identifier}' capabilities are up to date."
      end
    end
  end
end
