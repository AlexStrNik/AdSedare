# frozen_string_literal: true

require "xcodeproj"
require "base64"
require "fileutils"
require "tempfile"
require "plist"

require_relative "adsedare/version"
require_relative "adsedare/capabilities"
require_relative "adsedare/keychain"
require_relative "logging"

require_relative "starship"
require_relative "appstoreconnect"

module Adsedare
  class Error < StandardError; end

  class << self
    include Logging

    def renew_profiles(project_path = nil, certificate_id = nil, team_id = nil)
      raise "Project path is not set" unless project_path
      raise "Certificate ID is not set" unless certificate_id
      
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

    def make_export_options(project_path = nil, export_path = nil, team_id = nil, options = {})
      raise "Project path is not set" unless project_path
      raise "Export path is not set" unless export_path

      project = Xcodeproj::Project.open(project_path)
      export_options = {
        "method" => "ad-hoc",
        "destination" => "export",
        "signingStyle" => "manual",
        "signingCertificate" => "Apple Distribution",
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

    def patch_project(project_path, team_id = nil)
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
      
      project.targets.each do |target|
        target.build_configurations.each do |config|
          bundle_identifier = config.build_settings["PRODUCT_BUNDLE_IDENTIFIER"]
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

          config.build_settings["CODE_SIGN_IDENTITY"] = "iPhone Distribution"
          config.build_settings["CODE_SIGN_STYLE"] = "Manual"
          if team_id
            config.build_settings["DEVELOPMENT_TEAM"] = team_id
          end
          config.build_settings["PROVISIONING_PROFILE_SPECIFIER"] = ad_hoc_profile["attributes"]["name"]
        end
      end

      project.save
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
