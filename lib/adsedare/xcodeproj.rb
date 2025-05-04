require "xcodeproj"
require "plist"

require_relative "../appstoreconnect"

module Adsedare
  class << self
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

          logger.info "Bundle '#{bundle_identifier}' resolved to Bundle ID '#{bundle_id["id"]}'"

          profiles = bundle_id["relationships"]["profiles"]["data"]
          unless profiles
            logger.warn "Profile for Bundle ID '#{bundle_id["id"]}' is missing in App Store Connect. Skipping."
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
            logger.warn "Profile for Bundle ID '#{bundle_id["id"]}' is missing in App Store Connect. Skipping."
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
  end
end
