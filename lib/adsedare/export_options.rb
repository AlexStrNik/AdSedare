require "xcodeproj"
require "plist"

require_relative "../appstoreconnect"

module Adsedare
  class << self
    def make_export_options(project_path = nil, export_path = nil, team_id = nil, options = {})
      raise "Project path is not set" unless project_path
      raise "Export path is not set" unless export_path

      project = Xcodeproj::Project.open(project_path)
      export_options = {
        "method" => "ad-hoc",
        "destination" => "export",
        "signingStyle" => "manual",
        "signingCertificate" => "Apple Distribution",
        "provisioningProfiles" => {},
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

        logger.info "Profile for Bundle ID '#{bundle_id["id"]}' resolved to Profile '#{ad_hoc_profile["attributes"]["name"]}'"

        profile_name = ad_hoc_profile["attributes"]["name"]

        export_options["provisioningProfiles"][bundle_identifier] = profile_name
      end

      options_plist = Plist::Emit.dump(export_options)
      File.write(File.expand_path(export_path), options_plist)
    end
  end
end
