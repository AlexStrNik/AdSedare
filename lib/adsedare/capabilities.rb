require "plist"

module Adsedare
  ENTITLEMENTS_MAPPING = {
    "com.apple.security.application-groups" => "APP_GROUPS",
    "com.apple.developer.in-app-payments" => "APPLE_PAY",
    "com.apple.developer.associated-domains" => "ASSOCIATED_DOMAINS",
    "com.apple.developer.healthkit" => "HEALTHKIT",
    "com.apple.developer.homekit" => "HOMEKIT",
    "com.apple.developer.networking.HotspotConfiguration" => "HOTSPOT",
    "com.apple.developer.networking.multipath" => "MULTIPATH",
    "com.apple.developer.networking.networkextension" => "NETWORK_EXTENSION",
    "com.apple.developer.nfc.readersession.formats" => "NFC_TAG_READING",
    "com.apple.developer.networking.vpn.api" => "PERSONAL_VPN",
    "com.apple.external-accessory.wireless-configuration" => "WIRELESS_ACCESSORY_CONFIGURATION",
    "com.apple.developer.siri" => "SIRI",
    "com.apple.developer.pass-type-identifiers" => "WALLET",
    "com.apple.developer.icloud-services" => "ICLOUD",
    "com.apple.developer.icloud-container-identifiers" => "ICLOUD",
    "com.apple.developer.ubiquity-container-identifiers" => "ICLOUD",
    "com.apple.developer.ubiquity-kvstore-identifier" => "ICLOUD",
    "com.apple.developer.ClassKit-environment" => "CLASSKIT",
    "com.apple.developer.authentication-services.autofill-credential-provider" => "AUTOFILL_CREDENTIAL_PROVIDER",
    "com.apple.developer.applesignin" => "SIGN_IN_WITH_APPLE",
    "com.apple.developer.usernotifications.communication" => "COMMUNICATION_NOTIFICATIONS",
    "com.apple.developer.usernotifications.time-sensitive" => "USERNOTIFICATIONS_TIMESENSITIVE",
    "com.apple.developer.group-session" => "GROUP_ACTIVITIES",
    "com.apple.developer.family-controls" => "FAMILY_CONTROLS",
    "com.apple.developer.devicecheck.appattest-environment" => "APP_ATTEST",
    "com.apple.developer.game-center" => "GAME_CENTER",
    "com.apple.developer.carplay-maps" => "CARPLAY_NAVIGATION"
  }

  def self.parse_entitlements(path)
    raise Error, "Entitlements file not found: #{path}" unless File.exist?(path)
    
    entitlements = Plist.parse_xml(path)
    capabilities = []
    
    entitlements.each do |key, value|
      capability_type = ENTITLEMENTS_MAPPING[key]
      next unless capability_type
      
      if key == "com.apple.security.application-groups"
        capabilities << AppGroupsCapability.new(capability_type, value)
      else
        capabilities << SimpleCapability.new(capability_type)
      end
    end
    
    capabilities
  end
  
  class Capability
    attr_reader :type
    
    def initialize(type)
      @type = type
    end
    
    def check?(bundle_info)
      bundle_info["included"].any? { 
        |cap| cap["type"] == "capabilities" && cap["id"] == @type 
      }
    end
    
    def to_bundle_capability(bundle_info, team_id)
      return {
        "type" => "bundleIdCapabilities",
        "attributes" => {
          "enabled" => true,
          "settings" => []
        },
        "relationships" => {
          "capability" => {
            "data" => { "type" => "capabilities", "id" => @type }
          }
        }
      }
    end
  end

  class SimpleCapability < Capability
  end

  class AppGroupsCapability < Capability
    attr_reader :groups
    
    def initialize(type, groups)
      super(type)
      @groups = groups
    end
    
    def check?(bundle_info)
      have_capability = bundle_info["included"].any? { 
        |cap| cap["type"] == "capabilities" && cap["id"] == @type 
      }
      return false unless have_capability

      registered_groups = bundle_info["included"].select { 
        |cap| cap["type"] == "appGroups"
      }.map { 
        |cap| cap["attributes"]["identifier"]
      }
      
      return @groups.all? { |group| registered_groups.include?(group) }
    end
    
    def to_bundle_capability(bundle_info, team_id)
      registered_app_groups = {}
      
      Starship::Client.get_app_groups(team_id).each {
        |app_group| registered_app_groups[app_group["identifier"]] = app_group["applicationGroup"]
      }
      
      @groups.each do |group|
        if not registered_app_groups.include?(group)
          new_app_group = Starship::Client.create_app_group(group, team_id)
          registered_app_groups[new_app_group["identifier"]] = new_app_group["applicationGroup"]
        end
      end

      bundle_capability = super(bundle_info, team_id)

      app_groups = {
        "data" => @groups.map { |group| { "type" => "appGroups", "id" => registered_app_groups[group] } } 
      }

      bundle_capability["relationships"]["appGroups"] = app_groups
      
      return bundle_capability
    end
  end
end
