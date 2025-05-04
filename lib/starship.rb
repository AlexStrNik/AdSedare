# frozen_string_literal: true

require "faraday"
require "json"

require_relative "starship/auth_helper"

module Starship
  class Client
    DEV_SERVICES_V1 = "https://developer.apple.com/services-account/v1"
    DEV_SERVICES_QH65B2 = "https://developer.apple.com/services-account/QH65B2"

    class << self
      def auth_helper
        @auth_helper ||= AuthHelper.new
      end

      def get_bundle_ids(team_id)
        response = authenticated_request(
          DEV_SERVICES_V1 + "/bundleIds",
          method: :post,
          body: { teamId: team_id, urlEncodedQueryParams: "limit=1000&sort=name&filter[platform]=IOS,MACOS" }.to_json,
          headers: { "Content-Type" => "application/vnd.api+json" },
        )

        if response.status == 200
          JSON.parse(response.body)["data"]
        else
          raise "Failed to get bundle IDs: #{response.status}"
        end
      end

      def get_devices(team_id)
        response = authenticated_request(
          DEV_SERVICES_V1 + "/devices",
          method: :post,
          body: { teamId: team_id, urlEncodedQueryParams: "limit=1000&sort=name" }.to_json,
          headers: { "Content-Type" => "application/vnd.api+json" },
        )

        if response.status == 200
          JSON.parse(response.body)["data"]
        else
          raise "Failed to get devices: #{response.status}"
        end
      end

      def get_profiles(team_id)
        response = authenticated_request(
          DEV_SERVICES_V1 + "/profiles",
          method: :post,
          body: { teamId: team_id, urlEncodedQueryParams: "limit=1000&sort=name" }.to_json,
          headers: { "Content-Type" => "application/vnd.api+json" },
        )

        if response.status == 200
          JSON.parse(response.body)["data"]
        else
          raise "Failed to get profiles: #{response.status}"
        end
      end

      def get_provisioning_profile(profile_id, team_id)
        response = authenticated_request(
          DEV_SERVICES_QH65B2 + "/account/ios/profile/getProvisioningProfile.action",
          method: :post,
          body: URI.encode_www_form(
            "teamId" => team_id,
            "includeInactiveProfiles" => true,
            "provisioningProfileId" => profile_id,
          ),
          headers: { "Content-Type" => "application/x-www-form-urlencoded" },
        )

        if response.status == 200
          JSON.parse(response.body)
        else
          raise "Failed to get profile: #{response.status}"
        end
      end

      def get_bundle_info(bundle_id, team_id)
        response = authenticated_request(
          DEV_SERVICES_V1 + "/bundleIds/#{bundle_id}?include=bundleIdCapabilities,bundleIdCapabilities.capability,bundleIdCapabilities.appGroups",
          method: :post,
          body: { teamId: team_id }.to_json,
          headers: { "Content-Type" => "application/vnd.api+json" },
        )

        if response.status == 200
          JSON.parse(response.body)
        else
          raise "Failed to get bundle info: #{response.status}"
        end
      end

      def get_app_groups(team_id)
        response = authenticated_request(
          DEV_SERVICES_QH65B2 + "/account/ios/identifiers/listApplicationGroups.action",
          method: :post,
          body: URI.encode_www_form(
            "teamId" => team_id,
            "pageSize" => 1000,
            "pageNumber" => 1,
            "sort" => "name%3Dasc",
          ),
          headers: { "Content-Type" => "application/x-www-form-urlencoded" },
        )
        if response.status == 200
          JSON.parse(response.body)["applicationGroupList"]
        else
          raise "Failed to list bundle IDs: #{response.status}"
        end
      end

      def create_app_group(app_group, team_id)
        response = authenticated_request(
          DEV_SERVICES_QH65B2 + "/account/ios/identifiers/addApplicationGroup.action",
          method: :post,
          body: URI.encode_www_form(
            "name" => generate_name_for(app_group),
            "identifier" => app_group,
            "teamId" => team_id,
          ),
          headers: { "Content-Type" => "application/x-www-form-urlencoded" },
        )
        if response.status == 200
          JSON.parse(response.body)
        else
          raise "Failed to create app group: #{response.status}"
        end
      end

      def create_bundle(bundle_identifier, team_id, capabilities)
        response = authenticated_request(
          DEV_SERVICES_V1 + "/bundleIds",
          method: :post,
          body: {
            data: {
              type: "bundleIds",
              attributes: {
                identifier: bundle_identifier,
                name: generate_name_for(bundle_identifier),
                seedId: team_id,
                teamId: team_id,
              },
              relationships: {
                bundleIdCapabilities: {
                  data: capabilities,
                },
              },
            },
          }.to_json,
          headers: {
            "Content-Type" => "application/vnd.api+json",
            "X-HTTP-Method-Override" => nil,
          },
        )
        if response.status == 201
          JSON.parse(response.body)
        else
          raise "Failed to create bundle: #{response.status}"
        end
      end

      def patch_bundle(bundleInfo, team_id, capabilities)
        bundle_id = bundleInfo["data"]["id"]
        bundle_attributes = bundleInfo["data"]["attributes"]

        response = authenticated_request(
          DEV_SERVICES_V1 + "/bundleIds/#{bundle_id}",
          method: :patch,
          body: {
            data: {
              type: "bundleIds",
              id: bundle_id,
              attributes: {
                identifier: bundle_attributes["identifier"],
                permissions: { "edit": true, "delete": true },
                seedId: bundle_attributes["seedId"],
                name: bundle_attributes["name"],
                wildcard: bundle_attributes["wildcard"],
                teamId: team_id,
              },
              relationships: {
                bundleIdCapabilities: {
                  data: capabilities,
                },
              },
            },
          }.to_json,
          headers: { "Content-Type" => "application/vnd.api+json" },
        )

        if response.status == 200
          JSON.parse(response.body)
        else
          raise "Failed to patch bundle capabilities: #{response.status}"
        end
      end

      def create_provisioning_profile(team_id, bundle_id, bundle_identifier, certificate_id, devices)
        response = authenticated_request(
          DEV_SERVICES_V1 + "/profiles",
          method: :post,
          body: {
            data: {
              type: "profiles",
              attributes: {
                name: generate_name_for(bundle_identifier),
                profileType: "IOS_APP_ADHOC",
                teamId: team_id,
              },
              relationships: {
                bundleId: {
                  data: {
                    type: "bundleIds",
                    id: bundle_id,
                  },
                },
                certificates: {
                  data: [{
                    type: "certificates",
                    id: certificate_id,
                  }],
                },
                devices: {
                  data: devices.map { |device| { type: "devices", id: device["id"] } },
                },
              },
            },
          }.to_json,
          headers: {
            "Content-Type" => "application/vnd.api+json",
            "X-HTTP-Method-Override" => nil,
          },
        )
        if response.status == 201
          JSON.parse(response.body)
        else
          raise "Failed to create profile: #{response.status}"
        end
      end

      def regen_provisioning_profile(profile, team_id, devices)
        response = authenticated_request(
          DEV_SERVICES_QH65B2 + "/account/ios/profile/regenProvisioningProfile.action",
          method: :post,
          body: URI.encode_www_form(
            "appIdId" => profile["provisioningProfile"]["appIdId"],
            "provisioningProfileId" => profile["provisioningProfile"]["provisioningProfileId"],
            "distributionType" => profile["provisioningProfile"]["distributionType"],
            # TODO: figure out how to get this from old profile
            "isOfflineProfile" => false,
            "provisioningProfileName" => profile["provisioningProfile"]["name"],
            "certificateIds" => profile["provisioningProfile"]["certificateIds"].join(","),
            "deviceIds" => devices,
            "teamId" => team_id,
          ),
          headers: { "Content-Type" => "application/x-www-form-urlencoded" },
        )
        if response.status == 200
          JSON.parse(response.body)
        else
          raise "Failed to regenerate profile: #{response.status}"
        end
      end

      private

      def generate_name_for(resource_id)
        latinized = resource_id.gsub(/[^0-9A-Za-z\d\s]/, " ")

        return "ADSEDARE #{latinized}"
      end

      def authenticated_request(endpoint, method: :get, params: nil, body: nil, headers: nil)
        unless auth_helper.validate_token
          auth_helper.sign_in
        end

        # Make the request
        return auth_helper.request(
                 endpoint,
                 method: method,
                 params: params,
                 body: body,
                 headers: headers,
               )
      end
    end
  end
end
