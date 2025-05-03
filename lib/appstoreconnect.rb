# frozen_string_literal: true

require "faraday"
require "json"
require "jwt"

module AppStoreConnect
  class Client
    BASE_URL = "https://api.appstoreconnect.apple.com/v1"
    
    class << self
        def get_bundles_with_profiles(bundle_identifiers)
            response = request(
                BASE_URL + "/bundleIds",
                method: :get,
                params: {
                    "fields[bundleIds]" => "name,platform,identifier,profiles",
                    "filter[identifier]" => bundle_identifiers.join(","),
                    "fields[profiles]" => "name,profileType,profileState,profileContent,uuid",
                    "include" => "profiles",
                }
            )
            
            if response.status == 200
                JSON.parse(response.body)
            else
                puts response.body
                raise "Failed to get bundle IDs: #{response.status}"
            end
        end
      
        private

        def request(endpoint, method: :get, params: nil, body: nil, headers: nil)
            default_headers = {
                "Authorization" => "Bearer #{jwt_token}",
                "Content-Type" => "application/json",
                "Accept" => "application/json",
            }

            if headers
                default_headers = default_headers.merge(headers)
            end

            response = case method
            when :get
              Faraday.get(endpoint, params, default_headers)
            when :post
              Faraday.post(endpoint, body, default_headers)
            when :put
              Faraday.put(endpoint, body, default_headers)
            when :delete
              Faraday.delete(endpoint, default_headers)
            when :patch
              Faraday.patch(endpoint, body, default_headers)
            end

            return response
        end

        def jwt_token
            key_id = ENV["APPSTORE_CONNECT_KEY_ID"]
            key = ENV["APPSTORE_CONNECT_KEY"]
            issuer_id = ENV["APPSTORE_CONNECT_ISSUER_ID"]

            private_key = OpenSSL::PKey.read(key)
            token = JWT.encode(
                {
                    iss: issuer_id,
                    exp: Time.now.to_i + 20 * 60,
                    aud: "appstoreconnect-v1",
                },
                private_key,
                "ES256",
                header_fields = {
                    alg: "ES256",
                    kid: key_id,
                    typ: "JWT"
                }
            )

            return token
        end
    end
  end
end
