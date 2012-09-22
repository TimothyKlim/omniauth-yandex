require 'omniauth/strategies/oauth2'
require 'json'

module OmniAuth
  module Strategies

    # Authenticate to Yandex.ru utilizing OAuth 2.0
    # http://api.yandex.ru/oauth/

    class Yandex < OmniAuth::Strategies::OAuth2
      option :name, "yandex"

      option :client_options, {
        :site => 'https://oauth.yandex.ru/',
        :token_url     => '/token',
        :authorize_url => '/authorize'
      }

      option :provider_ignores_state, true

      uid do
        raw_info[:uid]
      end

      info do
        {
          :nickname => raw_info[:name],
          :email => raw_info[:email],
          :name => raw_info[:name],
          :image => raw_info[:photo],
          :location => raw_info[:country],
          :urls => {
            'Yandex' => raw_info[:yaru_profile]
          }
        }
      end

      extra do
        {:raw_info => raw_info}
      end

      def callback_url
        if options.authorize_options.respond_to? :callback_url
          options.authorize_options.callback_url
        else
          super
        end
      end

      private

      def raw_info
        @raw_info ||= begin
          # Get user info from Ya.ru API
          # http://api.yandex.ru/yaru/doc/ref/concepts/discovery.xml
          json_data = access_token.get("https://login.yandex.ru/info?format=json").body
          data = JSON.parse(json_data)

          {
            uid: data['id'],
            email: data['default_email']
          }
        end
      end

    end
  end
end
