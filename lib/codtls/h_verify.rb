require 'codtls/h_type'

module CoDTLS
  module Handshake
    # Tolle Klasse
    class HelloVerifyRequest < Type
      attr_reader :cookie

      def self.parse(data)
        # typedef struct {
        #   ProtocolVersion server_version;
        #   uint8_t cookie_len;
        #   uint8_t cookie[0];
        # } __attribute__ ((packed)) HelloVerifyRequest_t;

        # Zu erledigen: checks auf version und laenge
        HelloVerifyRequest.new(data.force_encoding('ASCII-8BIT')[3..-1])
      end

      public

      def initialize(cookie)
        super(3)
        @cookie = cookie
        @cookie = '' if cookie.nil?
        @cookie.force_encoding('ASCII-8BIT')
      end
    end
  end
end
