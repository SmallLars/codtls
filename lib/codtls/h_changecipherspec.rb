require 'codtls/h_type'

module CoDTLS
  module Handshake
    # Tolle Klasse
    class ChangeCipherSpec < Type
      def self.parse(data)
        data.force_encoding('ASCII-8BIT')
        fail HandshakeError, 'Missing data' if data.length < 1
        fail HandshakeError, 'Wrong value' unless data[0] == "\x01"
        ChangeCipherSpec.new
      end

      public

      def initialize
        super(32)
      end

      def to_wire
        "\x01".force_encoding('ASCII-8BIT')
      end
    end
  end
end
