require 'codtls/h_type'

module CoDTLS
  module Handshake
    # Tolle Klasse
    class ServerHelloDone < Type
      def self.parse(*)
        ServerHelloDone.new
      end

      public

      def initialize
        super(32)
      end

      def to_wire
        ''.force_encoding('ASCII-8BIT')
      end
    end
  end
end
