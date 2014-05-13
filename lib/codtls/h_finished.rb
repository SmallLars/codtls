require 'codtls/h_type'

module CoDTLS
  module Handshake
    # Tolle Klasse
    class Finished < Type
      attr_reader :value

      def self.parse(data)
        if data.force_encoding('ASCII-8BIT').length < 2
          fail HandshakeError, 'Missing data'
        end
        Finished.new(data)
      end

      public

      def initialize(value)
        super(20)
        @value = value
        @value = '' if value.nil?
        @value.force_encoding('ASCII-8BIT')
      end

      def to_wire
        @value.force_encoding('ASCII-8BIT')
      end
    end
  end
end
