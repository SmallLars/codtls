module CoDTLS
  module Handshake
    # Tolle Klasse
    class Type
      attr_reader :id

      def self.parse(*)
        fail HandshakeError, 'Not implemented'
      end

      public

      def initialize(id)
        @id = id
      end

      def to_wire
        fail HandshakeError, 'Not implemented'
      end
    end
  end
end
