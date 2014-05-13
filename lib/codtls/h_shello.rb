require 'codtls/h_type'

module CoDTLS
  module Handshake
    # Tolle Klasse
    class ServerHello < Type
      attr_reader :time, :random, :session

      def self.parse(data)
        data.force_encoding('ASCII-8BIT')
        data.slice!(0...2) # TODO: check version
        t = data.slice!(0...4).unpack('N')[0]
        r = data.slice!(0...28)
        s = data.slice!(0...data.slice!(0).ord)
        ServerHello.new(t, r, s)
      end

      public

      def initialize(time, random, session)
        super(2)
        self.time = time
        self.random = random
        self.session = session
      end

      def time=(time)
        if time.nil? || time > 0xFFFFFFFF
          fail HandshakeError, 'Invalid time value'
        end
        @time = time
      end

      def random=(random)
        if random.nil? || random.b.length != 28
          fail HandshakeError, 'Random needs to have a length of 28 byte'
        else
          @random = random.force_encoding('ASCII-8BIT')
        end
      end

      def session=(session)
        if session.nil? || session.b.length.between?(1, 255)
          fail HandshakeError, 'Session length needs to be in 1 - 255'
        end
        @session = session
        @session.force_encoding('ASCII-8BIT')
      end
    end
  end
end
