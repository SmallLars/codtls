require 'codtls/h_type'

module CoDTLS
  module Handshake
    # Tolle Klasse
    class ClientHello < Type
      attr_reader :time, :random, :cookie

      public

      def initialize(time, random, cookie = nil)
        super(1)
        self.time = time
        self.random = random
        self.cookie = cookie
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

      def cookie=(cookie)
        @cookie = cookie
        unless @cookie.nil?
          @cookie.force_encoding('ASCII-8BIT')
          if @cookie.length > 255
            fail HandshakeError, 'Maximum cookie length is 255'
          end
        end
      end

      def to_wire
        s = String.new("\xFE\xFD".force_encoding('ASCII-8BIT')) # Version 1.2
        s.concat([@time].pack('N'))
        s.concat(@random)
        if @cookie.nil?
          s.concat('00'.hex.chr)
        else
          s.concat([@cookie.length].pack('C'))
          s.concat(@cookie)
        end
        s.concat('00'.hex.chr) # Ciphersuite Length
        s.concat('02'.hex.chr) # Ciphersuite Length
        s.concat('FF'.hex.chr) # Ciphersuite: TLS_PSK_ECDH_WITH_AES_128_CCM_8
        s.concat('01'.hex.chr) # Ciphersuite: TLS_PSK_ECDH_WITH_AES_128_CCM_8
        s.concat('01'.hex.chr) # Compression Methods Length
        s.concat('00'.hex.chr) # No Compression
        s.concat('00'.hex.chr) # Extensions Length
        s.concat('0E'.hex.chr) # Extensions Length
        s.concat('00'.hex.chr) # Supported Elliptic Curves Extension
        s.concat('0a'.hex.chr) # Supported Elliptic Curves Extension
        s.concat('00'.hex.chr) # Supported Elliptic Curves Extension Length
        s.concat('04'.hex.chr) # Supported Elliptic Curves Extension Length
        s.concat('00'.hex.chr) # Elliptic Curves Arrays Length
        s.concat('02'.hex.chr) # Elliptic Curves Arrays Length
        s.concat('00'.hex.chr) # Elliptic Curve secp256r1
        s.concat('23'.hex.chr) # Elliptic Curve secp256r1
        s.concat('00'.hex.chr) # Supported Point Formats Extension
        s.concat('0B'.hex.chr) # Supported Point Formats Extension
        s.concat('00'.hex.chr) # Supported Point Formats Extension Length
        s.concat('02'.hex.chr) # Supported Point Formats Extension Length
        s.concat('01'.hex.chr) # Point Formats Arrays Length
        s.concat('00'.hex.chr) # Uncompressed Point
        s
      end
    end
  end
end
