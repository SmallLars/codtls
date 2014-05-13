require 'codtls/h_chello'
require 'codtls/h_verify'
require 'codtls/h_shello'
require 'codtls/h_keyexchange'
require 'codtls/h_shellodone'
require 'codtls/h_finished'
require 'codtls/h_changecipherspec'
require 'codtls/alert'

module CoDTLS
  module Handshake
    # Tolle Klasse
    class Content
      TYPE = Array.new(64, nil)
      # TYPE[0] = hello_request
      TYPE[1] = Handshake::ClientHello
      TYPE[2] = Handshake::ServerHello
      TYPE[3] = Handshake::HelloVerifyRequest
      # TYPE[11] = certificate
      TYPE[12] = Handshake::ServerKeyExchange
      # TYPE[13] = certificate_request
      TYPE[14] = Handshake::ServerHelloDone
      # TYPE[15] = certificate_verify
      TYPE[16] = Handshake::ClientKeyExchange
      TYPE[20] = Handshake::Finished
      TYPE[32] = Handshake::ChangeCipherSpec
      TYPE[33] = Alert

      # data == string -> content vorne abnehmen.
      # rueckgabe ist spezifisches content object
      def self.get_content(data)
        data.force_encoding('ASCII-8BIT')
        header = data.slice!(0).ord
        (4 - header & 0x03).times { data.insert(0, "\x00") }
        length = data.slice!(0...4).unpack('N')[0]
        if TYPE[(header & 0xFC) >> 2].nil?
          fail HandshakeError, 'unknown content type'
        end
        fail HandshakeError, 'missing handshake data' if data.length < length
        TYPE[(header & 0xFC) >> 2].parse(data.slice!(0...length))
      end

      # content braucht to_wire methode.
      # wird in content verpackt und an data-string angehangen
      def self.add_content(data, content)
        header = content.id << 2
        content = content.to_wire
        length = [content.length].pack('N')
        length.slice!(0) while length[0] == "\x00"
        header |= length.length
        data.concat(header.chr)
        data.concat(length)
        data.concat(content)
      end
    end
  end
end
