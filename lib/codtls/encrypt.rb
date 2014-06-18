require 'codtls/record'
require 'codtls/session'
require 'openssl/ccm'

module CoDTLS
  # TODO
  module RecordLayer
    # TODO
    def self.encrypt(mesg, ip, type = :default)
      session = RedisSession.new(ip)
      type = session.handshake? ? :handshake : :appdata if type == :default

      # WARNING: !!! -> disabled for testing purpose
      # if session.epoch == 0 && type == :appdata
      #   fail SecureSocketError, 'app-data not allowed in epoch 0'
      # end

      record = Record.new(type, session.epoch, session.seq)

      if record.epoch > 0
        keyblock = session.key_block
        ccm = OpenSSL::CCM.new('AES', keyblock[0...16], 8)
        record.to_wire + ccm.encrypt(mesg,
                                     record.nonce(keyblock[32...36]),
                                     record.additional_data(mesg.length))
      else
        record.to_wire + mesg
      end
    end
  end
end
