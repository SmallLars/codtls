require 'codtls/record'
require 'codtls/session'
require 'openssl/ccm'
require 'codtls/alert'

module CoDTLS
  # TODO
  module RecordLayer
    # first dtls message will be removed from mesg, so u can call parse
    # multiple times on a concatenation of many dtls records
    def self.decrypt(packet, maxlen)
      # packet = mesg, (address_family, port, hostname, numeric_address)

      mesg, sender_inet_addr = packet

      begin
        record, data = Record.parse(mesg)
      rescue RecordError
        send_alert(sender_inet_addr, :fatal, :decode_error)
        return ['', sender_inet_addr]
      end

      session = Session.new(sender_inet_addr[3])
      unless session.check_seq(record.seq_num)
        send_alert(sender_inet_addr, :fatal, :decode_error)
        return ['', sender_inet_addr]
      end

      if record.epoch > 0
        keyblock = session.key_block
        if keyblock.empty?
          send_alert(sender_inet_addr, :fatal, :decode_error)
          return ['', sender_inet_addr]
        end

        ccm = OpenSSL::CCM.new('AES', keyblock[16...32], 8)
        data = ccm.decrypt(data, record.nonce(keyblock[36...40]))
        if data.empty?
          send_alert(sender_inet_addr, :fatal, :bad_record_mac)
          return ['', sender_inet_addr]
        end
      else
        if session.epoch > 0
          # When Epoch > 0 is known, message in epoch 0 isnt acceptable
          send_alert(sender_inet_addr, :fatal, :unexpected_message)
          return ['', sender_inet_addr]
        end

        # WARNING: !!! -> disabled for testing purpose
        # if record.type == :appdata
        #   send_alert(sender_inet_addr, :fatal, :unexpected_message)
        #   return ['', sender_inet_addr]
        # end
      end

      if record.type == :alert
        session.clear
        return ['', sender_inet_addr]
      end

      session.seq = record.seq_num
      [data[0...maxlen], sender_inet_addr]
    end

    def self.send_alert(sender_inet_addr, lvl, desc)
      e = encrypt(Alert.new(lvl, desc).to_wire, sender_inet_addr[3], :alert)

      s = UDPSocket.new(sender_inet_addr[0])
      s.send(e, 0, sender_inet_addr[3], sender_inet_addr[1])
    end
  end
end
