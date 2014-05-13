require 'codtls/h_content'
require 'codtls/ecc'
require 'openssl/cmac'
require 'openssl/ccm'
require 'codtls/prf'
require 'codtls/pskdb'
require 'coap'

module CoDTLS
  # TODO
  class HandshakeError < StandardError
  end

  # Tolles Modul
  module Handshake
    # TODO
    def self.handshake(numeric_address)
      logger = Logger.new(STDOUT)
      logger.level = CoDTLS::LOG_LEVEL
      logger.debug("Handshake gestarted #{numeric_address}")

      session = Session.new(numeric_address)
      session.enable_handshake

      logger.debug("Session created")

      c = CoAP::Client.new(48).use_dtls
      uuid = c.get(numeric_address, 5684, '/d/uuid').payload

      logger.debug("UUID erhalten: #{uuid}")

      psk = CoDTLS::PSKDB.get_psk(uuid)
      logger.debug("PSK: #{psk}")
      psk.nil? ? 5 : 0
=begin
      session = Session.new(numeric_address)
      session.enable_handshake

      c = CoAP::Client.new(48).use_dtls

      state = State.new

      # Step 1 - ClientHello ohne Cookie
      msg = ''.force_encoding('ASCII-8BIT')
      client_hello = ClientHello.new(state.client_time, state.client_random)
      Content.add_content(msg, client_hello)
      r = c.post(numeric_address, 5684, '/dtls', msg)

      hello_verify = Content.get_content(r.payload)
      return 1 unless hello_verify.class == HelloVerifyRequest

      # Step 2 - ClientHello mit Cookie
      msg.clear
      client_hello.cookie = hello_verify.cookie
      Content.add_content(msg, client_hello)
      state.add_finished_source(msg)
      r = c.post(numeric_address, 5684, '/dtls', msg)
      state.add_finished_source(r)

      server_hello = Content.get_content(r.payload)
      return 2 unless server_hello == ServerHello
      server_key_exchange = Content.get_content(r.payload)
      return 3 unless server_key_exchange == ServerKeyExchange
      server_hello_done = Content.get_content(r.payload)
      return 4 unless server_hello_done == ServerHelloDone

      # Step 3 - ClientKeyExchange, ChangeCipherSpec, Finished
      msg.clear
      state.server_time = server_hello.time
      state.server_random = server_hello.random
      session.id = server_hello.session
      return 5 unless state.choose_psk(server_key_exchange.psk_hint)
      state.server_key = server_key_exchange.point
      session.key_block = state.key_block

      client_key_exchange = ClientKeyExchange.new(
        server_key_exchange.psk_hint,
        KeyExchange::NAMEDCURVE[:secp256r1],
        state.public_key)
      Content.add_content(msg, client_key_exchange)
      state.add_finished_source(msg)

      client_finished = state.finished('client finished')

      change_cipher_spec = ChangeCipherSpec.new
      Content.add_content(msg, change_cipher_spec)
      finished = Finished.new(client_finished)

      finished_content = ''.force_encoding('ASCII-8BIT')
      Content.add_content(msg, change_cipher_spec)
      state.add_finished_source(finished_content)

      server_finished = state.finished('server finished')

      ccm = OpenSSL::CCM.new('AES', state.key_block[0..15], 8)
      nonce = state.key_block[32..35] + ("\x00" * 8)
      msg.concat(ccm.encrypt(finished_content, nonce))

      r = c.post(numeric_address, 5684, '/dtls', msg)

      0
=end
    end

    # Finished muss enthalten:
    # ClientHello, ServerHello, ServerKeyExchange, ServerHelloDone,
    # ClientKeyExchange, (ClientFinished)

    # Tolle Klasse
    class State
      attr_reader :client_time, :client_random
      attr_accessor :server_time, :server_random

      def initialize
        @client_time = Time.new.to_i
        @client_random = Random.new.bytes(28)
        @private_key = Random.new.bytes(32)
        @finished_source = ''.force_encoding('ASCII-8BIT')
        @psk = ''
        @master_secret = ''
      end

      def client_full_random
        [@client_time].pack('N') + @client_random
      end

      def choose_psk(psk_hint)
        @psk = CoDTLS::PSKDB.get_psk(psk_hint)
        @psk.nil? ? false : true
      end

      def public_key
        CoDTLS::ECC.mult(@private_key)
      end

      def server_key=(key)
        secret = CoDTLS::ECC.mult(@private_key, key)
        pre_master = "\x00\x10"
        pre_master += @psk
        pre_master += "\x00\x20"
        pre_master += secret[1..32]

        server_full_random = [@server_time].pack('N') + @server_random

        prf = OpenSSL::PRF.new(pre_master, 'master secret',
                               client_full_random + server_full_random)
        @master_secret = prf.get(48)
      end

      def key_block
        fail HandshakeError, 'Missing mastersecret' if @master_secret == ''

        server_full_random = [@server_time].pack('N') + @server_random
        prf = OpenSSL::PRF.new(@master_secret, 'key expansion',
                               server_full_random + client_full_random)
        prf.get(40)
      end

      def add_finished_source(data)
        @finished_source.concat(data)
      end

      def finished(label)
        fail HandshakeError, 'Missing mastersecret' if @master_secret == ''
        fail HandshakeError, 'Missing pre-shared key' if @psk == ''

        seed = OpenSSL::CMAC.digest('AES', @psk, @finished_source)
        prf = OpenSSL::PRF.new(@master_secret, label, seed)
        prf.get(12)
      end
    end
  end
end
