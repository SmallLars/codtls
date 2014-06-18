require 'test_helper'
require 'codtls'

# Testclass
class KeyExchangeTest < Minitest::Unit::TestCase
  PSK_HINT = 'ABCDEFGHIJKLMNOP'
  CURVE = CoDTLS::Handshake::KeyExchange::ECCURVETYPE[:named_curve] +
          CoDTLS::Handshake::KeyExchange::NAMEDCURVE[:secp256r1]
  POINT = CoDTLS::Handshake::KeyExchange::POINTTYPE[:uncompressed] +
          ['6b17d1f2e12c4247f8bce6e563a440f2' \
           '77037d812deb33a0f4a13945d898c296'].pack('H*') +
          ['4fe342e2fe1a7f9b8ee7eb4a7c0f9e16' \
           '2bce33576b315ececbb6406837bf51f5'].pack('H*')

  # [fails?, psk_hint, curve, point, wire]
  V = [
    [0, PSK_HINT, CURVE, POINT,
     "\x00\x10" + PSK_HINT + CURVE + "\x41" + POINT] # ,
    # [1, nil, RANDOM, COOKIE, 'T1']
  ]

  def test_keyexchange
    V.each do |(f, psk, c, p, w)|
      if f == 1
        # assert_raises CoDTLS::HandshakeError, w do
        #   CoDTLS::Handshake::ClientHello.new(t, r, c)
        # end
      else
        wire = CoDTLS::Handshake::ClientKeyExchange.new(psk, c, p).to_wire
        assert_equal(w.b, wire)
        wire = CoDTLS::Handshake::ServerKeyExchange.new(psk, c, p).to_wire
        assert_equal(w.b, wire)
      end
    end
  end
end
