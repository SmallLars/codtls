require 'test_helper'
require 'codtls'

# Testclass
class ClientHelloTest < Minitest::Test
  RANDOM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZAB'
  COOKIE = 'ABCDEFGH'
  APPENDIX = "\x00\x02\xFF\x01\x01\x00\x00\x0E\x00\x0A\x00" \
             "\x04\x00\x02\x00\x23\x00\x0B\x00\x02\x01\x00"

  # [fails?, time, random, cookie, wire]
  V = [
    [0, 42, RANDOM, COOKIE,
     "\xFE\xFD\x00\x00\x00\x2A" + RANDOM + "\x08" + COOKIE + APPENDIX],
    [0, 24, RANDOM, nil,
     "\xFE\xFD\x00\x00\x00\x18" + RANDOM + "\x00" + APPENDIX],
    [0, 0xFFFFFFFF, RANDOM, nil,
     "\xFE\xFD\xFF\xFF\xFF\xFF" + RANDOM + "\x00" + APPENDIX],
    [1, nil, RANDOM, COOKIE, 'T1'],
    [1, 0x1FFFFFFFF, RANDOM, COOKIE, 'T2'],
    [1, 42, '', COOKIE, 'T3'],
    [1, 42, nil, COOKIE, 'T4'],
    [1, 42, RANDOM[0..26], COOKIE, 'T5'],
    [1, 42, RANDOM + 'C', COOKIE, 'T6'],
    [1, 42, RANDOM, 'A' * 256, 'T7']
  ]

  def test_clienthello
    V.each do |(f, t, r, c, w)|
      if f == 1
        assert_raises CoDTLS::HandshakeError, w do
          CoDTLS::Handshake::ClientHello.new(t, r, c)
        end
      else
        wire = CoDTLS::Handshake::ClientHello.new(t, r, c).to_wire
        assert_equal(w.b, wire)
      end
    end
  end
end
