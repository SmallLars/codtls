require 'test_helper'
require 'codtls'

# Testclass
class ContentTest < Minitest::Unit::TestCase
  COOKIE = 'ABCDEFGH'

  def test_content_get
    3.times do |i|
      c = ("\x0D\x0B\x03\x03\x08" + COOKIE) * (i + 1)
      o = CoDTLS::Handshake::Content.get_content(c)
      assert_equal(CoDTLS::Handshake::HelloVerifyRequest, o.class)
      assert_equal(COOKIE, o.cookie)
      assert_equal(("\x0D\x0B\x03\x03\x08" + COOKIE) * i, c)
    end

    c = "\x0D\x0B\x03\x03\x08" + COOKIE + 'A'
    CoDTLS::Handshake::Content.get_content(c)
    assert_equal('A', c)

    assert_raises CoDTLS::HandshakeError do
      c = "\x0D\x0B\x03\x03\x08" + COOKIE[0...6]
      CoDTLS::Handshake::Content.get_content(c)
    end

    assert_raises CoDTLS::HandshakeError do
      c = "\xFD\x0B\x03\x03\x08" + COOKIE
      CoDTLS::Handshake::Content.get_content(c)
    end
  end

  def test_add_content
    c = ''
    f = CoDTLS::Handshake::Finished.new('Hallo Welt!')
    CoDTLS::Handshake::Content.add_content(c, f)
    assert_equal("\x51\x0BHallo Welt!", c)

    CoDTLS::Handshake::Content.add_content(c, f)
    assert_equal("\x51\x0BHallo Welt!\x51\x0BHallo Welt!", c)

    c = 'ABC'
    f = CoDTLS::Handshake::Finished.new('Hallo Welt!')
    CoDTLS::Handshake::Content.add_content(c, f)
    assert_equal("ABC\x51\x0BHallo Welt!", c)

    c = ''
    f = CoDTLS::Handshake::Finished.new('')
    CoDTLS::Handshake::Content.add_content(c, f)
    assert_equal("\x50", c)

    f = CoDTLS::Handshake::Finished.new('Hallo Welt!')
    CoDTLS::Handshake::Content.add_content(c, f)
    assert_equal("\x50\x51\x0BHallo Welt!", c)

    f = CoDTLS::Handshake::Finished.new('')
    CoDTLS::Handshake::Content.add_content(c, f)
    assert_equal("\x50\x51\x0BHallo Welt!\x50", c)
  end
end
