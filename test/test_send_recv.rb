require 'test_helper'
require 'codtls'

# Testclass
class CoDTLSSendRecvTest < Minitest::Test
  DB_FILE = 'sendrecvtest.sqlite'
  KEY = 'ABCDEFGHIJKLMNOP'
  IV = 'ABCD'

  def setup
    create_sqlite_db(DB_FILE)
    SQLite3::Database.new(DB_FILE)
    ActiveRecord::Base.establish_connection(
      adapter: 'sqlite3',
      database: DB_FILE)
    ActiveRecord::Base.connection
    ActiveRecord::Migration.verbose = false
    ActiveRecord::Migrator.migrate('db/migrate')
  end

  def teardown
    #CoDTLS::Session.clear_all
    ActiveRecord::Base.remove_connection
    FileUtils.rm(DB_FILE)
  end

  def test_send
    # Setup - begin
    session = CoDTLS::Session.new('127.0.0.1')

    r = UDPSocket.new
    r.bind('127.0.0.1', 5684)

    s = CoDTLS::SecureSocket.new
    s.connect('127.0.0.1', 5684)
    # Setup - end

    # assert_raises(CoDTLS::SecureSocketError) { s.send('Hallo Welt!', 0) }

    session.enable_handshake

    s.send('Hallo Welt!', 0)
    h, d = CoDTLS::Record.parse(r.recvfrom(50)[0])
    check_header('Send 1', h, :handshake, 0, 1)
    assert_equal('Hallo Welt!', d)

    session.disable_handshake

    # assert_raises(CoDTLS::SecureSocketError) { s.send('Hallo Welt!', 0) }

    session.enable_handshake

    s.send('Hallo Welt!', 0)
    h, d = CoDTLS::Record.parse(r.recvfrom(50)[0])
    check_header('Send 2', h, :handshake, 0, 2)
    assert_equal('Hallo Welt!', d)

    s.send('Hallo Welt!', 0)
    h, d = CoDTLS::Record.parse(r.recvfrom(50)[0])
    check_header('Send 3', h, :handshake, 0, 3)
    assert_equal('Hallo Welt!', d)

    session.key_block = KEY * 2 + IV * 2

    s.send('Hallo Welt!', 0)
    h, d = CoDTLS::Record.parse(r.recvfrom(50)[0])
    check_header('Send 4', h, :handshake, 0, 4)
    assert_equal('Hallo Welt!', d)

    ccm = OpenSSL::CCM.new('AES', KEY, 8)
    session.increase_epoch

    session.disable_handshake

    s.send('Hallo Welt!', 0)
    h, d = CoDTLS::Record.parse(r.recvfrom(50)[0])
    check_header('Send 5', h, :appdata, 1, 1)
    c = ccm.encrypt('Hallo Welt!', IV + "\x00\x01\x00\x00\x00\x00\x00\x01")
    assert_equal(c.unpack('H*')[0], d.unpack('H*')[0])

    s.send('Hallo Welt!', 0)
    h, d = CoDTLS::Record.parse(r.recvfrom(50)[0])
    check_header('Send 6', h, :appdata, 1, 2)
    c = ccm.encrypt('Hallo Welt!', IV + "\x00\x01\x00\x00\x00\x00\x00\x02")
    assert_equal(c.unpack('H*')[0], d.unpack('H*')[0])

    session.enable_handshake

    s.send('Hallo Welt!', 0)
    h, d = CoDTLS::Record.parse(r.recvfrom(50)[0])
    check_header('Send 7', h, :handshake, 1, 3)
    c = ccm.encrypt('Hallo Welt!', IV + "\x00\x01\x00\x00\x00\x00\x00\x03")
    assert_equal(c.unpack('H*')[0], d.unpack('H*')[0])

    s.send('Hallo Welt!', 0)
    h, d = CoDTLS::Record.parse(r.recvfrom(50)[0])
    check_header('Send 8', h, :handshake, 1, 4)
    c = ccm.encrypt('Hallo Welt!', IV + "\x00\x01\x00\x00\x00\x00\x00\x04")
    assert_equal(c.unpack('H*')[0], d.unpack('H*')[0])

    session.disable_handshake

    s.send('Hallo Welt!', 0)
    h, d = CoDTLS::Record.parse(r.recvfrom(50)[0])
    check_header('Send 9', h, :appdata, 1, 5)
    c = ccm.encrypt('Hallo Welt!', IV + "\x00\x01\x00\x00\x00\x00\x00\x05")
    assert_equal(c.unpack('H*')[0], d.unpack('H*')[0])

    s.close
    r.close
  end

=begin
  def test_receive
    # Setup - begin
    session = CoDTLS::Session.new('127.0.0.1')
    session.enable_handshake

    r = CoDTLS::SecureSocket.new
    r.bind('127.0.0.1', 0)
    r.connect('127.0.0.1', 5684)

    s = UDPSocket.new
    s.bind('127.0.0.1', 5684)

    r.send('find Port', 0)
    port = s.recvfrom(12)[1][1]
#   s.connect('127.0.0.1', s.recvfrom(12)[1][1])

    session.disable_handshake
    # Setup - end

    h = CoDTLS::Record.new(:appdata, 0, 1)
    s.send(h.to_wire + 'Hallo Welt!', 0, '127.0.0.1', port)
    # ---
    d, = r.recvfrom(5)
    assert_equal('', d)
    # ---
    h, d = CoDTLS::Record.parse(s.recvfrom(20)[0])
    check_header('Receive 1', h, :alert, 0, 2)
    assert_equal("\x02\x0a", d) # fatal (2), unexpected_message (10)

    h = CoDTLS::Record.new(:handshake, 0, 1)
    s.send(h.to_wire + 'Hallo Welt!', 0, '127.0.0.1', port)
    d, = r.recvfrom(5)
    assert_equal('Hallo', d)

    h = CoDTLS::Record.new(:handshake, 0, 2)
    s.send(h.to_wire + 'Hallo Welt!', 0, '127.0.0.1', port)
    d, = r.recvfrom(20)
    assert_equal('Hallo Welt!', d)

    h = CoDTLS::Record.new(:handshake, 0, 104)
    s.send(h.to_wire + 'Hallo Welt!', 0, '127.0.0.1', port)
    # ---
    d, = r.recvfrom(5)
    assert_equal('', d)
    # ---
    h, d = CoDTLS::Record.parse(s.recvfrom(20)[0])
    check_header('Receive 2', h, :alert, 0, 3)
    assert_equal("\x02\x32", d) # fatal (2), decode_error (50)

    h = CoDTLS::Record.new(:handshake, 0, 103)
    s.send(h.to_wire + 'Hallo Welt!', 0, '127.0.0.1', port)
    d, = r.recvfrom(11)
    assert_equal('Hallo Welt!', d)

    s.close
    r.close
  end
=end

  def check_header(fail_msg, header, type, epoch, seq_num = nil)
    assert_equal(type, header.type, fail_msg)
    assert_equal(epoch, header.epoch, fail_msg)
    assert_equal(seq_num, header.seq_num, fail_msg) unless seq_num.nil?
  end
end
