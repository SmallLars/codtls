require 'test_helper'
require 'codtls/session'

# Testclass
class CoDTLSSessionTest < Minitest::Test
  def setup
    CoDTLS.connect_database('testdatabase.sqlite')
    CoDTLS.setup_database
    CoDTLS::Session.clear_all # only needed here, it is not normal that the
    # database gets changed while the program is still running
    @session = CoDTLS::Session.new('127.0.0.1')
  end

  def teardown
    @session.clear
    ActiveRecord::Base.remove_connection
    FileUtils.rm('testdatabase.sqlite') if File.exist?('testdatabase.sqlite')
  end

  # check values, set everything, check values, clear, check values,
  # create new session, check values
  def test_clear
    assert_equal(nil, @session.id)
    assert_equal(0, @session.epoch)
    assert_equal(true, @session.check_seq(1))
    assert_equal(1, @session.seq)
    assert_equal(nil, @session.key_block)
    assert_equal(false, @session.handshake?)

    @session.id = 'ABCDEFGH'
    @session.key_block = 'ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDABCD'
    @session.increase_epoch
    @session.seq = 5
    @session.enable_handshake

    assert_equal('ABCDEFGH', @session.id)
    assert_equal(1, @session.epoch)
    assert_equal(true, @session.check_seq(6))
    assert_equal(1, @session.seq)
    assert_equal('ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDABCD',
                 @session.key_block)
    assert_equal(true, @session.handshake?)

    @session.clear
    entry = nil
    ActiveRecord::Base.connection_pool.with_connection do
      entry = CODTLSConnection.find_by_ip('127.0.0.1')
    end
    assert_equal(nil, entry)
    assert_equal([], CoDTLS::Session.ip_list)

    assert_equal(nil, @session.id)
    assert_equal(0, @session.epoch)
    assert_equal(true, @session.check_seq(1))
    assert_equal(1, @session.seq)
    assert_equal(nil, @session.key_block)
    assert_equal(false, @session.handshake?)
  end

  # get_epoch and increase_epoch test
  def test_epoch
    assert_equal(nil, @session.id)
    assert_equal(0, @session.epoch)
    assert_equal(true, @session.check_seq(1))
    assert_equal(1, @session.seq)
    assert_equal(nil, @session.key_block)
    assert_equal(false, @session.handshake?)

    @session.seq
    @session.seq
    @session.seq = 50
    assert_raises(CoDTLS::SessionError) { @session.increase_epoch }

    @session.key_block = 'ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDABCD'
    assert_equal(nil, @session.key_block)

    @session.increase_epoch
    assert_equal(1, @session.epoch)
    assert_equal(true, @session.check_seq(1))
    assert_equal(1, @session.seq)
    assert_equal('ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDABCD',
                 @session.key_block)
  end

  # get_key_block and add_key_block tests, testing the overwriting off
  # new keyblocks and switching keyblocks when the epoch is increased
  def test_key_block
    assert_equal(nil, @session.key_block)
    exception = assert_raises(CoDTLS::SessionError) do
      @session.key_block = 'this_key_block_is_too_small'
    end
    assert_equal('key blocks have to be 40 byte long', exception.message)
    @session.key_block = 'key_block_with_fourty_bytes_number_00001'
    assert_equal(nil, @session.key_block)
    @session.increase_epoch
    assert_equal('key_block_with_fourt' \
                 'y_bytes_number_00001', @session.key_block)
    @session.key_block = 'key_block_with_fourty_bytes_number_00002'
    @session.key_block = 'key_block_with_fourty_bytes_number_00003'
    assert_equal('key_block_with_fourt' \
                 'y_bytes_number_00001', @session.key_block)
    @session.increase_epoch
    assert_equal('key_block_with_fourt' \
                 'y_bytes_number_00003', @session.key_block)
  end

  # enable_handshake and dissable_handshake tests.
  def test_handshake
    assert_equal(false, @session.handshake?)
    @session.enable_handshake
    assert_equal(true, @session.handshake?)
    @session.enable_handshake
    assert_equal(true, @session.handshake?)
    @session.disable_handshake
    assert_equal(false, @session.handshake?)
  end

  # get_seq and check_seq tests, testing the check_seq ranges and the
  # incrementing of get_seq.
  def test_seq
    assert_equal(1, @session.seq)
    assert_equal(2, @session.seq)
    assert_equal(3, @session.seq)

    # 1 is expected, so -9 ... 101 are valid values
    assert_equal(false, @session.check_seq(-10))
    assert_equal(false, @session.check_seq(102))
    assert_equal(true, @session.check_seq(-9))
    assert_equal(true, @session.check_seq(-1))
    assert_equal(true, @session.check_seq(0))
    assert_equal(true, @session.check_seq(1))
    assert_equal(true, @session.check_seq(101))

    @session.seq = 1
    (2..100).each do |n|
      assert_equal(true, @session.check_seq(n))
      @session.seq = n
    end
    # 101 is expected, so max allowed value is 201
    assert_equal(true, @session.check_seq(201))
    assert_equal(false, @session.check_seq(202))
  end

  def test_multiple_sessions
    new_session = CoDTLS::Session.new('127.0.0.1')
    assert_equal(1, CoDTLS::Session.ip_list.size)
    assert_equal(false, new_session.handshake?)
    assert_equal(false, @session.handshake?)
    new_session.enable_handshake
    assert_equal(true, new_session.handshake?)
    assert_equal(true, @session.handshake?)
    new_session.clear
    assert_equal(false, @session.handshake?)
  end
end
