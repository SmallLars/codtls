require 'test_helper'
require 'codtls'

# Testclass
class CoDTLSTest < Minitest::Test
  def setup
    fail CoDTLS::SessionError 'testdatabase already exists' if File.exist?(
                                                         'testdatabase.sqlite')
    SQLite3::Database.new('testdatabase.sqlite')
    ActiveRecord::Base.establish_connection(
      adapter: 'sqlite3',
      database: 'testdatabase.sqlite')
    ActiveRecord::Base.connection
    ActiveRecord::Migration.verbose = false # debug messages
    ActiveRecord::Migrator.migrate 'db/migrate'
    @session = CoDTLS::Session.new('127.0.0.1')
  end

  def teardown
    ActiveRecord::Base.remove_connection
    FileUtils.rm('testdatabase.sqlite') if File.exist?('testdatabase.sqlite')
  end

  def info(numeric_address, code)
    assert_equal numeric_address, '::1'
    @listener_test = 1 if numeric_address == '::1'
  end

=begin
  def test_listener
    @listener_test = 0
    CoDTLS::SecureSocket.add_new_node_listener(self)
    sleep(1)
    d = UDPSocket.new(Socket::AF_INET6)
    d.connect('::1', 5684)
    d.send("\x50\x03\x00", 0)
    sleep(1)
    assert_equal 1, @listener_test
    d.close
  end
=end

  def test_psk
    assert_equal [], CoDTLS::SecureSocket.psks

    CoDTLS::SecureSocket.add_psk(
      ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
      'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1')
    assert_equal [[['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
                   'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1']],
                 CoDTLS::SecureSocket.psks

    CoDTLS::SecureSocket.del_psk(
      ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'))
    assert_equal [], CoDTLS::SecureSocket.psks

    CoDTLS::SecureSocket.add_psk(
      ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
      'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1')
    CoDTLS::SecureSocket.add_psk(
      ['9425f01d39034295ad9447161e13251b'].pack('H*'),
      'abcdefghijklmnop', 'Rolladen Nummer 5')
    assert_equal [[['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
                   'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1'],
                  [['9425f01d39034295ad9447161e13251b'].pack('H*'),
                   'abcdefghijklmnop', 'Rolladen Nummer 5']],
                 CoDTLS::SecureSocket.psks

    CoDTLS::SecureSocket.del_psk(
      ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'))
    assert_equal [[['9425f01d39034295ad9447161e13251b'].pack('H*'),
                   'abcdefghijklmnop', 'Rolladen Nummer 5']],
                 CoDTLS::SecureSocket.psks
  end
end
