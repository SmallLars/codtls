require 'test_helper'
require 'codtls'

# Testclass
class CoDTLSTest < Minitest::Test
  def setup
    CoDTLS.connect_database('testdatabase.sqlite')
    CoDTLS.setup_database
    @session = CoDTLS::Session.new('127.0.0.1')
  end

  def teardown
    ActiveRecord::Base.remove_connection
    FileUtils.rm('testdatabase.sqlite') if File.exist?('testdatabase.sqlite')
  end

  def test_psk
    assert_equal [], CoDTLS::SecureSocket.psks

    CoDTLS::SecureSocket.add_psk(
      ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
      'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1')
    assert_equal [[['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
                   'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1']],
                 CoDTLS::SecureSocket.psks.map { |x| x[1..3] }

    CoDTLS::SecureSocket.del_psk(1)
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
                 CoDTLS::SecureSocket.psks.map { |x| x[1..3] }

    CoDTLS::SecureSocket.del_psk(2)
    assert_equal [[['9425f01d39034295ad9447161e13251b'].pack('H*'),
                   'abcdefghijklmnop', 'Rolladen Nummer 5']],
                 CoDTLS::SecureSocket.psks.map { |x| x[1..3] }
  end
end
