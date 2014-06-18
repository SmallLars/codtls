require 'test_helper'
require 'codtls'

# Testclass
class CoDTLSTest < Minitest::Unit::TestCase
  def setup
    @session = CoDTLS::RedisSession.new('127.0.0.1')
  end

  def teardown
    CoDTLS::RedisPSKDB.clear_all
  end

  def test_psk
    assert_equal [], CoDTLS::SecureSocket.psks

    CoDTLS::SecureSocket.add_psk(
      ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
      'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1')
    assert_equal [[0, ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
                   'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1']],
                 CoDTLS::SecureSocket.psks

    CoDTLS::SecureSocket.del_psk(0)
    assert_equal [], CoDTLS::SecureSocket.psks

    CoDTLS::SecureSocket.add_psk(
      ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
      'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1')
    assert_equal [[1, ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
                   'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1']],
                 CoDTLS::SecureSocket.psks
    CoDTLS::SecureSocket.add_psk(
      ['9425f01d39034295ad9447161e13251b'].pack('H*'),
      'abcdefghijklmnop', 'Rolladen Nummer 5')
    assert_equal true, CoDTLS::SecureSocket.psks.include?([1, ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
                   'ABCDEFGHIJKLMNOP', 'Temperaturgerät 1'])
    assert_equal true, CoDTLS::SecureSocket.psks.include?([2, ['9425f01d39034295ad9447161e13251b'].pack('H*'),
                   'abcdefghijklmnop', 'Rolladen Nummer 5'])

    CoDTLS::SecureSocket.del_psk(1)
    assert_equal [[2, ['9425f01d39034295ad9447161e13251b'].pack('H*'),
                   'abcdefghijklmnop', 'Rolladen Nummer 5']],
                 CoDTLS::SecureSocket.psks
  end
end
