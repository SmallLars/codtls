require 'test_helper'
require 'codtls/redis_pskdb'

# Testclass
class CoDTLSRedisPSKDBTest < Minitest::Unit::TestCase
  def setup
  end

  def teardown
    CoDTLS::RedisPSKDB.clear_all
  end

  # a new uuid gets registered and its psk gets updated.
  # The standard values for the epoch and handshake get checked.
  def test_psk
    assert_equal(nil, CoDTLS::RedisPSKDB.get_psk('UUID'))
    CoDTLS::RedisPSKDB.set_psk('UUID', '')
    assert_equal('', CoDTLS::RedisPSKDB.get_psk('UUID'))
    CoDTLS::RedisPSKDB.set_psk('UUID', 'PSK')
    assert_equal('PSK', CoDTLS::RedisPSKDB.get_psk('UUID'))
    CoDTLS::RedisPSKDB.set_psk('UUID2', 'PSK1')
    assert_equal('PSK1', CoDTLS::RedisPSKDB.get_psk('UUID2'))
    CoDTLS::RedisPSKDB.set_psk('UUID2', 'PSK2')
    assert_equal('PSK2', CoDTLS::RedisPSKDB.get_psk('UUID2'))
  end
end
