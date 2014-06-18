require 'test_helper'
require 'codtls/rampskdb'

# Testclass
class CoDTLSRAMPSKDBTest < Minitest::Unit::TestCase
  def setup
  end

  def teardown
    CoDTLS::RAMPSKDB.clear_all
  end

  # a new uuid gets registered and its psk gets updated.
  # The standard values for the epoch and handshake get checked.
  def test_psk
    assert_equal(nil, CoDTLS::RAMPSKDB.get_psk('UUID'))
    CoDTLS::RAMPSKDB.set_psk('UUID', '')
    assert_equal('', CoDTLS::RAMPSKDB.get_psk('UUID'))
    CoDTLS::RAMPSKDB.set_psk('UUID', 'PSK')
    assert_equal('PSK', CoDTLS::RAMPSKDB.get_psk('UUID'))
    CoDTLS::RAMPSKDB.set_psk('UUID2', 'PSK1')
    assert_equal('PSK1', CoDTLS::RAMPSKDB.get_psk('UUID2'))
    CoDTLS::RAMPSKDB.set_psk('UUID2', 'PSK2')
    assert_equal('PSK2', CoDTLS::RAMPSKDB.get_psk('UUID2'))
  end
end
