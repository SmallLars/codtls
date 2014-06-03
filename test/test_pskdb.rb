require 'test_helper'
require 'codtls/pskdb'

# Testclass
class CoDTLSPSKDBTest < Minitest::Test
  def setup
    CoDTLS.connect_database('testdatabase.sqlite')
    CoDTLS.setup_database
    @session = CoDTLS::Session.new('127.0.0.1')
  end

  def teardown
    ActiveRecord::Base.remove_connection
    FileUtils.rm('testdatabase.sqlite') if File.exist?('testdatabase.sqlite')
  end

  # a new uuid gets registered and its psk gets updated.
  # The standard values for the epoch and handshake get checked.
  def test_psk
    assert_equal(nil, CoDTLS::PSKDB.get_psk('UUID'))
    CoDTLS::PSKDB.set_psk('UUID', '')
    assert_equal('', CoDTLS::PSKDB.get_psk('UUID'))
    CoDTLS::PSKDB.set_psk('UUID', 'PSK')
    assert_equal('PSK', CoDTLS::PSKDB.get_psk('UUID'))
    CoDTLS::PSKDB.set_psk('UUID2', 'PSK1')
    assert_equal('PSK1', CoDTLS::PSKDB.get_psk('UUID2'))
    CoDTLS::PSKDB.set_psk('UUID2', 'PSK2')
    assert_equal('PSK2', CoDTLS::PSKDB.get_psk('UUID2'))
  end
end
