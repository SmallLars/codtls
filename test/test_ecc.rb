require 'test_helper'
require 'codtls/ecc'

# Testclass with Test Vectors from
# http://www.nsa.gov/ia/_files/nist-routines.pdf
class ECCTest < Minitest::Test
  BP_X = ['6b17d1f2e12c4247f8bce6e563a440f2' \
          '77037d812deb33a0f4a13945d898c296'].pack('H*')
  BP_Y = ['4fe342e2fe1a7f9b8ee7eb4a7c0f9e16' \
          '2bce33576b315ececbb6406837bf51f5'].pack('H*')

  S_X = ['de2444bebc8d36e682edd27e0f271508' \
         '617519b3221a8fa0b77cab3989da97c9'].pack('H*')
  S_Y = ['c093ae7ff36e5380fc01a5aad1e66659' \
         '702de80f53cec576b6350b243042a256'].pack('H*')

  KEY = ['c51e4753afdec1e6b6c6a5b992f43f8d' \
         'd0c7a8933072708b6522468b2ffb06fd'].pack('H*')

  R_X = '51d08d5f2d4278882946d88d83c97d11' \
        'e62becc3cfc18bedacc89ba34eeca03f'
  R_Y = '75ee68eb8bf626aa5b673ab51f6e744e' \
        '06f8fcf8a6c0cf3035beca956a7b41d5'

  KEY2 = ['00000000000000000000000000000000' \
          '00000000000000000000000000000002'].pack('H*')

  R2_X = '7669e6901606ee3ba1a8eef1e0024c33' \
         'df6c22f3b17481b82a860ffcdb6127b0'
  R2_Y = 'fa878162187a54f6c39f6ee0072f33de' \
         '389ef3eecd03023de10ca2c1db61d0c7'

  def test_ecc
    r = CoDTLS::ECC.mult(KEY, "\x04" + S_X + S_Y)
    assert_equal('04' + R_X + R_Y, r.unpack('H*')[0])

    r = CoDTLS::ECC.mult(KEY2, "\x04" + S_X + S_Y)
    assert_equal('04' + R2_X + R2_Y, r.unpack('H*')[0])

    r1 = CoDTLS::ECC.mult(KEY, "\x04" + BP_X + BP_Y)
    r2 = CoDTLS::ECC.mult(KEY)
    assert_equal(r1.unpack('H*')[0], r2.unpack('H*')[0])
  end
end
