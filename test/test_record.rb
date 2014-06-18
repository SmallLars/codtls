require 'test_helper'
require 'codtls'

# Testclass
class RecordTest < Minitest::Unit::TestCase
  # [fails?, input, header, headeradd]
  V = [[
    # Type
    [0, :alert,     0x2000, ''],
    [0, :handshake, 0x4000, ''],
    [0, :appdata,   0x6000, ''],
    [0, 0,          0x0000, '00'],
    [0, 128,        0x0000, '80'],
    [0, 255,        0x0000, 'ff'],
    [1, 'string',   0x0000, ''],
    [1, :unknown,   0x0000, ''],
    [1, -1,         0x0000, ''],
    [1, 256,        0x0000, '']
  ], [
    # Version
    [0, :v10,       0x0000, ''],
    [0, :v12,       0x1000, ''],
    [0, 0,          0x0800, '0000'],
    [0, 255,        0x0800, '00ff'],
    [0, 256,        0x0800, '0100'],
    [0, 2**16 - 1,  0x0800, 'ffff'],
    [1, 'string',   0x0800, ''],
    [1, :reserved,  0x0800, ''],
    [1, -1,         0x0800, ''],
    [1, 2**16,      0x0800, '']
  ], [
    # Epoch
    [0, :implizit,  0x0700, ''],
    [0, 0,          0x0000, ''],
    [0, 4,          0x0400, ''],
    [0, 5,          0x0500, '05'],
    [0, 255,        0x0500, 'ff'],
    [0, 256,        0x0600, '0100'],
    [0, 2**16 - 1,  0x0600, 'ffff'],
    [1, 'string',   0x0500, ''],
    [1, :unknown,   0x0500, ''],
    [1, -1,         0x0600, ''],
    [1, 2**16,      0x0600, '']
  ], [
    # Seq_Num
    [0, :none,      0x0000, ''],
    [0, :implizit,  0x001C, ''],
    [0, 0,          0x0004, '00'],
    [0, 255,        0x0004, 'ff'],
    [0, 256,        0x0008, '0100'],
    [0, 2**16 - 1,  0x0008, 'ffff'],
    [0, 2**16,      0x000C, '010000'],
    [0, 2**48 - 1,  0x0018, 'ffffffffffff'],
    [1, 'string',   0x0004, ''],
    [1, :unknown,   0x0008, ''],
    [1, -1,         0x000C, ''],
    [1, 2**48,      0x0018, '']
  ], [
    # Length
    [0, :implizit,  0x0003, ''],
    [0, 0,          0x0000, ''],
    [0, 5,          0x0001, '05'],
    [0, 128,        0x0001, '80'],
    [0, 255,        0x0001, 'ff'],
    [0, 256,        0x0002, '0100'],
    [0, 2**16 - 1,  0x0002, 'ffff'],
    [1, 'string',   0x0001, ''],
    [1, :unknown,   0x0001, ''],
    [1, -1,         0x0002, ''],
    [1, 2**16,      0x0002, '']
  ]]

  def test_record
    assert_raises(CoDTLS::RecordError) { CoDTLS::Record.parse('') }
    assert_raises(CoDTLS::RecordError) { CoDTLS::Record.parse(' ') }

    V[0].each do |t|
      V[1].each do |v|
        V[2].each do |e|
          V[3].each do |s|
            V[4].each do |l|
              header = 0x00C0 | t[2] | v[2] | e[2] | s[2] | l[2]
              to_add = t[3] + v[3] + e[3] + s[3] + l[3]
              complete = [header].pack('n').unpack('H*')[0] + to_add

              fail = t[0] | v[0] | e[0] | s[0] | l[0]
              if fail == 1
                assert_raises CoDTLS::RecordError, complete do
                  r = CoDTLS::Record.new(t[1], e[1], s[1])
                  r.version = v[1]
                  r.length = l[1]
                end
                assert_raises CoDTLS::RecordError, complete do
                  CoDTLS::Record.parse([complete].pack('H*'))
                end
              else
                nonce = 'abcd'
                nonce += [e[1].class == Symbol ? 0 : e[1]].pack('n')
                seq = [s[1].class == Symbol ? 0 : s[1]].pack('Q')
                nonce += seq[0...6].reverse
                # to_wire
                r = CoDTLS::Record.new(t[1], e[1], s[1])
                r.version = v[1]
                r.length = l[1]
                assert_equal(complete, r.to_wire.unpack('H*')[0], r.inspect)
                assert_equal(nonce, r.nonce('abcd'))
                # parse
                data = 'Hello World!'
                fail_info = complete + data
                complete = [complete].pack('H*') + data
                r, d = CoDTLS::Record.parse(complete)
                assert_equal(t[1], r.type, fail_info + ' Type')
                assert_equal(v[1], r.version, fail_info + ' Version')
                assert_equal(e[1], r.epoch, fail_info + ' Epoch')
                assert_equal(s[1], r.seq_num, fail_info + ' Seq_num')
                assert_equal(l[1], r.length, fail_info + ' Length')
                range = (r.length == :implizit ? 0..-1 : 0...r.length)
                assert_equal(data.slice!(range), d, fail_info + ' Payload')
                assert_equal(data, complete, fail_info + ' Rest')
                assert_equal(nonce, r.nonce('abcd'))
              end
            end
          end
        end
      end
    end
  end
end
