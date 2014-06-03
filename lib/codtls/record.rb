module CoDTLS
  # TODO
  class RecordError < StandardError
  end

  # Tolle Klasse
  class Record
    TYPE = { bit8: 0, alert: 1, handshake: 2, appdata: 3 }
    VERSION = { v10: 0, bit16: 1, v12: 2, reserved: 3 }
    EPOCH = { e0: 0, e1: 1, e2: 2, e3: 3, e4: 4,
              bit8: 5, bit16: 6, implizit: 7 }
    SEQ_NUM = { none: 0, bit8: 1, bit16: 2, bit24: 3,
                bit32: 4, bit40: 5, bit48: 6, implizit: 7 }
    LENGTH = { l0: 0, bit8: 1, bit16: 2, implizit: 3 }

    attr_reader :type, :version, :epoch, :seq_num, :length

    def self.parse(data)
      data.force_encoding('ASCII-8BIT')
      fail RecordError, 'GR1' if data.length < 2
      header = data.slice!(0...2).unpack('n')[0]

      type = TYPE.keys[header >> 13]
      if type == :bit8
        fail RecordError, 'GR1' if data.length < 1
        type = data.slice!(0...1).unpack('C')[0]
      end

      version = VERSION.keys[(header >> 11) & 0x03]
      if version == :bit16
        fail RecordError, 'GR1' if data.length < 2
        version = data.slice!(0...2).unpack('n')[0]
      end

      epoch = EPOCH.keys[(header >> 8) & 0x07]
      epoch = case epoch
              when :implizit then :implizit
              when :bit16
                fail RecordError, 'GR1' if data.length < 2
                data.slice!(0...2).unpack('n')[0]
              when :bit8
                fail RecordError, 'GR1' if data.length < 1
                data.slice!(0...1).unpack('C')[0]
              else EPOCH[epoch]
      end

      sequence = SEQ_NUM.keys[(header >> 2) & 0x07]
      sequence = case sequence
                 when :none then :none
                 when :implizit then :implizit
                 else
                   bytes = SEQ_NUM[sequence]
                   fail RecordError, 'GR1' if data.length < bytes
                   num = data.slice!(0...bytes).reverse
                   num += "\x00" while num.length < 8
                   num.unpack('Q')[0]
      end

      length = LENGTH.keys[header & 0x03]
      length = case length
               when :implizit then :implizit
               when :bit16
                 fail RecordError, 'GR1' if data.length < 2
                 data.slice!(0...2).unpack('n')[0]
               when :bit8
                 fail RecordError, 'GR1' if data.length < 1
                 data.slice!(0...1).unpack('C')[0]
               else LENGTH[length]
      end

      r = Record.new(type, epoch, sequence)
      r.version = version
      r.length = length
      [r, data.slice!(length == :implizit ? 0..-1 : 0...length)]
    end

    public

    def initialize(type, epoch, seq_num)
      self.type = type
      self.version = :v12
      self.epoch = epoch
      self.seq_num = seq_num
      self.length = :implizit

      @header_add = ''.force_encoding('ASCII-8BIT')
    end

    def type=(type)
      check_param(type, TYPE, [1, 2, 3], 2**8 - 1)
      @type = type
    end

    def version=(version)
      check_param(version, VERSION, [0, 2], 2**16 - 1)
      @version = version
    end

    def epoch=(epoch)
      check_param(epoch, EPOCH, [7], 2**16 - 1)
      @epoch = epoch
    end

    def seq_num=(seq_num)
      check_param(seq_num, SEQ_NUM, [0, 7], 2**48 - 1)
      @seq_num = seq_num
    end

    def length=(length)
      check_param(length, LENGTH, [3], 2**16 - 1)
      @length = length
    end

    def nonce(iv)
      nonce = iv + [@seq_num.class == Symbol ? 0 : @seq_num].pack('Q').reverse
      nonce[4..5] = [@epoch.class == Symbol ? 0 : @epoch].pack('n')
      nonce
    end

    def additional_data(len)
      num = @seq_num.class == Symbol ? 0 : @seq_num
      additional_data = [num].pack('Q')[0...6].reverse
      additional_data += (@type.class == Symbol ? TYPE[@type] + 20 : @type).chr
      additional_data += 254.chr
      additional_data += 253.chr
      additional_data += [len].pack('n')
      additional_data
    end

    def to_wire
      @header = 0x00C0
      @header_add.clear

      append_type
      append_version
      append_epoch
      append_seq_num
      append_length

      [@header].pack('n') + @header_add
    end

    private

    def check_param(value, hash, valid, max)
      case value
      when Symbol
        fail RecordError, 'GR1' unless valid.include?(hash[value])
      when Integer
        fail RecordError, 'GR2' unless value >= 0 && value <= max
      else fail RecordError, "GRU #{hash}, Input: #{value.class}"
      end
    end

    def append_type
      case @type
      when Symbol then @header |= TYPE[@type] << 13
      when Integer
        @header |= TYPE[:bit8] << 13
        @header_add += [@type].pack('C')
      end
    end

    def append_version
      case @version
      when Symbol then @header |= VERSION[@version] << 11
      when Integer
        @header |= VERSION[:bit16] << 11
        @header_add += [@version].pack('n')
      end
    end

    def append_epoch
      case @epoch
      when Symbol then @header |= EPOCH[@epoch] << 8
      when Integer
        case
        when @epoch < 5 then  @header |= @epoch << 8
        else
          num = [@epoch].pack('n').bytes.drop_while { |i| i == 0 }
          @header_add += num.pack('C*')
          @header |= (4 + num.length) << 8
        end
      end
    end

    def append_seq_num
      case @seq_num
      when Symbol then @header |= SEQ_NUM[@seq_num] << 2
      when Integer
        if @seq_num == 0
          @header_add += "\x00"
          @header |= 1 << 2
        else
          num = [@seq_num].pack('Q').reverse.bytes.drop_while { |i| i == 0 }
          @header_add += num.pack('C*')
          @header |= num.length << 2
        end
      end
    end

    def append_length
      case @length
      when Symbol then @header |= LENGTH[@length]
      when Integer
        num = [@length].pack('n').bytes.drop_while { |i| i == 0 }
        @header_add += num.pack('C*')
        @header |= num.length
      end
    end
  end
end
