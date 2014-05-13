require 'openssl'

module OpenSSL
  class PRFError < StandardError
  end

  # PRF(secret, label, seed) = P_<hash>(secret, label + seed)
  #
  # P_hash(secret, seed) = CMAC_hash(secret, A(1) + seed) +
  #                        CMAC_hash(secret, A(2) + seed) +
  #                        CMAC_hash(secret, A(3) + seed) + ...
  #
  # A() is defined as:
  #       A(0) = seed
  #       A(i) = CMAC_hash(secret, A(i-1))
  class PRF
    def initialize(secret, label, seed)
      @secret = secret.force_encoding('ASCII-8BIT')
      @seed = label.force_encoding('ASCII-8BIT')
      @seed += seed.force_encoding('ASCII-8BIT')
      @buffer = ''.force_encoding('ASCII-8BIT')
      @a_x = @seed.dup
    end

    def get(bytes)
      output = ''.force_encoding('ASCII-8BIT')
      while output.length < bytes
        output += @buffer.slice!(0...(bytes - output.length))
        fill_buffer if @buffer.length == 0
      end
      output
    end

    def fill_buffer
      @a_x = OpenSSL::CMAC.digest('AES', @secret, @a_x)
      @buffer = OpenSSL::CMAC.digest('AES', @secret, @a_x + @seed)
      @buffer.force_encoding('ASCII-8BIT')
    end
  end
end
