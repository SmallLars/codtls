require 'codtls/abstract_session'

module CoDTLS
  # Error class for wrong data inputs (for exampe keyblock)
  class SessionError < StandardError
  end

  # Storage class for a CoDTLS-Session with the following Fields:
  # Type     | Name               | Standard-Value
  # -------------------------------------------------------
  # uint8_t  | ip[16];            | Given IP
  # uint8_t  | id[8];             | empty
  # uint16_t | epoch;             | 0
  # uint48_t | seq_num_r;         | depends on implementation (-1, 0 or 1)
  # uint48_t | seq_num_w;         | depends on implementation (-1, 0 or 1)
  # uint8_t  | key_block[40];     | empty
  # uint8_t  | key_block_new[40]; | empty
  # uint8_t  | handshake;         | 0
  class RAMSession < CoDTLS::AbstractSession
    @connections = []
    # Constructor to create a new session for the given ip. When only ip is
    # given, its the value for searching in database. When its not found, a
    # new database entry with standard values will be created. When id is
    # also given, id is the first value for searching in database. When its
    # found, ip will be updated and other values are unchanged. In the other
    # case, when id isnt found, its the same behavior as without id but with
    # additional storing of the id. Throws excpetion if ip == nil.
    #
    # @param ip [IP] IP for this Session
    # @param id [String] Session-Id for this Session
    def initialize(ip, id = nil)
      fail SessionError 'IP is nil, not a valid value.' if ip.nil? ||
                                                           ip.class != String
      ip = IPAddr.new(ip)
      fail SessionError 'IP is not in a valid format' if ip.nil?
      ip = ip.to_s
      @ip = ip
      if id.nil?
        entry = CoDTLS::RAMSession.connections.select { |c| c.ip == @ip }
        if entry.empty?
          create_standard_ip_object
        else
          @database_object = entry[0]
        end
      else
        entry = CoDTLS::RAMSession.connections.select { |c| c.id == id }
        create_standard_ip_object if entry.empty?
        @database_object.id = id
      end
    end

    # Sets the ID of the current session.
    #
    # @param id [String] the Session-Id
    def id=(id)
      create_standard_ip_object if @database_object.nil?
      @database_object.session_id = id
    end

    # Returns the ID of the current session.
    #
    # @return [String] the Session-ID. nil if Session-ID is unknown
    def id
      create_standard_ip_object if @database_object.nil?
      @database_object.session_id
    end

    # Returns the Epoch of the session for the specified IP.
    #
    # @return [Number] the Epoch
    def epoch
      create_standard_ip_object if @database_object.nil?
      @database_object.epoch
    end

    # Increases the Epoch of the session by 1.
    # Also copy key_block_new to key_block and sets key_block_new to empty.
    # seq_num_r and seq_num_w are set back to standard value.
    # Throws excpetion if keyblock is not 40 bytes long.
    def increase_epoch
      create_standard_ip_object if @database_object.nil?
      if @database_object.key_block_new.nil?
        fail CoDTLS::SessionError, 'no new keyblock to set for this epoch.'
      end
      @database_object.epoch = @database_object.epoch + 1
      @database_object.seq_num_r = 0
      @database_object.seq_num_w = 0
      @database_object.key_block = @database_object.key_block_new
      @database_object.key_block_new = nil
    end

    # Checks the sequenze number of an incoming paket. Valid number is
    # -10 ... + 100 of the expected number.
    # The inital LAST number is 0, so the next expected is 1.
    #
    # @param num [Number] the recieved sequence number
    # @return [Bool] true if the number is valid. false if invalid
    def check_seq(num)
      create_standard_ip_entry if @database_object.nil?
      return false if num < @database_object.seq_num_r - 9 ||
                      num > @database_object.seq_num_r + 101
      true
    end

    # Sets the sequence number of the last received paket.
    #
    # @param num [Number] the new sequence number
    def seq=(num)
      create_standard_ip_object if @database_object.nil?
      @database_object.seq_num_r = num
      true
    end

    # Returns the sequence number for the next outgoing paket.
    # The inital sequence number is 1. Every return value needs
    # to be last value + 1.
    #
    # @return [Number] the sequence number for the next outgoing paket
    def seq
      create_standard_ip_object if @database_object.nil?
      temp = @database_object.seq_num_w + 1
      @database_object.seq_num_w = temp
    end

    # Inserts a new keyblock to key_block_new. Throws excpetion if
    # keyblock is not 40 bytes long.
    #
    # @param keyBlock [String] the 40 byte long new keyblock to be inserted
    def key_block=(keyBlock)
      if keyBlock.b.length != 40
        fail CoDTLS::SessionError, 'key blocks have to be 40 byte long'
      end
      create_standard_ip_object if @database_object.nil?
      @database_object.key_block_new = keyBlock
    end

    # Returns the active keyblock (key_block) for the specified IP.
    # If keyblock is empty, nil will be returned.
    #
    # @return [String] the 40 byte long keyblock or nil if empty
    def key_block
      create_standard_ip_object if @database_object.nil?
      @database_object.key_block
    end

    # Causes the next messages to be send as handshake messages.
    def enable_handshake
      create_standard_ip_object if @database_object.nil?
      @database_object.handshake = true
    end

    # Causes the next messages to not be send as handshake messages.
    def disable_handshake
      create_standard_ip_object if @database_object.nil?
      @database_object.handshake = false
    end

    # Checks if the next message should be send as a handshake message.
    #
    # @return [Bool] true if the next messages are handshake messages
    def handshake?
      create_standard_ip_object if @database_object.nil?
      @database_object.handshake
    end

    # Removes the whole entry from database.
    def clear
      fail CoDTLS::SessionError 'IP of a current session has'\
                                'been deleted by a '\
                                'third party.' if @database_object.nil?
      CoDTLS::RAMSession.connections.delete(@database_object)
      @database_object = nil
    end

    def self.clear_all
      @connections = []
    end

    def self.connections
      @connections unless @connections.nil?
    end

    private

    def create_standard_ip_object
      @database_object = TempDTLSConnection.new(@ip)
      CoDTLS::RAMSession.connections.push(@database_object)
    end
  end

  # class for representing a single connection. The IP address is unique.
  class TempDTLSConnection
    attr_accessor :ip,
                  :epoch,
                  :handshake,
                  :seq_num_w,
                  :seq_num_r,
                  :key_block,
                  :key_block_new,
                  :session_id

    def initialize(ip)
      @ip = ip
      @epoch = 0
      @handshake = false
      @seq_num_w = 0
      @seq_num_r = 0
    end
  end
end

def create_sqlite_db(dbname)
  SQLite3::Database.new(dbname)
end
