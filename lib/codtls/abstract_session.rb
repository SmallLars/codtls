module CoDTLS
  # Error class for wrong data inputs (for exampe keyblock)
  class SessionError < StandardError
  end

  # Storage class for a CoDTLS-Session with the following Fields:
  #
  # TABLE 1
  # Type     | Name               | Standard-Value
  # -------------------------------------------------------
  # uint8_t  | uuid[16];          | uuid - couldnt be empty
  # uint8_t  | psk[16];           | psk  - couldnt be empty
  # uint8_t  | psk_new[16];       | empty
  #
  # TABLE 2
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
  class AbstractSession
    # Creates a database connection if necessary
    def self.establish_connection
      fail 'SYSTEM ERROR: method missing'
    end

    # Sets PSK for the specified UUID. If PSK for UUID is already set,
    # PSK ist saved into PSK_new. So PSK is set one time, while PSK_new
    # maybe gets overwritten more times. Other values are set to standard.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    # @param psk [String] the 16 byte long pre-shared key of the device
    def self.set_psk(uuid, psk, desc = '')
      fail 'SYSTEM ERROR: method missing'
    end

    # Gets PSK for the specified UUID. If PSK_new is set, the return value
    # is PSK_new, else PSK is return value. If UUID is not existing
    # nil will be returned.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    # @return [String] the 16 byte long pre-shared key for the UUID
    def self.get_psk(uuid)
      fail 'SYSTEM ERROR: method missing'
    end

    # Deletes the PSK for the provided UUID. Handle with care, PSK_new and PSK
    # are lost after this.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    def self.del_psk!(uuid)
      fail 'SYSTEM ERROR: method missing'
    end

    # Returns an array of all registered UUIDs.
    #
    # @return [Array] of {uuid: A, psk: B, desc: C}
    def self.all_registered
      fail 'SYSTEM ERROR: method missing'
    end

    # Removes the all entrys from database in TABLE 2.
    def self.clear_all
      fail 'SYSTEM ERROR: method missing'
    end

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
      fail 'SYSTEM ERROR: method missing'
    end

    # Sets the ID of the current session.
    #
    # @param id [String] the Session-Id
    def id=(id)
      fail 'SYSTEM ERROR: method missing'
    end

    # Returns the ID of the current session.
    #
    # @return [String] the Session-ID. nil if Session-ID is unknown
    def id
      fail 'SYSTEM ERROR: method missing'
    end

    # Returns the Epoch of the session for the specified IP.
    #
    # @return [Number] the Epoch
    def epoch
      fail 'SYSTEM ERROR: method missing'
    end

    # Increases the Epoch of the session by 1.
    # Also copy key_block_new to key_block and sets key_block_new to empty.
    # seq_num_r and seq_num_w are set back to standard value.
    # Throws excpetion if keyblock is not 40 bytes long.
    def increase_epoch
      fail 'SYSTEM ERROR: method missing'
    end

    # Checks the sequenze number of an incoming paket. Valid number is
    # -10 ... + 100 of the expected number.
    # The inital LAST number is 0, so the next expected is 1.
    #
    # @param num [Number] the recieved sequence number
    # @return [Bool] true if the number is valid. false if invalid
    def check_seq(num)
      fail 'SYSTEM ERROR: method missing'
    end

    # Sets the sequence number of the last received paket.
    #
    # @param num [Number] the new sequence number
    def seq=(num)
      fail 'SYSTEM ERROR: method missing'
    end

    # Returns the sequence number for the next outgoing paket.
    # The inital sequence number is 1. Every return value needs
    # to be last value + 1.
    #
    # @return [Number] the sequence number for the next outgoing paket
    def seq
      fail 'SYSTEM ERROR: method missing'
    end

    # Inserts a new keyblock to key_block_new. Throws excpetion if
    # keyblock is not 40 bytes long.
    #
    # @param keyBlock [String] the 40 byte long new keyblock to be inserted
    def key_block=(keyBlock)
      fail 'SYSTEM ERROR: method missing'
    end

    # Returns the active keyblock (key_block) for the specified IP.
    # If keyblock is empty, nil will be returned.
    #
    # @return [String] the 40 byte long keyblock or nil if empty
    def key_block
      fail 'SYSTEM ERROR: method missing'
    end

    # Causes the next messages to be send as handshake messages.
    def enable_handshake
      fail 'SYSTEM ERROR: method missing'
    end

    # Causes the next messages to not be send as handshake messages.
    def disable_handshake
      fail 'SYSTEM ERROR: method missing'
    end

    # Checks if the next message should be send as a handshake message.
    #
    # @return [Bool] true if the next messages are handshake messages
    def handshake?
      fail 'SYSTEM ERROR: method missing'
    end

    # Removes the hole entry from database.
    def clear
      fail 'SYSTEM ERROR: method missing'
    end
  end
end
