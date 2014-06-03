require 'active_record'
require 'sqlite3'
require 'pathname'

require 'codtls/models/codtls_connection'

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
  class Session
    @ip_list = []
    def self.ip_list
      @ip_list
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
      CoDTLS.setup_database
      # logger = Logger.new(STDOUT)
      # logger.level = CoDTLS::LOG_LEVEL
      # logger.debug("Session wird erstellt")
      fail SessionError 'IP is nil, not a valid value.' if ip.nil? ||
                                                           ip.class != String
      # normalize IP
      ip = IPAddr.new(ip)
      fail SessionError 'IP is not in a valid format' if ip.nil?
      @ip = ip.to_s

      # Find IP Object, if not found -> create it
      database_entry = CoDTLS::Session.ip_list.select { |i| i[0] == @ip }
      if database_entry.empty?
        if id.nil?
          create_standard_ip_entry
        else
          ActiveRecord::Base.connection_pool.with_connection do
            database_entry = CODTLSConnection.find_by_id(id)
          end
          if database_entry.nil?
            create_standard_ip_entry
          else
            CoDTLS::Session.ip_list.push([ip, database_entry])
          end
          database_entry.session_id = id.to_s
          database_entry.save
        end
      else
        database_entry = database_entry[0][1]
      end
      ObjectSpace.define_finalizer(self, proc do
        entry = get_database_entry(ip)
        ActiveRecord::Base.connection_pool.with_connection do
          entry.save unless entry.nil?
        end
      end)
    end

    # Sets the ID of the current session.
    #
    # @param id [String] the Session-Id
    def id=(id)
      database_entry = get_database_entry(@ip)
      database_entry.session_id = id
      database_entry.save
    end

    # Returns the ID of the current session.
    #
    # @return [String] the Session-ID. nil if Session-ID is unknown
    def id
      database_entry = get_database_entry(@ip)
      return nil if database_entry.session_id.nil?
      database_entry.session_id
    end

    # Returns the Epoch of the session for the specified IP.
    #
    # @return [Number] the Epoch
    def epoch
      database_entry = get_database_entry(@ip)
      database_entry.epoch
    end

    # Increases the Epoch of the session by 1.
    # Also copy key_block_new to key_block and sets key_block_new to empty.
    # seq_num_r and seq_num_w are set back to standard value.
    # Throws excpetion if keyblock is not 40 bytes long.
    def increase_epoch
      database_entry = get_database_entry(@ip)

      if database_entry.key_block_new.nil?
        fail CoDTLS::SessionError, 'no new keyblock to set for this epoch.'
      end
      database_entry.epoch = database_entry.epoch + 1
      database_entry.seq_num_r = 0
      database_entry.seq_num_w = 0
      database_entry.key_block = database_entry.key_block_new
      database_entry.key_block_new = nil

      ActiveRecord::Base.connection_pool.with_connection do
        database_entry.save
      end
    end

    # Checks the sequenze number of an incoming paket. Valid number is
    # -10 ... + 100 of the expected number.
    # The inital LAST number is 0, so the next expected is 1.
    #
    # @param num [Number] the recieved sequence number
    # @return [Bool] true if the number is valid. false if invalid
    def check_seq(num)
      database_entry = get_database_entry(@ip)
      return false if num < database_entry.seq_num_r - 9 ||
                      num > database_entry.seq_num_r + 101
      true
    end

    # Sets the sequence number of the last received paket.
    #
    # @param num [Number] the new sequence number
    def seq=(num)
      database_entry = get_database_entry(@ip)
      database_entry.seq_num_r = num
      if (database_entry.seq_num_r % 50) == 0
        ActiveRecord::Base.connection_pool.with_connection do
          database_entry.save
        end
      end
      true
    end

    # Returns the sequence number for the next outgoing paket.
    # The inital sequence number is 1. Every return value needs
    # to be last value + 1.
    #
    # @return [Number] the sequence number for the next outgoing paket
    def seq
      database_entry = get_database_entry(@ip)
      database_entry.seq_num_w += 1
      if (database_entry.seq_num_w % 5) == 0
        ActiveRecord::Base.connection_pool.with_connection do
          database_entry.save
        end
      end
      database_entry.seq_num_w
    end

    # Inserts a new keyblock to key_block_new. Throws excpetion if
    # keyblock is not 40 bytes long.
    #
    # @param keyBlock [String] the 40 byte long new keyblock to be inserted
    def key_block=(keyBlock)
      if keyBlock.b.length != 40
        fail CoDTLS::SessionError, 'key blocks have to be 40 byte long'
      end
      database_entry = get_database_entry(@ip)
      database_entry.key_block_new = keyBlock
      ActiveRecord::Base.connection_pool.with_connection do
        database_entry.save
      end
    end

    # Returns the active keyblock (key_block) for the specified IP.
    # If keyblock is empty, nil will be returned.
    #
    # @return [String] the 40 byte long keyblock or nil if empty
    def key_block
      database_entry = get_database_entry(@ip)
      database_entry.key_block
    end

    # Causes the next messages to be send as handshake messages.
    def enable_handshake
      database_entry = get_database_entry(@ip)
      database_entry.handshake = true
      ActiveRecord::Base.connection_pool.with_connection do
        database_entry.save
      end
      true
    end

    # Causes the next messages to not be send as handshake messages.
    def disable_handshake
      database_entry = get_database_entry(@ip)
      database_entry.handshake = false
      ActiveRecord::Base.connection_pool.with_connection do
        database_entry.save
      end
      true
    end

    # Checks if the next message should be send as a handshake message.
    #
    # @return [Bool] true if the next messages are handshake messages
    def handshake?
      database_entry = get_database_entry(@ip)
      database_entry.handshake
    end

    # Removes the whole entry from database.
    def clear
      database_entry = nil
      ActiveRecord::Base.connection_pool.with_connection do
        database_entry = CODTLSConnection.find_by_ip(@ip)
      end
      return unless database_entry

      ActiveRecord::Base.connection_pool.with_connection do
        database_entry.destroy
      end
      entry = CoDTLS::Session.ip_list.select { |i| i[1] == database_entry }
      return nil if entry.empty?
      CoDTLS::Session.ip_list.delete(entry[0])
      # database_entry.session_id = nil
      # database_entry.epoch = 0
      # database_entry.seq_num_r = 0
      # database_entry.seq_num_w = 0
      # database_entry.key_block = nil
      # database_entry.key_block_new = nil
      # database_entry.handshake = false
      # database_entry.save
      # database_entry = nil
    end

    def get_database_entry(ip)
      # mutex lock
      entry = CoDTLS::Session.ip_list.select { |i| i[1].ip == ip }
      if entry.empty?
        create_standard_ip_entry
        # return the new entry
      else
        entry[0][1]
      end
      # mutex unlock
    end

    def self.clear_all
      # ActiveRecord::Base.connection_pool.with_connection do
      #   CoDTLSConnection.destroy_all
      # end
      @ip_list = []
    end

    private

    def create_standard_ip_entry
      database_entry = nil
      ActiveRecord::Base.connection_pool.with_connection do
        if (database_entry = CODTLSConnection.find_by_ip(@ip)).nil?
          database_entry = CODTLSConnection.create(ip: @ip,
                                                   epoch: 0,
                                                   handshake: false,
                                                   seq_num_w: 0,
                                                   seq_num_r: 0
                                                   )
          database_entry.save
          CoDTLS::Session.ip_list.push([@ip, database_entry])
        end
      end
      database_entry
    end
  end
end

# refactoren: jedes mal, wenn auf den "database_entry" zugegriffen wird,
# muss er aus der Tabelle geholt werden. Am besten noch den Zugriff auf
# die Tabelle mit nem Mutex schuetzen
