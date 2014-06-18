require 'redis'
require 'pathname'
require 'yaml'

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
  class RedisSession
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
      redis = CoDTLS.redis_connection
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
      if redis.exists(@ip)
        entry = YAML.load(redis.get("ip_#{@ip}"))
      else
        if id.nil?
          create_standard_ip_entry
        else
          lookup_by_id = redis.get("id_#{id}")
          entry = redis.get("ip_#{lookup_by_id}")
          if entry.nil?
            entry = create_standard_ip_entry
          else
            entry = YAML.load(entry)
          end
          entry.session_id = id.to_s
          redis.set("ip_#{@ip}", YAML.dump(entry))
        end
      end
    end

    # Sets the ID of the current session.
    #
    # @param id [String] the Session-Id
    def id=(id)
      redis = CoDTLS.redis_connection
      entry = database_entry
      redis.del("id_#{entry.session_id}")
      entry.session_id = id
      save_entry(entry)
      redis.set("id_#{id}", @ip)
    end

    # Returns the ID of the current session.
    #
    # @return [String] the Session-ID. nil if Session-ID is unknown
    def id
      entry = database_entry
      return nil if entry.session_id.nil?
      entry.session_id
    end

    # Returns the Epoch of the session for the specified IP.
    #
    # @return [Number] the Epoch
    def epoch
      entry = database_entry
      entry.epoch
    end

    # Increases the Epoch of the session by 1.
    # Also copy key_block_new to key_block and sets key_block_new to empty.
    # seq_num_r and seq_num_w are set back to standard value.
    # Throws excpetion if keyblock is not 40 bytes long.
    def increase_epoch
      entry = database_entry

      if entry.key_block_new.nil?
        fail CoDTLS::SessionError, 'no new keyblock to set for this epoch.'
      end
      entry.epoch = entry.epoch + 1
      entry.seq_num_r = 0
      entry.seq_num_w = 0
      entry.key_block = entry.key_block_new
      entry.key_block_new = nil

      save_entry(entry)
    end

    # Checks the sequenze number of an incoming paket. Valid number is
    # -10 ... + 100 of the expected number.
    # The inital LAST number is 0, so the next expected is 1.
    #
    # @param num [Number] the recieved sequence number
    # @return [Bool] true if the number is valid. false if invalid
    def check_seq(num)
      entry = database_entry
      return false if num < entry.seq_num_r - 9 || num > entry.seq_num_r + 101
      true
    end

    # Sets the sequence number of the last received paket.
    #
    # @param num [Number] the new sequence number
    def seq=(num)
      entry = database_entry
      entry.seq_num_r = num
      save_entry(entry)
      true
    end

    # Returns the sequence number for the next outgoing paket.
    # The inital sequence number is 1. Every return value needs
    # to be last value + 1.
    #
    # @return [Number] the sequence number for the next outgoing paket
    def seq
      entry = database_entry
      entry.seq_num_w += 1
      save_entry(entry)
      entry.seq_num_w
    end

    # Inserts a new keyblock to key_block_new. Throws excpetion if
    # keyblock is not 40 bytes long.
    #
    # @param keyBlock [String] the 40 byte long new keyblock to be inserted
    def key_block=(keyBlock)
      if keyBlock.b.length != 40
        fail CoDTLS::SessionError, 'key blocks have to be 40 byte long'
      end
      entry = database_entry
      entry.key_block_new = keyBlock
      save_entry(entry)
    end

    # Returns the active keyblock (key_block) for the specified IP.
    # If keyblock is empty, nil will be returned.
    #
    # @return [String] the 40 byte long keyblock or nil if empty
    def key_block
      entry = database_entry
      entry.key_block
    end

    # Causes the next messages to be send as handshake messages.
    def enable_handshake
      entry = database_entry
      entry.handshake = true
      save_entry(entry)
      true
    end

    # Causes the next messages to not be send as handshake messages.
    def disable_handshake
      entry = database_entry
      entry.handshake = false
      save_entry(entry)
      true
    end

    # Checks if the next message should be send as a handshake message.
    #
    # @return [Bool] true if the next messages are handshake messages
    def handshake?
      entry = database_entry
      entry.handshake
    end

    # Removes the whole entry from database.
    def clear
      redis = CoDTLS.redis_connection
      redis.del("ip_#{@ip}")
    end

    def database_entry
      redis = CoDTLS.redis_connection
      entry = redis.get("ip_#{@ip}")
      if entry.nil?
        create_standard_ip_entry
        # return the new entry
      else
        YAML.load(entry)
      end
    end

    def save_entry(connection_object)
      redis = CoDTLS.redis_connection
      redis.set("ip_#{@ip}", YAML.dump(connection_object))
    end

    def self.clear_all
      # ActiveRecord::Base.connection_pool.with_connection do
      #   CoDTLSConnection.destroy_all
      # end
      redis = CoDTLS.redis_connection
      redis.flushall
    end

    private

    def create_standard_ip_entry
      redis = CoDTLS.redis_connection
      database_entry = redis.get("ip_#{@ip}")
      if database_entry.nil?
        database_entry = DTLSConnection.new(ip: @ip)
        redis.set("ip_#{@ip}", YAML.dump(database_entry))
      else
        database_entry = YAML.load(database_entry)
      end
      database_entry
    end
  end

  # class for representing a single connection. The IP address is unique.
  class DTLSConnection
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

# refactoren: jedes mal, wenn auf den "database_entry" zugegriffen wird,
# muss er aus der Tabelle geholt werden. Am besten noch den Zugriff auf
# die Tabelle mit nem Mutex schuetzen
