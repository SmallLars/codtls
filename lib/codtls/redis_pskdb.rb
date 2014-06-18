require 'redis'
require 'pathname'
require 'yaml'

module CoDTLS
  # A Class for managing PSKs per IP. The class has no initializer, because
  # every method is static.
  class RedisPSKDB
    # Sets PSK for the specified UUID. If PSK for UUID is already set,
    # PSK ist saved into PSK_new. So PSK is set one time, while PSK_new
    # maybe gets overwritten more times. Other values are set to standard.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    # @param psk [String] the 16 byte long pre-shared key of the device
    def self.set_psk(uuid, psk, desc = '')
      entry = get_database_entry(uuid)
      if entry.nil?
        create_standard_psk_entry(uuid, psk, desc)
      else
        if entry.psk.nil?
          entry.psk = psk
        else
          entry.psk_new = psk
        end
        save_entry(uuid, entry)
      end
    end

    # Gets PSK for the specified UUID. If PSK_new is set, the return value
    # is PSK_new, else PSK is return value. If UUID is not existing
    # nil will be returned.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    # @return [String] the 16 byte long pre-shared key for the UUID
    def self.get_psk(uuid)
      entry = get_database_entry(uuid)
      return nil if entry.nil?

      if entry.psk_new.nil?
        return entry.psk
      else
        return entry.psk_new
      end
    end

    # Deletes the PSK for the provided UUID. Handle with care, PSK_new and PSK
    # are lost after this.
    #
    # @param uuid [Binary] the ID of the database entry
    # (get with all_registered)
    # @return [NilCLass] nil if uuid couldn't be found
    def self.del_psk!(id)
      redis = CoDTLS.redis_connection
      uuids = redis.smembers('uuid')
      return nil if uuids.nil? || uuids.empty?
      uuids.map! do |x| entry = redis.get("uuid_#{x}")
                        if entry.nil?
                          nil
                        else
                          YAML.load(entry)
                        end
      end
      uuids.compact
      return nil if uuids.nil? || uuids.empty?
      uuids.delete_if { |x| x.id != id }
      return nil if uuids.nil? || uuids.empty?
      redis.del("uuid_#{uuids[0].uuid}")
      redis.srem('uuid', uuids[0].uuid)
    end

    # Returns an array of all registered UUIDs.
    #
    # @return [Array] of {uuid: A, psk: B, desc: C}
    def self.all_registered
      redis = CoDTLS.redis_connection
      uuids = redis.smembers('uuid')
      uuids.map! do |x| entry = redis.get("uuid_#{x}")
                        if entry.nil?
                          nil
                        else
                          object = YAML.load(entry)
                          [object.id,
                           [object.uuid].pack('H*'),
                           object.psk_new.nil? ? object.psk : object.psk_new,
                           object.desc]
                        end
      end
      uuids.compact
    end

    # Removes the all entrys from database in TABLE 2.
    def self.clear_all
      redis = CoDTLS.redis_connection
      redis.flushall
    end

    def self.get_database_entry(uuid)
      redis = CoDTLS.redis_connection
      return if uuid.nil?
      entry = redis.get("uuid_#{uuid.unpack('H*')[0]}")
      if entry.nil?
        nil
      else
        YAML.load(entry)
      end
    end

    def self.save_entry(uuid, connection_object)
      redis = CoDTLS.redis_connection
      return if uuid.nil?
      redis.set("uuid_#{uuid.unpack('H*')[0]}", YAML.dump(connection_object))
      redis.sadd('uuid', uuid.unpack('H*')[0])
    end

    def self.create_standard_psk_entry(uuid, psk, desc)
      redis = CoDTLS.redis_connection
      return if uuid.nil?
      database_entry = redis.get("uuid_#{uuid.unpack('H*')[0]}")
      if database_entry.nil?
        id = redis.get('pskdb_current_id')
        if id.nil?
          id = 0
          redis.set('pskdb_current_id', 1)
        else
          id = id.to_i
          redis.incr('pskdb_current_id')
        end
        database_entry = RedisPSK.new(id, uuid.unpack('H*')[0], psk, desc)
        redis.set("uuid_#{uuid.unpack('H*')[0]}", YAML.dump(database_entry))
        redis.sadd('uuid', uuid.unpack('H*')[0])
      else
        database_entry = YAML.load(database_entry)
      end
      database_entry
    end
  end

  # Class representn the dtls_devices table in the database
  class RedisPSK
    attr_accessor :id, :uuid, :psk, :psk_new, :desc

    def initialize(id, uuid, psk, desc)
      @id = id
      @uuid = uuid
      @psk = psk
      @desc = desc
    end
  end
end
