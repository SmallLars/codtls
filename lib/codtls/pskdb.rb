require 'pathname'

module CoDTLS
  # A Class for managing PSKs per IP. The class has no initializer, because
  # every method is static.
  class PSKDB
    # Sets PSK for the specified UUID. If PSK for UUID is already set,
    # PSK ist saved into PSK_new. So PSK is set one time, while PSK_new
    # maybe gets overwritten more times. Other values are set to standard.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    # @param psk [String] the 16 byte long pre-shared key of the device
    def self.set_psk(uuid, psk, desc = '')
      CoDTLS.setup_database
      ActiveRecord::Base.connection_pool.with_connection do
        entry = CODTLSDevice.find_by_uuid(uuid)
        if entry.nil?
          CODTLSDevice.create(psk: psk,
                              uuid: uuid,
                              desc: desc
                              )
        else
          if entry.psk.nil?
            entry.psk = psk
          else
            entry.psk_new = psk
          end
          entry.save
        end
      end
    end

    # Gets PSK for the specified UUID. If PSK_new is set, the return value
    # is PSK_new, else PSK is return value. If UUID is not existing
    # nil will be returned.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    # @return [String] the 16 byte long pre-shared key for the UUID
    def self.get_psk(uuid)
      CoDTLS.setup_database
      logger = Logger.new(STDOUT)
      logger.level = CoDTLS::LOG_LEVEL
      logger.debug('get_psk 1')
      entry = nil
      ActiveRecord::Base.connection_pool.with_connection do
        logger.debug('get_psk 2')
        entry = CODTLSDevice.find_by_uuid(uuid)
      end
      logger.debug('get_psk 3')
      return nil if entry.nil?

      if entry.psk_new.nil?
        logger.debug('get_psk 4.1')
        return entry.psk
      else
        logger.debug('get_psk 4.2')
        return entry.psk_new
      end
    end

    # Deletes the PSK for the provided UUID. Handle with care, PSK_new and PSK
    # are lost after this.
    #
    # @param id [Integer] the ID of the database entry (get with all_registered)
    # @return [NilCLass] nil if uuid couldn't be found
    def self.del_psk!(id)
      CoDTLS.setup_database
      ActiveRecord::Base.connection_pool.with_connection do
        entry = CODTLSDevice.find_by_id(id)
        return nil if entry.nil?
        entry.destroy
      end
    end

    # Returns an array of all registered UUIDs.
    #
    # @return [Array] of [id, uuid, psk, desc]
    def self.all_registered
      CoDTLS.setup_database
      ActiveRecord::Base.connection_pool.with_connection do
        entries = CODTLSDevice.all
        return nil if entries.nil?
        entries.map do |i| [i.id,
                            i.uuid,
                            i.psk_new.nil? ? i.psk : i.psk_new,
                            i.desc]
        end
      end
    end

    # Removes the all entrys from database in TABLE 2.
    def self.clear_all
      CoDTLS.setup_database
      ActiveRecord::Base.connection_pool.with_connection do
        CODTLSDevice.destroy_all
      end
    end
  end
end
