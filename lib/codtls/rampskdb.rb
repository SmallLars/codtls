require 'active_record'
require 'sqlite3'
require 'pathname'

module CoDTLS
  # A Class for managing PSKs per IP. The class has no initializer, because
  # every method is static. All data are not saved, so they are lost at a
  # restart.
  class RAMPSKDB
    @psks = []
    # Sets PSK for the specified UUID. If PSK for UUID is already set,
    # PSK ist saved into PSK_new. So PSK is set one time, while PSK_new
    # maybe gets overwritten more times. Other values are set to standard.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    # @param psk [String] the 16 byte long pre-shared key of the device
    def self.set_psk(uuid, psk, desc = '')
      entry = @psks.select { |p| p.uuid = uuid }
      if entry.empty?
        @psks.push(PSK.new(uuid, psk, desc))
      else
        entry = entry[0]
        if entry.psk.nil?
          entry.psk = psk
        else
          entry.psk_new = psk
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
      entry = @psks.select { |p| p.uuid = uuid }
      return nil if entry.empty?
      entry = entry[0]
      if entry.psk_new.nil?
        return entry.psk
      else
        return entry.psk_new
      end
    end

    # Deletes the PSK for the provided UUID. Handle with care, PSK_new and PSK
    # are lost after this.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    # @return [NilCLass] nil if uuid couldn't be found
    def self.del_psk!(uuid)
      entry = @psks.select { |p| p.uuid = uuid }
      return nil if entry.empty?
      @psks.delete(entry)
    end

    # Returns an array of all registered UUIDs.
    #
    # @return [Array] of {uuid: A, psk: B, desc: C}
    def self.all_registered
      entries = @psks
      entries.map { |i| [i.uuid, i.psk_new.nil? ? i.psk : i.psk_new, i.desc] }
    end

    # Removes the all entrys from database in TABLE 2.
    def self.clear_all
      @psks = []
    end
  end

  # Class representn the dtls_devices table in the database
  class PSK
    attr_accessor :uuid, :psk, :psk_new, :desc

    def initialize(uuid, psk, desc)
      @uuid = uuid
      @psk = psk
      @desc = desc
    end
  end
end

def create_sqlite_db(dbname)
  SQLite3::Database.new(dbname)
end
