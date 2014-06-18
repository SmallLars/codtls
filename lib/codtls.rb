require 'socket'
require 'logger'
require 'redis'

require 'codtls/encrypt'
require 'codtls/decrypt'
require 'codtls/handshake'
require 'codtls/record'
# require 'codtls/session'
require 'codtls/redis_session'
require 'codtls/redis_pskdb'

# laber
module CoDTLS
  LOG_LEVEL = Logger::ERROR # UNKNOWN,FATAL,ERROR,WARN,INFO,DEBUG
  @redis_connection_object = nil
  @redis_host = '127.0.0.1'
  @redis_port = 6379
  @redis_db = 0

  # TODO
  class SecureSocketError < StandardError
  end

  def self.redis_connection
    return @redis_connection_object unless @redis_connection_object.nil?
    @redis_connection_object = Redis.new(host: @redis_host,
                                         port: @redis_port,
                                         db: @redis_db)
  end

  def self.set_redis_connection_data(host, port, db)
    @redis_host = host
    @redis_port = port
    @redis_db = db
  end

  def self.save_redis
    CoDTLS.redis_connection.save
  end

  # Secure UDP-Socket based on a CoAP using handshake
  #
  # Usage of SecureSocket ist the same as of UDPSocket.
  # There are two additional class methods:
  #
  # set_psk(uuid, psk) to save PSK for specified UUID
  #
  # add_new_node_listener(listener) to enable autohandshake
  # when a new node was found.
  class SecureSocket < UDPSocket
    # Recieves message via secure UDP-Socket. Blocks until data is recieved.
    #
    # @param maxlen [Number] the number of bytes to receive from the socket
    # @param flags [Number] should be a bitwise OR of Socket::MSG_* constants
    # @return [Array] mesg, (address_family, port, hostname, numeric_address).
    #         mesg is empty, if recieved data is corrupt
    def recvfrom(maxlen, flags = nil)
      if flags.nil?
        mesg = super(maxlen + 23)
      else
        mesg = super(maxlen + 23, flags)
      end
      CoDTLS::RecordLayer.decrypt(mesg, maxlen)
    end

    # Recieves message via secure UDP-Socket.
    #
    # @param maxlen [Number] the number of bytes to receive from the socket
    # @param flags [Number] should be a bitwise OR of Socket::MSG_* constants
    # @return [Array] mesg, (address_family, port, hostname, numeric_address).
    #         message is empty, if data there is no data or data is corrupt
    def recvfrom_nonblock(maxlen, flags = nil)
      if flags.nil?
        mesg = super(maxlen + 23)
      else
        mesg = super(maxlen + 23, flags)
      end
      CoDTLS::RecordLayer.decrypt(mesg, maxlen)
    end

    # === Usage:
    # * send(mesg, flags, host, port)
    # * send(mesg, flags, sockaddr_to)
    # * send(mesg, flags)
    #
    # Sends message via secure UDP-Socket.
    #
    # @param mesg [String] the message to send
    # @param flags [Number] should be a bitwise OR of Socket::MSG_* constants
    # @param argv [String] the hostname or sockaddr of the remote machine or
    #             [Number, Number] Host, Port of the remote machine
    # @return [Number] the number of bytes sent.
    #         If mesg.length > 0 && return value == 0 an error happend
    def send(mesg, flags, *argv)
      return 0 if mesg.length <= 0
      if argv.length > 2
        fail ArgumentError, 'wrong number of arguments ' \
                            "(#{2 + argv.length} for 2-4)"
      end

      secure_mesg = case argv.length
                    when 0
                      CoDTLS::RecordLayer.encrypt(
                        mesg,
                        peeraddr(:numeric)[3])
                    when 1
                      CoDTLS::RecordLayer.encrypt(
                        mesg,
                        Socket.unpack_sockaddr_in(argv[0])[1])
                    when 2
                      CoDTLS::RecordLayer.encrypt(
                        mesg,
                        IPSocket.getaddress(argv[0]))
      end
      super(secure_mesg, flags, *argv)
      mesg.length
    end

    # Sets pre-shared key for the device with the specified uuid.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    # @param psk [String] the 16 byte long pre-shared key of the device
    # @param desc [String] Optional Description of the device
    def self.add_psk(uuid, psk, desc = '')
      CoDTLS::RedisPSKDB.set_psk(uuid, psk, desc)
    end

    # Returns all known devices as an Array.
    #
    # @return [Array] of [id, uuid, psk, desc]
    def self.psks
      CoDTLS::RedisPSKDB.all_registered
      # [{ uuid: ['a9d984d1fe2b4c06afe8da98d8924005'].pack('H*'),
      #    psk: 'ABCDEFGHIJKLMNOP', desc: 'Temperaturgeraet 1' },
      #  { uuid: ['9425f01d39034295ad9447161e13251b'].pack('H*'),
      #   psk: 'abcdefghijklmnop', desc: 'Rolladen Nummer 5' }]
    end

    # Deletes the entry of the specified uuid.
    #
    # @param uuid [Binary] the UUID of the device to delete
    # @return [Bool] true if uuid was found and deleted, else false
    def self.del_psk(uuid)
      CoDTLS::RedisPSKDB.del_psk!(uuid)
    end

    # Starts a listening thread on port 5684. If HelloRequest is recieved,
    # listener.info(numeric_address) is called.
    # numeric_address contains the ip of the remote.
    def self.add_new_node_listener(listener)
      Thread.new do
        s = UDPSocket.new(Socket::AF_INET6)
        s.bind('::0', 5684)
        loop do
          packet = s.recvfrom(3)

          logger = Logger.new(STDOUT)
          logger.level = CoDTLS::LOG_LEVEL
          logger.debug(packet.inspect)

          if packet[0] == "\x50\x03\x00"
            logger.debug('HelloRequest erhalten')
            listener.info(packet[1][3])
          end
        end
      end
    end
  end
end
