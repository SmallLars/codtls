require 'socket'
require 'logger'

require 'codtls/encrypt'
require 'codtls/decrypt'
require 'codtls/handshake'
require 'codtls/record'
require 'codtls/session'

# laber
module CoDTLS
  LOG_LEVEL = Logger::ERROR # UNKNOWN,FATAL,ERROR,WARN,INFO,DEBUG

  # TODO
  class SecureSocketError < StandardError
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
  class SecureSocket
    # Creates a new CoDTLS Socket. Behavior is like UDPSocket.
    #
    # @param address_family [Symbol] the address family of the socket,
    #        `Socket::AF_INET` or `Socket::AF_INET6`
    # @return [Object] the new CoDTLS socket object
    def initialize(address_family = nil)
      if address_family.nil?
        @socket = UDPSocket.new
      else
        @socket = UDPSocket.new(address_family)
      end
    end

    # Binds codtlssocket to host:port.
    #
    # @param host [IP] the address of the local machine
    # @param port [Number] the port of the local machine
    # @return [Number] 0 if bind succeed
    def bind(host, port)
      @socket.bind(host, port)
    end

    # Connects codtlssocket to host:port.
    #
    # @param host [IP] the address of the remote machine
    # @param port [Number] the port of the remote machine
    # @return [Number] 0 if bind succeed
    def connect(host, port)
      @socket.connect(host, port)
    end

    # Recieves message via secure UDP-Socket. Blocks until data is recieved.
    #
    # @param maxlen [Number] the number of bytes to receive from the socket
    # @param flags [Number] should be a bitwise OR of Socket::MSG_* constants
    # @return [Array] mesg, (address_family, port, hostname, numeric_address).
    #         mesg is empty, if recieved data is corrupt
    def recvfrom(maxlen, flags = nil)
      if flags.nil?
        mesg = @socket.recvfrom(maxlen + 23)
      else
        mesg = @socket.recvfrom(maxlen + 23, flags)
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
        mesg = @socket.recvfrom_nonblock(maxlen + 23)
      else
        mesg = @socket.recvfrom_nonblock(maxlen + 23, flags)
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
    # @param host_or_sockaddr_to [String] the hostname or sockaddr of the
    #        remote machine
    # @param port [Number] the port of the remote machine
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
                        @socket.peeraddr(:numeric)[3])
                    when 1
                      CoDTLS::RecordLayer.encrypt(
                        mesg,
                        Socket.unpack_sockaddr_in(argv[0])[1])
                    when 2
                      CoDTLS::RecordLayer.encrypt(
                        mesg,
                        IPSocket.getaddress(argv[0]))
      end
      @socket.send(secure_mesg, flags, *argv)
      mesg.length
    end

    # Disallows further read and write using shutdown system call.
    def close
      @socket.close
    end

    # Sets pre-shared key for the device with the specified uuid.
    #
    # @param uuid [Binary] the UUID of the device in 16 byte binary form
    # @param psk [String] the 16 byte long pre-shared key of the device
    # @param desc [String] Optional Description of the device
    def self.add_psk(uuid, psk, desc = '')
      CoDTLS::PSKDB.set_psk(uuid, psk, desc)
    end

    # Returns all known devices as an Array.
    #
    # @return [Array] of {uuid: A, psk: B, desc: C}
    def self.psks
      CoDTLS::PSKDB.all_registered
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
      CoDTLS::PSKDB.del_psk!(uuid)
    end

    # Starts a listening thread on port 5684. If HelloRequest is recieved,
    # listener.info(numeric_address, code) is called, after a handshake.
    # numeric_address contains the ip of the remote and code == 0 if
    # handshake succeed. Code == 1 if handshake failed or PSK is missing.
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
            logger.debug("HelloRequest erhalten")
            numeric_address = packet[1][3]
            listener.info(numeric_address,
                          CoDTLS::Handshake.handshake(numeric_address))
          end
        end
      end
    end
  end
end
