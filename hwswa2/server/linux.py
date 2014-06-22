import logging
import paramiko
import socket

from hwswa2.server import Server, ServerException

logger = logging.getLogger(__name__)


class LinuxServerException(ServerException):
    pass


class TunnelException(LinuxServerException):
    pass


class LinuxServer(Server):

    def __init__(self, *args, **kwargs):
        super(LinuxServer, self).__init__(*args, **kwargs)
        self._sshclient = None
        # tunnel via gateway used for connections to this server
        self._sshtunnel = None
        # tunnels for other servers. 'name': {'sshclient': sshclient, 'tunnel': tunnel}
        self._sshtunnels = {}
        if self.port is None:
            self._port = 22
        else:
            self._port = self.port

    def _address(self):
        if self.port is None:
            address = self.account['login'] + '@' + self.address
        else:
            address = self.account['login'] + '@' + self.address + ':' + self.port
        return address

    def is_connected(self):
        return self._sshclient is not None

    def _connect(self, timeout=None):
        """Initiates connection and returns SSHClient object

        Returns None if connection fails.
        """
        logger.debug("Trying to connect to %s" % self)
        if timeout is None:
            timeout = self._timeout
        username = self.account['login']
        if 'password' in self.account:
            password = self.account['password']
        else:
            password = None
        if 'key' in self.account:
            key_filename = self.account['key']
        else:
            key_filename = None
        # _connect_to_gateway() will initialize self._sshtunnel used later
        if not self._connect_to_gateway():
            return None
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=self.address, port=self._port, username=username, password=password,
                           key_filename=key_filename, timeout=timeout, sock=self._sshtunnel)
        except paramiko.BadHostKeyException:
            self._last_connection_error = 'BadHostKeyException raised while connecting to %s' % self._address()
            logger.error(self._last_connection_error)
        except paramiko.AuthenticationException:
            self._last_connection_error = 'Authentication failure while connecting to %s' % self._address()
            logger.error(self._last_connection_error)
        except paramiko.SSHException as pe:
            self._last_connection_error = 'SSHException raised while connecting to %s: %s' % (self._address(), pe)
            logger.error(self._last_connection_error)
        except socket.error as serr:
            self._last_connection_error = 'socket.error raised while connecting to %s: %s' % (self._address(), serr)
            logger.error(self._last_connection_error)
        else:
            logger.debug('Established connection with %s' % self)
            return client
        return None

    def _connect_to_gateway(self):
        """Asks gateway to create ssh tunnel to this server

        Returns true if ssh tunnel is created successfully or there is no need for it
        """
        if self.gateway is None:
            return True
        else:
            try:
                self._sshtunnel = self.gateway.create_tunnel(self.name, self.address, self._port)
            except TunnelException as te:
                self._last_connection_error = "cannot connect via gateway %s: %s" % (self.gateway, te.value)
                logger.error(self._last_connection_error)
                return False
            else:
                return True

    def _disconnect_from_gateway(self):
        if self.gateway is not None:
            self.gateway.destroy_tunnel(self.name)

    def connect(self, reconnect=False, timeout=None):
        """Initiates SSH connection to the server.

            Returns true if connection was successful.
        """
        if timeout is None:
            timeout = self._timeout
        if self.is_connected() and not reconnect:
            return True
        else:
            if reconnect:
                self.disconnect()
                logger.debug("Will reconnect to %s" % self)
            client = self._connect(timeout)
            if client is None:
                return False
            else:
                self._sshclient = client
                return True

    def disconnect(self):
        if self._sshclient is not None:
            logger.debug("Will disconnect from %s" % self)
            self._sshclient.close()
            self._sshclient = None
            self._disconnect_from_gateway()

    def create_tunnel(self, name, address, port, timeout=None):
        """Creates SSH tunnel via itself, using separate connection

        Returns tunnel, which can be used as socket
        Raises TunnelException in case of failure
        """
        if timeout is None:
            timeout = self._timeout
        if name in self._sshtunnels:
            if self._sshtunnels[name]['sshclient'] is not None:
                if self._sshtunnels[name]['tunnel'] is not None:
                    return self._sshtunnels[name]['tunnel']
                else:
                    self._sshtunnels[name]['sshclient'].close()
        self._sshtunnels[name] = {'sshclient': None, 'tunnel': None}
        sshclient = self._connect(timeout=timeout)
        if sshclient is None:
            del self._sshtunnels[name]
            raise TunnelException(self._last_connection_error)
        else:
            self._sshtunnels[name]['sshclient'] = sshclient
            transport = sshclient.get_transport()
            try:
                channel = transport.open_channel('direct-tcpip', (address, port), ('127.0.0.1', 0))
            except paramiko.ssh_exception.ChannelException, chan_e:
                del self._sshtunnels[name]
                raise TunnelException("cannot create tunnel via %s: %s" % (self, chan_e))
            else:
                self._sshtunnels[name]['tunnel'] = channel
                return channel

    def destroy_tunnel(self, name):
        try:
            self._sshtunnels[name]['sshclient'].close()
        except:
            pass
        try:
            del self._sshtunnels[name]
        except:
            pass

    def __del__(self):
        # remove ssh tunnel connections
        servers = [server for server in self._sshtunnels]
        for server in servers:
            sshclient = self._sshtunnels[server]['sshclient']
            if sshclient is not None:
                sshclient.close()
                del self._sshtunnels[server]
        # clean up temporary files/dirs and disconnect
        if self.is_connected():
            for tmp in self._tmp:
                self.remove(tmp, privileged=False)
            self.disconnect()
