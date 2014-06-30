import ntpath
import os.path
import socket
import logging

from impacket.dcerpc.v5.transport import DCERPCStringBindingCompose, DCERPCTransportFactory
from impacket.dcerpc.v5 import scmr
from impacket.smbconnection import SessionError

import hwswa2.server
from hwswa2.server import Server, ServerException, TimeoutException

logger = logging.getLogger(__name__)

# default timeout value for all operations
TIMEOUT = hwswa2.server.TIMEOUT
REBOOT_TIMEOUT = hwswa2.server.REBOOT_TIMEOUT


class WindowsServerException(ServerException):
    pass


class WindowsServer(Server):

    def __init__(self, *args, **kwargs):
        super(WindowsServer, self).__init__(*args, **kwargs)
        self._transport = None
        self._param_cmd_prefix = None
        self._param_binpath = None

    def _connect(self, reconnect=False, timeout=TIMEOUT):
        """Connect to server
        
        Return True on success 
        """
        if self._transport is not None:
            if reconnect:
                self._transport.disconnect()
                self._transport = None
                logger.debug("Will reconnect to  %s" % self)
            else:
                return True
        logger.debug("Trying to connect to  %s" % self)
        hostname = self.address
        username = self.account['login']
        password = self.account['password']
        strbinding = DCERPCStringBindingCompose(protocol_sequence='ncacn_np',
                                                network_address=hostname,
                                                endpoint='\pipe\svcctl')
        transport = DCERPCTransportFactory(strbinding)
        transport.set_credentials(username, password)
        transport.set_connect_timeout(timeout)
        dce = transport.get_dce_rpc()

        try:
            dce.connect()
        except SessionError, se:
            logger.debug('Failed to establish connection with %s: %s' % (self, se))
            self._last_connection_error = 'SessionError raised while connecting: %s' % se
            return False
        except socket.error, serr:
            logger.debug('socket.error raised while connecting to %s@%s: %s' % (username, hostname, serr))
            self._last_connection_error = 'socket.error raised while connecting to %s@%s: %s' \
                                          % (username, hostname, serr)
            return False
        else:
            dce.bind(scmr.MSRPC_UUID_SCMR)
            logger.debug('Established connection with %s@%s' % (username, hostname))
            self._transport = transport
            return True

    def shell(self, privileged=True):
        """Opens remote cmd session"""
        raise NotImplementedError

    def accessible(self, retry=False):
        """Checks if server is accessible and manageable"""
        return self._connect(reconnect=retry)

    def exec_cmd_i(self, cmd, privileged=True, timeout=TIMEOUT, get_pty=False):
        """Executes command interactively"""
        raise NotImplementedError

    def exec_cmd(self, cmd, input_data=None, timeout=TIMEOUT, privileged=True):
        """Executes command and returns tuple of stdout, stderr and status"""
        raise NotImplementedError

    def get_cmd_out(self, cmd, input_data=None, timeout=TIMEOUT, privileged=True):
        """Returns command output (stdout)"""
        raise NotImplementedError

    def remove(self, path, privileged=True):
        """Removes file/directory"""
        raise NotImplementedError

    def put(self, localpath, remotepath):
        """Copies local file/directory to the server"""
        logger.logger.debug("Copying %s to %s:%s" % (localpath, self.name, remotepath))
        if not os.path.exists(localpath):
            raise Exception("Local path does not exist: %s" % localpath)
        self._connect()
        smbconnection = self._transport.get_smb_connection()
        fh = open(localpath, 'rb')
        # remotepath = C:\somedir\somefile
        # => share = C$, sharepath = somedir\somefile
        share = remotepath[0] + '$'
        sharepath = remotepath[3:]
        smbconnection.putFile(share, sharepath, fh.read)

    def mktemp(self, template='hwswa2.XXXXX', ftype='d', path='`pwd`'):
        """Creates directory using mktemp and returns its name"""
        raise NotImplementedError

    def mkdir(self, path):
        """Creates directory"""
        logger.logger.debug("MKDIR %s on %s" %(path, self))
        self._connect()
        smbconnection = self._transport.get_smb_connection()
        share = path[0] + '$'
        sharepath = path[3:]
        smbconnection.createDirectory(share, sharepath)

    def rmdir(self, path):
        """Removes directory"""
        logger.logger.debug("RMDIR %s on %s" %(path, self))
        self._connect()
        smbconnection = self._transport.get_smb_connection()
        share = path[0] + '$'
        sharepath = path[3:]
        smbconnection.deleteDirectory(share, sharepath)

    def exists(self, path):
        raise NotImplementedError

    def write(self, path, data):
        raise NotImplementedError

    def is_it_me(self):
        raise NotImplementedError

    def check_reboot(self, timeout=300):
        """Reboot the server and check the time it takes to come up"""
        raise NotImplementedError

    def cleanup(self):
        if self._transport is not None:
            self._transport.disconnect()
            self._transport = None
            logger.logger.debug("Closed connection to  %s" % self)

    def serverd_start(self):
        """Starts serverd on server"""
        raise NotImplementedError


    def serverd_stop(self):
        """Stops serverd on server"""
        raise NotImplementedError


    def serverd_cmd(self, cmd):
        """Sends command to serverd and returns tuple (status_ok_or_not, result)"""
        raise NotImplementedError

