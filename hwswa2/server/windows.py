import logging
import inrm

import hwswa2
from hwswa2.server import (Server, ServerException, TimeoutException, TIMEOUT,
                           REBOOT_TIMEOUT)

__all__ = [ 'WindowsServer', 'WindowsServerException', 'TIMEOUT', 'REBOOT_TIMEOUT' ]

logger = logging.getLogger(__name__)


class WindowsServerException(ServerException):
    pass


class WindowsServer(Server):

    def __init__(self, *args, **kwargs):
        super(WindowsServer, self).__init__(*args, **kwargs)
        self._transport = None
        self._param_cmd_prefix = None
        self._param_binpath = None
        self._agent_pipe = None

    def _connect(self, reconnect=False, timeout=None):
        """Connect to server
        
        Return True on success 
        """
        timeout = timeout or TIMEOUT
        if self._transport is not None:
            if reconnect:
                try:
                    self._transport.disconnect()
                except socket.error:
                    pass
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
            self._dce = dce
            self._transport = transport
            return True

    def shell(self, privileged=True):
        """Opens remote cmd session"""
        raise NotImplementedError

    def accessible(self, retry=False):
        """Checks if server is accessible and manageable"""
        return self._connect(reconnect=retry)

    def exec_cmd_i(self, cmd, privileged=True, timeout=None, get_pty=False):
        """Executes command interactively"""
        raise NotImplementedError

    def exec_cmd(self, cmd, input_data=None, timeout=None, privileged=True):
        """Executes command and returns tuple of stdout, stderr and status"""
        timeout = timeout or TIMEOUT
        logger.debug("Executing on %s: %s" % (self, cmd))
        if not self._connect():
            raise WindowsServerException("Connection to %s failed: %s" % (self, self._last_connection_error))
        else:
            if not self.agent_start():
                logger.error("Failed to start agent on %s" % self)
                raise WindowsServerException("Failed to start agent on %s" % self)
            else:
                if input_data:
                    acmd = ('exec_in ' + encode_arg(cmd) + ' ' +
                            encode_arg(input_data) + ' ' + str(timeout))
                elif cmd.startswith('cmd|'):
                    acmd = ('exec_cmd ' + encode_arg(cmd[4:]) + ' ' + str(timeout))
                elif cmd.startswith('ps|'):
                    acmd = ('exec_pse ' + encode_arg(cmd[3:]) + ' ' + str(timeout))
                else:
                    acmd = ('exec ' + encode_arg(cmd) + ' ' + str(timeout))
                status, result = self.agent_cmd(acmd)
                # result is "[reason:<reason of failure>] \
                # returncode:<num> stdout:<base64encoded> stderr:<base64encoded>"
                logger.debug("exec_cmd result %s" % result)
                result = dict([r.split(':') for r in result.split(' ')])
                if status:
                    return (decode_res(result['stdout']),
                            decode_res(result['stderr']),
                            int(result['returncode']))
                else:
                    reason = decode_res(result.get('reason'))
                    if reason == 'timeout':
                        raise TimeoutException("Timeout during execution of %s" % cmd,
                                               output=decode_res(result['stdout']),
                                               stderr=decode_res(result['stderr']))
                    else:
                        raise WindowsServerException("Execution of %s failed: %s" % (cmd, reason))

    def get_cmd_out(self, cmd, input_data=None, timeout=None, privileged=True):
        """Returns command output (stdout)"""
        timeout = timeout or TIMEOUT
        stdout_data, stderr_data, status = self.exec_cmd(cmd, input_data, timeout=timeout)
        # remove last trailing newline
        if len(stdout_data) > 0 and stdout_data[-1] == '\n':
            stdout_data = stdout_data[:-1]
        return stdout_data

    def param_cmd(self, cmd):
        """Execute cmd in prepared environment to obtain some server parameter

        :param cmd: raw command to execute
        :return: (status, output, failure)
        """
        if not self.agent_start():
            return False, None, "Agent is not started on the server"
        try:
            output = self.get_cmd_out(cmd).strip()
        except TimeoutException as te:
            output = te.details.get('output').strip()
            return False, output, "Timeout exception: %s" % te
        else:
            return True, output, None

    def remove(self, path, privileged=True):
        """Removes file/directory"""
        raise NotImplementedError

    def put(self, localpath, remotepath):
        """Copies local file/directory to the server"""
        logger.debug("Copying %s to %s:%s" % (localpath, self.name, remotepath))
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
        logger.debug("MKDIR %s on %s" %(path, self))
        self._connect()
        smbconnection = self._transport.get_smb_connection()
        share = path[0] + '$'
        sharepath = path[3:]
        smbconnection.createDirectory(share, sharepath)

    def rmdir(self, path):
        """Removes directory"""
        logger.debug("RMDIR %s on %s" %(path, self))
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
            if self._agent_pipe is not None:
                self.agent_stop()
            self._transport.disconnect()
            self._transport = None
            logger.debug("Closed connection to  %s" % self)

