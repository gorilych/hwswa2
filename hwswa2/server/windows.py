import ntpath
import os.path
import socket
import logging
import base64

from impacket.dcerpc.v5.transport import DCERPCStringBindingCompose, DCERPCTransportFactory
from impacket.dcerpc.v5 import scmr
from impacket.smbconnection import SessionError

import hwswa2
from hwswa2.server import (Server, ServerException, TimeoutException, TIMEOUT,
                           REBOOT_TIMEOUT)

__all__ = [ 'WindowsServer', 'WindowsServerException', 'TIMEOUT', 'REBOOT_TIMEOUT' ]

logger = logging.getLogger(__name__)

_agent_pipe_name = 'hwswa2_agent'


def encode_arg(arg):
    return base64.b64encode(arg.encode('utf-16le'))


def decode_res(res):
    return base64.b64decode(res).decode('utf-16le')


class WindowsServerException(ServerException):
    pass


class WindowsServer(Server):

    def __init__(self, *args, **kwargs):
        super(WindowsServer, self).__init__(*args, **kwargs)
        self._transport = None
        self._param_cmd_prefix = None
        self._param_binpath = None
        self._agent_pipe = None

    def _connect(self, reconnect=False, timeout=TIMEOUT):
        """Connect to server
        
        Return True on success 
        """
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

    def _create_service(self, name, binpath):
        scManagerHandle = scmr.hROpenSCManagerW(self._dce)['lpScHandle']
        resp = scmr.hRCreateServiceW(self._dce, scManagerHandle, name + '\x00',
                                     name + '\x00', lpBinaryPathName=binpath + '\x00')
        serviceHandle = resp['lpServiceHandle']
        scmr.hRStartServiceW(self._dce, serviceHandle)
        scmr.hRCloseServiceHandle(self._dce, serviceHandle)
        scmr.hRCloseServiceHandle(self._dce, scManagerHandle)

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
            self._transport.disconnect()
            self._transport = None
            logger.debug("Closed connection to  %s" % self)

    def agent_start(self):
        """Start remote agent on server
        :return: True on success
        """
        if self._agent_pipe is not None:
            return True
        else:
            try:
                if not self._connect():
                    return False
                else:
                    wagent_exe = 'wagent-debug.exe' if hwswa2.config['remote_debug'] else 'wagent.exe'
                    wagent_exe = hwswa2.config['resources'] + os.sep + wagent_exe
                    wagent_remote_path = 'C:\\wagent.exe'
                    self.put(wagent_exe, wagent_remote_path)
                    self._create_service('hwswa2_agent', wagent_remote_path)
                    self._agent_pipe = self.open_pipe(_agent_pipe_name)
                    banner = self._agent_pipe.read()
                    logger.debug("agent started, banner: %s" % banner)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                logger.debug("agent not started, exception %s: %s" %
                             (type(e).__name__, e.args), exc_info=True)
                return False
            else:
                return True

    def agent_stop(self):
        """Stop remote agent on server"""
        if self._agent_pipe is not None:
            try:
                self.agent_cmd("exit", wait_result=False)
                self._agent_pipe.close()
            except Exception as e:
                logger.debug("agent: error closing named pipe, exception %s: %s" %
                             (type(e).__name__, e.args), exc_info=True)
            self._agent_pipe = None

    def agent_cmd(self, cmd, wait_result=True):
        """Send command to remote agent and returns tuple (status, result)"""
        if not self.agent_start():
            return False, 'agent not started'
        else:
            pipe = self._agent_pipe
            logger.debug('command: ' + cmd)
            pipe.write(cmd)
            reply = pipe.read()
            logger.debug('accept reply: ' + reply)
            accepted, space, reason = reply.partition(' ')
            if accepted == 'accepted_notok':
                return False, 'command not accepted: ' + reason
            elif not accepted == 'accepted_ok':
                return False, 'wrong accept message, should start with accepted_ok/accepted_notok: ' + reply
            else:  # accepted == 'accepted_ok'
                if not wait_result:
                    return True, None
                else:
                    logger.debug('command accepted on server %s: %s' % (self, reason))
                    reply = pipe.read()
                    logger.debug('result reply: ' + reply)
                    result_status, space, result = reply.partition(' ')
                    if result_status == 'result_ok':
                        return True, result
                    elif result_status == 'result_notok':
                        return False, 'command failed: ' + result
                    else:
                        return False, 'wrong result message, should start with result_ok/result_notok: ' + reply

    def open_pipe(self, name):
        return NamedPipe(self._transport.get_smb_connection(), name)


class NamedPipe(object):

    def __init__(self, smbconnection, name):
        self.name = name
        self._smbconnection = smbconnection
        self._tid = smbconnection.connectTree('IPC$')
        self._fid = smbconnection.openFile(self._tid, '\\' + name)

    def write(self, data):
        self._smbconnection.writeNamedPipe(self._tid, self._fid, data.encode('utf-16le'))

    def read(self, bytesToRead=None):
        return self._smbconnection.readNamedPipe(self._tid, self._fid, bytesToRead).decode('utf-16le')

    def close(self):
        self._smbconnection.closeFile(self._tid, self._fid)
