import logging
import winrmlib.shell
import base64

import hwswa2
from hwswa2.server import (Server, ServerException, TimeoutException, TIMEOUT,
                           REBOOT_TIMEOUT)

__all__ = [ 'WindowsServer', 'WindowsServerException', 'TIMEOUT', 'REBOOT_TIMEOUT' ]

logger = logging.getLogger(__name__)


def encode_arg(arg):
    return base64.b64encode(arg.encode('utf-16le'))


def decode_res(res):
    return base64.b64decode(res).decode('utf-16le')


class WindowsServerException(ServerException):
    pass


class WindowsServer(Server):

    def __init__(self, *args, **kwargs):
        super(WindowsServer, self).__init__(*args, **kwargs)
        self._shell = None

    def _connect(self, reconnect=False, timeout=None):
        """Connect to server
        
        Return True on success 
        """
        timeout = timeout or TIMEOUT
        if self._shell is not None:
            if reconnect:
                self._shell.close()
                self._shell = None
                logger.debug("Will reconnect to  %s" % self)
            else:
                return True
        logger.debug("Trying to connect to  %s" % self)
        self._shell = winrmlib.shell.CommandShell("http://{0}:5985/wsman".format(self.address), self.account['login'], self.account['password'])
        self._shell.open()
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
        """Execute command

        Return tuple of stdout, stderr and status
        """
        timeout = timeout or TIMEOUT
        skip_cmd_shell = True
        arguments=()
        logger.debug("Executing on %s: %s" % (self, cmd))
        if not self._connect():
            raise WindowsServerException("Connection to %s failed: %s" % (self, self._last_connection_error))
        if cmd.startswith('cmd|'):
                command = cmd[4:]
                skip_cmd_shell = False
        elif cmd.startswith('ps|'):
                command = 'powershell.exe'
                posh_cmd = cmd[3:]
                arguments = ('-encodedCommand', encode_arg(posh_cmd))
        else:
            #TODO: split cmd into command and arguments 
            command = cmd
        command_id = self._shell.run(command, arguments, skip_cmd_shell=skip_cmd_shell)
        return self._shell.receive(command_id)

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
        try:
            output = self.get_cmd_out(cmd).strip()
        except TimeoutException as te:
            output = te.details.get('output').strip()
            return False, output, "Timeout exception: %s" % te
        else:
            return True, output, None

    def cleanup(self):
        if self._shell:
            self._shell.close()

    def remove(self, path, privileged=True):
        """Removes file/directory"""
        raise NotImplementedError

    def put(self, localpath, remotepath):
        """Copies local file/directory to the server"""
        raise NotImplementedError

    def mktemp(self, template='hwswa2.XXXXX', ftype='d', path='`pwd`'):
        """Creates directory using mktemp and returns its name"""
        raise NotImplementedError

    def mkdir(self, path):
        """Creates directory"""
        raise NotImplementedError

    def rmdir(self, path):
        """Removes directory"""
        raise NotImplementedError

    def exists(self, path):
        raise NotImplementedError

    def write(self, path, data):
        raise NotImplementedError

    def is_it_me(self):
        raise NotImplementedError

    def check_reboot(self, timeout=300):
        """Reboot the server and check the time it takes to come up"""
        self.check_reboot_result = "not implemented"
        return self.check_reboot_result
        raise NotImplementedError


