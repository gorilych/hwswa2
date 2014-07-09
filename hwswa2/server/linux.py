import logging
import paramiko
import socket
import os
import stat
import sys
import select
import signal
import termios
import tty
import time
import subprocess
import posixpath
from ipcalc import Network

import hwswa2.auxiliary as aux

import hwswa2.server
from hwswa2.server import Server, ServerException, TunnelException, TimeoutException

logger = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)

# default timeout value for all operations
TIMEOUT = hwswa2.server.TIMEOUT
REBOOT_TIMEOUT = hwswa2.server.REBOOT_TIMEOUT


class LinuxServerException(ServerException):
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
        self._supath = None
        self._param_cmd_prefix = None
        self._param_binpath = None

    def cleanup(self):
        # remove ssh tunnel connections
        servers = [server for server in self._sshtunnels]
        for server in servers:
            sshclient = self._sshtunnels[server]['sshclient']
            if sshclient is not None:
                sshclient.close()
                del self._sshtunnels[server]
        # clean up temporary files/dirs and disconnect
        if self._is_connected():
            self.agent_stop()
            for tmp in self._tmp:
                self._remove(tmp, privileged=False)
            self._disconnect()

    ########## Internal methods

    def _is_connected(self):
        return self._sshclient is not None

    def _address(self):
        if self.port is None:
            address = self.account['login'] + '@' + self.address
        else:
            address = self.account['login'] + '@' + self.address + ':' + self.port
        return address

    def _new_sshclient(self, timeout=TIMEOUT):
        """Initiates connection and returns SSHClient object

        Returns None if connection fails.
        """
        logger.debug("Trying to connect to %s" % self)
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
        if not self._connect_to_gateway(timeout=timeout):
            return None
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=self.address, port=self._port, username=username, password=password,
                           key_filename=key_filename, timeout=timeout, sock=self._sshtunnel)
        except paramiko.BadHostKeyException:
            self._last_connection_error = 'BadHostKeyException raised while connecting to %s' % self._address()
        except paramiko.AuthenticationException:
            self._last_connection_error = 'Authentication failure while connecting to %s' % self._address()
        except paramiko.SSHException as pe:
            self._last_connection_error = 'SSHException raised while connecting to %s: %s' % (self._address(), pe)
        except socket.error as serr:
            self._last_connection_error = 'socket.error raised while connecting to %s: %s' % (self._address(), serr)
        except Exception as e:
            self._last_connection_error = '%s raised while connecting to %s: %s' % (type(se), self._address(), e)
        else:
            logger.debug('Established connection with %s' % self)
            return client
        logger.debug(self._last_connection_error)
        return None

    def _connect_to_gateway(self, timeout=TIMEOUT):
        """Asks gateway to create ssh tunnel to this server

        Returns true if ssh tunnel is created successfully or there is no need for it
        """
        if self.gateway is None:
            return True
        else:
            try:
                self._sshtunnel = self.gateway.create_tunnel(self.name, self.address, self._port, timeout=timeout)
            except TunnelException as te:
                self._last_connection_error = "cannot connect via gateway %s: %s" % (self.gateway, te.value)
                logger.debug(self._last_connection_error)
                return False
            else:
                logger.debug("created tunnel via %s" % self.gateway)
                return True

    def _disconnect_from_gateway(self):
        if self.gateway is not None:
            try:
                self.gateway.destroy_tunnel(self.name)
            finally:
                logger.debug("destroyed tunnel via %s" % self.gateway)
                self._sshtunnel = None

    def _connect(self, reconnect=False, timeout=TIMEOUT):
        """Initiates SSH connection to the server.

        Returns true if connection was successful.
        """
        if self._is_connected() and not reconnect:
            return True
        else:
            if reconnect:
                self._disconnect()
                logger.debug("Will reconnect to %s" % self)
            client = self._new_sshclient(timeout)
            if client is None:
                return False
            else:
                self._sshclient = client
                return True

    def _disconnect(self):
        if self._sshclient is not None:
            self._sshclient = None
            self._disconnect_from_gateway()

    def _prepare_su_cmd(self, cmd, timeout=TIMEOUT):
        if not ('su' in self.account or 'sudo' in self.account):
            return cmd
        if self._supath is None:
            self._prepare_su()
        supath = self._supath
        su_py = os.path.join(supath, 'su.py')
        stdout_fifo = os.path.join(supath, 'stdout')
        stderr_fifo = os.path.join(supath, 'stderr')
        if 'sudo' in self.account:
            sutype = 'sudo'
            password = self.account['sudo']
            if password is None:
                password = ''
        elif 'su' in self.account:
            sutype = 'su'
            password = self.account['su']
        else:
            logger.error("BUG: _prepare_su_cmd() call for %s, while it does not have account with su/sudo", self)
            return None
        if cmd == 'shell':  # pass window size instead of fifos
            stdout_fifo, stderr_fifo = aux.getTerminalSize()
        return 'python %s %s "%s" %s %s "%s" %s' % (su_py,
                                                    sutype,
                                                    aux.shell_escape(password),
                                                    stderr_fifo,
                                                    stdout_fifo,
                                                    aux.shell_escape(cmd),
                                                    timeout)

    def _prepare_su(self):
        """Copies su.py to remote server and returns path to containing directory"""
        su_py = os.path.join(self._remote_scripts_dir, 'bin32', 'su.py')
        pexpect_py = os.path.join(self._remote_scripts_dir, 'bin32', 'pexpect.py')
        # create directory
        supath = self.mktemp(template='su.XXXX', path='/tmp')
        self.put(pexpect_py, supath)
        self.put(su_py, supath)
        # prepare stdout and stderr fifos:
        self.exec_cmd("mkfifo %s" % os.path.join(supath, 'stdout'), privileged=False)
        self.exec_cmd("mkfifo %s" % os.path.join(supath, 'stderr'), privileged=False)
        self._supath = supath

    def _prepare_param_scripts(self):
        """Copy remote scripts to server, configure cmd prefix

        :return True on success
        """
        if self._param_cmd_prefix is not None:
            return True
        try:
            arch = self.get_cmd_out('uname --machine', privileged=False)
            if arch.endswith('64'):
                rscriptdir = os.path.join(self._remote_scripts_dir,'bin64')
            else:
                rscriptdir = os.path.join(self._remote_scripts_dir,'bin32')
            remote_hwswa2_dir = self.mktemp()
        except ServerException as se:
            logger.error("Failed to prepare remote scripts for parameters check: %s" % se)
            return False
        else:
            binpath = posixpath.join(remote_hwswa2_dir, 'bin')
            self.put(rscriptdir, binpath)
            self._param_binpath = binpath
            self._param_cmd_prefix = 'export PATH=$PATH:%s; ' % binpath
            return True

    def _exists(self, path):
        if self._connect():
            sftp = self._sshclient.open_sftp()
            try:
                sftp.stat(path)
                return True
            except KeyboardInterrupt:
                raise
            except IOError as ie:
                return False

    def _listdir(self, remotedir):
        if self._connect():
            sftp = self._sshclient.open_sftp()
            return sftp.listdir(remotedir)

    def _isdir(self, remotepath):
        if self._connect():
            sftp = self._sshclient.open_sftp()
            attrs = sftp.stat(remotepath)
            return stat.S_ISDIR(attrs.st_mode)

    def _isfile(self, remotepath):
        if self._connect():
            sftp = self._sshclient.open_sftp()
            attrs = sftp.stat(remotepath)
            return stat.S_ISREG(attrs.st_mode)

    def _put_dir_content(self, localdir, remotedir):
        for f in os.listdir(localdir):
            lname = os.path.join(localdir, f)
            rname = os.path.join(remotedir, f)
            if os.path.isfile(lname):
                self.put(lname, rname)
            if os.path.isdir(lname):
                self.mkdir(rname)
                self._put_dir_content(lname, rname)

    def _get_dir_content(self, remotedir, localdir):
        for f in self._listdir(remotedir):
            lname = os.path.join(localdir, f)
            rname = os.path.join(remotedir, f)
            if self._isfile(rname):
                self.get(rname, lname)
            if self._isdir(rname):
                os.makedirs(lname)
                self._get_dir_content(rname, lname)

    def _remove(self, path, privileged=True):
        self.exec_cmd("rm -rf %s" % path, privileged=privileged)

    def _bootid(self):
        return self.get_cmd_out('cat /proc/sys/kernel/random/boot_id')

    def _is_it_me(self):
        if hasattr(subprocess, 'check_output'):
            mybootid = subprocess.check_output(['cat', '/proc/sys/kernel/random/boot_id']).strip()
        else:
            mybootid = subprocess.Popen(
                ['cat', '/proc/sys/kernel/random/boot_id'],
                stdout=subprocess.PIPE
            ).communicate()[0].strip()
        server_bootid = self._bootid()
        logger.debug("Is it me? Comparing %s and %s" % (mybootid, server_bootid))
        return mybootid == server_bootid

    @staticmethod
    def _pipe_to_channel(channel):
        """redirects sys.stdin,out,err to/from channel"""
        while True:
            try:
                r, w, e = select.select([sys.stdin, channel], [], [])
            except select.error:
                continue
            except Exception, e:
                logger.debug("select.select() raised exception %s: %s"
                             % (type(e).__name__, e.args))
                raise e
            if sys.stdin in r:
                x = os.read(sys.stdin.fileno(), 1)
                if len(x) == 0:
                    channel.shutdown_write()
                channel.send(x)
            if channel in r:
                if channel.recv_ready():
                    x = channel.recv(1024)
                    sys.stdout.write(x)
                    sys.stdout.flush()
                if channel.recv_stderr_ready():
                    x = channel.recv_stderr(1024)
                    sys.stderr.write(x)
                    sys.stderr.flush()
            if channel.exit_status_ready():
                break
        while channel.recv_ready():
            x = channel.recv(1024)
            sys.stdout.write(x)
            sys.stdout.flush()
        while channel.recv_stderr_ready():
            x = channel.recv_stderr(1024)
            sys.stderr.write(x)
            sys.stderr.flush()

    @staticmethod
    def _interactive_shell(channel):
        # get current terminal's settings
        height, width = aux.term_winsz()
        if not channel is None and \
                not channel.closed and \
                not channel.eof_received and \
                not channel.eof_sent and \
                channel.active:
            channel.resize_pty(width=width, height=height)
        # remember current signal handler
        old_handler = signal.getsignal(signal.SIGWINCH)
        # remember old tty settings
        old_tty = termios.tcgetattr(sys.stdin)
        # set our handler for winchange signal

        def on_win_resize(signum, frame):
            if not channel is None and \
                    not channel.closed and \
                    not channel.eof_received and \
                    not channel.eof_sent and \
                    channel.active:
                height, width = aux.term_winsz()
                channel.resize_pty(width=width, height=height)

        signal.signal(signal.SIGWINCH, on_win_resize)
        try:
            # change tty settings
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            # interact
            LinuxServer._pipe_to_channel(channel)
        finally:
            signal.signal(signal.SIGWINCH, old_handler)
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)

    ########## Public methods

    def accessible(self, retry=False):
        if self._is_connected() and not retry:
            return True
        else:
            return self._connect(reconnect=True, timeout=TIMEOUT)

    def create_tunnel(self, name, address, port, timeout=TIMEOUT):
        """Creates SSH tunnel via itself, using separate connection

        Returns tunnel, which can be used as socket
        Raises TunnelException in case of failure
        """
        logger.debug("%s was asked to create tunnel to %s" % (self, name))
        if name in self._sshtunnels:
            if self._sshtunnels[name]['sshclient'] is not None:
                if self._sshtunnels[name]['tunnel'] is not None:
                    return self._sshtunnels[name]['tunnel']
                else:
                    self._sshtunnels[name]['sshclient'].close()
        self._sshtunnels[name] = {'sshclient': None, 'tunnel': None}
        sshclient = self._new_sshclient(timeout=timeout)
        if sshclient is None:
            del self._sshtunnels[name]
            raise TunnelException(self._last_connection_error)
        else:
            self._sshtunnels[name]['sshclient'] = sshclient
            transport = sshclient.get_transport()
            try:
                logger.debug("%s: about to create channel to %s:%s" % (self, address, port))
                channel = transport.open_channel('direct-tcpip', (address, port), ('127.0.0.1', 0))
                logger.debug("%s: created channel to %s:%s" % (self, address, port))
            except paramiko.ChannelException, chan_e:
                del self._sshtunnels[name]
                raise TunnelException("cannot create tunnel via %s: %s" % (self, chan_e))
            else:
                self._sshtunnels[name]['tunnel'] = channel
                return channel

    def destroy_tunnel(self, name):
        logger.debug("%s was asked to destroy tunnel to %s" % (self, name))
        try:
            self._sshtunnels[name]['sshclient'].close()
        except Exception as e:
            logger.debug("trying to remove tunnel %s (sshclient.close()): exception %s: %s"
                         % (name, type(e).__name__, e.args))
            pass
        try:
            del self._sshtunnels[name]
        except Exception as e:
            logger.debug("trying to remove tunnel %s (del key): exception %s: %s"
                         % (name, type(e).__name__, e.args))
            pass

    def write(self, path, data):
        if self._connect():
            sftp = self._sshclient.open_sftp()
            f = sftp.open(path, 'w')
            f.write(data)
            f.close()

    def mkdir(self, path):
        if self._connect():
            sftp = self._sshclient.open_sftp()
            sftp.mkdir(path)

    def exec_cmd_i(self, cmd, privileged=True, timeout=TIMEOUT, get_pty=False):
        """Executes command interactively"""
        if self._connect():
            if privileged and ('su' in self.account or 'sudo' in self.account):
                cmd = self._prepare_su_cmd(cmd, timeout)
            if get_pty and sys.stdin.isatty():
                channel = self._sshclient.get_transport().open_session()
                height, width = aux.term_winsz()
                channel.get_pty(term=aux.term_type(), width=width, height=height)
                channel.exec_command(cmd)
                LinuxServer._interactive_shell(channel)
                status = channel.recv_exit_status()
                channel.close()
            else:
                stdin, stdout, stderr = self._sshclient.exec_command(cmd, timeout=0.0, get_pty=False)
                LinuxServer._pipe_to_channel(stdout.channel)
                status = stdout.channel.recv_exit_status()
            return status

    def exec_cmd(self, cmd, input_data=None, timeout=TIMEOUT, privileged=True):
        """Executes command and returns tuple of stdout, stderr and status"""
        logger.debug("Executing on %s: %s" % (self, cmd))
        if self._connect():
            if privileged and ('su' in self.account or 'sudo' in self.account):
                cmd = self._prepare_su_cmd(cmd, timeout)
                logger.debug("Privileged command: %s" % cmd)
            try:
                stdin, stdout, stderr = self._sshclient.exec_command(cmd, timeout=timeout, get_pty=False)
                if input_data:
                    stdin.write(input_data)
                    stdin.flush()
                stdout_data = stdout.read().splitlines()
                stderr_data = stderr.read().splitlines()
                status = stdout.channel.recv_exit_status()
            except socket.timeout as e:
                raise TimeoutException("Timeout during execution of %s" % cmd)
            except paramiko.SSHException as e:
                raise LinuxServerException("SSH exception: %s" % e)
            logger.debug("Executon results: exit status %s, stdout %s, stderr %s" %
                         (status, stdout_data, stderr_data))
            return stdout_data, stderr_data, status

    def get_cmd_out(self, cmd, input_data=None, timeout=TIMEOUT, privileged=True):
        stdout_data, stderr_data, status = self.exec_cmd(cmd, input_data, timeout=timeout, privileged=privileged)
        return '\n'.join(stdout_data)

    def mktemp(self, template='hwswa2.XXXXX', ftype='d', path='`pwd`'):
        """Creates directory/file using mktemp and returns its name"""
        cmd = 'mktemp '
        if ftype == 'd':
            cmd += '-d '
        cmd += '-p %s %s' % (path, template)
        tmp = self.get_cmd_out(cmd, privileged=False)
        self._tmp.append(tmp)
        return tmp

    def put(self, localpath, remotepath=None):
        if remotepath is None or remotepath == '':
            remotepath = '.'
        logger.debug("Copying %s to %s:%s" % (localpath.decode('utf-8'), self, remotepath.decode('utf-8')))
        if not os.path.exists(localpath):
            raise LinuxServerException("Local path does not exist: %s" % localpath.decode('utf-8'))
        if self._connect():
            sftp = self._sshclient.open_sftp()
            if os.path.isfile(localpath):
                if self._exists(remotepath):
                    attrs = sftp.stat(remotepath)
                    if stat.S_ISDIR(attrs.st_mode):
                        remotepath = os.path.join(remotepath, os.path.basename(localpath))
                    sftp.put(localpath, remotepath, confirm=True)
                    sftp.chmod(remotepath, os.stat(localpath).st_mode)
                else:
                    sftp.put(localpath, remotepath, confirm=True)
                    sftp.chmod(remotepath, os.stat(localpath).st_mode)
            if os.path.isdir(localpath):
                if self._exists(remotepath):
                    rname = os.path.join(remotepath, os.path.basename(localpath))
                    self.mkdir(rname)
                    self._put_dir_content(localpath, rname)
                else:
                    self.mkdir(remotepath)
                    self._put_dir_content(localpath, remotepath)

    def get(self, remotepath, localpath=None):
        if localpath is None or localpath == '':
            localpath = '.'
        logger.debug("Copying to %s from %s:%s" % (localpath.decode('utf-8'), self, remotepath.decode('utf-8')))
        if self._connect():
            sftp = self._sshclient.open_sftp()
            if not self._exists(remotepath):
                raise LinuxServerException("Remote path does not exist: %s" % remotepath.decode('utf-8'))
            if self._isdir(remotepath):
                if os.path.exists(localpath):
                    lname = os.path.join(localpath, os.path.basename(remotepath))
                    os.makedirs(lname)
                    self._get_dir_content(remotepath, lname)
                else:
                    os.makedirs(localpath)
                    self._get_dir_content(remotepath, localpath)
            elif self._isfile(remotepath):
                attrs = sftp.stat(remotepath)
                if os.path.exists(localpath):
                    if os.path.isdir(localpath):
                        localpath = os.path.join(localpath, os.path.basename(remotepath))
                    sftp.get(remotepath, localpath)
                    os.chmod(localpath, attrs.st_mode)
                else:  # localpath does not exist
                    sftp.get(remotepath, localpath)
                    os.chmod(localpath, attrs.st_mode)

    def check_reboot(self, timeout=REBOOT_TIMEOUT):
        """Reboots the server and checks the time it takes to come up

        Returns number of seconds (int/long) or reason why check is not possible (string)
        """
        if self._is_it_me():
            self.check_reboot_result = "we are running here, no reboot"
            return self.check_reboot_result
        logger.debug("Trying to reboot %s" % self)
        starttime = time.time()
        try:  # reboot will most probably fail with socket.timeout exception
            self.exec_cmd('reboot', timeout=3)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            logger.debug("self.exec_cmd('reboot', timeout=3) caused exception %s: %s"
                         % (type(e).__name__, e.args))
            pass
        logger.debug("reboot command is sent, now wait till server is down")
        # wait till shutdown:
        if aux.wait_for_not(self.accessible, [True], timeout):
            logger.debug("%s is down" % self)
            delta = time.time() - starttime
            # wait till boot
            if aux.wait_for(self.accessible, [True], timeout - delta):
                self.check_reboot_result = int(round(time.time() - starttime))
                return self.check_reboot_result
            else:
                self.check_reboot_result = "server is not accessible after %s seconds" % timeout
                return self.check_reboot_result
        else:
            # check uptime, it can be the case server reboots too fast
            uptime, space, idle = self.get_cmd_out('cat /proc/uptime', privileged=False).partition(' ')
            uptime = float(uptime)
            if uptime < timeout + 10:
                self.check_reboot_result = 0
                return self.check_reboot_result
            else:
                self.check_reboot_result = "server does not go to reboot: still accessible after %s seconds" % timeout
                return self.check_reboot_result

    def shell(self, privileged=True):
        """Opens remote SSH session"""
        if self._connect():
            channel = self._sshclient.invoke_shell(aux.term_type())
            if privileged and ('su' in self.account or 'sudo' in self.account):
                cmd = self._prepare_su_cmd('shell')
                channel.sendall(cmd + '; exit \n')
                # cleanup previous output, leaving only prompt
                data = ''
                while channel.recv_ready():
                    data += channel.recv(1000)
                time.sleep(0.3)
                while channel.recv_ready():
                    data += channel.recv(1000)
                print data.split('\n')[-1],
                sys.stdout.flush()
            LinuxServer._interactive_shell(channel)
            channel.close()

    def agent_start(self):
        """Starts remote agent on server"""
        if self._agent is not None:
            return True
        try:
            if self._connect():
                serverd_py = os.path.join(self._remote_scripts_dir, 'bin32', 'serverd.py')
                # remote path
                r_serverd_py = self.mktemp(template='serverd.XXXX', ftype='f', path='/tmp')
                self.put(serverd_py, r_serverd_py)
                if 'su' in self.account or 'sudo' in self.account:
                    r_serverd_py_cmd = self._prepare_su_cmd('stty -echo; ' + r_serverd_py)
                    r_serverd_py_privileged = True
                    get_pty = True
                else:
                    r_serverd_py_cmd = r_serverd_py
                    r_serverd_py_privileged = False
                    get_pty = False
                stdin, stdout, stderr = self._sshclient.exec_command(r_serverd_py_cmd, get_pty=get_pty)
                banner = stdout.readline()
                if not banner.startswith('started_ok'):
                    banner = stdout.readline()
                logger.debug('remote agent started on %s: %s' % (self, banner))
                self._agent = {'r_serverd_py': r_serverd_py,
                               'privileged': r_serverd_py_privileged,
                               'pty': get_pty,
                               'stdin': stdin,
                               'stdout': stdout,
                               'stderr': stderr}
                return True
        except KeyboardInterrupt:
            raise
        except Exception as e:
            logger.debug("agent not started, exception %s: %s"
                         % (type(e).__name__, e.args), exc_info=True)
            return False

    def agent_stop(self):
        """Stops remote agent on server"""
        if self._agent is not None:
            try:
                self.agent_cmd('exit')
                self._agent['stdin'].close()
            except Exception as e:
                logger.debug("could not stop agent, exception %s: %s"
                             % (type(e).__name__, e.args))
            finally:
                self._agent = None

    def agent_cmd(self, cmd):
        """Sends command to remote agent and returns tuple (status, result)"""
        if not self.agent_start():
            return False, 'agent not started'
        else:
            stdin = self._agent['stdin']
            stdout = self._agent['stdout']
            logger.debug('command: ' + cmd)
            stdin.write(cmd + '\n')
            reply = stdout.readline().strip()
            logger.debug('accept reply: ' + reply)
            accepted, space, reason = reply.partition(' ')
            if accepted == 'accepted_notok':
                return False, 'command not accepted: ' + reason
            elif not accepted == 'accepted_ok':
                return False, 'wrong accept message, should start with accepted_ok/accepted_notok: ' + reply
            else:  # accepted == 'accepted_ok'
                logger.debug('command accepted on server %s: %s' % (self, reason))
                reply = stdout.readline().strip()
                logger.debug('result reply: ' + reply)
                result_status, space, result = reply.partition(' ')
                if result_status == 'result_ok':
                    return True, result
                elif result_status == 'result_notok':
                    return False, 'command failed: ' + result
                else:
                    return False, 'wrong result message, should start with result_ok/result_notok: ' + reply

    def param_cmd(self, cmd):
        """Execute cmd in prepared environment to obtain some server parameter

        :param cmd: raw command to execute
        :return: (status, output, failure)
        """
        if not self._prepare_param_scripts():
            return False, None, "Remote scripts are not on the server"
        prefixed_cmd = self._param_cmd_prefix + cmd
        try:
            output = self.get_cmd_out(prefixed_cmd)
        except TimeoutException as te:
            output = None
            if 'output' in te.details:
                output = te.details['output']
            return False, output, "Timeout exception: %s" % te
        else:
            return True, output, None

    def param_script(self, script):
        """Execute script in prepared environment to obtain some server parameter

        :param script: script content
        :return: (status, output, failure)
        """
        if not self._prepare_param_scripts():
            return False, None, "Remote scripts are not on the server"
        scriptpath = self.mktemp(ftype='f', path=self._param_binpath)
        self.write(scriptpath, script)
        self.exec_cmd('chmod +x %s' % scriptpath)
        return self.param_cmd(scriptpath)

    def get_ips(self, networks=None):
        """Obtain IPv4 addresses from server and save result to self.nw_ips.

        :param networks: [{name: '', address: '', prefix: ''}, ... ]
        :return: True, if any found IP matches some network from passed networks
        """
        cmd = "/sbin/ip -family inet -oneline address list scope global | awk '{print $4}'"
        ips = [Network(ip) for ip in self.get_cmd_out(cmd).split()]
        status = False
        for ip in ips:
            m = ip.mask
            n_a = "%s" % ip.network()
            ip_addr = "%s" % ip
            network_name = None
            if networks:
                network_name = next((n['name'] for n in networks if n['prefix'] == m and n['address'] == n_a), None)
            if network_name:
                self.nw_ips[network_name] = ip_addr
                status = True
            else:
                self.nw_ips[n_a + '/' + str(m)] = ip_addr
        return status

