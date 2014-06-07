import stat
import time
import os
import os.path
import sys
import subprocess
import signal
import termios
import tty
import select
import paramiko
import socket
import hwswa2.auxiliary as aux
from hwswa2.globals import config
from logging import debug

ssh_timeout = 30


def _connect(server, timeout=30):
    """Initiates connection and returns SSHClient object
       Does not store information about the client"""
    debug("Trying to connect to server %s" % server['name'])
    hostname = server['address']
    if 'port' in server:
        port = server['port']
    else:
        port = 22
    username = server['account']['login']
    password = None
    key_filename = None
    if 'password' in server['account']: password = server['account']['password']
    if 'key' in server['account']: key_filename = server['account']['key']

    try:
        jump_channel = _jump_channel(server)
    except _JumpException, je:
        err_msg = 'Gateway failure while connecting: %s' % je
        debug(err_msg)
        server['lastConnectionError'] = err_msg
        return None
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname, port, username, password=password,
                       key_filename=key_filename, timeout=timeout, sock=jump_channel)
    except paramiko.BadHostKeyException:
        debug('BadHostKeyException raised while connecting to %s@%s:%s' % (username, hostname, port))
        server['lastConnectionError'] = 'BadHostKeyException raised while connecting to %s@%s:%s' % (
        username, hostname, port)
    except paramiko.AuthenticationException:
        debug('Authentication failure while connecting to %s@%s:%s' % (username, hostname, port))
        server['lastConnectionError'] = 'Authentication failure while connecting to %s@%s:%s' % (
        username, hostname, port)
    except paramiko.SSHException:
        debug('SSHException raised while connecting to %s@%s:%s' % (username, hostname, port))
        server['lastConnectionError'] = 'SSHException raised while connecting to %s@%s:%s' % (username, hostname, port)
    except socket.error as serr:
        debug('socket.error raised while connecting to %s@%s:%s: %s' % (username, hostname, port, serr))
        server['lastConnectionError'] = 'socket.error raised while connecting to %s@%s:%s: %s' % (
        username, hostname, port, serr)
    else:
        debug('Established connection with %s@%s:%s' % (username, hostname, port))
        return client
    return None


def connect(server, reconnect=False, timeout=30):
    """Connects to server and returns SSHClient object
       SSHClient is cached inside server object"""
    if 'sshclient' in server:
        if reconnect:
            server['sshclient'].close()
            del server['sshclient']
            _cleanjump(server)
            debug("Will reconnect to server %s" % server['name'])
        else:
            return server['sshclient']
    client = _connect(server)
    if client is None:
        return None
    else:
        server['sshclient'] = client
        return server['sshclient']


def shell(server, privileged=True):
    """Opens remote SSH session"""
    client = connect(server)
    channel = client.invoke_shell(aux.term_type())
    if privileged and ('su' in server['account'] or 'sudo' in server['account']):
        sshcmd = prepare_su_cmd(server, 'shell')
        channel.sendall(sshcmd + '; exit \n')
        # cleanup previous output, leaving only prompt
        data = ''
        while channel.recv_ready(): data += channel.recv(1000)
        time.sleep(0.3)
        while channel.recv_ready(): data += channel.recv(1000)
        print data.split('\n')[-1],
        sys.stdout.flush()
    interactive_shell(channel)
    channel.close()


def accessible(server, retry=False):
    if 'accessible' in server and not retry:
        return server['accessible']
    else:
        client = connect(server, reconnect=True, timeout=10)
        if not (client is None):
            server['accessible'] = True
            return True
        else:
            server['accessible'] = False
            return False


def pingable(server):
    command = "ping -w 1 -q -c 1 %s" % server['address']
    return subprocess.call(command) == 0


def exec_cmd_i(server, sshcmd, privileged=True, timeout=ssh_timeout, get_pty=False):
    """Executes command interactively"""
    client = connect(server)
    if privileged and ('su' in server['account'] or 'sudo' in server['account']):
        sshcmd = prepare_su_cmd(server, sshcmd, timeout)

    if get_pty and sys.stdin.isatty():
        channel = client.get_transport().open_session()
        height, width = aux.term_winsz()
        channel.get_pty(term=aux.term_type(), width=width, height=height)
        channel.exec_command(sshcmd)
        interactive_shell(channel)
        status = channel.recv_exit_status()
        channel.close()
    else:
        stdin, stdout, stderr = client.exec_command(sshcmd, timeout=0.0, get_pty=False)
        pipe_to_channel(stdout.channel)
        status = stdout.channel.recv_exit_status()

    return status


def exec_cmd(server, sshcmd, input_data=None, timeout=ssh_timeout, privileged=True):
    """Executes command and returns tuple of stdout, stderr and status"""
    debug("Executing %s on server %s" % (sshcmd, server['name']))
    client = connect(server)
    if privileged and ('su' in server['account'] or 'sudo' in server['account']):
        sshcmd = prepare_su_cmd(server, sshcmd, timeout)
        debug("Privileged command %s on server %s" % (sshcmd, server['name']))
    stdin, stdout, stderr = client.exec_command(sshcmd, timeout=timeout, get_pty=False)
    if input_data:
        stdin.write(input_data)
        stdin.flush()
    stdout_data = stdout.read().splitlines()
    stderr_data = stderr.read().splitlines()
    status = stdout.channel.recv_exit_status()
    debug("Executed %s on server %s: stdout %s, stderr %s, exit status %s" %
          (sshcmd, server['name'], stdout_data, stderr_data, status))
    return stdout_data, stderr_data, status


def get_cmd_out(server, sshcmd, input_data=None, timeout=ssh_timeout, privileged=True):
    stdout_data, stderr_data, status = exec_cmd(server, sshcmd, input_data, timeout=timeout, privileged=privileged)
    return '\n'.join(stdout_data)


def remove(server, path, privileged=True):
    exec_cmd(server, "rm -rf %s" % path, privileged=privileged)


def put(server, localpath, remotepath):
    debug("Copying %s to %s:%s" % (localpath.decode('utf-8'), server['name'], remotepath))
    if not os.path.exists(localpath):
        raise Exception("Local path does not exist: %s" % localpath)
    client = connect(server)
    sftp = client.open_sftp()
    if os.path.isfile(localpath):
        if exists(server, remotepath):
            attrs = sftp.stat(remotepath)
            if stat.S_ISDIR(attrs.st_mode):
                remotepath = os.path.join(remotepath, os.path.basename(localpath))
            sftp.put(localpath, remotepath, confirm=True)
            sftp.chmod(remotepath, os.stat(localpath).st_mode)
        else:
            sftp.put(localpath, remotepath, confirm=True)
            sftp.chmod(remotepath, os.stat(localpath).st_mode)
    if os.path.isdir(localpath):
        if exists(server, remotepath):
            rname = os.path.join(remotepath, os.path.basename(localpath))
            mkdir(server, rname)
            put_dir_content(server, localpath, rname)
        else:
            mkdir(server, remotepath)
            put_dir_content(server, localpath, remotepath)


def mktemp(server, template='hwswa2.XXXXX', ftype='d', path='`pwd`'):
    """Creates directory using mktemp and returns its name"""
    sshcmd = 'mktemp '
    if ftype == 'd':
        sshcmd = sshcmd + '-d '
    sshcmd = sshcmd + '-p %s %s' % (path, template)
    tmpdir = get_cmd_out(server, sshcmd, privileged=False)
    if 'tmpdirs' in server:
        server['tmpdirs'].append(tmpdir)
    else:
        server['tmpdirs'] = [tmpdir]
    return tmpdir


def mkdir(server, path):
    client = connect(server)
    sftp = client.open_sftp()
    sftp.mkdir(path)


def exists(server, path):
    client = connect(server)
    sftp = client.open_sftp()
    try:
        sftp.stat(path)
        return True
    except KeyboardInterrupt:
        raise
    except:
        return False


def put_dir_content(server, localdir, remotedir):
    for f in os.listdir(localdir):
        lname = os.path.join(localdir, f)
        rname = os.path.join(remotedir, f)
        if os.path.isfile(lname):
            put(server, lname, rname)
        if os.path.isdir(lname):
            mkdir(server, rname)
            put_dir_content(server, lname, rname)


def write(server, path, data):
    client = connect(server)
    sftp = client.open_sftp()
    file = sftp.open(path, 'w')
    file.write(data)
    file.close()


def bootid(server):
    return get_cmd_out(server, 'cat /proc/sys/kernel/random/boot_id')


def is_it_me(server):
    if hasattr(subprocess, 'check_output'):
        mybootid = subprocess.check_output(['cat', '/proc/sys/kernel/random/boot_id']).strip()
    else:
        mybootid = subprocess.Popen(['cat', '/proc/sys/kernel/random/boot_id'], stdout=subprocess.PIPE).communicate()[
            0].strip()
    server_bootid = bootid(server)
    debug("Is it me? Comparing %s and %s" % (mybootid, server_bootid))
    return mybootid == server_bootid


def check_reboot(server, timeout=300):
    """Reboots the server and checks the time it takes to come up

    Returns number of seconds (int/long) or reason why check is not possible (string)
    """
    if is_it_me(server):
        return "we are running here, no reboot"
    starttime = time.time()
    try:  # reboot will most probably fail with socket.timeout exception
        exec_cmd(server, 'reboot', timeout=3)
    except KeyboardInterrupt:
        raise
    except:  # we are going to ignore this
        pass
    debug("reboot command is sent, now wait till server is down")
    # wait till shutdown:
    if aux.wait_for_not(accessible, [server, True], timeout):
        debug("Server %s is down" % server['name'])
        delta = time.time() - starttime
        # wait till boot
        if aux.wait_for(accessible, [server, True], timeout - delta):
            return int(round(time.time() - starttime))
        else:
            return "server is not accessible after %s seconds" % timeout
    else:
        # check uptime, it can be the case server reboots too fast
        uptime, space, idle = get_cmd_out(server, 'cat /proc/uptime', privileged=False).partition(' ')
        uptime = float(uptime)
        if uptime < timeout + 10:
            return 0
        else:
            return "server does not go to reboot: still accessible after %s seconds" % timeout


def prepare_su(server):
    """Copies su.py to remote server and returns path to containing directory"""
    su_py = os.path.join(config['rscriptdir'], 'bin32', 'su.py')
    pexpect_py = os.path.join(config['rscriptdir'], 'bin32', 'pexpect.py')
    # create directory
    supath = mktemp(server, template='su.XXXX', path='/tmp')
    put(server, pexpect_py, supath)
    put(server, su_py, supath)
    # prepare stdout and stderr fifos:
    exec_cmd(server, "mkfifo %s" % os.path.join(supath, 'stdout'), privileged=False)
    exec_cmd(server, "mkfifo %s" % os.path.join(supath, 'stderr'), privileged=False)
    server['supath'] = supath


def prepare_su_cmd(server, cmd, timeout=ssh_timeout):
    if not ('su' in server['account'] or 'sudo' in server['account']):
        return cmd
    if not 'supath' in server:
        prepare_su(server)
    supath = server['supath']
    su_py = os.path.join(supath, 'su.py')
    stdout_fifo = os.path.join(supath, 'stdout')
    stderr_fifo = os.path.join(supath, 'stderr')
    if 'sudo' in server['account']:
        sutype = 'sudo'
        password = server['account']['sudo']
        if password == None: password = ''
    elif 'su' in server['account']:
        sutype = 'su'
        password = server['account']['su']
    if cmd == 'shell':  # pass window size instead of fifos
        (stdout_fifo, stderr_fifo) = aux.getTerminalSize()
    return 'python %s %s "%s" %s %s "%s" %s' % (su_py,
                                                sutype,
                                                aux.shell_escape(password),
                                                stderr_fifo,
                                                stdout_fifo,
                                                aux.shell_escape(cmd),
                                                timeout)


def cleanup(server):
    if 'sshclient' in server:
        if 'tmpdirs' in server:
            for tmpdir in server['tmpdirs']:
                remove(server, tmpdir, privileged=False)
            del server['tmpdirs']
        if 'supath' in server:
            del server['supath']
        server['sshclient'].close()
        _cleanjump(server)
        debug("Closed connection to server %s" % server['name'])
        del server['sshclient']
        try:
            del server['cmd_prefix']
        except KeyError:
            pass
        try:
            del server['binpath']
        except KeyError:
            pass
        try:
            del server['tmppath']
        except KeyError:
            pass


def _cleanjump(server):
    if 'jumpclient' in server:
        server['jumpclient'].close()
        del server['jumpclient']
    if 'jumpchannel' in server:
        del server['jumpchannel']


def _jump_channel(server):
    if 'gateway' in server:
        hostname = server['address']
        if 'port' in server:
            port = server['port']
        else:
            port = 22
        if 'jumpclient' in server:
            server['jumpclient'].close()
            del server['jumpclient']
        jumphost = aux.get_server(server['gateway'])
        jumpclient = _connect(jumphost)
        if jumpclient is None:
            raise _JumpException(
                "cannot connect to jump host %s: %s" % (server['gateway'], jumphost['lastConnectionError']))
        server['jumpclient'] = jumpclient
        jumptransport = jumpclient.get_transport()
        try:
            jumpchannel = jumptransport.open_channel('direct-tcpip', (hostname, port), ('127.0.0.1', 0))
        except paramiko.ssh_exception.ChannelException, chan_e:
            raise _JumpException("cannot create channel via jump host %s: %s" % (server['gateway'], chan_e))
        server['jumpchannel'] = jumpchannel
        return jumpchannel
    else:
        return None


def pipe_to_channel(channel):
    """redirects sys.stdin,out,err to/from channel"""
    while True:
        try:
            r, w, e = select.select([sys.stdin, channel], [], [])
        except select.error:
            continue
        except Exception, e:
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
    if channel.recv_ready():
        x = channel.recv(1024)
        sys.stdout.write(x)
        sys.stdout.flush()
    if channel.recv_stderr_ready():
        x = channel.recv_stderr(1024)
        sys.stderr.write(x)
        sys.stderr.flush()


def interactive_shell(channel):
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
        pipe_to_channel(channel)
    finally:
        signal.signal(signal.SIGWINCH, old_handler)
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)


def serverd_start(server):
    """Starts serverd.py on server"""
    try:
        client = connect(server)
        serverd_py = os.path.join(config['rscriptdir'], 'bin32', 'serverd.py')
        # remote path
        r_serverd_py = mktemp(server, template='serverd.XXXX', ftype='f', path='/tmp')
        put(server, serverd_py, r_serverd_py)
        if 'su' in server['account'] or 'sudo' in server['account']:
            r_serverd_py_cmd = prepare_su_cmd(server, 'stty -echo; ' + r_serverd_py)
            r_serverd_py_privileged = True
            get_pty = True
        else:
            r_serverd_py_cmd = r_serverd_py
            r_serverd_py_privileged = False
            get_pty = False
        stdin, stdout, stderr = client.exec_command(r_serverd_py_cmd, get_pty=get_pty)
        banner = stdout.readline()
        if not banner.startswith('started_ok'):
            banner = stdout.readline()
        debug('serverd started on %s: %s' % (server['name'], banner))
        server['serverd'] = {'r_serverd_py': r_serverd_py,
                             'privileged': r_serverd_py_privileged,
                             'pty': get_pty,
                             'stdin': stdin,
                             'stdout': stdout,
                             'stderr': stderr}
        return True
    except KeyboardInterrupt:
        raise
    except Exception as e:
        debug('serverd not started: %s' % e.message)
        return False


def serverd_stop(server):
    """Stops serverd.py on server"""
    if 'serverd' in server:
        serverd_cmd(server, 'exit')
        server['serverd']['stdin'].close()
        del server['serverd']


def serverd_cmd(server, cmd):
    """Sends command to serverd.py and returns tuple (status_ok_or_not, result)"""
    if 'serverd' in server:
        stdin = server['serverd']['stdin']
        stdout = server['serverd']['stdout']
        debug('command: ' + cmd)
        stdin.write(cmd + '\n')
        reply = stdout.readline().strip()
        debug('accept reply: ' + reply)
        accepted, space, reason = reply.partition(' ')
        if accepted == 'accepted_ok':
            debug('command accepted on server %s: %s' % (server['name'], reason))
            reply = stdout.readline().strip()
            debug('result reply: ' + reply)
            result_status, space, result = reply.partition(' ')
            if result_status == 'result_ok':
                return True, result
            elif result_status == 'result_notok':
                return False, 'command failed: ' + result
            else:
                return False, 'wrong result message, should start with result_ok/result_notok: ' + reply
        elif accepted == 'accepted_notok':
            return False, 'command not accepted: ' + reason
        else:
            return False, 'wrong accept message, should start with accepted_ok/accepted_notok: ' + reply
    else:
        return False, 'serverd not started'


class _JumpException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

