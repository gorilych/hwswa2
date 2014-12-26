#!/usr/bin/env python
import os
import sys
import socket
import select
import traceback
import Queue
import threading
import time
import base64
import pty
import shlex
import tty
import signal
import struct
import fcntl
import termios
import errno
from subprocess import Popen, PIPE


# Debugging routines
DEBUG=False

def debug(msg):
    global DEBUG
    global DEBUGFILE
    if DEBUG:
        stack = traceback.extract_stack()
        del stack[-1]
        stackstr = ''
        for s in stack:
            stackstr += s[2] + '(%s):' % s[1]
        os.write(DEBUGFILE, stackstr + ' ' + str(msg) + '\n')


if DEBUG:
    DEBUGFILE = os.open('/tmp/serverd.' + str(os.getpid()) + '.log', os.O_RDWR | os.O_CREAT)
    debug('started')


class Unbuffered:
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        self.stream.write(data)
        self.stream.flush()

    def __getattr__(self, attr):
        return getattr(self.stream, attr)


sys.stdout = Unbuffered(sys.stdout)

# array of dicts {socket: socketobject, proto:tcp/udp, address: IP/hostname, port: port number}
sockets = []

def count_alive_threads(name):
    c = 0
    for th in threading.enumerate():
        if name == th.name and th.isAlive():
            c += 1
    return c


def check(address, ports):
    """Checks if address:port is listened"""
    PROC_TCP = "/proc/net/tcp"
    STATE = {'01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
             '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
             '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
             '0A': 'LISTEN', '0B': 'CLOSING'}

    def _load():
        """ Read the table of tcp connections & remove header  """
        f = open(PROC_TCP, 'r')
        content = f.readlines()
        f.close()
        content.pop(0)
        return content

    def _hex2dec(s):
        return str(int(s, 16))

    def _ip(s):
        ip = [(_hex2dec(s[6:8])), (_hex2dec(s[4:6])), (_hex2dec(s[2:4])), (_hex2dec(s[0:2]))]
        return '.'.join(ip)

    def _convert_ip_port(array):
        host, port = array.split(':')
        return _ip(host), int(_hex2dec(port))

    def _get_list_listening():
        l = []
        content = _load()
        for line in content:
            line_array = line.split()
            state = STATE[line_array[3]]
            if state == 'LISTEN':
                l.append(_convert_ip_port(line_array[1]))
        return l

    # ports which are listen on address
    lp = (p for a, p in _get_list_listening() if (a == address) or (a == '0.0.0.0'))
    result = []
    for p in lp:
        if p in ports:
            result.append(p)
    return result


def listen(proto, address, port):
    if proto == 'tcp':
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif proto == 'udp':
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((address, port))
        if proto == 'tcp':
            s.listen(1)
    except:  # let's assume it is already listened
        return
    sockets.append({'socket': s, 'proto': proto, 'address': address, 'port': port})


def send(proto, address, port, message=None, timeout=1):
    if proto == 'tcp':
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif proto == 'udp':
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((address, port))
        if message is None:
            message = 'from' + s.getsockname()[0]
        s.sendall(message)
        s.close()
        return True
    except:
        return False


def close(proto, address, port):
    # pair = (index, socket)
    pair = find_socket(proto, address, port)
    if not (pair is None):
        pair[1]['socket'].close()
        del sockets[pair[0]]


def close_all():
    for i in xrange(len(sockets) - 1, -1, -1):
        sockets[i]['socket'].close()
        del sockets[i]


def find_socket(proto, address, port):
    for (i, s) in enumerate(sockets):
        if (s['proto'] == proto) and \
                (s['address'] == address) and \
                (s['port'] == port):
            return (i, s)
    return None


def portrange(ports):
    """Converts ports range 'port1,port2-port3,port4-port5,...' to list of ports"""
    ps = []
    for prange in ports.split(','):
        if prange.find('-') == -1:  # single port
            ps.append(int(prange))
        else:  # port range start-end
            start, end = prange.split('-')
            ps.extend(range(int(start), int(end) + 1))
    return ps


def packports(ports):
    """Converts list ports to port range string, f.e. [1,2,3,5,7,8,9] -> 1-3,5,7-9"""
    if len(ports) == 0:
        return ''
    ps = sorted(ports)
    previous = start = ps[0]
    result = '%s' % start
    for p in ps[1:]:
        if p == previous + 1:
            previous = p
        else:
            if start == previous:
                result = result + ',%s' % p
            else:
                result = result + '-%s,%s' % (previous, p)
            start = previous = p
    if previous > start:
        result = result + '-%s' % previous
    return result


def spawn(cmd):
    """Create new process with pty attached
    Return child pid, pty and stderr
    """
    debug("cmd: %s" % cmd)
    if not isinstance(cmd, tuple) and not isinstance(cmd, list):
        argv = shlex.split(cmd)
    else:
        argv = cmd
    stderrout, stderrin = os.pipe()
    pid, fd = pty.fork()
    if pid == 0: # child
        os.close(stderrout)
        os.dup2(stderrin, 2)
        if stderrin > 2:
            os.close(stderrin)
        os.execlp(argv[0], *argv)
    else:
        os.close(stderrin)
        return pid, fd, stderrout


def wait_and_send(fd, expect, send=None, timeout=5, stderr=None):
    """Wait for a expected line and send a string"""
    buf=""
    fds = [fd]
    buf = {fd: ''}
    if stderr:
        fds.append(stderr)
        buf[stderr] = ''
    while True:
        if not fds:
            debug("did not find %s" % expect)
            return False
        rfds, wfds, xfds = select.select(fds, [], [], timeout)
        if not rfds:
            debug("timeout, did not find %s" % expect)
            return False
        for d in rfds:
            data = os.read(d, 1024)
            if not data: # reached EOF
                fds.remove(d)
            else:
                buf[d] += data
                debug("read from %s: %s" % (d, data))
                if buf[d].find(expect) > -1:
                    debug("found %s" % expect)
                    if send:
                        debug("will send: %s" % send)
                        write(fd, send)
                        debug("just sent: %s" % send)
                    #os.fsync(fd)
                    return True


def interact(fd, stderr=None):
    """Interact with pty"""
    ## window size change handler
    debug("started")
    def change_winsz(signum, frame):
        winsz_fmt = "HHHH"
        winsz_arg = " " * struct.calcsize(winsz_fmt)
        fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ, winsz_arg)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsz_arg)
    old_handler = signal.signal(signal.SIGWINCH, change_winsz)
    try:
        mode = termios.tcgetattr(sys.stdin)
        tty.setraw(sys.stdin, termios.TCSANOW)
        restore = 1
    except tty.error:
        restore = 0
    debug("stdin: %s" % sys.stdin.fileno())
    debug("child tty: %s" % fd)
    fds = [fd, sys.stdin.fileno()]
    if stderr:
        fds.append(stderr)
        debug("child stderr: %s" % stderr)
    debug("before loop")
    try:
        try:
            while True:
                if not fds:
                    break
                try:
                    rfds, wfds, xfds = select.select(fds, [], [])
                except select.error, se:
                    if se[0] == errno.EINTR:
                        continue # Interrupted system call
                    else:
                        raise se
                for i, o in [[fd, sys.stdout.fileno()],
                             [stderr, sys.stderr.fileno()],
                             [sys.stdin.fileno(), fd]]:
                    if i in rfds:
                        data = os.read(i, 1024)
                        if not data:  # Reached EOF.
                            fds.remove(i)
                            debug('EOF %s' % i)
                        else:
                            debug('read from %s: %s' % (i, data))
                            os.write(o, data)
        except (IOError, OSError):
            debug("IOError/OSError")
            pass
    finally:
        debug("finished")
        if restore:
            tty.tcsetattr(sys.stdin, tty.TCSAFLUSH, mode)
        signal.signal(signal.SIGWINCH, old_handler)
        os.close(fd)


def write(fd, data):
    while data != '':
        n = os.write(fd, data)
        data = data[n:]

def spawn_expect_send_interact_exit(cmd, expect_send=None):
    """Spawn cmd with pty and interact 

    expect_send = [('expect1', 'send1'), ('expect2', 'send2') ...]
    """
    status = 0
    if not isinstance(cmd, tuple):
        cmd = shlex.split(cmd)
    if not expect_send:
        expect_send = []
    child_pid, child_pty, child_stderr = spawn(cmd)
    for e_s in expect_send:
        expect, send = e_s
        if not wait_and_send(child_pty, expect, send, stderr=child_stderr):
            #TODO kill child_pid, if needed
            msg = "result_notok failed wait '%s' and send '%s'" % (expect, send)
            print(msg)
            debug("sent: %s" % msg)
            return
    # disable echo to prevent double echo from master pty and child pty
    modenoecho = termios.tcgetattr(sys.stdin)
    modenoecho[3] = modenoecho[3] &  ~termios.ECHO
    termios.tcsetattr(sys.stdin, termios.TCSANOW, modenoecho)
    msg = "result_ok spawned"
    print(msg)
    debug("sent: %s" % msg)
    interact(child_pty, child_stderr)
    status = os.waitpid(child_pid,0) # returns (pid, exit_status << 8 + signal)
    sys.exit(status[1] >> 8)

        
def elevate(cmd_fmt, expect=None, send=None):
    """Elevate privileges with cmd_fmt.

    {serverd} in <command format> is replaced by path to serverd.py.
    Example elevate('sudo -u admin -p prmpt {serverd}s', 'prmpt', 'secret')
    """
    global BANNER
    serverd_path = os.path.realpath(__file__)
    cmd = cmd_fmt.replace('{serverd}', serverd_path)
    expect_send = [(expect, send), (BANNER + '\r\n', None)]
    spawn_expect_send_interact_exit(cmd, expect_send)


def shell(sh=None):
    if not sh:
        sh='/bin/bash'
    exec_i(sh)


def exec_i(cmd):
    if not isinstance(cmd, tuple):
        cmd = shlex.split(cmd)
    p = Popen(cmd, shell=False, stdin=None, stdout=None, stderr=None, close_fds=False)
    sys.exit(p.wait())


##### Machinery for parallel cmd execution
# commands dict, mapping cmd id to CMD object
cmds = {}

def exec_cmd(cmd, input_data, timeout):
    c = CMD(cmd, input_data, timeout)
    c.start()
    return c.wait()


def schedule_cmd(cmd, input_data, timeout):
    """Schedule cmd for execution

    Return cmd_id
    """
    global cmds
    # generate cmd_id
    if not hasattr(schedule_cmd, "cmd_id"):
        schedule_cmd.cmd_id = 0  # it doesn't exist yet, so initialize it
    schedule_cmd.cmd_id += 1
    cmd_id = schedule_cmd.cmd_id
    c = CMD(cmd, input_data, timeout)
    c.start()
    cmds[cmd_id] = c
    return cmd_id


def get_cmd_state(cmd_id):
    global cmds
    if not cmd_id in cmds:
        return None
    return cmds[cmd_id].state


def get_cmd_result(cmd_id):
    global cmds
    if not cmd_id in cmds:
        return None
    return cmds[cmd_id].wait()


def cancel_cmd(cmd_id):
    global cmds
    if not cmd_id in cmds:
        return None
    cmds[cmd_id].cancel()
    return 'cancelled'


class CMD(object):

    def __init__(self, cmd, input_data=None, timeout=None): # timeout=0 means no timeout
        self._cmd = cmd
        self._input_data = input_data
        self._timeout = timeout or 30
        self._timed_out = False
        self._exec_th = None # thread which controls execution
        self._to_th = None # timeout thread
        self.state = 'inited'
        self.cancelled = False
        self.succeeded = None
        self.returncode = None
        self.stdout = ''
        self.stderr = ''
        self.reason = None

    def __del__(self):
        try:
            self.cancel()
        except:
            pass

    def _exec_th_func(self):
        self.state = 'running'
        # start process
        try:
            try:
                p = Popen(shlex.split(self._cmd), shell=False,
                          stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
            except Exception, e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                self.reason = "Exception in Popen %s: %s" % \
                    (traceback.format_exception_only(exc_type, exc_obj)[0],
                           traceback.format_tb(exc_tb))
                self.succeeded = False
            else:
                self._process = p
                input_data = self._input_data
                rlist = [p.stdout, p.stderr]
                wlist = [p.stdin]
                # loop input,read until process finishes or time goes out or cancelled
                while True:
                    if self.cancelled:
                        self.succeeded = False
                        # terminate process
                        try:
                            p.terminate() # give it a chance to stop gracefully
                            time.sleep(0.1) # give it some time to terminate
                            p.kill() # kill, just in case it ignored SIGTERM
                        except OSError: # can raise if process already exited
                            pass
                        break
                    if not input_data:
                        p.stdin.close()
                        wlist = []
                        #  read or write
                    rfds, wfds, xfds = select.select(rlist, wlist, [], 0.01)
                    if p.stdin in wfds:
                        n = os.write(p.stdin.fileno(), input_data)
                        input_data = input_data[n:]
                    if p.stdout in rfds:
                        self.stdout += os.read(p.stdout.fileno(), 1024)
                    if p.stderr in rfds:
                        self.stderr += os.read(p.stderr.fileno(), 1024)
                    if p.poll() is not None: # process has finished
                        self.succeeded = True
                        break
                #read buffered stdout/stderr
                rfds, wfds, xfds = select.select(rlist, [], [], 0.01)
                if p.stdout in rfds:
                    self.stdout += p.stdout.read()
                if p.stderr in rfds:
                    self.stderr += p.stderr.read()
                p.stdin.close(); p.stdout.close(); p.stderr.close()
                self.returncode = p.poll()
        finally:
            # stop timeout thread
            if self._to_th and self._to_th.isAlive():
                self._to_th.cancel()
            self.state = 'finished'

    def _to_th_func(self):
        self.reason = 'timeout'
        self._timed_out = True
        self.cancel()

    def start(self):
        # start execution thread
        self._exec_th = threading.Thread(target=self._exec_th_func, name="cmd_exec")
        self._exec_th.start()
        # start timer thread
        if self._timeout > 0:
            self._to_th = threading.Timer(self._timeout, self._to_th_func)
            self._to_th.start()

    def cancel(self):
        # stop timeout thread
        if self._to_th and self._to_th.isAlive():
            self._to_th.cancel()
        if self.reason is None:
            self.reason = 'cancelled'
        self.cancelled = True
        # wait for execution thread
        if self._exec_th:
            self._exec_th.join()

    def finished(self):
        return self.state == 'finished'

    def wait(self, check_interval=0.01):
        """Block till execution is is finished"""
        if self.state == 'inited':
            raise CMDException("not started")
        while not self.finished():
            time.sleep(check_interval)
        return self.succeeded, self.reason, self.returncode, self.stdout, self.stderr


class CMDException(Exception):
    """Base class for CMD exceptions"""
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


############### Commands
## each command name should start with 'cmd_' prefix

def cmd_check(address, ports):
    """checks if there are services listening on ports. usage: check address ports"""
    return True, 'ports:' + packports(check(address, portrange(ports)))


def cmd_close(proto, address, ports):
    """closes listening sockets. usage: close proto address ports"""
    for p in portrange(ports):
        close(proto, address, p)
    return True, 'socket(s) closed'


def cmd_closeall():
    """closeall: close all listening sockets"""
    close_all()
    return True, 'sockets are closed'


def cmd_exit():
    """exit: command to close all listening sockets and quit server"""
    close_all()
    sys.exit()


def cmd_listen(proto, address, ports):
    """usage: listen proto address ports. Ports arg example 1050,1100-1200,2024,2040-2056"""
    for p in portrange(ports):
        listen(proto, address, p)
    return True, "sockets are ready"


def cmd_receive(proto, address, ports):
    """usage: receive proto address ports"""
    socks = []
    for p in portrange(ports):
        # pair = (index, socket)
        pair = find_socket(proto, address, p)
        if not (pair is None):
            s = pair[1]
            socks.append(s['socket'])
    read, write, error = select.select(socks, [], [], 2)
    result = ''
    for s in read:
        if proto == 'tcp':
            conn, address = s.accept()
            f = conn.makefile()
            message = f.readline()
            conn.close()
            result = result + '%s:%s:%s:%s ' % (s.getsockname()[1], message, address[0], address[1])
        elif proto == 'udp':
            message, address = s.recvfrom(1024)
            result = result + '%s:%s:%s:%s ' % (s.getsockname()[1], message, address[0], address[1])
    if result == '':
        result = 'no messages'
    return True, result


def cmd_help(command=None):
    """usage: help command"""
    if command:
        return True, commands[command].__doc__
    else:
        return True, 'use: help command. possible commands: %s' % ', '.join(commands.keys())


def cmd_send(proto, address, ports, timeout=1):
    """usage: send proto address ports [timeout]. Ports arg example 1050,1100-1200,2024,2040-2056"""
    portsOKQ = Queue.Queue()
    portsNOKQ = Queue.Queue()

    timeout=float(timeout)
    def thread_send(proto, address, port, portsOKQ, portsNOKQ):
        if send(proto, address, port, timeout=timeout):
            portsOKQ.put(port)
        else:
            portsNOKQ.put(port)

    for port in portrange(ports):
        th = threading.Thread(target=thread_send, name="send", args=(proto, address, port, portsOKQ, portsNOKQ))
        th.start()

    portsOK = []
    portsNOK = []
    while count_alive_threads("send") > 0:
        while not portsOKQ.empty():
            portsOK.append(portsOKQ.get())
        while not portsNOKQ.empty():
            portsNOK.append(portsNOKQ.get())
        time.sleep(0.1)

    while not portsOKQ.empty():
        portsOK.append(portsOKQ.get())
    while not portsNOKQ.empty():
        portsNOK.append(portsNOKQ.get())

    return True, "OK:%s NOK:%s" % (packports(portsOK), packports(portsNOK))


def cmd_elevate(cmd_fmt, expect=None, send=None):
    """Elevate privileges.

    Usage: elevate <command format> [<expect> <send>]. 
    {serverd} in <command format> is replaced by path to serverd.py.
    Example: elevate 'sudo -u admin -p prmpt {serverd}' 'prmpt' 'secret'
    """
    elevate(cmd_fmt, expect, send)


def cmd_elevate_su(password):
    """Elevate root privileges with su.

    Usage: elevate_su <password>.
    """
    cmd_fmt = "su --login root --shell {serverd}"
    expect = ":"
    send = password + "\n"
    elevate(cmd_fmt, expect, send)


def cmd_elevate_sudo(password=None):
    """Elevate root privileges with sudo.

    Usage: elevate_sudo [<password>].
    """
    if password is None:
        elevate("sudo {serverd}")
    else:
        cmd_fmt = "sudo --reset-timestamp --prompt=password: {serverd}"
        expect = "password:"
        send = password + "\n"
        elevate(cmd_fmt, expect, send)


def cmd_shell(sh=None):
    """Run shell. Usage: shell [sh/bash/zsh/whatever]"""
    shell(sh)


def cmd_exec_i(*cmd):
    """Execute command interactively and exit. Usage: exec_i cmd
    
    Usage: exec_i cmd arg1 arg2 ..
    """
    exec_i(cmd)


def cmd_cmd_exec(cmd, input_data=None, timeout=None):
    """Execute command with timeout

    Usage: cmd_exec 'cmd arg1 arg2 ...' [<base64 encoded input> [<timeout in seconds>]]
    Return "[reason:<reason of failure>] returncode:<num> stdout:<base64encoded> stderr:<base64encoded>"
    """
    if input_data:
        i = base64.b64decode(input_data)
    else:
        i = None
    if timeout is not None:
        timeout = float(timeout)
    status, reason, retcode, stdout, stderr = exec_cmd(cmd, i, timeout)
    if status:
        return True, "returncode:%s stdout:%s stderr:%s" % (
            retcode, base64.b64encode(stdout), base64.b64encode(stderr))
    else:
        return False, "reason:%s returncode:%s stdout:%s stderr:%s" % (
            base64.b64encode(reason), retcode, base64.b64encode(stdout),
            base64.b64encode(stderr))


def cmd_cmd_schedule(cmd, input_data=None, timeout=None):
    """Schedule command execution

    Usage: cmd_schedule 'cmd arg1 arg2 ...' [<base64 encoded input> [<timeout in seconds>]]
    Return "cmd_id:<num>"
    """
    if input_data:
        i = base64.b64decode(input_data)
    else:
        i = None
    if timeout:
        timeout = float(timeout)
    return True, "cmd_id:%s" % schedule_cmd(cmd, i, timeout)


def cmd_cmd_state(cmd_id):
    """Get state of scheduled command

    Usage: cmd_state <id>
    Return state
    Or return "no such command"
    """
    state = get_cmd_state(int(cmd_id))
    if state is None:
        return False, 'no such command'
    else:
        return True, state


def cmd_cmd_result(cmd_id):
    """Get result of scheduled command execution

    Usage: cmd_result <id>
    Return "status:True|False reason:<reason of failure> returncode:<num> stdout:<base64encoded> stderr:<base64encoded>"
    Or return "no such command"
    """
    result = get_cmd_result(int(cmd_id))
    if result is None:
        return False, 'no such command'
    else:
        status, reason, retcode, stdout, stderr = result
        if status:
            return True, "returncode:%s stdout:%s stderr:%s" % (
                retcode, base64.b64encode(stdout), base64.b64encode(stderr))
        else:
            return False, "reason:%s returncode:%s stdout:%s stderr:%s" % (
                base64.b64encode(reason), retcode, base64.b64encode(stdout),
                base64.b64encode(stderr))


def cmd_cmd_cancel(cmd_id):
    """Cancel scheduled command

    Usage: cmd_cancel <id>
    Can return "no such command"
    """
    state = cancel_cmd(int(cmd_id))
    if state is None:
        return False, 'no such command'
    else:
        return True, state

############### MAIN

if __name__ == '__main__':
    returncode = 0
    commands = dict((k[4:], globals()[k]) for k in globals() if k.startswith('cmd_'))
    BANNER = 'started_ok possible commands: %s' % ', '.join(sorted(commands.keys()))
    print(BANNER)
    debug(BANNER)
    line = ' '
    while (line):
        line = sys.stdin.readline()
        debug("read: %s" % line)
        try:
            argv = shlex.split(line)
        except ValueError, e:
            msg = 'accepted_notok cannot parse line: %s' % e.message
            print msg
            debug('sent: %s' % msg)
            continue
        if not argv: # empty line
            continue
        command = argv[0]
        args = argv[1:]
        if command in commands:
            msg = 'accepted_ok command %s with args %s' % (command, args)
            print msg
            debug('sent: %s' % msg)
            try:
                status, result = commands[command](*args)
                if status:
                    msg = 'result_ok %s' % result
                    print msg
                    debug('sent: %s' % msg)
                else:
                    msg = 'result_notok %s' % result
                    print msg
                    debug('sent: %s' % msg)
            except SystemExit, e:
                if e.args:
                    returncode = e.args[0]
                close_all()
                break
            except Exception, e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                msg = "result_notok Exception %s: %s" % \
                      (traceback.format_exception_only(exc_type, exc_obj)[0],
                       traceback.format_tb(exc_tb))
                print msg
                debug('sent: %s' % msg)
        else:
            msg = 'accepted_notok no such command %s' % command
            print msg
            debug('sent: %s' % msg)
    close_all()
    debug("will exit with %s" % returncode)
    os._exit(returncode)
