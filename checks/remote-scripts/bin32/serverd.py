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
        if name == th.name and th.is_alive():
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
    Return child pid and pty
    """
    argv = shlex.split(cmd)
    pid, fd = pty.fork()
    if pid == 0: # child
        os.execlp(argv[0], *argv)
    else:
        return pid, fd


def wait_and_send(fd, expect, send=None, timeout=5):
    """Wait for a expected line and send a string"""
    buf=""
    while True:
        rfds, wfds, xfds = select.select([fd], [], [], timeout)
        if not rfds:
            print("result_notok: %s not found" % expect)
            return False
        data = os.read(fd, 1024)
        if not data: # reached EOF
            print("result_notok: %s not found" % expect)
            return False
        buf += data
        if buf.find(expect) > -1:
            if send:
                write(fd, send)
            #os.fsync(fd)
            return True


def interact(fd):
    """Interact with pty"""
    ## window size change handler
    def change_winsz(signum, frame):
        winsz_fmt = "HHHH"
        winsz_arg = " " * struct.calcsize(winsz_fmt)
        fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ, winsz_arg)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsz_arg)
    old_handler = signal.signal(signal.SIGWINCH, change_winsz)
    try:
        mode = tty.tcgetattr(sys.stdin)
        tty.setraw(sys.stdin)
        restore = 1
    except tty.error:
        restore = 0
    fds = [fd, sys.stdin]
    try:
        while True:
            if not fds:
                break
            try:
                rfds, wfds, xfds = select.select(fds, [], [])
            except select.error as se:
                if se[0] == errno.EINTR:
                    continue # Interrupted system call
                else:
                    raise
            if fd in rfds:
                data = os.read(fd, 1024)
                if not data:  # Reached EOF.
                    fds.remove(fd)
                else:
                    os.write(sys.stdout.fileno(), data)
            if sys.stdin in rfds:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    fds.remove(sys.stdin)
                else:
                    write(fd, data)
    except (IOError, OSError):
        pass
    finally:
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
    if not expect_send:
        expect_send = []
    child_pid, child_pty = spawn(cmd)
    for e_s in expect_send:
        expect, send = e_s
        if not wait_and_send(child_pty, expect, send):
            print("result_notok failed wait '%s' and send '%s'" % (expect, send))
            return
    print("result_ok spawned")
    interact(child_pty)
    status = os.waitpid(child_pid,0) # returns (pid, exit_status << 8 + signal)
    sys.exit(status[1] >> 8)

        
def elevate(cmd_fmt, expect=None, send=None):
    """Elevate privileges with cmd_fmt.

    {serverd} in <command format> is replaced by path to serverd.py.
    Example elevate('sudo -u admin -p prmpt {serverd}s', 'prmpt', 'secret')
    """
    global BANNER
    serverd_path = os.path.realpath(__file__)
    cmd = cmd_fmt.format(**{'serverd': serverd_path})
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
    All arguments should be encoded with 64base.encodestring(), to allow special characters.
    {serverd} in <command format> is replaced by path to serverd.py.
    Example (with decoded strings): elevate 'sudo -u admin -p prmpt {serverd}s' 'prmpt' 'secret'
    """
    cmd_fmt = base64.decodestring(cmd_fmt)
    if expect is not None:
        expect = base64.decodestring(expect)
        send = base64.decodestring(send)
    elevate(cmd_fmt, expect, send)


def cmd_elevate_su(password):
    """Elevate root privileges with su.

    Usage: elevate_su <password>.
    Password should be encoded with 64base.encodestring(), to allow special characters.
    """
    cmd_fmt = "su --login root --shell {serverd}"
    expect = ":"
    send = base64.decodestring(password) + "\n"
    elevate(cmd_fmt, expect, send)


def cmd_elevate_sudo(password=None):
    """Elevate root privileges with sudo.

    Usage: elevate_sudo [<password>].
    Password should be encoded with 64base.encodestring(), to allow special characters.
    """
    if password is None:
        elevate("sudo {serverd}")
    else:
        cmd_fmt = "sudo --reset-timestamp --prompt=password: {serverd}"
        expect = "password:"
        send = base64.decodestring(password) + "\n"
        elevate(cmd_fmt, expect, send)


def cmd_shell(sh=None):
    """Run shell. Usage: shell [sh/bash/zsh/whatever]"""
    shell(sh)


def cmd_exec_i(*cmd):
    """Execute command interactively and exit. Usage: exec_i cmd
    
    Usage: exec_i cmd arg1 arg2 ..
    """
    exec_i(cmd)


############### MAIN

if __name__ == '__main__':
    returncode = 0
    commands = dict((k[4:], globals()[k]) for k in globals() if k.startswith('cmd_'))
    BANNER = 'started_ok possible commands: %s' % ', '.join(sorted(commands.keys()))
    print(BANNER)
    line = ' '
    while (line):
        line = sys.stdin.readline()
        try:
            argv = shlex.split(line)
        except ValueError as e:
            print 'accepted_notok cannot parse line: %s' % e.message
            continue
        if not argv: # empty line
            continue
        command = argv[0]
        args = argv[1:]
        if command in commands:
            print 'accepted_ok command %s with args %s' % (command, args)
            try:
                status, result = commands[command](*args)
                if status:
                    print 'result_ok %s' % result
                else:
                    print 'result_nok %s' % result
            except SystemExit as e:
                returncode = e.args[0]
                close_all()
                break
            except Exception, e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                print "result_notok Exception %s: %s" % \
                      (traceback.format_exception_only(exc_type, exc_obj)[0],
                       traceback.format_tb(exc_tb))
        else:
            print 'accepted_notok no such command %s' % command
    close_all()
    os._exit(returncode)
