#!/usr/bin/env python
import os, sys, socket, select, traceback, Queue, threading, time


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


############### Commands
## each command name should start with 'cmd_' prefix

def cmd_check(address, ports):
    """checks if there are services listening on ports. usage: check address ports"""
    return 'ports:' + packports(check(address, portrange(ports)))


def cmd_close(proto, address, ports):
    """closes listening sockets. usage: close proto address ports"""
    for p in portrange(ports):
        close(proto, address, p)
    return 'socket(s) closed'


def cmd_closeall():
    """closeall: close all listening sockets"""
    close_all()
    return 'sockets are closed'


def cmd_exit():
    """exit: command to close all listening sockets and quit server"""
    close_all()
    sys.exit()


def cmd_listen(proto, address, ports):
    """usage: listen proto address ports. Ports arg example 1050,1100-1200,2024,2040-2056"""
    for p in portrange(ports):
        listen(proto, address, p)
    return "sockets are ready"


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
    return result


def cmd_help(command=None):
    """usage: help command"""
    if not (command is None):
        return commands[command].__doc__
    else:
        return 'use: help command. possible commands: %s' % ', '.join(commands.keys())


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
        th = threading.Thread(target=thread_send, args=(proto, address, port, portsOKQ, portsNOKQ))
        th.start()

    portsOK = []
    portsNOK = []
    while threading.activeCount() > 1:
        while not portsOKQ.empty():
            portsOK.append(portsOKQ.get())
        while not portsNOKQ.empty():
            portsNOK.append(portsNOKQ.get())
        time.sleep(0.1)

    while not portsOKQ.empty():
        portsOK.append(portsOKQ.get())
    while not portsNOKQ.empty():
        portsNOK.append(portsNOKQ.get())

    return "OK:%s NOK:%s" % (packports(portsOK), packports(portsNOK))

############### MAIN
if __name__ == '__main__':
    commands = dict((k[4:], globals()[k]) for k in globals() if k.startswith('cmd_'))
    print 'started_ok possible commands: %s' % ', '.join(commands.keys())

    line = ' '
    while (line):
        line = sys.stdin.readline()
        commandline = line.strip()
        if commandline.find(' ') == -1:  # no args
            command = commandline
            rest = ''
        else:
            command, rest = line.strip().split(None, 1)
        if (command == ''):
            continue
        args = rest.split()
        if command in commands:
            print 'accepted_ok command %s with args %s' % (command, args)
            try:
                result = commands[command](*args)
                print 'result_ok %s' % result
            except SystemExit:
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
