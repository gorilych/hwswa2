# !/usr/bin/env python
import pexpect
import sys
import os
import threading
import struct
import signal
import fcntl
import termios

sutype = sys.argv[1]
password = sys.argv[2]
stderr_fifo = sys.argv[3]
stdout_fifo = sys.argv[4]
command = sys.argv[5]
timeout = int(sys.argv[6])


def read_from_to(fifo_name, fout):
    fifo = os.fdopen(os.open(fifo_name, os.O_RDONLY), 'r')
    while True:
        line = fifo.readline()
        if not line: break
        fout.write(line)
        fout.flush()
    fifo.close()


def term_winsz():
    """Return terminal window size (height, width)"""
    winsz_fmt = "HHHH"
    winsz_arg = " " * struct.calcsize(winsz_fmt)
    if not sys.stdin.isatty():
        #raise type("NotConnectToTTYDevice", (Exception,), {})()
        return (25, 80)
    return struct.unpack(winsz_fmt, fcntl.ioctl(sys.stdin, termios.TIOCGWINSZ, winsz_arg))[:2]


if command == 'shell':
    if password == '' and sutype == 'sudo':
        sucmd = 'sudo'
        suargs = ['su', '-']
    if not password == '':
        if sutype == 'su':
            sucmd = 'su'
        if sutype == 'su':
            sucmd = 'su'
            suargs = ['-']
        elif sutype == 'sudo':
            sucmd = 'sudo'
            suargs = ['-p', 'password: ', '--', 'su', '-']
    old_handler = signal.getsignal(signal.SIGWINCH)
    try:
        child = None

        def on_win_resize(signum, frame):
            if child is not None:
                child.setwinsize(*term_winsz())

        signal.signal(signal.SIGWINCH, on_win_resize)
        child = pexpect.spawn(sucmd, suargs, timeout=timeout)
        child.setwinsize(*term_winsz())
        if not password == '':
            child.expect_exact('assword: ')
            child.sendline(password)
        child.interact()
    finally:
        signal.signal(signal.SIGWINCH, old_handler)
else:
    if password == '' and sutype == 'sudo':
        sucmd = 'sudo'
        suargs = ['su']
    if not password == '':
        if sutype == 'sudo':
            sucmd = 'sudo'
            suargs = ['-p', 'password: ', 'su']
        if sutype == 'su':
            sucmd = 'su'
            suargs = []
    # cleanup cached credentials
    if sutype == 'sudo':
        child = pexpect.spawn('sudo -k')
        child.close()

    if sys.stdin.isatty():
        suargs += ['-', '-c', '%s' % command]
    else:
        suargs += ['-', '-c', '{ %s; } 1>%s 2>%s' % (command, stdout_fifo, stderr_fifo)]
        stdout_th = threading.Thread(name='stdout', target=read_from_to, args=(stdout_fifo, sys.stdout))
        stderr_th = threading.Thread(name='stderr', target=read_from_to, args=(stderr_fifo, sys.stderr))
        stdout_th.start()
        stderr_th.start()

    child = pexpect.spawn(sucmd, suargs)
    if not password == '':
        child.expect('assword: ')
        child.sendline(password)

    if sys.stdin.isatty():
        old_handler = signal.getsignal(signal.SIGWINCH)
        try:
            def on_win_resize(signum, frame):
                child.setwinsize(*term_winsz())

            signal.signal(signal.SIGWINCH, on_win_resize)
            child.setwinsize(*term_winsz())
            child.interact()
        finally:
            signal.signal(signal.SIGWINCH, old_handler)
    else:
        child.expect_exact(pexpect.EOF)
        child.close()
        stdout_th.join()
        stderr_th.join()

    exitcode = child.exitstatus
    sys.exit(child.exitstatus)

