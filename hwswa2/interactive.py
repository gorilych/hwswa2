# This file was copied from paramiko and adjusted (basically removals)

import os, sys, socket, termios, tty, select

def interactive_shell(chan):
 
  oldtty = termios.tcgetattr(sys.stdin)
  try:
    tty.setraw(sys.stdin.fileno())
    tty.setcbreak(sys.stdin.fileno())
    chan.settimeout(0.0)

    while True:
      try:
        r, w, e = select.select([chan, sys.stdin], [], [])
      except select.error:
        continue
      except Exception, e:
        raise e

      if chan in r:
        try:
          x = chan.recv(1024)
          if len(x) == 0:
            break
          sys.stdout.write(x)
          sys.stdout.flush()
        except socket.timeout:
          pass
      if sys.stdin in r:
        x = os.read(sys.stdin.fileno(), 1)
        if len(x) == 0:
          break
        chan.send(x)

  finally:
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)

