#!/usr/bin/env python
import os, sys, socket, select, traceback

# array of dicts {socket: socketobject, proto:tcp/udp, address: IP/hostname, port: port number}
sockets = []
commands = {'exit': None, 'listen': None}

def listen(proto, address, port):
  if proto == 'tcp':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  elif proto == 'udp':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((address, port))
  if proto == 'tcp':
    s.listen(1)
  sockets.append({'socket': s, 'proto': proto, 'address': address, 'port': port})

def close_all():
  for i in xrange(len(sockets) - 1, -1, -1):
    sockets[i]['socket'].close()
    del sockets[i]

def find_socket(proto, address, port):
  return next((s for s in sockets if (s['proto'] == proto) and \
                                     (s['address'] == address) and \
                                     (s['port'] == port)), None)

def portrange(ports):
  '''Converts ports range 'port1,port2-port3,port4-port5,...' to list of ports'''
  ps = []
  for prange in ports.split(','):
    start, minus, end = prange.partition('-')
    if minus == '': # single port
      ps.append(int(start))
    else: # port range start-end
      ps.extend(range(int(start),int(end)+1))
  return ps


############### Commands
## each command name should start with 'cmd_' prefix

def cmd_close(proto, address, port):
  '''closes listening socket. usage: close proto address port'''
  s = find_socket(proto, address, int(port))
  if not (s is None):
    s['socket'].close()
    return 'socket closed'
  else:
    return 'such socket not found'

def cmd_closeall():
  '''closeall: close all listening sockets'''
  close_all()
  return 'sockets are closed'

def cmd_exit():
  '''exit: command to close all listening sockets and quit server'''
  close_all()
  print 'finished_ok'
  sys.exit()

def cmd_listen(proto, address, ports):
  '''usage: listen proto address ports. Ports arg example 1050,1100-1200,2024,2040-2056'''
  for p in portrange(ports):
    listen(proto, address, p)
  return "sockets are ready"

def cmd_receive(proto, address, ports):
  socks = []
  for p in portrange(ports):
    s = find_socket(proto, address, p)
    if not (s is None):
      socks.append(s['socket'])
  read, write, error = select.select(socks,[],[], 2)
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
  '''usage: help command'''
  if not (command is None):
    return commands[command].__doc__
  else:
    return 'use: help command. possible commands: %s' % ', '.join(commands.keys())

#commands = dict((k[4:], v) for k, v in slice(globals(), 'cmd_'))
commands = dict((k[4:],globals()[k]) for k in globals() if k.startswith('cmd_'))

############### MAIN
if __name__ == '__main__':

  print 'started_ok possible commands: %s' % ', '.join(commands.keys())
 
  line = ' '
  while(line):
    line = sys.stdin.readline()
    command, space, rest = line.strip().partition(' ')
    if (command == ''):
      continue
    args = rest.split()
    cmd_func = 'cmd_' + command
    if command in commands:
      print 'accepted_ok command %s with args %s' % (command, args)
      try:
        result=commands[command](*args)
        print 'result_ok %s' % result
      except SystemExit:
        close_all()
        break 
      except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print "result_notok Exception %s: %s" % (traceback.format_exception_only(exc_type, exc_obj)[0], traceback.format_tb(exc_tb))
    else:
      print 'accepted_notok no such command %s' % command
