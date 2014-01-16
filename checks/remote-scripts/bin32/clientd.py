#!/usr/bin/env python
import os, sys, socket, select, traceback

def send(proto, address, port, message=None, timeout=1):
  if proto == 'tcp':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  elif proto == 'udp':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.settimeout(timeout)
  if message is None:
    message = 'from' + s.getsockname()[0]
  try:
    s.connect((address, port))
    s.sendall(message)
    s.close()
    return True
  except:
    return False

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

def packports(ports):
  '''Converts list ports to port range string, f.e. [1,2,3,5,7,8,9] -> 1-3,5,7-9'''
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

def cmd_exit():
  '''exit: finish work'''
  print 'finished_ok'
  sys.exit()

def cmd_send(proto, address, ports):
  '''usage: send proto address ports. Ports arg example 1050,1100-1200,2024,2040-2056'''
  portsOK = []
  portsNOK = []
  for p in portrange(ports):
    if send(proto, address, p):
      portsOK.append(p)
    else:
      portsNOK.append(p)
  return "OK:%s NOK:%s" % (packports(portsOK), packports(portsNOK))

def cmd_help(command=None):
  '''usage: help command'''
  if not (command is None):
    return commands[command].__doc__
  else:
    return 'use: help command. possible commands: %s' % ', '.join(commands.keys())


############### MAIN
if __name__ == '__main__':
  commands = dict((k[4:],globals()[k]) for k in globals() if k.startswith('cmd_'))
  print 'started_ok possible commands: %s' % ', '.join(commands.keys())
 
  line = ' '
  while(line):
    line = sys.stdin.readline()
    command, space, rest = line.strip().partition(' ')
    if (command == ''):
      continue
    args = rest.split()
    if command in commands:
      print 'accepted_ok command %s with args %s' % (command, args)
      try:
        result=commands[command](*args)
        print 'result_ok %s' % result
      except SystemExit:
        break 
      except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print "result_notok Exception %s: %s" % \
            (traceback.format_exception_only(exc_type, exc_obj)[0],
                traceback.format_tb(exc_tb))
    else:
      print 'accepted_notok no such command %s' % command
