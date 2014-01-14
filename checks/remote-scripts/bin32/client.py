#!/usr/bin/env python
import sys, socket

address = sys.argv[1]
proto   = sys.argv[2]
port    = int(sys.argv[3])
message = sys.argv[4]
timeout = int(sys.argv[5])

if proto == 'tcp':
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
elif proto == 'udp':
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(timeout)
try:
  s.connect((address, port))
  s.sendall(message)
  s.close()
  print "OK"
except:
  print "NOK"
  sys.exit(1)
