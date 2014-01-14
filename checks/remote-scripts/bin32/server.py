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
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((address, port))
s.listen(1)
s.settimeout(timeout)
try:
  conn, addr = s.accept()
  data = conn.recv(1024).rstrip()
  conn.close()
  if data == message:
    print "OK"
  else:
    print "NOK"
    sys.exit(1)
except SystemExit:
  sys.exit(1)
except:
  print "NOK"
  sys.exit(1)
