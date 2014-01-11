#!/usr/bin/env python
import pexpect
import sys
import os
import threading

sutype      = sys.argv[1]
password    = sys.argv[2]
stderr_fifo = sys.argv[3]
stdout_fifo = sys.argv[4]
command     = sys.argv[5]
timeout     = int(sys.argv[6])

def read_from_to(fifo_name, fout):
  fifo = os.fdopen(os.open(fifo_name, os.O_RDONLY), 'r')
  while True:
    line = fifo.readline()
    if not line: break
    fout.write(line)
  fifo.close()

if command == 'shell':
  if password == '' and sutype == 'sudo':
    sucmd = 'sudo'
    suargs = ['su', '-']
  if not password == '':
    if sutype == 'su'  :
      sucmd = 'su'
    if sutype == 'su'  :
      sucmd = 'su'
      suargs = ['-']
    elif sutype == 'sudo':
      sucmd = 'sudo'
      suargs = ['-p', 'password: ', '--', 'su', '-']
  try:
    pexpect.WINHEIGHT = int(stdout_fifo)
    pexpect.WINWIDTH  = int(stderr_fifo)
  except:
    pass
  child = pexpect.spawn(sucmd, suargs, timeout=timeout)
  if not password == '':
    child.expect_exact('assword: ')
    child.sendline(password)
  child.interact()
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
  suargs += ['-', '-c', '{ %s; } 1>%s 2>%s' % (command, stdout_fifo, stderr_fifo)]

  stdout_th = threading.Thread(name='stdout', target=read_from_to, args=(stdout_fifo, sys.stdout))
  stderr_th = threading.Thread(name='stderr', target=read_from_to, args=(stderr_fifo, sys.stderr))

  stdout_th.start()
  stderr_th.start()

  # cleanup cached credentials
  if sutype == 'sudo':
    child = pexpect.spawn('sudo -k')
    child.close()
  child = pexpect.spawn(sucmd, suargs)
  if not password == '':
    child.expect('assword: ')
    child.sendline(password)
  child.expect_exact(pexpect.EOF)
  child.close()
  exitcode = child.exitstatus

  stdout_th.join()
  stderr_th.join()

  sys.exit(child.exitstatus)

