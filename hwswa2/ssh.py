import stat
import time
import os
import os.path
import sys
import subprocess
import signal
import paramiko
import hwswa2.interactive as interactive
import hwswa2.aux as aux
from hwswa2.log import debug

ssh_timeout = 30

def connect(server):
  """Connects to server and returns SSHClient object"""
  hostname = server['address']
  if 'port' in server:
    port = server['port']
  else:
    port = 22
  username          = server['account']['login']
  password          = None
  key_filename      = None
  if 'password' in server['account']: password     = server['account']['password']
  if 'key'      in server['account']: key_filename = server['account']['key']
  client = paramiko.SSHClient()
  client.load_system_host_keys()
  client.set_missing_host_key_policy(paramiko.WarningPolicy())
  client.connect(hostname, port, username, password=password, key_filename=key_filename)
  return client

def shell(server, privileged=True):
  client = connect(server)
  chan = client.invoke_shell()
  if privileged and ('su' in server['account'] or 'sudo' in server['account']):
    sshcmd = prepare_su_cmd(server, 'shell')
    chan.sendall(sshcmd + '; exit \n')
    # cleanup previous output, leaving only prompt
    data = ''
    while chan.recv_ready(): data += chan.recv(1000)
    time.sleep(0.3)
    while chan.recv_ready(): data += chan.recv(1000)
    print data.split('\n')[-1],
    sys.stdout.flush()
  interactive.interactive_shell(chan)
  chan.close()
  client.close()

def accessible(server, retry=False):
  if 'accessible' in server and not retry:
    return server['accessible']
  else:
    try:
      client = connect(server)
      client.close()
      server['accessible'] = True
      return True
    except:
      server['accessible'] = False
      return False

def pingable(server):
  command = "ping -w 1 -q -c 1 %s" % server['address']
  return subprocess.call(command) == 0

def exec_cmd_i(server, sshcmd, privileged=True):
  """Executes command interactively"""
  client = connect(server)
  if privileged and ('su' in server['account'] or 'sudo' in server['account']):
    sshcmd = prepare_su_cmd(server, sshcmd)
  channel = client.get_transport().open_session()
  channel.get_pty()
  channel.settimeout(ssh_timeout)
  channel.exec_command(sshcmd)
  interactive.interactive_shell(channel)
  status = channel.recv_exit_status()
  channel.close()
  client.close()
  return status

def exec_cmd(server, sshcmd, input_data=None, timeout=ssh_timeout, privileged=True):
  """Executes command and returns tuple of stdout, stderr and status"""
  debug("Executing %s on server %s" % (sshcmd, server['name']))
  client = connect(server)
  if privileged and ('su' in server['account'] or 'sudo' in server['account']):
    sshcmd = prepare_su_cmd(server, sshcmd)
  stdin, stdout, stderr = client.exec_command(sshcmd, timeout=timeout, get_pty=False)
  if input_data:
    stdin.write(input_data)
    stdin.flush()
  stdout_data = stdout.read().splitlines()
  stderr_data = stderr.read().splitlines()
  status = stdout.channel.recv_exit_status()
  client.close()
  return stdout_data, stderr_data, status

def get_cmd_out(server, sshcmd, input_data=None, timeout=ssh_timeout, privileged=True):
  stdout_data, stderr_data, status = exec_cmd(server, sshcmd, input_data, timeout=timeout, privileged=privileged)
  return '\n'.join(stdout_data)

def remove(server, path):
  exec_cmd(server, "rm -rf %s" % path)

def put(server, localpath, remotepath):
  debug("Copying %s to %s:%s" %(localpath, server['name'], remotepath))
  if not os.path.exists(localpath):
    raise Exception("Local path does not exist: %s" % localpath)
  client = connect(server)
  sftp = client.open_sftp()
  if os.path.isfile(localpath):
    if exists(server, remotepath):
      attrs = sftp.stat(remotepath)
      if stat.S_ISDIR(attrs.st_mode):
        remotepath = os.path.join(remotepath, os.path.basename(localpath))
      sftp.put(localpath,remotepath,confirm=True)
      sftp.chmod(remotepath, os.stat(localpath).st_mode)
    else:
      sftp.put(localpath,remotepath,confirm=True)
      sftp.chmod(remotepath, os.stat(localpath).st_mode)
  if os.path.isdir(localpath):
    if exists(server, remotepath): 
      rname = os.path.join(remotepath, os.path.basename(localpath))
      mkdir(server, rname)
      put_dir_content(server, localpath, rname)
    else:
      mkdir(server, remotepath)
      put_dir_content(server, localpath, remotepath)
  client.close()

def mktemp(server, template='hwswa2.XXXXX', ftype='d', path='`pwd`'):
  """Creates directory using mktemp and returns its name"""
  sshcmd = 'mktemp '
  if ftype == 'd':
    sshcmd = sshcmd + '-d '
  sshcmd = sshcmd + '-p %s %s' % (path, template)
  return get_cmd_out(server, sshcmd, privileged=False)

def mkdir(server, path):
  client = connect(server)
  sftp = client.open_sftp()
  sftp.mkdir(path)
  client.close()

def exists(server, path):
  client = connect(server)
  sftp = client.open_sftp()
  try:
    sftp.stat(path)
    return True
  except:
    return False

def put_dir_content(server, localdir, remotedir):
  for f in os.listdir(localdir):
    lname = os.path.join(localdir, f)
    rname = os.path.join(remotedir, f)
    if os.path.isfile(lname):
      put(server, lname, rname)
    if os.path.isdir(lname):
      mkdir(server, rname)
      put_dir_content(server, lname, rname)

def write(server, path, data):
  client = connect(server)
  sftp = client.open_sftp()
  file = sftp.open(path, 'w')
  file.write(data)
  file.close()
  client.close()

def hostid(server):
  return get_cmd_out(server, 'hostid')

def is_it_me(server):
  if hasattr(subprocess, 'check_output'):
    myhostid = subprocess.check_output('hostid').strip()
  else:
    myhostid = subprocess.Popen(["hostid"], stdout=subprocess.PIPE).communicate()[0].strip()
  server_hostid = hostid(server)
  debug("Is it me? Comparing %s and %s" % (myhostid, server_hostid))
  return myhostid == server_hostid

def check_reboot(server, timeout=300):
  """Reboot the server and check the time it takes to come up"""
  if is_it_me(server):
    return "we are running here, no reboot"
  starttime = time.time()
  try: # reboot will most probably fail with socket.timeout exception
    exec_cmd(server, 'reboot', timeout=3)
  except: # we are going to ignore this
    pass
  debug("reboot command is sent, now wait till server is down")
  # wait till shutdown:
  if aux.wait_for_not(accessible, [server, True], timeout):
    debug("Server %s is down" % server['name'])
    delta = time.time() - starttime
    # wait till boot
    if aux.wait_for(accessible, [server, True], timeout - delta):
      return round(time.time() - starttime)
    else:
      return "server is not accessible after %s seconds" % timeout
  else:
    return "server does not go to reboot: still accessible after %s seconds" % timeout

def prepare_su(server):
  """Copies su.py to remote server and returns path to containing directory"""
  su_py = """#!/usr/bin/env python
import pexpect
import sys
import os
import threading

sutype      = sys.argv[1]
password    = sys.argv[2]
stderr_fifo = sys.argv[3]
stdout_fifo = sys.argv[4]
command     = sys.argv[5]

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
      suargs = ['-']
    elif sutype == 'sudo':
      sucmd = 'sudo'
      suargs = ['-p', 'password: ', '--', 'su', '-']
  try:
    pexpect.WINHEIGHT = int(stdout_fifo)
    pexpect.WINWIDTH  = int(stderr_fifo)
  except:
    pass
  child = pexpect.spawn(sucmd, suargs)
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
"""
  # create directory
  supath = mktemp(server, template='su.XXXX', path='/tmp')
  # copy pexpect.py
  import pexpect
  pexpect_file = pexpect.__file__
  if pexpect_file.endswith('.pyc'):
    pexpect_file = pexpect_file[:-1]
  put(server, pexpect_file, supath)
  # copy su.py
  su_py_path = os.path.join(supath, 'su.py')
  write(server, su_py_path, su_py)
  # prepare stdout and stderr fifos:
  exec_cmd(server, "mkfifo %s" % os.path.join(supath, 'stdout'), privileged=False)
  exec_cmd(server, "mkfifo %s" % os.path.join(supath, 'stderr'), privileged=False)
  server['supath'] = supath
  return supath

def prepare_su_cmd(server, cmd):
  if not ('su' in server['account'] or 'sudo' in server['account']):
    return cmd
  if not 'supath' in server:
    prepare_su(server)
  supath      = server['supath'] 
  su_py       = os.path.join(supath, 'su.py')
  stdout_fifo = os.path.join(supath, 'stdout')
  stderr_fifo = os.path.join(supath, 'stderr')
  if 'sudo' in server['account']:
    sutype   = 'sudo'
    password = server['account']['sudo']
    if password == None: password = ''
  elif 'su' in server['account']:
    sutype   = 'su'
    password = server['account']['su']
  if cmd == 'shell': # pass window size instead of fifos
    (stdout_fifo, stderr_fifo) = aux.getTerminalSize()
  return 'python %s %s "%s" %s %s "%s"' % (su_py,
    sutype,
    aux.shell_escape(password),
    stderr_fifo,
    stdout_fifo,
    aux.shell_escape(cmd))

def cleanup(server):
  if 'supath' in server:
    remove(server, server['supath'])
    del server['supath']
