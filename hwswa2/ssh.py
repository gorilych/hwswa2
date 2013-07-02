import stat
import os
import os.path
import paramiko
import hwswa2.interactive as interactive

def connect(server):
  """Connects to server and returns SSHClient object"""
  hostname = server['address']
  if 'port' in server:
    port = server['port']
  else:
    port = 22
  username = server['account']['login']
  password = server['account']['password']
  client = paramiko.SSHClient()
  client.load_system_host_keys()
  client.set_missing_host_key_policy(paramiko.WarningPolicy())
  client.connect(hostname, port, username, password)
  return client

def shell(server):
  client = connect(server)
  chan = client.invoke_shell()
  interactive.interactive_shell(chan)
  chan.close()
  client.close()

def accessible(server):
  try:
    client = connect(server)
    client.close()
    return True
  except:
    return False

def exec_cmd_i(server, sshcmd):
  """Executes command interactively"""
  client = connect(server)
  channel = client.get_transport().open_session()
  channel.get_pty()
  channel.settimeout(5)
  channel.exec_command(sshcmd)
  interactive.interactive_shell(channel)
  status = channel.recv_exit_status()
  channel.close()
  client.close()
  return status

def exec_cmd(server, sshcmd, input_data=None):
  """Executes command and returns tuple of stdout, stderr and status"""
  client = connect(server)
  stdin, stdout, stderr = client.exec_command(sshcmd)
  if input_data:
    stdin.write(input_data)
    stdin.flush()
  stdout_data = stdout.readlines()
  stderr_data = stderr.readlines()
  status = stdout.channel.recv_exit_status()
  client.close()
  return stdout_data, stderr_data, status

def put(server, localpath, remotepath):
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
    else:
      sftp.put(localpath,remotepath,confirm=True)
  if os.path.isdir(localpath):
    if exists(server, remotepath): 
      rname = os.path.join(remotepath, os.path.basename(localpath))
      mkdir(server, rname)
      put_dir_content(server, localpath, rname)
    else:
      mkdir(server, remotepath)
      put_dir_content(server, localpath, remotepath)
  client.close()

def mktemp(server, template='hwswa2.XXXXX'):
  """Creates directory using mktemp and returns its name"""
  sshcmd = 'mktemp -d -p \`pwd\` %s' % template
  dirname, stderr, status = exec_cmd(server, sshcmd)
  if status:
    return dirname
  else:
    raise Exception("Failed to create directory on server %s, stderr: %s " % (server, stderr))

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
