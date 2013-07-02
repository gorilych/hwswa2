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
