import paramiko
import hwswa2.interactive as interactive

def shell(server):
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
  chan = client.invoke_shell()
  interactive.interactive_shell(chan)
  chan.close()
  client.close()

def accessible(server):
  """Checks, if it is possible to establish ssh connection"""
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
  try:
    client.connect(hostname, port, username, password)
    client.close()
    return True
  except:
    return False

def exec_cmd_i(server, sshcmd):
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
  stdin, stdout, stderr = client.exec_command(sshcmd)
  if input_data:
    stdin.write(input_data)
    stdin.flush()
  stdout_data = stdout.readlines()
  stderr_data = stderr.readlines()
  status = stdout.channel.recv_exit_status()
  client.close()
  return stdout_data, stderr_data, status