import paramiko
import interactive

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
