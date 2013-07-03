#!/usr/bin/python

import os.path
import yaml
from hwswa2.globals import config
from hwswa2.log import info, debug, error
import hwswa2.ssh as ssh
from hwswa2.aux import get_server


def check():
  """Check only specified servers"""
  debug("Checking servers: %s" % config['servernames'])
  allnames = [ elem['name'] for elem in config['servers'] ]
  for name in config['servernames']:
    if not name in allnames:
      error("Cannot find server %s in servers list" % name)
      exit(1)
  for name in config['servernames']:
    result = _check(get_server(name))
    _save_report(name, result)

def _check(server):
  name = server['name']
  role = server['role']
  result = {'name': name, 'role': role, 'parameters': {}}
  checksdir = config['checksdir']
  parameters = yaml.load(open(os.path.join(checksdir, role.lower() + '.yaml')))['parameters']
  for param in parameters:
    val = parameters[param]
    if isinstance(val, (str, unicode)): # simple command
      stdout, stderr, status = ssh.exec_cmd(server, val)
      param_result = '\n'.join(stdout)
      result[param] = param_result
  # plan:
  # 1. copy remote scripts
  # 2. prepare PATH variable
  # 3. read role.yaml/parameters
  # 4. for each parameter run command and store result
  # 5. check reboot: send reboot cmd, wait till accessible
  # 6. dump result into reports/server.yaml
  # 7. do cleanup
  return result
  
def _save_report(name, result):
  path = os.path.join(config['reportsdir'], name)
  yaml.dump(result, open(path, 'w'))

def checkall():
  """Check all servers"""
  debug("Checking all servers")

def prepare():
  """Prepare only specified servers"""
  debug("Preparing servers: %s" % config['servernames'])
  allnames = [ elem['name'] for elem in config['servers'] ]
  for name in config['servernames']:
    if not name in allnames:
      error("Cannot find server %s in servers list" % name)
      exit(1)

def prepareall():
  """Prepare all servers"""
  debug("Preparing all servers")

def shell():
  """Open interactive shell to specific server"""
  servername = config['servername']
  debug("Opening interactive shell to server %s" % servername)
  server = get_server(servername)
  if not server:
    error("Cannot find server %s in servers list" % servername)
    exit(1)
  if ssh.accessible(server):
    ssh.shell(server)
  else:
    error("Failed to connect to server %s" % servername)
    exit(1)

def exec_cmd():
  """Exec command on specified server interactively"""
  servername = config['servername']
  sshcmd = " ".join(config['sshcmd'])
  debug("Executing `%s` on server %s" % (sshcmd, servername))
  server = get_server(servername)
  if not server:
    error("Cannot find server %s in servers list" % servername)
    exit(1)
  if ssh.accessible(server):
    exitstatus = ssh.exec_cmd_i(server, sshcmd)
    debug("exitstatus = %s" % exitstatus)
  else:
    error("Failed to connect to server %s" % servername)
    exit(1)

def _exec_cmd():
  """Exec command on specified server non-interactively"""
  servername = config['servername']
  sshcmd = " ".join(config['sshcmd'])
  debug("Executing `%s` on server %s" % (sshcmd, servername))
  server = get_server(servername)
  if not server:
    error("Cannot find server %s in servers list" % servername)
    exit(1)
  if ssh.accessible(server):
    stdout, stderr, exitstatus = ssh.exec_cmd(server, sshcmd)
    print("stdout = %s" % stdout)
    print("stderr = %s" % stderr)
    print("exitstatus = %s" % exitstatus)
  else:
    error("Failed to connect to server %s" % servername)
    exit(1)

def put():
  """Copy file to server"""
  servername = config['servername']
  localpath  = config['localpath']
  remotepath = config['remotepath']
  debug("Copying '%s' to '%s' on server %s" % (localpath, remotepath, servername))
  server = get_server(servername)
  if not server:
    error("Cannot find server %s in servers list" % servername)
    exit(1)
  if ssh.accessible(server):
    ssh.put(server, localpath, remotepath)
  else:
    error("Failed to connect to server %s" % servername)
    exit(1)
