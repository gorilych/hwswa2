#!/usr/bin/python

import os.path
import yaml
import time
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
  result = {'name': name, 'role': role, 
            'check_time': time.asctime(time.localtime(time.time())),
            'parameters': {}}
  checksdir = config['checksdir']

  # prepare remote end (copy remote scripts, etc)
  arch = ssh.get_cmd_out(server, 'uname --machine')
  if arch.endswith('64'):
    rscriptdir = config['rscriptdir'] + '/bin64'
  else:
    rscriptdir = config['rscriptdir'] + '/bin32'
  remote_hwswa2_dir = ssh.mktemp(server)
  binpath = os.path.join(remote_hwswa2_dir, 'bin')
  tmppath = os.path.join(remote_hwswa2_dir, 'tmp')
  ssh.mkdir(server, tmppath)
  ssh.put(server, rscriptdir, binpath)
  cmd_prefix = 'export PATH=%s:$PATH ;' % binpath

  # get parameters
  parameters = yaml.load(open(os.path.join(checksdir, role.lower() + '.yaml')))['parameters']
  parameters['_type'] = 'dictionary'
  result['parameters'] = _get_param_value(server, parameters, cmd_prefix)

  # clean up
  ssh.remove(server, remote_hwswa2_dir)

  # plan:
  # 1. copy remote scripts
  # 2. prepare PATH variable
  # 3. read role.yaml/parameters
  # 4. for each parameter run command and store result
  # 5. check reboot: send reboot cmd, wait till accessible
  # 6. dump result into reports/server.yaml
  # 7. do cleanup
  return result

def _get_param_value(server, param, cmd_prefix=None, deps=None):
  val = None
  if isinstance(param, (str, unicode)):
    val = ssh.get_cmd_out(server, _prepare_cmd(param, cmd_prefix, deps))
  elif param['_type'] == 'dictionary':
    val = {}
    for p in param:
      if not p.startswith('_'):
        val[p] = _get_param_value(server, param[p], cmd_prefix, deps)
  return val

def _prepare_cmd(cmd, cmd_prefix=None, deps=None):
  if cmd_prefix:
    cmd = cmd_prefix + cmd
  if deps:
    cmd = cmd % deps
  return cmd

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
