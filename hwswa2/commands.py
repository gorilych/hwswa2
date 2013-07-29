#!/usr/bin/python

import os.path
import yaml
import time
from hwswa2.globals import config
from hwswa2.log import info, debug, error
import hwswa2.ssh as ssh
from hwswa2.aux import get_server, passbyval
import threading
import Queue
import time

def check():
  """Check only specified servers"""
  debug("Checking servers: %s" % config['servernames'])
  allnames = [ elem['name'] for elem in config['servers'] ]
  for name in config['servernames']:
    if not name in allnames:
      error("Cannot find server %s in servers list" % name)
      exit(1)
  results = Queue.Queue()
  for name in config['servernames']:
    cth = threading.Thread(name=name, target=_check, args=(get_server(name), results))
    cth.start()
  while threading.active_count() > 1:
    while not results.empty():
      result = results.get()
      _save_report(result['name'], result)
    time.sleep(1)
  while not results.empty():
    result = results.get()
    _save_report(result['name'], result)
                
def _check(server, resultsqueue):
  name = server['name']
  role = server['role']
  result = {'name': name, 'role': role, 
            'check_time': time.asctime(),
            'parameters': {}, 'requirements': {}}
  checksdir = config['checksdir']

  if not ssh.accessible(server):
    result['check_status'] = 'server is not accessible'
  else:
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
    cmd_prefix = 'export PATH=$PATH:%s; ' % binpath

    (parameters, requirements) = get_checks(role)

    result['check_status'] = 'in progress'
    result['parameters'] = _get_param_value(server, parameters, cmd_prefix, binpath=binpath, tmppath=tmppath)

    # clean up
    ssh.remove(server, remote_hwswa2_dir)
  
    # check reboot
    if config['check_reboot']:
      result['reboot_check'] = ssh.check_reboot(server)

    result['check_status'] = 'finished'
  
  resultsqueue.put(result)

def get_checks(roles):
  """Gathers parameters and requirements from role.yaml
  
  roles - list of roles, from more specific to less specific
          or one role
  Returns tuple (parameters, requirements)
  """
  parameters   = {}
  requirements = {}
  checksdir    = config['checksdir']
  if type(roles) == type([]): # list of roles
    for role in roles:
      (rp, rq) = get_checks(role)
      rp.update(parameters)
      rq.update(requirements)
      parameters   = rp
      requirements = rq
  else: # one role
    role = roles
    role_yaml = yaml.load(open(os.path.join(checksdir, role.lower() + '.yaml')))
    if 'parameters'   in role_yaml: parameters   = role_yaml['parameters']
    if 'requirements' in role_yaml: requirements = role_yaml['requirements']
    parameters['_type'] = 'dictionary'

    # process includes
    if 'includes' in role_yaml:
      (rp, rq) = get_checks(role_yaml['includes'])
      rp.update(parameters)
      rq.update(requirements)
      parameters   = rp
      requirements = rq
  return (parameters, requirements)

@passbyval
def _get_param_value(server, param, cmd_prefix=None, deps={}, binpath=None, tmppath='/tmp'):
  val = None
  if isinstance(param, (str, unicode)):
    val = ssh.get_cmd_out(server, _prepare_cmd(param, cmd_prefix, deps))
  else: # non-scalar type
    # process _uses
    if '_uses' in param:
      for key in param['_uses']:
        keyfile = ssh.mktemp(server, ftype='f', path=tmppath)
        ssh.write(server, keyfile, yaml.dump(config[key]))
        deps.update({param['_uses'][key]: keyfile})
      del param['_uses']
    # convert _script to _command
    if '_script' in param:
      scriptpath = ssh.mktemp(server, ftype='f', path=binpath)
      ssh.write(server, scriptpath, _prepare_cmd(param['_script'], deps=deps))
      ssh.exec_cmd(server, 'chmod +x %s' % scriptpath)
      param['_command'] = scriptpath
    # different type processing
    if param['_type'] == 'dictionary':
      val = {}
      for p in param:
        if not p.startswith('_'):
          val[p] = _get_param_value(server, param[p], cmd_prefix, deps, binpath, tmppath)
    elif param['_type'] == 'table':
      val = []
      if '_command' in param:
        rows = ssh.get_cmd_out(server, _prepare_cmd(param['_command'], cmd_prefix, deps))
        if not '_separator' in param:
          param['_separator'] = ' '
        if not rows == '':
          for row in rows.split('\n'):
            val.append(dict(zip(param['_fields'], row.split(param['_separator']))))
    elif param['_type'] == 'list':
      val = []
      # evaluate generator first
      for generator in param['_generator']: # there should be only one
        placeholder = param['_generator'][generator]
        gen_values = ssh.get_cmd_out(server, _prepare_cmd(param[generator], cmd_prefix, deps)).split('\n')
        del param[generator]
        for gen_value in gen_values:
          deps.update({placeholder: gen_value})
          elem = {generator: gen_value}
          # evaluate other parameters based on generator
          for p in param:
            if not p.startswith('_'):
              elem[p] = _get_param_value(server, param[p], cmd_prefix, deps, binpath, tmppath)
          val.append(elem)
  return val

def _prepare_cmd(cmd, cmd_prefix=None, deps=None):
  if cmd_prefix:
    cmd = cmd_prefix + cmd
  if deps:
    cmd = cmd % deps
  return cmd

def _save_report(name, result):
  path = os.path.join(config['reportsdir'], name)
  reportfile = os.path.join(path, time.strftime('%F.%Hh%Mm%Ss'))
  if not os.path.exists(path): os.makedirs(path)
  yaml.dump(result, open(reportfile, 'w'))

def checkall():
  """Check all servers"""
  debug("Checking all servers")
  allnames = [ elem['name'] for elem in config['servers'] ]
  config['servernames'] = allnames
  check()

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
  allnames = [ elem['name'] for elem in config['servers'] ]
  config['servernames'] = allnames
  prepare()

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

def reboot():
  """Reboots server and prints results"""
  servername = config['servername']
  debug("Rebooting server %s" % servername)
  server = get_server(servername)
  if not server:
    error("Cannot find server %s in servers list" % servername)
    exit(1)
  if ssh.accessible(server):
    print ssh.check_reboot(server)
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
