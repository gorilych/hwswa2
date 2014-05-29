#!/usr/bin/python

import os.path
import yaml
import time
from hwswa2.globals import config
from logging import info, debug, error
import hwswa2.ssh as ssh
from hwswa2.aux import get_server, passbyval, threaded, splitrange, joinranges, list2range, differenceranges
import threading
import Queue
import time
from copy import deepcopy
from sys import exit
import sys


def firewall():
  '''Check connections between servers'''
  allnames = [ elem['name'] for elem in config['servers'] ]

  servers = []
  for name in config['servernames']:
    if not name in allnames:
      error("Cannot find server %s in servers list" % name)
      sys.exit(1)
    servers.append(get_server(name))

  # collect IPs from last reports
  for server in servers:
    report = _last_report(server)
    if not ('parameters' in report and \
            'network' in report['parameters'] and \
            'network_interfaces' in report['parameters']['network']):
      error('Report (with nic info) for server %s is not generated, check the server first' % server['name'])
      sys.exit(1)
    else:
      nics = report['parameters']['network']['network_interfaces']
      nw_ips = {}
      for nic in nics:
        ips = nic['ip']
        for ip in ips:
          nw_ips[ip['network']] = ip['address']
      if len(nw_ips) == 0:
        error('Found no IPs in last report for server %s' % server['name'])
        sys.exit(1)
      server['nw_ips'] = nw_ips
      debug('IPs of %s: %s' % (server['name'], server['nw_ips']) )

  # collect roles
  roles = {} # dict {role1: [server1, server2], role2: [server3, server4]}
  for server in servers:
    role = server['role']
    (parameters, requirements, firewall) = get_checks(role)
    server['firewall'] = firewall
    if not (type(role) == type([])): # single role
      role = [role,] # convert to list of roles
    for r in role:
      rr = r.lower()
      if not rr in roles:
        roles[rr] = set([server['name']])
      else:
        roles[rr] |= set([server['name']])
  debug("Roles: %s" % roles)

  # expand rule groups to rules in firewall
  for server in servers:
    rulegroups = [g for g in server['firewall'] if ('group' in g) and g['group']]
    rules = [r for r in server['firewall'] if (not ('group' in r)) or (not r['group'])]
    for rg in rulegroups:
      common_props = [key for key in ['connect_with', 'type', 'ports',
                                      'protos', 'networks', 'direction',
                                      'policy'] if key in rg]
      for r in rg['rules']:
        for key in common_props:
          if not (key in r):
            r[key] = rg[key]
        rules.append(r)
    server['firewall'] = rules

  # collect rules
  rules = [] # list [ {'serverfrom': server1name, 'serverto': server2name, 'network': ..., 'proto': ..., 'ports': ...}, { ... } ]
  for server in servers:
    fw = server['firewall']
    for rule in fw:
      if rule['policy'] == 'deny':
        continue # we need 'allow'
      if rule['type'] == 'internet':
        continue # we need 'infra'
      for network in rule['networks']:
        for proto in rule['protos']:
          if rule['direction'] == 'incoming':
            this_server_key = 'serverto'
            other_server_key = 'serverfrom'
          elif rule['direction'] == 'outgoing':
            this_server_key = 'serverfrom'
            other_server_key = 'serverto'
          else:
            info('Rule %s: wrong direction %s (should be either outgoing or incoming)'\
                 % (rule['description'], rule['direction']))
            continue
          for r in rule['connect_with']['roles']:
            role = r.lower()
            if role in roles:
              for other_server_name in roles[role]:
                if other_server_name == server['name']:
                  continue # skip the same server
                rules.append({this_server_key: server['name'],
                              other_server_key: other_server_name,
                              'network': network, 'proto': proto.lower(),
                              'ports': str(rule['ports'])})

  joined_rules = [] # join ports for the same rules, so not to check twice
  for rule in rules:
    joined_rule = next((jr for jr in joined_rules \
                                  if jr['serverto'] == rule['serverto'] and \
                                     jr['serverfrom'] == rule['serverfrom'] and \
                                     jr['network'] == rule['network'] and \
                                     jr['proto'] == rule['proto']), None)
    if joined_rule is None:
      joined_rules.append(rule)
    else:
      joined_rule['ports'] = joinranges(joined_rule['ports'], rule['ports'])

  # update joined_rules with IPs and replace server names with server objects
  for rule in joined_rules:
    rule['serverto'] = get_server(rule['serverto'])
    rule['serverfrom'] = get_server(rule['serverfrom'])
    debug('Rule %s' % rule)
    try:
      toIP = rule['serverto']['nw_ips'][rule['network']]
    except KeyError:
      error('Cannot find IP for server %s from network %s' % (rule['serverto'], rule['network']))
      sys.exit(1)
    rule['toIP'] = toIP
    try:
      fromIP = rule['serverfrom']['nw_ips'][rule['network']]
    except KeyError:
      error('Cannot find IP for server %s from network %s' % (rule['serverfrom'], rule['network']))
      sys.exit(1)
    rule['fromIP'] = fromIP
  
  # check connections and collect results.
  results = []
  for rule in joined_rules:
    results.append(_check_rule(rule))
  print "        Below connections are OK:"
  for res in results:
    if not (res['OK'] == ''):
      print '%s -> %s %s:%s (%s)' % (res['serverfrom'], res['serverto'], res['proto'], res['OK'], res['network'])
  print "        Below connections are NOT OK:"
  for res in results:
    if not (res['NOK'] == ''):
      print '%s -> %s %s:%s (%s)' % (res['serverfrom'], res['serverto'], res['proto'], res['NOK'], res['network'])
  print 'Finished.'


def _check_rule(rule):
  maxopensockets = 256
  serverfrom = rule['serverfrom']
  serverto = rule['serverto']
  proto = rule['proto']
  ports = rule['ports']
  toIP = rule['toIP']
  fromIP = rule['fromIP']

  ssh.serverd_start(serverfrom)
  ssh.serverd_start(serverto)

  grand_result = {'serverfrom': serverfrom['name'],
                  'serverto': serverto['name'],
                  'network': rule['network'],
                  'ports': ports, 'proto': proto,
                  'OK': '', 'NOK': '', 'failures': []}
  for ps in splitrange(ports, maxopensockets):
    listencmd = 'listen %s %s %s' % (proto, toIP, ps)
    sendcmd = 'send %s %s %s' % (proto, toIP, ps)
    status, result = ssh.serverd_cmd(serverto, listencmd)
    if status: # listen ok
      status, result = ssh.serverd_cmd(serverfrom, sendcmd)
      if status: # send ok
        ok, space, nok = result.partition(' ')
        OK, colon, ok_range = ok.partition(':')
        NOK, colon, nok_range = nok.partition(':')
        if len(ok_range) > 0:
          if proto == 'tcp':
            grand_result['OK'] = joinranges(grand_result['OK'], ok_range)
          elif proto == 'udp': # need to receive to check
            receivecmd = 'receive %s %s %s' % (proto, toIP, ok_range)
            status, result = ssh.serverd_cmd(serverto, receivecmd)
            if status: #receive ok
              msgs = result.split() # each message is port:msg:fromaddr:fromport
              new_ok_range = list2range([int(msg.split(':')[0]) for msg in msgs])
              grand_result['OK'] = joinranges(grand_result['OK'], new_ok_range)
              nok_range = joinranges(nok_range, differenceranges(ok_range, new_ok_range))
            else: #receive failed
              grand_result['failures'].append('receive failure: ' + result)
              nok_range = joinranges(nok_range, ok_range)
        if len(nok_range) > 0:
          grand_result['NOK'] = joinranges(grand_result['NOK'], nok_range)
      else: # send failed
        grand_result['failures'].append('send failure: ' + result)
    else: # listen failed
      grand_result['failures'].append('listen failure: ' + result)
    ssh.serverd_cmd(serverto, 'closeall')
  return grand_result

def check():
  """Check only specified servers"""
  debug("Checking servers: %s" % config['servernames'])
  allnames = [ elem['name'] for elem in config['servers'] ]
  for name in config['servernames']:
    if not name in allnames:
      error("Cannot find server %s in servers list" % name)
      sys.exit(1)
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
    result['accessible'] = 'NO, %s' % server['lastConnectionError']
    info("Server %s is not accessible" % name)
  else:
    result['accessible'] = 'Yes'
    _prepare_remote_scripts(server)
    (parameters, requirements, firewall) = get_checks(role)
    result['check_status'] = 'in progress'
    result['parameters'] = _get_param_value(server, parameters, 
                            cmd_prefix=server['cmd_prefix'],
                            binpath=server['binpath'], 
                            tmppath=server['tmppath'])
    # check expected parameters
    if 'expect' in server:
      result['expect'] = {}
      for expectation in server['expect']:
        # checking expected IP addresses
        if 'ip' in expectation:
          if 'network' in result['parameters'] and \
              'network_interfaces' in result['parameters']['network']:
            interfaces = result['parameters']['network']['network_interfaces']
            ip_nw_nic = []
            for nic in interfaces:
              for ip in nic['ip']:
                ip_nw_nic.append({'ip': ip['address'], 'nw': ip['network'], 'nic': nic['name']})
          e_key = e_ip = expectation['ip']
          if 'network' in expectation:
            e_nw = expectation['network']
            e_key += '/' + e_nw
          e_found = next((ip for ip in ip_nw_nic if ip['ip'] == e_ip), None)
          if e_found is None:
            result['expect'][e_key] = 'NOT OK, IP address NOT found'
          else:
            if not ('network' in expectation):
              result['expect'][e_key] = 'OK, IP address found on ' + e_found['nic']
            else:
              if e_nw == e_found['nw']:
                result['expect'][e_key] = 'OK, IP address found on ' + e_found['nic']
              else:
                result['expect'][e_key] = 'NOT OK, IP address found on ' + e_found['nic'] + ' but network is NOT the same: ' + e_found['nw']

    # check reboot
    if config['check_reboot']:
      result['reboot_check'] = ssh.check_reboot(server)

    # clean up
    ssh.cleanup(server)

    result['check_status'] = 'finished'
  
  resultsqueue.put(result)

def _prepare_remote_scripts(server):
  """Copy remote scripts to server, prepare tmp, configure cmd prefix"""
  if 'cmd_prefix' in server: # called twice?
    return
  arch = ssh.get_cmd_out(server, 'uname --machine', privileged=False)
  if arch.endswith('64'):
    rscriptdir = config['rscriptdir'] + '/bin64'
  else:
    rscriptdir = config['rscriptdir'] + '/bin32'
  server['arch'] = arch
  remote_hwswa2_dir = ssh.mktemp(server)
  server['binpath'] = os.path.join(remote_hwswa2_dir, 'bin')
  server['tmppath'] = os.path.join(remote_hwswa2_dir, 'tmp')
  ssh.mkdir(server, server['tmppath'])
  ssh.put(server, rscriptdir, server['binpath'])
  server['cmd_prefix'] = 'export PATH=$PATH:%s; ' % server['binpath']

def get_checks(roles, included_roles=None):
  """Gathers parameters and requirements from role.yaml
  
  roles - list of roles, from more specific to less specific
          or one role
  Returns tuple (parameters, requirements)
  """
  if included_roles is None:
    included_roles = []
  parameters   = {}
  requirements = {}
  firewall = []
  checksdir    = config['checksdir']
  if type(roles) == type([]): # list of roles
    for role in roles:
      if not (role in included_roles):
        (rp, rq, fw) = get_checks(role, included_roles)
        rp.update(parameters)
        rq.update(requirements)
        fw.extend(firewall)
        parameters   = rp
        requirements = rq
        firewall     = fw
  else: # one role
    role = roles
    if not (role in included_roles):
      role_yaml = yaml.load(open(os.path.join(checksdir, role.lower() + '.yaml')))
      if 'parameters'   in role_yaml: parameters   = role_yaml['parameters']
      if 'requirements' in role_yaml: requirements = role_yaml['requirements']
      if 'firewall'     in role_yaml: firewall     = role_yaml['firewall']
      parameters['_type'] = 'dictionary'
      included_roles.append(role)

      # process includes
      if 'includes' in role_yaml:
        (rp, rq, fw) = get_checks(role_yaml['includes'], included_roles)
        rp.update(parameters)
        rq.update(requirements)
        fw.extend(firewall)
        parameters   = rp
        requirements = rq
        firewall     = fw
  return (parameters, requirements, firewall)

#@passbyval
def _get_param_value(server, param, cmd_prefix=None, deps={}, binpath=None, tmppath='/tmp'):
  mydeps = deepcopy(deps)
  myparam = deepcopy(param)
  val = None
  if isinstance(myparam, (str, unicode)):
    val = ssh.get_cmd_out(server, _prepare_cmd(myparam, cmd_prefix, mydeps))
  else: # non-scalar type
    # process _uses
    if '_uses' in myparam:
      for key in myparam['_uses']:
        keyfile = ssh.mktemp(server, ftype='f', path=tmppath)
        ssh.write(server, keyfile, yaml.safe_dump(config[key]))
        mydeps.update({myparam['_uses'][key]: keyfile})
      del myparam['_uses']
    # convert _script to _command
    if '_script' in myparam:
      scriptpath = ssh.mktemp(server, ftype='f', path=binpath)
      ssh.write(server, scriptpath, _prepare_cmd(myparam['_script'], deps=mydeps))
      ssh.exec_cmd(server, 'chmod +x %s' % scriptpath)
      myparam['_command'] = scriptpath
      del myparam['_script']
    # different type processing
    if myparam['_type'] == 'dictionary':
      val = {}
      for p in myparam:
        if not p.startswith('_'):
          val[p] = _get_param_value(server, myparam[p], cmd_prefix, mydeps, binpath, tmppath)
    elif myparam['_type'] == 'table':
      val = []
      if '_command' in myparam:
        rows = ssh.get_cmd_out(server, _prepare_cmd(myparam['_command'], cmd_prefix, mydeps))
        if not '_separator' in myparam:
          myparam['_separator'] = ' '
        if not rows == '':
          maxsplit = len(myparam['_fields']) - 1 
          for row in rows.split('\n'):
            val.append(dict(zip(myparam['_fields'], row.split(myparam['_separator'], maxsplit))))
    elif myparam['_type'] == 'list':
      val = []
      # evaluate generator first
      for generator in myparam['_generator']: # there should be only one
        placeholder = myparam['_generator'][generator]
        gen_values = ssh.get_cmd_out(server, _prepare_cmd(myparam[generator], cmd_prefix, mydeps)).split('\n')
        del myparam[generator]
        for gen_value in gen_values:
          mydeps.update({placeholder: gen_value})
          elem = {generator: gen_value}
          # evaluate other parameters based on generator
          for p in myparam:
            if not p.startswith('_'):
              elem[p] = _get_param_value(server, myparam[p], cmd_prefix, mydeps, binpath, tmppath)
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
  yaml.safe_dump(result, open(reportfile, 'w'))
  info('%s status: %s, report file: %s' %(name, result['check_status'], reportfile))

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
      sys.exit(1)

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
    sys.exit(1)
  if ssh.accessible(server):
    ssh.shell(server)
  else:
    error("Failed to connect to server %s" % servername)
    sys.exit(1)

def reboot():
  """Reboots server and prints results"""
  servername = config['servername']
  debug("Rebooting server %s" % servername)
  server = get_server(servername)
  if not server:
    error("Cannot find server %s in servers list" % servername)
    sys.exit(1)
  if ssh.accessible(server):
    print ssh.check_reboot(server)
  else:
    error("Failed to connect to server %s" % servername)
    sys.exit(1)

def exec_cmd():
  """Exec command on specified server interactively"""
  servername = config['servername']
  sshcmd = " ".join(config['sshcmd'])
  if 'tty' in config:
    get_pty=config['tty']
  debug("Executing `%s` on server %s" % (sshcmd, servername))
  server = get_server(servername)
  if not server:
    error("Cannot find server %s in servers list" % servername)
    sys.exit(1)
  if ssh.accessible(server):
    exitstatus = ssh.exec_cmd_i(server, sshcmd, get_pty=get_pty)
    debug("exitstatus = %s" % exitstatus)
  else:
    error("Failed to connect to server %s" % servername)
    sys.exit(1)

def ni_exec_cmd():
  """Exec command on specified server non-interactively"""
  servername = config['servername']
  sshcmd = " ".join(config['sshcmd'])
  debug("Executing `%s` on server %s" % (sshcmd, servername))
  server = get_server(servername)
  if not server:
    error("Cannot find server %s in servers list" % servername)
    sys.exit(1)
  if ssh.accessible(server):
    stdout, stderr, exitstatus = ssh.exec_cmd(server, sshcmd)
    print("stdout = %s" % stdout)
    print("stderr = %s" % stderr)
    print("exitstatus = %s" % exitstatus)
  else:
    error("Failed to connect to server %s" % servername)
    sys.exit(1)

def put():
  """Copy file to server"""
  servername = config['servername']
  localpath  = config['localpath']
  remotepath = config['remotepath']
  debug("Copying '%s' to '%s' on server %s" % (localpath, remotepath, servername))
  server = get_server(servername)
  if not server:
    error("Cannot find server %s in servers list" % servername)
    sys.exit(1)
  if ssh.accessible(server):
    ssh.put(server, localpath, remotepath)
  else:
    error("Failed to connect to server %s" % servername)
    sys.exit(1)

def check_conn():
  """Checks connection between two servers"""
  from_server_name = config['server1']
  to_server_name = config['server2']
  port = config['port']

  from_server = get_server(from_server_name)
  to_server = get_server(to_server_name)
  if not from_server:
    error("Cannot find server %s in servers list" % from_server_name)
    sys.exit(1)
  if not to_server:
    error("Cannot find server %s in servers list" % to_server_name)
    sys.exit(1)
  if not ssh.accessible(from_server):
    error("Failed to connect to server %s" % from_server_name)
    sys.exit(1)
  if not ssh.accessible(to_server):
    error("Failed to connect to server %s" % to_server_name)
    sys.exit(1)
  ssh.serverd_start(from_server)
  ssh.serverd_start(to_server)

  status, result = ssh.serverd_cmd(to_server, 'listen tcp %s %s' % (to_server['address'], port))
  if status: # listen ok
    status, result = ssh.serverd_cmd(from_server, 'send tcp %s %s' % (to_server['address'], port))
    if status: # send ok
      print result
    else: # send failed
      print 'send failure: ' + result
  else: # listen failed
    print 'listen failure: ' + result

  ssh.serverd_stop(from_server)
  ssh.serverd_stop(to_server)

def _reports(server):
  '''Returns list of reports for server, ordered by time (first element is the last report): 
     [ {'file': ..., 'path': ..., 'time': ...}, ... ]'''
  name = server['name']
  path = os.path.join(config['reportsdir'], name)
  if not os.path.isdir(path):
    return []
  file_path_time = []
  for filename in os.listdir(path):
    if os.path.isfile(os.path.join(path, filename)):
      try: # time.strptime raises exception if filename does not match format
        filetime = time.mktime(time.strptime(filename,'%Y-%m-%d.%Hh%Mm%Ss'))
      except ValueError: # we will just ignore other files
        pass
      else:
        file_path_time.append({'file': filename,
                               'path': os.path.join(path, filename),
                               'time': filetime})
  return sorted(file_path_time, key=lambda elem: elem['time'], reverse = True)

def _last_report(server):
  reports = _reports(server)
  if len(reports) == 0:
    return None
  else:
    return yaml.load(open(reports[0]['path']))

def _get_report(server, reportname):
  reports = _reports(server)
  report = next((r for r in reports if r['file'] == reportname), None)
  if report is None:
    return None
  else:
    return yaml.load(open(report['path']))

def lastreport():
  servername = config['servername']
  server = get_server(servername)
  _print_report(_last_report(server))

def reports():
  servername = config['servername']
  server = get_server(servername)
  print '\n'.join(r['file'] for r in _reports(server))

def _is_equal(val1, val2):
  diff = _deepdiff(val1, val2)
  return (diff['old'] is None) and (diff['new'] is None)

def _deepdiff(val1, val2):
  diff = {'new': None, 'old': None}

  if isinstance(val1,(type(None),str,int,float,bool)):
    if not (val1 == val2):
      diff = {'new': val2, 'old': val1}

  # we are considering list as a set of different elements
  # algo is wrong if we have duplicates
  if isinstance(val1, list):
    diff['new'] = []
    diff['old'] = []
    for elem in val1:
      # try to find equal
      equal_elem = next((el for el in val2 if _is_equal(el, elem)), None)
      if equal_elem is None:
        diff['old'].append(elem)
    for elem in val2:
      # try to find equal
      equal_elem = next((el for el in val1 if _is_equal(el, elem)), None)
      if equal_elem is None:
        diff['new'].append(elem)

    if diff['new'] == []:
      diff['new'] = None
    if diff['old'] == []:
      diff['old'] = None

  if isinstance(val1, dict):
    diff['new'] = {}
    diff['old'] = {}
    for key in val1:
      if not (key in val2):
        diff['old'][key] = val1[key]
      else:
        oldval = val1[key]
        newval = val2[key]
        diffval = _deepdiff(oldval, newval)
        if not (diffval['old'] is None):
          diff['old'][key] = diffval['old']
        if not (diffval['new'] is None):
          diff['new'][key] = diffval['new']

    for key in val2:
      if not (key in val1):
        diff['new'][key] = val2[key]

    if diff['new'] == {}:
      diff['new'] = None
    if diff['old'] == {}:
      diff['old'] = None

  return diff

def reportdiff():
  server = get_server(config['servername'])
  report1 = _get_report(server, config['report1'])
  report2 = _get_report(server, config['report2'])
  diff = _deepdiff(report1, report2)
  print "       ###DIFF NEW###"
  _print_report(diff['new'])
  print "       ###DIFF OLD###"
  _print_report(diff['old'])

def _print_report(report):
  if report is None:
    print 'NO REPORT'
  else:
    # print all scalars
    for key in report:
      val = report[key]
      if isinstance(val,(type(None),str,int,float,bool)):
        print key + ', ' + str(val)
    if 'expect' in report:
      print '  Expectations'
      for e in report['expect']:
        print e + ', ' + report['expect'][e]
    if 'parameters' in report:
      print '  Parameters'
      parameters = deepcopy(report['parameters'])
      # trying to print in pretty order
      for key in ['hostname', 'OS', 'architecture', 'processors', 'ram', 'swap',
                  'partitions', 'blockdevs', 'time', 'time_utc', 
                  'ntp_service_status', 'uptime', 'iptables', 'selinux', 
                  'yum_repos', 'umask']:
        if key in parameters:
          val = parameters[key]
          if isinstance(val,(type(None),str,int,float,bool)):
            print key + ', ' + str(val)
          elif key == 'processors':
            count = val['count']
            frequency = val['frequency']
            print 'processors, ' + count + 'x' + frequency
          elif key == 'partitions':
            print 'partitions, ' + ' | '.join(p['device'] + ' ' + \
                                              p['fs_type'] + ' ' + \
                                              p['mountpoint'] + ' ' + \
                                              p['size'] for p in val)
          elif key == 'blockdevs':
            print 'blockdevs, ' + ' | '.join(d['type'] + ' ' + \
                                             d['name'] + ' ' + \
                                             d['size'] for d in val)
          else:
            info('wrong type for value: %s' % key)
          del parameters[key]
      # print all the rest (scalars only)
      for key in parameters:
        val = parameters[key]
        if isinstance(val,(type(None),str,int,float,bool)):
          print key + ', ' + str(val)
      if 'network' in parameters:
        print '  Network parameters'
        network = parameters['network']
        # print scalars
        for key in network:
          val = network[key]
          if isinstance(val,(type(None),str,int,float,bool)):
            print key + ', ' + str(val)
        if 'network_interfaces' in network:
          nic_ips = []
          network_interfaces = network['network_interfaces']
          for nic in network_interfaces:
            res_str = nic['name']
            for ip in nic['ip']:
              res_str += ' ' + ip['address'] + '/' + ip['network']
            nic_ips.append(res_str)
          print 'nics, ' + ' | '.join(nic_ips)
