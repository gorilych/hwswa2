#!/usr/bin/python

import os, sys
import argparse
import logging
from configobj import ConfigObj
from validate import Validator
import yaml

from hwswa2.globals import apppath, configspec, config
from logging import info, debug, error
import hwswa2.subcommands as subcommands
from hwswa2.ssh import cleanup

__version__ = '0.01'

def read_servers():
  config['servers']  = yaml.load(open(config['serversfile']))['servers']
  debug("Read info from servers file: %s" % config['servers'])
  # check for dups
  names = [ elem['name'] for elem in config['servers'] ]
  if len(names) != len(set(names)):
    error("Found duplicates in servers file! Exiting ...")
    sys.exit(1)

def read_networks():
  config['networks'] = yaml.load(open(config['networksfile']))['networks']
  debug("Read info from networks file: %s" % config['networks'])

def run_subcommand():
  try:
    config['subcommand']()
  finally:
    for server in config['servers']:
      cleanup(server)

def init_logger():
  if not os.path.exists(os.path.dirname(config['logfile'])):
    os.makedirs(os.path.dirname(config['logfile']))
  logging.basicConfig(filename=config['logfile'], filemode = 'a', level=logging.INFO,
      format="%(asctime)s %(levelname)s %(module)s.%(funcName)s: %(message)s")
  if sys.hexversion >= 0x2070000: logging.captureWarnings(True)
  config['logger'] = logging.getLogger()
  if config['debug']:
    config['logger'].setLevel(logging.DEBUG)
  logging.getLogger("paramiko").setLevel(logging.WARNING)
  # define a Handler which writes INFO messages or higher to the sys.stderr
  console = logging.StreamHandler()
  console.setLevel(logging.INFO)
  # set a format which is simpler for console use
  formatter = logging.Formatter('%(message)s')
  # tell the handler to use this format
  console.setFormatter(formatter)
  # add the handler to the root logger
  config['logger'].addHandler(console)


##################################
### Reads configuration from command line args and main.cfg
def read_configuration():
  ### Parsing commandline options
  parser = argparse.ArgumentParser(
    prog='hwswa2', argument_default=argparse.SUPPRESS,
    description='HWSWA: tool for automatization of hardware/software check')
  
  parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
  parser.add_argument('-c', '--config',   help='path to config file', dest='configfile')
  parser.add_argument('-s', '--servers',  help='path to servers file', dest='serversfile')
  parser.add_argument('-n', '--networks', help='path to networks file', dest='networksfile')
  parser.add_argument('-l', '--log',      help='path to log file', dest='logfile')
  parser.add_argument('-r', '--reports',  help='directory to store reports', dest='reportsdir')
  parser.add_argument('-d', '--debug',    help='enable debug', action='store_true')
  
  subparsers = parser.add_subparsers(title='Subcommands', help= 'Run `hwswa2 <subcommand> -h` for usage')

  parser_check = subparsers.add_parser('check', help='check specific servers')
  parser_check.add_argument('servernames', nargs='+', help='server name to check', metavar='server')
  parser_check.set_defaults(subcommand=subcommands.check)

  parser_prepare = subparsers.add_parser('prepare', help='prepare specific servers')
  parser_prepare.add_argument('servernames', nargs='+', help='server name to prepare', metavar='server')
  parser_prepare.set_defaults(subcommand=subcommands.prepare)

  parser_checkall = subparsers.add_parser('checkall', help='check all servers')
  parser_checkall.set_defaults(subcommand=subcommands.checkall)

  parser_prepareall = subparsers.add_parser('prepareall', help='prepare all servers')
  parser_prepareall.set_defaults(subcommand=subcommands.prepareall)

  parser_shell = subparsers.add_parser('shell', help='open shell to server')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.set_defaults(subcommand=subcommands.shell)

  parser_shell = subparsers.add_parser('reboot', help='reboot server and check time')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.set_defaults(subcommand=subcommands.reboot)

  parser_shell = subparsers.add_parser('exec', help='execute command interactively')
  parser_shell.add_argument('-t', '--tty', help='enable pseudo-tty allocation', action='store_true')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.add_argument('sshcmd', nargs=argparse.REMAINDER, metavar='cmd')
  parser_shell.set_defaults(subcommand=subcommands.exec_cmd)

  parser_shell = subparsers.add_parser('ni_exec', help='execute command non-interactively')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.add_argument('sshcmd', nargs=argparse.REMAINDER, metavar='cmd')
  parser_shell.set_defaults(subcommand=subcommands.ni_exec_cmd)

  parser_shell = subparsers.add_parser('put', help='copy file to server')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.add_argument('localpath')
  parser_shell.add_argument('remotepath')
  parser_shell.set_defaults(subcommand=subcommands.put)

  parser_shell = subparsers.add_parser('firewall', help='check connection from server1 to server2 on port')
  parser_shell.add_argument('server1')
  parser_shell.add_argument('server2')
  parser_shell.add_argument('port')
  parser_shell.set_defaults(subcommand=subcommands.check_conn)

  parser_shell = subparsers.add_parser('lastreport')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.set_defaults(subcommand=subcommands.lastreport)

  parser_shell = subparsers.add_parser('reports')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.set_defaults(subcommand=subcommands.reports)

  args = parser.parse_args()
    
  ### Parse configuration file
  if hasattr(args, 'configfile'):
    config['configfile'] = args.configfile
  
  # add apppath definition to configuration file and read configobj from it
  f = open(config['configfile'])
  config_lines = f.readlines()
  f.close()
  config_lines.insert(0, 'apppath=' + apppath)
  config_from_file = ConfigObj(config_lines, interpolation='Template', configspec=configspec)
  
  # validation is required to convert values to correct type
  # say, from string to boolean
  val = Validator()
  config_from_file.validate(val)
  
  # update defaults by values from configuration file
  config.update(config_from_file.dict()) 
  
  # update defaults by values from command line args
  # values from command line take precedence over configuration file options
  config.update(vars(args))

  # create reportsdir
  if not os.path.exists(config['reportsdir']):
    os.makedirs(config['reportsdir'])

  # set global ssh timeout
  import hwswa2.ssh as ssh
  ssh.ssh_timeout = config['ssh_timeout']


