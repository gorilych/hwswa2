#!/usr/bin/python

import os
import argparse
import logging
from configobj import ConfigObj
from validate import Validator
import yaml

from hwswa2.globals import apppath, configspec, config
from hwswa2.log import info, debug, error
import hwswa2.commands as commands

__version__ = '0.01'

def read_servers():
  config['servers']  = yaml.load(open(config['serversfile']))['servers']
  debug("Read info from servers file: %s" % config['servers'])
  # check for dups
  names = [ elem['name'] for elem in config['servers'] ]
  if len(names) != len(set(names)):
    error("Found duplicates in servers file! Exiting ...")
    exit(1)

def read_networks():
  config['networks'] = yaml.load(open(config['networksfile']))['networks']
  debug("Read info from networks file: %s" % config['networks'])
  # check for dups
  names = [ elem['name'] for elem in config['networks'] ]
  if len(names) != len(set(names)):
    error("Found duplicates in networks file! Exiting ...")
    exit(1)

def run_command():
  config['command']()

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
  
  subparsers = parser.add_subparsers(title='Commands')

  parser_check = subparsers.add_parser('check', help='check specific servers')
  parser_check.add_argument('servernames', nargs='+', help='server name to check', metavar='server')
  parser_check.set_defaults(command=commands.check)

  parser_prepare = subparsers.add_parser('prepare', help='prepare specific servers')
  parser_prepare.add_argument('servernames', nargs='+', help='server name to prepare', metavar='server')
  parser_prepare.set_defaults(command=commands.prepare)

  parser_checkall = subparsers.add_parser('checkall', help='check all servers', add_help=False)
  parser_checkall.set_defaults(command=commands.checkall)

  parser_prepareall = subparsers.add_parser('prepareall', help='prepare all servers', add_help=False)
  parser_prepareall.set_defaults(command=commands.prepareall)

  parser_shell = subparsers.add_parser('shell', help='open shell to server')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.set_defaults(command=commands.shell)

  parser_shell = subparsers.add_parser('reboot', help='reboot server and check time')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.set_defaults(command=commands.reboot)

  parser_shell = subparsers.add_parser('exec', help='execute command interactively')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.add_argument('sshcmd', nargs=argparse.REMAINDER, metavar='cmd')
  parser_shell.set_defaults(command=commands.exec_cmd)

  parser_shell = subparsers.add_parser('_exec', help='execute command non-interactively')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.add_argument('sshcmd', nargs=argparse.REMAINDER, metavar='cmd')
  parser_shell.set_defaults(command=commands._exec_cmd)

  parser_shell = subparsers.add_parser('put', help='copy file to server')
  parser_shell.add_argument('servername', metavar='server')
  parser_shell.add_argument('localpath')
  parser_shell.add_argument('remotepath')
  parser_shell.set_defaults(command=commands.put)

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


