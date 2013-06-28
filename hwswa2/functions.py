#!/usr/bin/python

import argparse
import logging
from configobj import ConfigObj
from validate import Validator
import yaml

__version__ = '0.01'

from hwswa2.globals import (apppath,configspec,config,exitcode)

def exitapp():
  exit(exitcode)

def info(msg):
  config['logger'].info(msg)

def debug(msg):
  config['logger'].debug(msg)

def read_servers():
  config['servers']  = yaml.load(open(config['serversfile']))['servers']
  debug("Read info from servers file: %s" % config['servers'])

def read_networks():
  config['networks'] = yaml.load(open(config['networksfile']))['networks']
  debug("Read info from networks file: %s" % config['networks'])

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
  parser_check.set_defaults(command=check)

  parser_prepare = subparsers.add_parser('prepare', help='prepare specific servers')
  parser_prepare.add_argument('servernames', nargs='+', help='server name to prepare', metavar='server')
  parser_prepare.set_defaults(command=prepare)

  parser_checkall = subparsers.add_parser('checkall', help='check all servers', add_help=False)
  parser_checkall.set_defaults(command=checkall)

  parser_prepareall = subparsers.add_parser('prepareall', help='prepare all servers', add_help=False)
  parser_prepareall.set_defaults(command=prepareall)
  
  args = parser.parse_args()
    
  ### Parse configuration file
  if hasattr(args, 'configfile'):
    config['configfile'] = args.configfile
  
  # add apppath definition to configuration file and read configobj from it
  with open(config['configfile']) as f:
      config_lines = f.readlines()
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
  return config  

##################################
### Check only specified servers
def check():
  debug("Checking servers: %s" % config['servernames'])

##################################
### Check all servers
def checkall():
  debug("Checking all servers")

##################################
### Prepare only specified servers
def prepare():
  debug("Preparing servers: %s" % config['servernames'])

##################################
### Prepare all servers
def prepareall():
  debug("Preparing all servers")



##################################
### Initializes logger
def init_logger():
  logging.basicConfig(filename=config['logfile'], filemode = 'a', level=logging.INFO,
                      format="%(asctime)s %(levelname)s %(message)s")
  config['logger'] = logging.getLogger()
  if config['debug']:
    config['logger'].setLevel(logging.DEBUG)


