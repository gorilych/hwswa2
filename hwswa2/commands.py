#!/usr/bin/python

from hwswa2.globals import config
from hwswa2.log import info, debug, error

def check():
  """Check only specified servers"""
  debug("Checking servers: %s" % config['servernames'])
  allnames = [ elem['name'] for elem in config['servers'] ]
  for name in config['servernames']:
    if not name in allnames:
      error("Cannot find server %s in servers list" % name)
      exit(1)

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
  debug("Opening interactive shell to server %s" % config['servername'])
  allnames = [ elem['name'] for elem in config['servers'] ]
  if not config['servername'] in allnames:
    error("Cannot find server %s in servers list" % config['servername'])
    exit(1)

