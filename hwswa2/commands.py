#!/usr/bin/python

from hwswa2.globals import config
import hwswa2.functions

def check():
  """Check only specified servers"""
  hwswa2.functions.debug("Checking servers: %s" % config['servernames'])
  allnames = [ elem['name'] for elem in config['servers'] ]
  for name in config['servernames']:
    if not name in allnames:
      hwswa2.functions.error("Cannot find server %s in servers list" % name)
      hwswa2.functions.exitapp(1)

def checkall():
  """Check all servers"""
  hwswa2.functions.debug("Checking all servers")

def prepare():
  """Prepare only specified servers"""
  hwswa2.functions.debug("Preparing servers: %s" % config['servernames'])
  allnames = [ elem['name'] for elem in config['servers'] ]
  for name in config['servernames']:
    if not name in allnames:
      hwswa2.functions.error("Cannot find server %s in servers list" % name)
      hwswa2.functions.exitapp(1)

def prepareall():
  """Prepare all servers"""
  hwswa2.functions.debug("Preparing all servers")

def shell():
  """Open interactive shell to specific server"""
  hwswa2.functions.debug("Opening interactive shell to server %s" % config['servername'])
  allnames = [ elem['name'] for elem in config['servers'] ]
  if not config['servername'] in allnames:
    hwswa2.functions.error("Cannot find server %s in servers list" % config['servername'])
    hwswa2.functions.exitapp(1)

