#!/usr/bin/python

import os
import sys
import logging

from hwswa2.globals import config

def info(msg):
  config['logger'].info(msg)

def debug(msg):
  config['logger'].debug(msg)

def error(msg):
  sys.stderr.write(msg + '\n')

def init_logger():
  if not os.path.exists(os.path.dirname(config['logfile'])):
    os.makedirs(os.path.dirname(config['logfile']))
  logging.basicConfig(filename=config['logfile'], filemode = 'a', level=logging.INFO,
                      format="%(asctime)s %(levelname)s %(message)s")
  logging.captureWarnings(True)
  config['logger'] = logging.getLogger()
  if config['debug']:
    config['logger'].setLevel(logging.DEBUG)


