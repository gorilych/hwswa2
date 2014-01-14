#!/usr/bin/python

from hwswa2.functions import read_configuration, read_servers, read_networks, run_subcommand, init_logger
from logging import info, debug, error

def main():
  read_configuration()
  init_logger()
  debug("Application started")
  read_servers()
  read_networks()
  run_subcommand()
  debug("Application finished")

if __name__ == '__main__':
  main()

