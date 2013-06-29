#!/usr/bin/python

from hwswa2.functions import read_configuration, read_servers, read_networks, run_command
from hwswa2.log import info, debug, error, init_logger

def main():
  read_configuration()
  init_logger()
  info("Application started")
  read_servers()
  read_networks()
  run_command()
  info("Application finished")

if __name__ == '__main__':
  main()

