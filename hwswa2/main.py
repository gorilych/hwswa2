#!/usr/bin/python

from hwswa2.functions import ( read_configuration, init_logger, info, debug,
                               read_servers, read_networks, run_command, exitapp )

def main():
  read_configuration()
  init_logger()
  info("Application started")
  read_servers()
  read_networks()
  run_command()
  info("Application finished")
  exitapp()

if __name__ == '__main__':
  main()

