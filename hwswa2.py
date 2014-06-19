#!/usr/bin/env python

from hwswa2.functions import read_configuration, read_servers, read_networks, run_subcommand, init_logger
from logging import info, debug, error
from hwswa2.globals import config

def main():
    read_configuration()
    init_logger()
    debug("Application started")
    debug("Configuration: %s" % config)
    read_servers()
    read_networks()
    run_subcommand()
    debug("Application finished")


if __name__ == '__main__':
    main()

