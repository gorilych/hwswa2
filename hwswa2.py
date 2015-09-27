#!/usr/bin/env python
import logging
import os
import sys

import hwswa2
from hwswa2.functions import read_configuration, read_servers, read_networks, run_subcommand


def init_logger():
    logdir = os.path.dirname(os.path.abspath(hwswa2.config['logfile']))
    if not os.path.exists(logdir):
        os.makedirs(logdir)
    logging.basicConfig(filename=hwswa2.config['logfile'], filemode='a', level=logging.INFO,
                        format="%(asctime)s %(levelname)s " +
                               "[%(threadName)s:%(name)s.%(funcName)s():%(lineno)d] " +
                               "%(message)s")
    if sys.hexversion >= 0x2070000:
        logging.captureWarnings(True)
    logger = logging.getLogger("hwswa2")
    if hwswa2.config['debug']:
        logger.setLevel(logging.DEBUG)
    return logger


def main():
    read_configuration()
    logger = init_logger()
    logger.debug("Application started")
    logger.debug("Configuration: %s" % hwswa2.config)
    read_servers()
    read_networks()
    run_subcommand()
    logger.debug("Application finished")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted")
