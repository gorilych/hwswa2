#!/usr/bin/env python
import logging
import os
import sys

from hwswa2.functions import read_configuration, read_servers, read_networks, run_subcommand
from hwswa2.globals import config


def init_logger():
    if not os.path.exists(os.path.dirname(config['logfile'])):
        os.makedirs(os.path.dirname(config['logfile']))
    logging.basicConfig(filename=config['logfile'], filemode='a', level=logging.INFO,
                        format="%(asctime)s %(levelname)s " +
                               "[%(threadName)s:%(name)s.%(funcName)s():%(lineno)d] " +
                               "%(message)s")
    if sys.hexversion >= 0x2070000:
        logging.captureWarnings(True)
    logger = logging.getLogger("hwswa2")
    if config['debug']:
        logger.setLevel(logging.DEBUG)
    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logger.addHandler(console)
    return logger


def main():
    read_configuration()
    logger = init_logger()
    logger.debug("Application started")
    logger.debug("Configuration: %s" % config)
    read_servers()
    read_networks()
    run_subcommand()
    logger.debug("Application finished")


if __name__ == '__main__':
    main()
