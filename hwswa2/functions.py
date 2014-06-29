import os
import sys
import re
import argparse
import logging
from configobj import ConfigObj
from validate import Validator
import yaml

from hwswa2.globals import apppath, configspec, config
from hwswa2.auxiliary import merge_config
from hwswa2.server.factory import servers_context
import hwswa2.subcommands as subcommands
from hwswa2.aliases import AliasedSubParsersAction

__version__ = '0.3.0'

logger = logging.getLogger(__name__)


def read_servers():
    config['servers'] = yaml.load(open(config['serversfile']))['servers']
    logger.debug("Read info from servers file: %s" % config['servers'])
    # check for dups
    names = [elem['name'] for elem in config['servers']]
    if len(names) != len(set(names)):
        logger.error("Found duplicates in servers file! Exiting ...")
        sys.exit(1)


def read_networks():
    logger.debug("Read networks from cli: %s" % config['networks'])
    networks_from_file = yaml.load(open(config['networksfile']))['networks']
    logger.debug("Read info from networks file: %s" % networks_from_file)
    config['networks'].extend(networks_from_file)
    logger.debug("Resulting networks: %s" % config['networks'])


def run_subcommand():
    with servers_context(config['servers'],
                         config['checksdir'],
                         config['reportsdir'],
                         config['rscriptdir']):
        config['subcommand']()


def _network(string):
    """'Convert network:addr/prefix' to {name: 'network', address: 'addr', prefix: 'prefix'}"""
    regex = re.compile("^(\w+):((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})$")
    match = regex.match(string)
    if not match:
        raise argparse.ArgumentTypeError("Network not in format name:addr/prefix: %s" % string)
    else:
        return {'name': match.group(1), 'address': match.group(2), 'prefix': match.group(3)}


def read_configuration():
    """Reads configuration from command line args and main.cfg"""
    ### Parsing commandline options
    parser = argparse.ArgumentParser(
        prog='hwswa2', argument_default=argparse.SUPPRESS,
        description='HWSWA: tool for automatization of hardware/software check')
    parser.register('action', 'parsers', AliasedSubParsersAction)

    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-c', '--config', help='path to config file', dest='configfile')
    parser.add_argument('-s', '--servers', help='path to servers file', dest='serversfile')
    parser.add_argument('-n', '--networks', help='path to networks file', dest='networksfile')
    parser.add_argument('-k', '--network', help='network in format name:addr/prefix',
                        type=_network, action='append', metavar='NETWORK', dest='networks',
                        default=[])
    parser.add_argument('-l', '--log', help='path to log file', dest='logfile')
    parser.add_argument('-r', '--reports', help='directory to store reports', dest='reportsdir')
    parser.add_argument('-d', '--debug', help='enable debug', action='store_true')

    subparsers = parser.add_subparsers(title='Subcommands', help='Run `hwswa2 <subcommand> -h` for usage')

    subparser = subparsers.add_parser('check', help='check specific servers', aliases=('c',))
    group = subparser.add_mutually_exclusive_group(required=False)
    group.add_argument('--with-reboot', help='perform reboot check',
                       dest='check_reboot', action='store_true', default=argparse.SUPPRESS)
    group.add_argument('--wo-reboot', help='skip reboot check',
                       dest='check_reboot', action='store_false', default=argparse.SUPPRESS)
    subparser.add_argument('servernames', nargs='+', help='server name to check', metavar='server')
    subparser.set_defaults(subcommand=subcommands.check)

    subparser = subparsers.add_parser('prepare', help='prepare specific servers', aliases=('p',))
    subparser.add_argument('servernames', nargs='+', help='server name to prepare', metavar='server')
    subparser.set_defaults(subcommand=subcommands.prepare)

    subparser = subparsers.add_parser('checkall', help='check all servers', aliases=('ca',))
    subparser.set_defaults(subcommand=subcommands.checkall)

    subparser = subparsers.add_parser('prepareall', help='prepare all servers', aliases=('pa',))
    subparser.set_defaults(subcommand=subcommands.prepareall)

    subparser = subparsers.add_parser('shell', help='open shell to server', aliases=('s',))
    subparser.add_argument('servername', metavar='server')
    subparser.set_defaults(subcommand=subcommands.shell)

    subparser = subparsers.add_parser('reboot', help='reboot server(s) and measure reboot time')
    subparser.add_argument('servernames', nargs='+', help='servers to reboot', metavar='server')
    subparser.set_defaults(subcommand=subcommands.reboot)

    subparser = subparsers.add_parser('exec', help='execute command interactively', aliases=('e',))
    subparser.add_argument('-t', '--tty', help='enable pseudo-tty allocation', action='store_true')
    subparser.add_argument('servername', metavar='server')
    subparser.add_argument('sshcmd', nargs=argparse.REMAINDER, metavar='cmd')
    subparser.set_defaults(subcommand=subcommands.exec_cmd)

    subparser = subparsers.add_parser('ni_exec', help='execute command non-interactively', aliases=('ne',))
    subparser.add_argument('servername', metavar='server')
    subparser.add_argument('sshcmd', nargs=argparse.REMAINDER, metavar='cmd')
    subparser.set_defaults(subcommand=subcommands.ni_exec_cmd)

    subparser = subparsers.add_parser('put', help='copy file to server', aliases=('p',))
    subparser.add_argument('servername', metavar='server')
    subparser.add_argument('localpath')
    subparser.add_argument('remotepath')
    subparser.set_defaults(subcommand=subcommands.put)

    subparser = subparsers.add_parser('get', help='copy file from server', aliases=('g',))
    subparser.add_argument('servername', metavar='server')
    subparser.add_argument('remotepath')
    subparser.add_argument('localpath')
    subparser.set_defaults(subcommand=subcommands.get)

    subparser = subparsers.add_parser('firewall', help='check connections between servers', aliases=('f',))
    subparser.add_argument('servernames', nargs='+', help='server name to check', metavar='server')
    subparser.set_defaults(subcommand=subcommands.firewall)

    subparser = subparsers.add_parser('lastreport', help='show last report for the server', aliases=('lr',))
    subparser.add_argument('-r', '--raw', help='show raw file content', action='store_true')
    subparser.add_argument('servername', metavar='server')
    subparser.set_defaults(subcommand=subcommands.lastreport)

    subparser = subparsers.add_parser('report', help='show particular report for server', aliases=('r',))
    subparser.add_argument('-r', '--raw', help='show raw file content', action='store_true')
    subparser.add_argument('servername', metavar='server')
    subparser.add_argument('reportname', metavar='report')
    subparser.set_defaults(subcommand=subcommands.show_report)

    subparser = subparsers.add_parser('reports', help='show all generated reports for the server', aliases=('rs',))
    subparser.add_argument('servername', metavar='server')
    subparser.set_defaults(subcommand=subcommands.reports)

    subparser = subparsers.add_parser('reportdiff', help='show difference between reports', aliases=('rd',))
    subparser.add_argument('servername', metavar='server')
    subparser.add_argument('oldreport')
    subparser.add_argument('newreport')
    subparser.set_defaults(subcommand=subcommands.reportdiff)

    args = parser.parse_args()

    ### Parse configuration file
    if hasattr(args, 'configfile'):
        config['configfile'] = args.configfile

    # add apppath definition to configuration file and read configobj from it
    f = open(config['configfile'])
    config_lines = f.readlines()
    f.close()
    config_lines.insert(0, 'apppath=' + apppath)
    config_from_file = ConfigObj(config_lines, interpolation='Template', configspec=configspec)

    # validation is required to convert values to correct type
    # say, from string to boolean
    val = Validator()
    config_from_file.validate(val)

    # update defaults by values from configuration file
    merge_config(config, config_from_file.dict())

    # update defaults by values from command line args
    # values from command line take precedence over configuration file options
    config.update(vars(args))

    # create reportsdir
    if not os.path.exists(config['reportsdir']):
        os.makedirs(config['reportsdir'])

    # create logsdir
    if not os.path.exists(config['logdir']):
        os.makedirs(config['logdir'])

    # set global ssh timeout
    import hwswa2.server.linux

    hwswa2.server.linux.TIMEOUT = config['ssh_timeout']


