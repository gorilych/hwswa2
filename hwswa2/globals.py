import os
import sys
from configobj import ConfigObj

if getattr(sys, 'frozen', False):
    apppath = os.path.dirname(sys.executable)
elif __file__:
    apppath = os.path.abspath(os.path.dirname(os.path.realpath(sys.argv[0])))

configspec = ConfigObj(_inspec=True, list_values=False)
configspec['debug'] = 'boolean()'
configspec['check_reboot'] = 'boolean()'
configspec['ssh_timeout'] = 'integer(0,7200,default=30)'
configspec['firewall'] = {
    'send_timeout': 'float(0, 99, default=1)',
    'max_open_sockets': 'integer(1,10000,default=100)',
    }

# default parameters
config = {'configdir': apppath + '/' + 'config',
          'logdir': apppath + '/' + 'logs',
          'checksdir': apppath + '/' + 'checks',
          'debug': False,
          'check_reboot': False,
          'ssh_timeout': 30}
config['configfile'] = config['configdir'] + '/' + 'main.cfg'
config['serversfile'] = config['configdir'] + '/' + 'servers.yaml'
config['networksfile'] = config['configdir'] + '/' + 'networks.yaml'
config['logfile'] = config['logdir'] + '/' + 'hwswa2.log'
config['reportsdir'] = config['logdir'] + '/' + 'reports'
config['rscriptdir'] = config['checksdir'] + '/' + 'remote-scripts'
config['firewall'] = {
    'send_timeout': 1,
    'max_open_sockets': 100,
    }

exitcode = 0 

