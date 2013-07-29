#################################
##### Global parameters

import os
from configobj import ConfigObj

binpath      = os.getenv('BINPATH')
apppath      = os.path.dirname(binpath)

configspec = ConfigObj(["debug=boolean()",
                        "check_reboot=boolean()"],
                       _inspec=True, list_values=False)

# default parameters
config   = { 'configdir'    : apppath + '/' + 'config',
             'logdir'       : apppath + '/' + 'logs',
             'checksdir'    : apppath + '/' + 'checks',
             'debug'        : False,
             'check_reboot' : False,
             'ssh_timeout'  : 20 }
config['configfile']   = config['configdir'] + '/' + 'main.cfg'
config['serversfile']  = config['configdir'] + '/' + 'servers.yaml'
config['networksfile'] = config['configdir'] + '/' + 'networks.yaml'
config['logfile']      = config['logdir']    + '/' + 'hwswa2.log'
config['reportsdir']   = config['logdir']    + '/' + 'reports'
config['rscriptdir']   = config['checksdir'] + '/' + 'remote-scripts'

exitcode = 0 

