import os
import sys
from configobj import ConfigObj

__all__ = ['config', 'configspec']

if getattr(sys, 'frozen', False):
    # pyinstaller binary
    _apppath = os.path.dirname(sys.executable)
    _res_path = sys._MEIPASS
elif __file__:
    # script
    _apppath = os.path.abspath(os.path.dirname(os.path.realpath(sys.argv[0])))
    _res_path = _apppath + os.sep + 'resources'
else:
    # something else
    _apppath = '.'
    _res_path = _apppath + os.sep + 'resources'

_configdir = _apppath + os.sep + 'config'
_logdir = _apppath + os.sep + 'logs'
_configfile = _configdir + os.sep + 'main.cfg'

configspec = ConfigObj(_inspec=True, list_values=False)
configspec['resources'] = "string(default='" + _res_path + "')"
configspec['serversfile'] = "string(default='" + _configdir + os.sep + "servers.yaml')"
configspec['networksfile'] = "string(default='" + _configdir + os.sep + "networks.yaml')"
configspec['logfile'] = "string(default='" + _logdir + os.sep + "hwswa2.log')"
configspec['reportsdir'] = "string(default='" + _logdir + os.sep + "reports')"
configspec['checksdir'] = "string(default='" + _apppath + os.sep + "checks')"
configspec['rscriptdir'] = "string(default='" + _apppath + os.sep + "checks" + os.sep + "remote-scripts')"
configspec['debug'] = 'boolean(default=False)'
configspec['remote_debug'] = 'boolean(default=False)'
configspec['ssh_timeout'] = 'integer(0,7200,default=30)'
configspec['reboot_timeout'] = 'integer(5,7200,default=300)'
configspec['firewall'] = {
    'send_timeout': 'float(0, 99, default=1)',
    'max_open_sockets': 'integer(1,10000,default=100)',
    'report_period': 'integer(1,10000,default=10)',
    'max_failures': 'integer(0,10000,default=10)',
    'max_closed_ports': 'integer(0,10000,default=500)',
    }
configspec['check'] = {
    'report_period': 'integer(1,10000,default=5)',
    }

config = {'configfile': _configfile}
