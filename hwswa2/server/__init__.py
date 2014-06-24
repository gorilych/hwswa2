import logging
import os
import yaml
import time

from hwswa2.server.report import Report, ReportException

logger = logging.getLogger(__name__)

# default timeout value for all operations
TIMEOUT = 30
REBOOT_TIMEOUT = 300

class Server(object):

    def __init__(self, name, account, address,
                 role=None, port=None, ostype=None, dontcheck=False, gateway=None, expect=None):
        self.name = name
        self.ostype = ostype
        self.role = role
        if isinstance(role, list):
            self.roles = role
        elif role is None:
            self.roles = []
        else:
            self.roles = [role, ]
        self.account = account
        self.address = address
        self.port = port
        self.dontcheck = dontcheck
        #gateway should be Server object
        self.gateway = gateway
        self.expect = expect
        self.reports = []
        self._last_connection_error = None
        self._accessible = None
        # list of temporary dirs/files
        self._tmp = []
        # remote agent
        self._agent = None
        # ordered list of reports, last generated report goes first

    @classmethod
    def fromserverdict(cls, serverdict):
        """Instantiate from server dict which can be read from servers.yaml"""
        # these properties can be defined in servers.yaml
        properties = ['account', 'name', 'role', 'address', 'port', 'ostype', 'expect', 'dontcheck', 'gateway']
        initargs = {}
        for key in properties:
            if key in serverdict:
                initargs[key] = serverdict[key]
        return cls(**initargs)

    def __str__(self):
        return "server %s" % self.name

    def last_connection_error(self):
        return self._last_connection_error

    def accessible(self, retry=False):
        if self._accessible is None or retry:
            if self._connect(reconnect=retry):
                self._accessible = True
            else:
                self._accessible = False
        return self._accessible

    def _connect(self, reconnect=False, timeout=None):
        """Initiates connection to the server.

            Returns true if connection was successful.
        """
        raise NotImplemented

    def read_reports(self, reportsdir):
        """Read server reports"""
        path = os.path.join(reportsdir, self.name)
        timeformat = '%Y-%m-%d.%Hh%Mm%Ss'
        reports = []
        if os.path.isdir(path):
            for filename in os.listdir(path):
                filepath = os.path.join(path, filename)
                if os.path.isfile(filepath):
                    try:
                        filetime = time.mktime(time.strptime(filename, timeformat))
                        reports.append(Report(yamlfile=filepath, time=filetime))
                    except ValueError as ve:
                        logger.debug("File name %s is not in format %s: %s" % (filename, timeformat, ve))
                    except ReportException as re:
                        logger.debug("Error reading report from file %s: %s" % (filename, re))
            self.reports = sorted(reports, key=lambda report: report.time, reverse = True)

    def list_reports(self):
        for report in self.reports:
            print(report.filename())

    def report(self, name):
        return next((r for r in self.reports if name == r.filename()), None)

    def last_report(self):
        if self.reports:
            return self.reports[0]
        else:
            return None

    def last_finished_report(self):
        return next((r for r in self.reports if r.finished()), None)

    def get_nw_ips(self, networks=None):
        """Collect network -> ip into self.nw_ips from last finished report
        
        Returns true on success
        """
        lfr = self.last_finished_report()
        if lfr is None:
            logger.error("No finished reports for %s" % self)
            return False
        else:
            if networks is not None:
                lfr.fix_networks(networks)
            report = lfr.data
            if not ('parameters' in report and
                    'network' in report['parameters'] and
                    'network_interfaces' in report['parameters']['network']):
                logger.error("Last finished report for %s does not contain nic info")
                return False
            else:
                nw_ips = {}
                nics = report['parameters']['network']['network_interfaces']
                for nic in nics:
                    ips = nic['ip']
                    for ip in ips:
                        nw_ips[ip['network']] = ip['address']
                if nw_ips == {}:
                    logger.error('Found no IPs for %s' % self)
                    return False
                else:
                    self.nw_ips = nw_ips
                    return True


class ServerException(Exception):
    """Base class for server exceptions"""
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class TunnelException(ServerException):
    """Exception for tunnel creation"""
    pass


class TimeoutException(ServerException):
    """Timeout exception for server operations

    Attributes:
        msg - error message
        **kwargs - additional information, f.e. partial result of function execution
    """
    def __init__(self, msg, **kwargs):
        self.msg = msg
        self.details = kwargs

    def __str__(self):
        return self.msg
