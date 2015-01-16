import logging
import os
import time

import hwswa2.auxiliary as aux
import hwswa2
from hwswa2.server.report import Report, ReportException
from hwswa2.server.role import RoleCollection

__all__ = ['Server', 'TIMEOUT', 'REBOOT_TIMEOUT', 'ServerException',
           'TunnelException', 'TimeoutException', 'FirewallException']

logger = logging.getLogger(__name__)

# default timeout value for all operations
TIMEOUT = 30
REBOOT_TIMEOUT = 300


class Server(object):

    time_format = '%Y-%m-%d.%Hh%Mm%Ss'

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
        self._rolecollection = None
        self.account = account
        self.address = address
        self.port = port
        self.dontcheck = dontcheck
        #gateway should be Server object
        self.gateway = gateway
        self.expect = expect
        # ordered list of reports, last generated report goes first
        self._reports = None
        # {network: ip, ...}
        self._nw_ips = None
        self.parameters = None
        self.param_failures = None
        self.param_check_status = "not started"
        self.param_check_time = None
        self.report = None
        self.check_reboot_result = None
        self._last_connection_error = None
        self._accessible = None
        # list of temporary dirs/files
        self._tmp = []
        # remote agent
        self._agent = None
        self.requirement_failures = []
        self.requirement_successes = []

    @property
    def reports(self):
        if self._reports is None:
            logger.debug("Postponed initialization of reports for %s started" % self)
            self._read_reports()
        return self._reports

    @property
    def nw_ips(self):
        if self._nw_ips is None:
            logger.debug("Postponed initialization of network->ip list for %s started" % self)
            self._find_nw_ips()
        return self._nw_ips

    @property
    def rolecollection(self):
        if self._rolecollection is None:
            logger.debug("Postponed initialization of rolecollection for %s started" % self)
            self._rolecollection = RoleCollection(self.roles)
        return self._rolecollection

    def _connect(self, reconnect=False, timeout=None):
        """Initiates connection to the server.

            Returns true if connection was successful.
        """
        raise NotImplemented

    @classmethod
    def fromserverdict(cls, serverdict):
        """Instantiate from server dict which can be read from servers.yaml"""
        # these properties can be defined in servers.yaml
        properties = ['account', 'name', 'role', 'address', 'port', 'ostype', 'expect', 'dontcheck', 'gateway']
        initargs = {}
        for key in properties:
            if key in serverdict:
                initargs[key] = serverdict[key]
        if 'dontcheck' in initargs:
            initargs['dontcheck'] = True
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

    def _read_reports(self):
        """Read server reports"""
        self._reports = []
        reports_dir = hwswa2.config.get('reportsdir')
        if not reports_dir:
            return
        path = os.path.join(reports_dir, self.name)
        timeformat = Server.time_format
        reports = []
        if os.path.isdir(path):
            for filename in os.listdir(path):
                filepath = os.path.join(path, filename)
                if os.path.isfile(filepath):
                    try:
                        filetime = time.mktime(time.strptime(filename, timeformat))
                        reports.append(Report(yamlfile=filepath, time=filetime))
                    except ValueError as ve:
                        logger.error("File name %s is not in format %s: %s" % (filename, timeformat, ve))
                    except ReportException as re:
                        logger.error("Error reading report from file %s: %s" % (filename, re))
            self._reports = sorted(reports, key=lambda report: report.time, reverse=True)

    def list_reports(self):
        for report in self.reports:
            print(report.filename())

    def get_report(self, name):
        return next((r for r in self.reports if name == r.filename()), None)

    def last_report(self):
        if self.reports:
            return self.reports[0]
        else:
            return None

    def last_finished_report(self):
        return next((r for r in self.reports if r.finished()), None)

    def _find_nw_ips(self):
        """Collect network -> ip into self.nw_ips from last finished report
        
        Returns true on success
        """
        self._nw_ips = {}
        lfr = self.last_finished_report()
        if lfr is None:
            logger.info("No finished reports for %s" % self)
            return False
        else:
            self._nw_ips = lfr.get_nw_ips()
            if self._nw_ips == {}:
                logger.info('Found no IPs for %s' % self)
                return False
            else:
                return True

    def agent_start(self):
        """Starts remote agent on server"""
        raise NotImplemented

    def agent_stop(self):
        """Stops remote agent on server"""
        raise NotImplemented

    def agent_cmd(self, cmd):
        """Sends command to remote agent and returns tuple (status, result)"""
        raise NotImplemented

    def param_cmd(self, cmd):
        """Execute cmd in prepared environment to obtain some server parameter

        :param cmd: raw command to execute
        :return: (status, output, failure)
        """
        raise NotImplemented

    def param_script(self, script):
        """Execute script in prepared environment to obtain some server parameter

        :param script: script content
        :return: (status, output, failure)
        """
        raise NotImplemented

    def check_internet_access(self, port_timeout=1):
        """Check firewall for connections from server to Internet resourses

        :return: { OK: {address->ports}, NOK: {..}, failed: {..} }
        """
        grand_result = {'OK': {}, 'NOK': {}, 'failed': {}}
        rules = self.rolecollection.collect_outgoing_internet_rules()
        for address in rules:
            ports = rules[address]
            sendcmd = 'send %s %s %s %s' % ('tcp', address, ports, port_timeout)
            status, result = self.agent_cmd(sendcmd)
            if not status:  # send failed
                grand_result['failed'][address] = ports
            else:  # send ok
                ok, space, nok = result.partition(' ')
                OK, colon, ok_range = ok.partition(':')
                NOK, colon, nok_range = nok.partition(':')
                if ok_range:
                    grand_result['OK'][address] = ok_range
                if nok_range:
                    grand_result['NOK'][address] = nok_range
        return grand_result

    def check_firewall_with(self, other,
                            concurrent_ports=100,
                            port_timeout=1,
                            max_closed=100,
                            max_failures=10):
        """Check firewall for incoming connections from other server.

        :param other: Server
        :return: generator of { OK: [{proto: .., network: .., ports: ..}, ..],
                                NOK: [ ... ],
                                failures: [ ... ],
                                OKnum: num,
                                NOKnum: num,
                                failed: num,
                                left: num }
        :raises: FirewallException
        """
        if self.dontcheck and other.dontcheck:
            raise FirewallException("Dontcheck is set for both %s and %s" % (self, other))
        logger.debug("Checking connections %s <- %s" % (self, other))
        rules = self.rolecollection.collect_incoming_fw_rules(other.rolecollection)
        ports_left = reduce(lambda s, rule: s + aux.range_len(rule['ports']), rules, 0)
        grand_result = {'OK': [], 'NOK': [], 'failures': [],
                        'OKnum': 0, 'NOKnum': 0, 'failed': 0,
                        'left': ports_left}

        def _update_grand_result(status, proto, network, ports):
            if not ports == '':
                res = next((res for res in grand_result[status]
                            if res['proto'] == proto and res['network'] == network), None)
                if res is None:
                    grand_result[status].append({'proto': proto,
                                                 'network': network,
                                                 'ports': ports})
                else:
                    res['ports'] = aux.joinranges(res['ports'], ports)
                num_field = status + 'num'
                ports_num = aux.range_len(ports)
                grand_result[num_field] = grand_result[num_field] + ports_num
                grand_result['left'] = grand_result['left'] - ports_num

        def _update_grand_result_failures(num, message):
            grand_result['failures'].append(message)
            grand_result['failed'] = grand_result['failed'] + num
            grand_result['left'] = grand_result['left'] - num

        for rule in rules:
            logger.debug("Rule %s" % rule)
            network = rule['network']
            ip = self.nw_ips[network]
            proto = rule['proto']
            ports = rule['ports']
            for ps in aux.splitrange(ports, concurrent_ports):
                if grand_result['failed'] > max_failures > 0:
                    raise FirewallException("Number of failures exceeded allowed limit")
                if grand_result['NOKnum'] > max_closed > 0:
                    raise FirewallException("Number of closed ports exceeded allowed limit")
                listencmd = 'listen %s %s %s' % (proto, ip, ps)
                sendcmd = 'send %s %s %s %s' % (proto, ip, ps, port_timeout)
                status, result = self.agent_cmd(listencmd)
                if not status:  # listen failed
                    _update_grand_result_failures(aux.range_len(ps), 'listen failure: ' + result)
                else:  # listen ok
                    status, result = other.agent_cmd(sendcmd)
                    if not status:  # send failed
                        _update_grand_result_failures(aux.range_len(ps), 'send failure: ' + result)
                    else:  # send ok
                        ok, space, nok = result.partition(' ')
                        OK, colon, ok_range = ok.partition(':')
                        NOK, colon, nok_range = nok.partition(':')
                        if proto == 'tcp':  # for tcp: success on send is enough
                            _update_grand_result('OK', proto, network, ok_range)
                            _update_grand_result('NOK', proto, network, nok_range)
                        elif proto == 'udp':  # for udp: we need to receive to be sure
                            receivecmd = 'receive %s %s %s' % (proto, ip, ok_range)
                            status, result = self.agent_cmd(receivecmd)
                            if not status:  # receive failed
                                _update_grand_result_failures(aux.range_len(ps), 'receive failure: ' + result)
                            else:  # receive ok
                                if result == 'no messages':
                                    msgs = []
                                else:
                                    msgs = result.split()  # each message is port:msg:fromaddr:fromport
                                ok_range = aux.list2range([int(msg.split(':')[0]) for msg in msgs])
                                nok_range = aux.differenceranges(ps, ok_range)
                                _update_grand_result('OK', proto, network, ok_range)
                                _update_grand_result('NOK', proto, network, nok_range)
                self.agent_cmd('closeall')
                yield grand_result

    def collect_parameters(self):
        """Generate report

        :return: generator of progress: number of checks done
        """
        if self.dontcheck:
            raise ServerException("Dontcheck is set for %s" % self)
        logger.debug("Start collecting parameters for %s" % self)
        if not self.accessible():
            self.param_check_status = "server is not accessible"
            self.parameters = {}
            return
        else:
            self.param_check_status = "in progress"
        try:
            for result in self.rolecollection.collect_parameters(self.param_cmd, self.param_script):
                self.param_check_status = "in progress, %s checks" % result['progress']
                self.parameters = result['parameters']
                self.param_failures = result['failures']
                self.param_check_time = time.time()
                yield result['progress']
        except ServerException as se:
            self.param_check_status = "FAILED with ServerException: %s" % se
            self.parameters = {}
        else:
            for req in self.rolecollection.requirements:
                if not req.istemplate():
                    (result, reason) = req.check(self.parameters)
                    if result:
                        self.requirement_successes.append(str(req))
                    else:
                        self.requirement_failures.append(reason)
            self.param_check_status = "finished"

    def prepare_and_save_report(self, rtime=None):
        """Prepare report from previously generated parameters. Save it to reports dir.

        :param rtime: report creation time, used for filename
        :return: True on success
        """
        if self.parameters is None:
            return False
        if rtime is None:
            rtime = time.localtime()
        reports_path = os.path.join(hwswa2.config['reportsdir'], self.name)
        if not os.path.exists(reports_path):
            os.makedirs(reports_path)
        yamlfile = os.path.join(reports_path, time.strftime(Server.time_format, rtime))
        self.report = Report(data={'check_status': self.param_check_status,
                                   'check_time': time.ctime(self.param_check_time),
                                   'name': self.name,
                                   'role': self.role,
                                   'parameters': self.parameters,
                                   'parameters_failures': self.param_failures,
                                   'requirement_successes': self.requirement_successes,
                                   'requirement_failures': self.requirement_failures},
                             yamlfile=yamlfile,
                             time=rtime)
        self.reports.insert(0, self.report)
        if self.report.finished():
            self.report.fix_networks()
            self.report.check_expect(self.expect)
        self.report.save()
        return True

    def cleanup(self):
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


class FirewallException(ServerException):
    """Exception for tunnel creation"""
    pass
