import logging
import yaml
import copy
import os
from ipcalc import Network

import hwswa2
import hwswa2.auxiliary as aux

__all__ = ['Report', 'ReportException']

logger = logging.getLogger(__name__)


class ReportException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Report(object):

    def __init__(self, data=None, yamlfile=None, time=None):
        """Constructs report either from data or from yamlfile"""
        if data is None and yamlfile is None:
            raise ReportException("Report(None, None) is not allowed. Specify at least one arg")
        self.yamlfile = yamlfile
        self._data = data
        self.time = time

    @property
    def data(self):
        if not self._data:
            self._read()
        return self._data

    def _read(self, yamlfile=None):
        if yamlfile is None:
            if self.yamlfile is None:
                raise ReportException("No filename to read from")
            yamlfile = self.yamlfile
        else:
            self.yamlfile = yamlfile
        try:
            self._data = yaml.load(open(yamlfile))
        except IOError as ie:
            raise ReportException("Error opening file %s: %s" % (yamlfile, ie))
        except yaml.YAMLError as ye:
            raise ReportException("Error parsing file %s: %s" % (yamlfile, ye))

    def finished(self):
        return self.data is not None and 'check_status' in self.data and self.data['check_status'] == 'finished'

    def filename(self):
        """Returns file name of report file"""
        return os.path.basename(self.yamlfile)

    def fix_networks(self):
        """Substitutes network name for network address in report

        1.2.3.0/24 -> frontnet
        """
        report = self.data
        networks = hwswa2.config.get('networks')
        if not networks:
            return
        try:
            nics = report['parameters']['network']['network_interfaces']
        except (TypeError, KeyError):
            pass
        else:
            if hasattr(nics, '__iter__'):
                for nic in nics:
                    ips = nic['ip']
                    if hasattr(ips, '__iter__'):
                        for ip in ips:
                            ip_a = ip['address']
                            ip_p = ip['prefix']
                            n_a = "%s" % Network(ip_a + '/' + ip_p).network()
                            ip['network'] = next((n['name'] for n in networks 
                                                  if "%s" % n['prefix'] == ip_p
                                                  and n['address'] == n_a),
                                                 n_a + '/' + ip_p)

    def get_nw_ips(self):
        """Obtains network -> ip dict from report"""
        self.fix_networks()
        try:
            nics = self.data['parameters']['network']['network_interfaces']
        except KeyError:
            return {}
        else:
            nw_ips = {}
            for nic in nics:
                ips = nic['ip']
                for ip in ips:
                    nw_ips[ip['network']] = ip['address']
            return nw_ips

    def get_ip_nw_nic(self):
        """Obtain list of ip-network-nic

        :return: [{ip:, network:, nic:}, ...]
        """
        ip_nw_nic = []
        try:
            interfaces = self.data['parameters']['network']['network_interfaces']
        except KeyError:
            pass
        else:
            if hasattr(interfaces, '__iter__'):
                for nic in interfaces:
                    if hasattr(nic['ip'], '__iter__'):
                        for ip in nic['ip']:
                            ip_nw_nic.append({'ip': ip['address'],
                                              'nw': ip['network'],
                                              'nic': nic['name']})
        return ip_nw_nic

    def check_expect(self, expect=None):
        """ Check parameters for expected values and update report data

        :param expect: list of expected parameters
        """
        if expect is None:
            return
        self.data['expect'] = {}
        ip_nw_nic = self.get_ip_nw_nic()
        for expectation in expect:
            # checking expected IP addresses
            if 'ip' in expectation:
                e_key = e_ip = expectation['ip']
                if 'network' in expectation:
                    e_nw = expectation['network']
                    e_key += '/' + e_nw
                e_found = next((ip for ip in ip_nw_nic if ip['ip'] == e_ip), None)
                if e_found is None:
                    self.data['expect'][e_key] = 'NOT OK, IP address NOT found'
                else:
                    if not 'network' in expectation:
                        self.data['expect'][e_key] = 'OK, IP address found on ' + e_found['nic']
                    else:
                        if e_nw == e_found['nw']:
                            self.data['expect'][e_key] = 'OK, IP address found on ' + e_found['nic']
                        else:
                            self.data['expect'][e_key] = 'NOT OK, IP address found on ' + e_found['nic'] + \
                                                         ' but network is NOT the same: ' + e_found['nw']

    def save(self, yamlfile=None):
        if self.data is None:
            raise ReportException("Won't save empty report")
        if yamlfile is None:
            if self.yamlfile is None:
                raise ReportException("No filename to save to")
            yamlfile = self.yamlfile
        else:
            self.yamlfile = yamlfile
        try:
            yaml.safe_dump(self.data, open(yamlfile, 'w'))
        except (IOError, yaml.YAMLError) as e:
            raise ReportException("Error writing to file %s: %s" % (yamlfile, e))

    def show(self, raw=False):
        indent = '    '
        report = copy.deepcopy(self.data)
        def printkey(key):
            aux.printout(indent + key + ' ', aux.MAGENTA, nonewline=True)
        if report is None:
            aux.printout(indent + 'NO REPORT', aux.RED)
        elif raw:
            print yaml.safe_dump(report)
        else:
            # trying to print in pretty order
            for key in ['name', 'role', 'check_status', 'check_time']:
                if key in report:
                    val = report[key]
                    if key == 'role' and isinstance(val, list):
                        printkey(key)
                        print(', '.join(val))
                    else:
                        printkey(key)
                        print(str(report[key]))
                    del report[key]
            # print all others, scalars only
            for key in report:
                val = report[key]
                if isinstance(val, (type(None), str, unicode, int, float, bool)):
                    printkey(key)
                    print(str(val))
            if 'expect' in report:
                aux.printout(indent + '  == Expectations ==', aux.WHITE)
                for e in report['expect']:
                    printkey(e)
                    print(report['expect'][e])
            if 'parameters' in report:
                aux.printout(indent + '  == Parameters ==', aux.WHITE)
                parameters = copy.deepcopy(report['parameters'])
                # trying to print in pretty order
                skip_keys = ['OS_SP', 'updates_number', 'umask', 'time_utc',
                             'ntp_service_status', 'uptime', 'tmp_noexec']
                for key in ['hostname', 'hw_id', 'OS', 'SP_level', 'OSLanguage',
                            'Activation', 'sid', 'architecture', 'processors',
                            'ram(GB)', 'swap(GB)', 'partitions', 'blockdevs',
                            'time', 'iptables', 'selinux', 'yum_repos']:
                    if key in parameters:
                        val = parameters[key]
                        if isinstance(val, (type(None), str, unicode, int, float, bool)):
                            printkey(key)
                            print(str(val))
                        elif key == 'processors':
                            count = val['count']
                            frequency = val['frequency(GHz)']
                            printkey('processors')
                            print(count + 'x' + frequency + 'GHz')
                        elif key == 'partitions':
                            printkey(key)
                            print(' | '.join(p['device'] + ' ' +
                                             p['fs_type'] + ' ' + 
                                             p['mountpoint'] + ' ' + 
                                             p['size(GB)'] + 'GB' for p in val))
                        elif key == 'blockdevs':
                            printkey(key)
                            print(' | '.join(d['type'] + ' ' +
                                             d['name'] + ' ' + 
                                             d['size(GB)'] + 'GB' for d in val))
                        else:
                            logger.info('wrong type for value: %s' % key)
                        del parameters[key]
                # print all the rest (scalars only)
                for key in parameters:
                    if key in skip_keys:
                        continue
                    val = parameters[key]
                    if isinstance(val, (type(None), str, unicode, int, float, bool)):
                        printkey(key)
                        print(str(val))
                if 'network' in parameters:
                    aux.printout(indent + '  == Network parameters ==', aux.WHITE)
                    network = parameters['network']
                    # print scalars
                    for key in network:
                        val = network[key]
                        if isinstance(val, (type(None), str, unicode, int, float, bool)):
                            printkey(key)
                            print(str(val))
                    if 'network_interfaces' in network:
                        nic_ips = []
                        network_interfaces = network['network_interfaces']
                        for nic in network_interfaces:
                            if nic.get('slaveof'):  # do not show slave nics
                                continue
                            name = nic['name']
                            res_str = name
                            slaves = [n['name'] for n in network_interfaces 
                                    if n.get('slaveof') == name]
                            if slaves:
                                res_str += '(' + ','.join(slaves) + ')'
                            for ip in nic['ip']:
                                if ip['address'].find(':') == -1:  # filter out IPv6 addresses
                                    res_str += ' ' + ip['address'] + '/' + ip['network']
                            nic_ips.append(res_str)
                        printkey('nics')
                        print(' | '.join(nic_ips))
            if 'parameters_failures' in report:
                pf = report['parameters_failures']
                if pf:
                    aux.printout(indent + '  == Parameter FAILURES (parameter: failure) ==', aux.RED)
                    for p in pf:
                        printkey(p)
                        print(pf[p])
            if 'requirement_failures' in report:
                aux.printout(indent + '  == Requirement FAILURES (role:req: reason) ==', aux.RED)
                for failure in report['requirement_failures']:
                    print(indent + failure)
            if 'requirement_successes' in report:
                aux.printout(indent + '  == Requirement successes (role:req) ==', aux.WHITE)
                for success in report['requirement_successes']:
                    print(indent + success)
  
    @staticmethod
    def print_diff(oldr, newr):
        """Prints reports differences: oldr->newr"""
        diff = _deepdiff(oldr.data, newr.data)
        aux.printout("NEW", aux.WHITE)
        Report(data=diff['new']).show()
        aux.printout("OLD", aux.WHITE)
        Report(data=diff['old']).show()
        

def _is_equal(val1, val2):
    diff = _deepdiff(val1, val2)
    return (diff['old'] is None) and (diff['new'] is None)


def _deepdiff(oldval, newval):
    """Compares oldval and newval recursively

    Returns {'old': oldparts, 'new': newparts}
    """
    diff = {'new': None, 'old': None}
    if isinstance(oldval, (type(None), str, int, float, bool)):
        if not (oldval == newval):
            diff = {'new': newval, 'old': oldval}
    elif isinstance(oldval, list):
        # we presume list contains different elements
        # algo is wrong if we have duplicates
        diff['new'] = []
        diff['old'] = []
        for elem in oldval:
            # try to find equal
            equal_elem = next((el for el in newval if _is_equal(el, elem)), None)
            if equal_elem is None:
                diff['old'].append(elem)
        for elem in newval:
            # try to find equal
            equal_elem = next((el for el in oldval if _is_equal(el, elem)), None)
            if equal_elem is None:
                diff['new'].append(elem)
    elif isinstance(oldval, dict):
        diff['new'] = {}
        diff['old'] = {}
        for key in oldval:
            if not (key in newval):
                diff['old'][key] = oldval[key]
            else:
                diffval = _deepdiff(oldval[key], newval[key])
                if not (diffval['old'] is None):
                    diff['old'][key] = diffval['old']
                if not (diffval['new'] is None):
                    diff['new'][key] = diffval['new']
        for key in newval:
            if not (key in oldval):
                diff['new'][key] = newval[key]
    if diff['new'] == {} or diff['new'] == []:
        diff['new'] = None
    if diff['old'] == {} or diff['old'] == []:
        diff['old'] = None
    return diff
