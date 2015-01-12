import logging
import yaml
import copy
import os
from ipcalc import Network

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

    def fix_networks(self, networks):
        """Substitutes network name for network address in report

        1.2.3.0/24 -> frontnet

        @param networks: list of dicts: [ {'network': nw, 'address': addr, 'prefix': px}, ... ]
        """
        report = self.data
        try:
            nics = report['parameters']['network']['network_interfaces']
        except (TypeError, KeyError):
            pass
        else:
            for nic in nics:
                ips = nic['ip']
                for ip in ips:
                    ip_a = ip['address']
                    ip_p = ip['prefix']
                    n_a = "%s" % Network(ip_a + '/' + ip_p).network()
                    ip['network'] = next((n['name'] for n in networks 
                                          if "%s" % n['prefix'] == ip_p 
                                          and n['address'] == n_a),
                                         n_a + '/' + ip_p)

    def get_nw_ips(self, networks=None):
        """Obtains network -> ip dict from report"""
        if networks is not None:
            self.fix_networks(networks)
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
            for nic in interfaces:
                for ip in nic['ip']:
                    ip_nw_nic.append({'ip': ip['address'], 'nw': ip['network'], 'nic': nic['name']})
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
        report = copy.deepcopy(self.data)
        if report is None:
            print('NO REPORT')
        elif raw:
            print yaml.safe_dump(report)
        else:
            # trying to print in pretty order
            for key in ['name', 'role', 'check_status', 'check_time', 'parameters_failures']:
                if key in report:
                    val = report[key]
                    if key == 'role' and isinstance(val, list):
                        print(key + ', ' + ', '.join(val))
                    else:
                        print(key + ', ' + str(report[key]))
                    del report[key]
            # print all others, scalars only
            for key in report:
                val = report[key]
                if isinstance(val, (type(None), str, unicode, int, float, bool)):
                    print(key + ', ' + str(val))
            if 'expect' in report:
                print('  Expectations')
                for e in report['expect']:
                    print(e + ', ' + report['expect'][e])
            if 'parameters' in report:
                print('  Parameters')
                parameters = copy.deepcopy(report['parameters'])
                # trying to print in pretty order
                for key in ['hostname', 'OS', 'architecture', 'processors', 'ram(GB)', 'swap(GB)',
                            'partitions', 'blockdevs', 'time', 'time_utc',
                            'ntp_service_status', 'uptime', 'iptables', 'selinux',
                            'yum_repos', 'umask']:
                    if key in parameters:
                        val = parameters[key]
                        if isinstance(val, (type(None), str, unicode, int, float, bool)):
                            print(key + ', ' + str(val))
                        elif key == 'processors':
                            count = val['count']
                            frequency = val['frequency(GHz)']
                            print('processors, ' + count + 'x' + frequency + 'GHz')
                        elif key == 'partitions':
                            print('partitions, ' + 
                                  ' | '.join(p['device'] + ' ' +
                                             p['fs_type'] + ' ' + 
                                             p['mountpoint'] + ' ' + 
                                             p['size(GB)'] + 'GB' for p in val))
                        elif key == 'blockdevs':
                            print('blockdevs, ' + 
                                  ' | '.join(d['type'] + ' ' +
                                             d['name'] + ' ' + 
                                             d['size(GB)'] + 'GB' for d in val))
                        else:
                            logger.info('wrong type for value: %s' % key)
                        del parameters[key]
                # print all the rest (scalars only)
                for key in parameters:
                    val = parameters[key]
                    if isinstance(val, (type(None), str, unicode, int, float, bool)):
                        print(key + ', ' + str(val))
                if 'network' in parameters:
                    print('  Network parameters')
                    network = parameters['network']
                    # print scalars
                    for key in network:
                        val = network[key]
                        if isinstance(val, (type(None), str, unicode, int, float, bool)):
                            print(key + ', ' + str(val))
                    if 'network_interfaces' in network:
                        nic_ips = []
                        network_interfaces = network['network_interfaces']
                        for nic in network_interfaces:
                            res_str = nic['name']
                            for ip in nic['ip']:
                                res_str += ' ' + ip['address'] + '/' + ip['network']
                            nic_ips.append(res_str)
                        print('nics, ' + ' | '.join(nic_ips))
            if 'requirement_failures' in report:
                print('  Requirement FAILURES')
                for failure in report['requirement_failures']:
                    print failure
            if 'requirement_successes' in report:
                print('  Requirement successes')
                for success in report['requirement_successes']:
                    print success
  
    @staticmethod
    def print_diff(oldr, newr):
        """Prints reports differences: oldr->newr"""
        diff = _deepdiff(oldr.data, newr.data)
        print("       ###DIFF NEW###")
        Report(data=diff['new']).show()
        print("       ###DIFF OLD###")
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
