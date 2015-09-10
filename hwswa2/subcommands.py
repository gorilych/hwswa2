import logging
import threading
import Queue
import time
import sys
import glob
import os

import hwswa2
from hwswa2.server.factory import get_server, server_names
from hwswa2.server import FirewallException
from hwswa2.server.report import Report
from hwswa2.server.role import Role

__all__ = ['show_firewall', 'firewall', 'check', 'checkall', 'prepare',
           'prepareall', 'shell', 'reboot', 'exec_cmd', 'ni_exec_cmd', 'put',
           'get', 'lastreport', 'show_report', 'reports', 'reportdiff',
           'list_roles', 'agent_console']

logger = logging.getLogger(__name__)


def list_servers():
    for name in server_names():
        print(get_server(name))


def show_firewall():
    """Show firewall requirements"""
    servers = []
    if hwswa2.config['allservers']:
        hwswa2.config['servernames'] = server_names()
    for name in hwswa2.config['servernames']:
        server = get_server(name)
        if server is None:
            logger.error("Cannot find server %s in servers list" % name)
            sys.exit(1)
        else:
            servers.append(server)
    intranet_rules = []
    internet_rules = []
    for s in servers:
        for other_s in servers:
            if not other_s.name == s.name:
                rules = s.rolecollection.collect_incoming_fw_rules(other_s.rolecollection)
                for rule in rules:
                    intranet_rules.append({'source': other_s.name, 
                                           'destination': s.name, 
                                           'proto': rule['proto'],
                                           'ports': rule['ports'],
                                           'network': rule['network']})
        inet_rules = s.rolecollection.collect_outgoing_internet_rules()
        for address in inet_rules:
            internet_rules.append({'source': s.name, 
                                   'destination': address, 
                                   'proto': '',
                                   'ports': inet_rules[address],
                                   'network': ''})
    all_rules = intranet_rules + internet_rules
    if hwswa2.config['csv']:
        import csv
        dw = csv.DictWriter(sys.stdout, all_rules[0].keys())
        dw.writeheader()
        dw.writerows(all_rules)
    elif hwswa2.config['compact']:
        print("=============BEGIN======================")
        # sort intranet_rules by source to have the same order as in servers
        for rule in (rule for s in servers for rule in intranet_rules if rule['source'] == s.name):
            print("{source} -> {destination} {proto}:{ports} ({network})".format(**rule))
    else:
        print("=============BEGIN======================")
        for s in servers:
            # find networks:
            networks = set([rule['network'] for rule in intranet_rules if rule['source'] == s.name or rule['destination'] == s.name])
            if networks:
                print("==== Server %s" % s.name)
                for network in networks:
                    outgoing = [rule for rule in intranet_rules if rule['source'] == s.name and rule['network'] == network]
                    if outgoing:
                        print("%s outgoing:" % network)
                        for rule in outgoing:
                            print(" to {destination} {proto}:{ports}".format(**rule))
                    incoming = [rule for rule in intranet_rules if rule['destination'] == s.name and rule['network'] == network]
                    if incoming:
                        print("%s incoming:" % network)
                        for rule in incoming:
                            print(" from {source} {proto}:{ports}".format(**rule))
    if not hwswa2.config['csv']:
        print("===== Internet access requirements =====")
        for rule in internet_rules:
            print("{source} -> {destination}:{ports}".format(**rule))
        print("=============END========================")


def firewall():
    """Check connections between servers"""
    start_time = time.time()
    port_timeout = hwswa2.config['firewall']['send_timeout']
    report_period = hwswa2.config['firewall']['report_period']
    max_failures = hwswa2.config['firewall']['max_failures']
    max_closed_ports = hwswa2.config['firewall']['max_closed_ports']
    servers = []
    if hwswa2.config['allservers']:
        hwswa2.config['servernames'] = server_names()
    for name in hwswa2.config['servernames']:
        server = get_server(name)
        if server is None:
            logger.error("Cannot find server %s in servers list" % name)
            sys.exit(1)
        elif not server.nw_ips:
            if server.get_ips(hwswa2.config['networks']):
                servers.append(server)
            else:
                logger.error("Cannot find IPs for server %s" % name)
        else:
            servers.append(server)
    for s in servers:
        if not s.accessible():
            logger.error("%s is not accessible" % s)
            sys.exit(1)
    # check connections and collect results.
    results = {}
    for s in servers:
        results[s.name] = {}
        for other_s in servers:
            if (not other_s.name == s.name and
                not (s.dontcheck and other_s.dontcheck)):
                logger.info("Checking %s <- %s" % (s.name, other_s.name))
                try:
                    for res in s.check_firewall_with(other_s,
                                                     max_closed=max_closed_ports,
                                                     max_failures=max_failures,
                                                     port_timeout=port_timeout):
                        results[s.name][other_s.name] = res
                        cur_time = time.time()
                        if cur_time - start_time > report_period:
                            start_time = cur_time
                            logger.info("OK: %s NOK: %s Failed: %s Left: %s" % (res['OKnum'],
                                                                                res['NOKnum'],
                                                                                res['failed'],
                                                                                res['left']))
                except FirewallException as fe:
                    logger.info("Interrupted check because: %s" % fe)
                    if other_s.name in results[s.name]:
                        results[s.name][other_s.name]['interrupted'] = fe
        if not results[s.name]:
            del results[s.name]
    logger.info("Start Internet access checks ...")
    internet_fw_res = {}
    for s in servers:
        sres = s.check_internet_access(port_timeout=port_timeout)
        if sres['OK'] or sres['NOK'] or sres['failed']:
            internet_fw_res[s.name] = sres
    if results:
        print "============== FINISHED ================"
        print "        Below connections are OK:"
        for sn in results:
            for osn in results[sn]:
                for res in results[sn][osn]['OK']:
                    print '%s <- %s %s:%s (%s)' % (sn, osn, res['proto'], res['ports'], res['network'])
        print "        Below connections are NOT OK:"
        for sn in results:
            for osn in results[sn]:
                for res in results[sn][osn]['NOK']:
                    print '%s <- %s %s:%s (%s)' % (sn, osn, res['proto'], res['ports'], res['network'])
        print "============= INTERRUPTED =============="
        for sn in results:
            for osn in results[sn]:
                if 'interrupted' in results[sn][osn]:
                    print '%s <- %s: %s' % (sn, osn, results[sn][osn]['interrupted'])
        print "==============  TOTALS  ================"
        tOK = 0
        tNOK = 0
        tFailed = 0
        tLeft = 0
        for sn in results:
            for osn in results[sn]:
                r = results[sn][osn]
                tOK += r['OKnum']
                tNOK += r['NOKnum']
                tFailed += r['failed']
                tLeft += r['left']
        print "OK %s NOK %s Failed %s Left %s" % (tOK, tNOK, tFailed, tLeft)
    if internet_fw_res:
        print "=============  INTERNET  ==============="
        for sname in internet_fw_res:
            OK = internet_fw_res[sname]['OK']
            NOK = internet_fw_res[sname]['NOK']
            failed = internet_fw_res[sname]['failed']
            for addr in OK:
                print "OK: %s -> %s:%s" % (sname, addr, OK[addr])
            for addr in NOK:
                print "NOK: %s -> %s:%s" % (sname, addr, NOK[addr])
            for addr in failed:
                print "failed: %s -> %s:%s" % (sname, addr, failed[addr])
    print "========================================"


def check():
    """Check servers"""
    check_time = time.localtime()
    report_period = hwswa2.config['check']['report_period']
    servers = []
    if hwswa2.config['allservers']:
        hwswa2.config['servernames'] = server_names()
    logger.info("Checking servers: %s" % hwswa2.config['servernames'])
    for name in hwswa2.config['servernames']:
        server = get_server(name)
        if server is None:
            logger.error("Cannot find server %s in servers list" % name)
            sys.exit(1)
        else:
            if server.dontcheck:
                logger.info("Skipping server %s because of dontcheck option" % name)
            else:
                servers.append(server)
    results = Queue.Queue()
    cth = {}
    status = {}
    for server in servers:
        cth[server.name] = threading.Thread(name=server.name, target=_check, args=(server, results))
        cth[server.name].start()
        status[server.name] = 'not started'

    def there_is_alive_check_thread():
        for name in cth:
            if cth[name].is_alive():
                return True
        return False
    while there_is_alive_check_thread():
        while not results.empty():
            result = results.get()
            name = result['name']
            progress = result['progress']
            status[name] = progress
        for name in status:
            if not cth[name].is_alive():
                status[name] = "finished"
        print("Progress: %s" % status)
        time.sleep(report_period)
    for server in servers:
        server.prepare_and_save_report(check_time)
        logger.info("%s status: %s, report file: %s" %
                    (server.name, server.last_report().data['check_status'], server.last_report().yamlfile))


def _check(server, resultsqueue):
    name = server.name
    for progress in server.collect_parameters():
        resultsqueue.put({'name': name, 'progress': progress})


def prepare():
    """Prepare servers"""
    logger.debug("Preparing servers: %s" % hwswa2.config['servernames'])
    servers = []
    if hwswa2.config['allservers']:
        hwswa2.config['servernames'] = server_names()
    for name in hwswa2.config['servernames']:
        server = get_server(name)
        if server is None:
            logger.error("Cannot find server %s in servers list" % name)
            sys.exit(1)
        else:
            if server.dontcheck:
                logger.info("Skipping server %s because of dontcheck option" % name)
            else:
                servers.append(server)


def shell():
    """Open interactive shell to specific server"""
    servername = hwswa2.config['servername']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    logger.info("Opening interactive shell to server %s" % servername)
    if server.accessible():
        server.shell()
    else:
        logger.error("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def reboot():
    """Reboots specified servers"""
    logger.info("Rebooting servers: %s" % hwswa2.config['servernames'])
    servers = []
    if hwswa2.config['allservers']:
        hwswa2.config['servernames'] = server_names()
    for name in hwswa2.config['servernames']:
        server = get_server(name)
        if server is None:
            logger.error("Cannot find server %s in servers list" % name)
            sys.exit(1)
        else:
            if server.dontcheck:
                logger.info("Skipping server %s because of dontcheck option" % name)
            else:
                servers.append(server)
    cth = {}
    finished = []
    for server in servers:
        cth[server.name] = threading.Thread(name=server.name, target=server.check_reboot)
        cth[server.name].start()

    def there_is_alive_check_thread():
        for n in cth:
            if cth[n].is_alive():
                return True
        return False
    while there_is_alive_check_thread():
        for name in cth:
            if not cth[name].is_alive():
                if not name in finished:
                    logger.info("%s: %s" % (name, get_server(name).check_reboot_result))
                    finished.append(name)
        time.sleep(1)
    print "============== FINISHED ================"
    for server in servers:
        if server.check_reboot_result is None:
            print("%s: reboot failed?" % server)
        else:
            print("%s: %s" % (server, server.check_reboot_result))


def exec_cmd():
    """Exec command on specified server interactively"""
    servername = hwswa2.config['servername']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    sshcmd = " ".join(hwswa2.config['sshcmd'])
    get_pty = hwswa2.config['tty']
    logger.debug("Executing `%s` on server %s" % (sshcmd, servername))
    if server.accessible():
        exitstatus = server.exec_cmd_i(sshcmd, get_pty=get_pty)
        sys.exit(exitstatus)
    else:
        logger.error("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(255)


def ni_exec_cmd():
    """Exec command on specified server non-interactively"""
    servername = hwswa2.config['servername']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    sshcmd = " ".join(hwswa2.config['sshcmd'])
    logger.debug("Executing `%s` on server %s" % (sshcmd, servername))
    if server.accessible():
        stdout, stderr, exitstatus = server.exec_cmd(sshcmd)
        print(" = stdout = \n%s" % stdout)
        print(" = stderr = \n%s" % stderr)
        print("exitstatus = %s" % exitstatus)
    else:
        logger.error("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def put():
    """Copy file to server"""
    servername = hwswa2.config['servername']
    localpath = hwswa2.config['localpath']
    remotepath = hwswa2.config['remotepath']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    logger.debug("Copying '%s' to '%s' on %s" % (localpath, remotepath, server))
    if server.accessible():
        server.put(localpath, remotepath)
    else:
        logger.error("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def get():
    """Copy file from server"""
    servername = hwswa2.config['servername']
    localpath = hwswa2.config['localpath']
    remotepath = hwswa2.config['remotepath']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    logger.debug("Copying to '%s' from '%s' on %s" % (localpath, remotepath, server))
    if server.accessible():
        server.get(remotepath, localpath)
    else:
        logger.error("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def lastreport():
    servername = hwswa2.config['servername']
    raw = hwswa2.config['raw']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    report = server.last_report()
    if report is None:
        logger.info("%s has no reports" % server)
    else:
        report.show(raw=raw)


def show_report():
    servername = hwswa2.config['servername']
    reportname = hwswa2.config['reportname']
    raw = hwswa2.config['raw']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    report = server.get_report(reportname)
    if report is None:
        logger.error("%s has no report %s" % (server, reportname))
        sys.exit(1)
    report.show(raw=raw)


def reports():
    servers = []
    if hwswa2.config['allservers']:
        hwswa2.config['servernames'] = server_names()
    for name in hwswa2.config['servernames']:
        server = get_server(name)
        if server is None:
            logger.error("Cannot find server %s in servers list" % name)
            sys.exit(1)
        else:
            servers.append(server)
    for server in servers:
        print "==== %s" % server
        server.list_reports()


def reportdiff():
    servername = hwswa2.config['servername']
    r1name = hwswa2.config['oldreport']
    r2name = hwswa2.config['newreport']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    report1 = server.get_report(r1name)
    report2 = server.get_report(r2name)
    if report1 is None:
        logger.error("%s has no report %s" % (server, r1name))
        sys.exit(1)
    if report2 is None:
        logger.error("%s has no report %s" % (server, r2name))
        sys.exit(1)
    Report.print_diff(report1, report2)


def reportshistory():
    servername = hwswa2.config['servername']
    max_reports = hwswa2.config['reportsnumber']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    last_reports = server.reports[:max_reports]
    if len(last_reports) == 0:
        print "%s has no reports" % server
    elif len(last_reports) == 1:
        print "%s has one report only" % server
        last_reports[0].show()
    else:
        newer_report = last_reports[0]
        for report in last_reports[1:]:
            print("### DIFF %s -> %s ###" % (report.filename(), newer_report.filename()) )
            Report.print_diff(report, newer_report)
            newer_report = report
        print("###############")


def list_roles(roles_dir=None):
    if roles_dir is None:
        roles_dir = hwswa2.config['checksdir']
    roles = []
    role_names = []
    # Read all roles from role files
    for role_file in glob.glob(os.path.join(roles_dir, '*.yaml')):
        role_name = os.path.basename(role_file)[:-5].lower()
        roles.append(Role(role_name))
        role_names.append(role_name)
    # Find roles which are mentioned in firewall rules but do not have role file
    aux_role_names = []
    for role in roles:
        new_names = [r for r in role.connects_with_roles if r not in role_names and r not in aux_role_names]
        aux_role_names.extend(new_names)
    # find role names for non-internal roles
    noninternal_role_names = [r.name for r in roles if not r.internal]
    noninternal_role_names.sort()
    # find role names for internal roles
    internal_role_names = [r.name for r in roles if r.internal]
    internal_role_names.sort()
    aux_role_names.sort()
    print("==== Roles ====\n" + ', '.join(noninternal_role_names))
    print("==== Auxiliary roles (no yaml files, but mentioned in firewall rules) ====\n" + ', '.join(aux_role_names))
    print("==== Internal roles ====\n" + ', '.join(internal_role_names))


def agent_console():
    """Open interactive shell to specific server"""
    servername = hwswa2.config['servername']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    logger.info("Opening agent console for server %s" % servername)
    if server.accessible():
        server.agent_console()
    else:
        logger.error("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)
