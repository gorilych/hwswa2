import logging
from multiprocessing import Process
from multiprocessing.queues import SimpleQueue
import time
import sys
import glob
import os

import hwswa2
import hwswa2.auxiliary as aux
from hwswa2.server.factory import get_server, server_names
from hwswa2.server import FirewallException, TimeoutException
from hwswa2.server.report import Report
from hwswa2.server.role import Role

__all__ = ['show_firewall', 'firewall', 'check', 'checkall', 'prepare',
           'prepareall', 'shell', 'reboot', 'exec_cmd', 'ni_exec_cmd', 'put',
           'get', 'lastreport', 'show_report', 'reports', 'reportdiff',
           'list_roles', 'agent_console']

logger = logging.getLogger(__name__)


def log_info_and_print(msg):
    logger.info(msg)
    print(msg)


def log_error_and_print(msg):
    logger.error(msg)
    print(msg)


def list_servers():
    for name in server_names():
        print(get_server(name))


def get_server_or_exit(name):
    server = get_server(name)
    if server:
        return server
    else:
        log_error_and_print("Cannot find or init server %s, check log file" % name)
        sys.exit(1)


def get_servers_or_exit(skip_dontcheck=True):
    if hwswa2.config['allservers']:
        hwswa2.config['servernames'] = server_names()
    servers = [get_server_or_exit(name) for name in hwswa2.config['servernames']]
    if skip_dontcheck:
        for server in servers:
            if server.dontcheck:
                log_info_and_print("Skipping server %s because of dontcheck option" % name)
        servers = [server for server in servers if not server.dontcheck]
    return servers


def show_firewall():
    """Show firewall requirements"""
    if hwswa2.config['allservers']:
        hwswa2.config['servernames'] = server_names()
    servers = get_servers_or_exit(skip_dontcheck=False)
    intranet_rules = []
    internet_in_rules = []
    internet_out_rules = []
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
        inet_rules = s.rolecollection.collect_internet_rules()
        for rule in inet_rules:
            if rule['direction'] == 'outgoing':
                internet_out_rules.append({'source': s.name,
                    'destination': rule['address'],
                    'proto': rule['proto'],
                    'ports': rule['ports'],
                    'network': ''})
            elif rule['direction'] == 'incoming':
                internet_in_rules.append({'source': rule['address'],
                    'destination': s.name,
                    'proto': rule['proto'],
                    'ports': rule['ports'],
                    'network': ''})
    all_rules = intranet_rules + internet_in_rules + internet_out_rules
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
        for rule in internet_out_rules:
            print("{source} -> {destination}:{ports}".format(**rule))
        for rule in internet_in_rules:
            print("{destination} {proto}:{ports} <- {source}".format(**rule))
        print("=============END========================")


def firewall():
    """Check connections between servers"""
    start_time = time.time()
    port_timeout = hwswa2.config['firewall']['send_timeout']
    report_period = hwswa2.config['firewall']['report_period']
    max_failures = hwswa2.config['firewall']['max_failures']
    max_closed_ports = hwswa2.config['firewall']['max_closed_ports']
    servers = []
    for server in get_servers_or_exit(skip_dontcheck=False):
        if not server.nw_ips:
            if server.get_ips(hwswa2.config['networks']):
                servers.append(server)
            else:
                log_error_and_print("Cannot find IPs for server %s" % name)
        else:
            servers.append(server)
    for s in servers:
        if not s.accessible():
            log_error_and_print("%s is not accessible" % s)
            sys.exit(1)
    # check connections and collect results.
    results = {}
    for s in servers:
        results[s.name] = {}
        for other_s in servers:
            if (not other_s.name == s.name and
                not (s.dontcheck and other_s.dontcheck)):
                log_info_and_print("Checking %s <- %s" % (s.name, other_s.name))
                try:
                    for res in s.check_firewall_with(other_s,
                                                     max_closed=max_closed_ports,
                                                     max_failures=max_failures,
                                                     port_timeout=port_timeout):
                        results[s.name][other_s.name] = res
                        cur_time = time.time()
                        if cur_time - start_time > report_period:
                            start_time = cur_time
                            log_info_and_print("OK: %s NOK: %s Failed: %s Left: %s" % (res['OKnum'],
                                                                                res['NOKnum'],
                                                                                res['failed'],
                                                                                res['left']))
                except FirewallException as fe:
                    log_info_and_print("Interrupted check because: %s" % fe)
                    if other_s.name in results[s.name]:
                        results[s.name][other_s.name]['interrupted'] = fe
        if not results[s.name]:
            del results[s.name]
    log_info_and_print("Start Internet access checks ...")
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


def show_reqs():
    servers = get_servers_or_exit()
    print("REQUIREMENTS")
    for server in servers:
        print("====== {}".format(server))
        for req in server.rolecollection.requirements:
            if not req.istemplate():
                print('    ' + req.pretty_str())
    print("==== END ====")


def check():
    """Check servers"""
    check_time = time.localtime()
    report_period = hwswa2.config['check']['report_period']
    progress = ""; sep = '  |  '
    log_info_and_print("Checking servers: %s" % hwswa2.config['servernames'])
    servers = get_servers_or_exit()
    # process, status and queue for each server
    proc = {}; status = {}; queue = {}
    for server in servers:
        name = server.name
        queue[name] = SimpleQueue()
        proc[name] = Process(name=name, target=_check, args=(server, check_time, queue[name]))
        proc[name].start()
        status[name] = 'not started'
    finished = []; interrupted = []
    # while there is at least one alive child
    while next((p for p in proc.values() if p.is_alive()), None):
        for name in queue:
            while not queue[name].empty():
                status[name] = queue[name].get()
        for name in proc:
            if not proc[name].is_alive():
                if str(status[name]).startswith("finished"):
                    finished.append(name)
                    if name in interrupted: interrupted.remove(name)
                else:
                    status[name] = "interrupted?"
                    if not name in interrupted: interrupted.append(name)
        # remove finished processes
        proc = dict([(n, p) for (n, p) in proc.items() if not str(status[n]).startswith("finished")])
        # show progress: Finished | Not started | Interrupted? | Waiting for
        waiting = ', '.join([server.name + '(' + str(status[server.name]) +')'
            for server in servers if isinstance(status[server.name], int)])
        not_started = ', '.join([server.name
            for server in servers if status[server.name] == 'not started'])
        progress = ""
        for (k, v) in [("Finished", ', '.join(finished)), ('Not started', not_started),
                ('Interrupted?', ', '.join(interrupted)), ('Waiting', waiting)]:
            if v:
                if not progress:  progress = k + ': ' + v
                else:             progress += sep + k + ': ' + v
        print(progress)
        time.sleep(report_period)
    # processes finished, let's clean up queues
    for name in queue:
        while not queue[name].empty():
            status[name] = queue[name].get()
            if not str(status[name]).startswith("finished"):
                status[name] = "interrupted?"
    print("============== FINISHED =============")
    for server in servers:
        print("{0} status: {1}".format(server.name, status[server.name]))


def _check(server, check_time, resultsqueue):
    name = server.name
    try:
        for progress in server.collect_parameters():
            resultsqueue.put(progress)
    finally:
        server.cleanup()
    server.prepare_and_save_report(check_time)
    resultsqueue.put("{0}, report file: {1}".format(
        server.last_report().data['check_status'],
        server.last_report().yamlfile))


def prepare():
    """Prepare servers"""
    logger.debug("Preparing servers: %s" % hwswa2.config['servernames'])
    servers = get_servers_or_exit()


def shell():
    """Open interactive shell to specific server"""
    servername = hwswa2.config['servername']
    server = get_server_or_exit(servername)
    log_info_and_print("Opening interactive shell to server %s" % servername)
    if server.accessible():
        server.shell()
    else:
        log_error_and_print("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def reboot():
    """Reboots specified servers"""
    log_info_and_print("Rebooting servers: %s" % hwswa2.config['servernames'])
    progress = ""; sep = '  |  '
    servers = get_servers_or_exit()
    # process, status and queue for each server
    proc = {}; queue = {}; status = {}
    rebooted = []; interrupted = []; failed = []; waiting = []
    for server in servers:
        name = server.name
        waiting.append(name)
        queue[name] = SimpleQueue()
        proc[name] = Process(name=server.name, target=_reboot, args=(server, queue[name]))
        proc[name].start()
    # while there is at least one alive child
    while next((p for p in proc.values() if p.is_alive()), None):
        # remove finished processes
        proc = dict([(n, p) for (n, p) in proc.items() if p.is_alive()])
        # receive new statuses
        for name in queue:
            if not queue[name].empty():
                status[name] = queue[name].get()
        # update rebooted/failed/interupted/waiting
        for server in servers:
            name = server.name
            if (name not in rebooted) and (name not in failed):
                if name in status:  # status just received
                    if name in interrupted: interrupted.remove(name)
                    if name in waiting: waiting.remove(name)
                    if isinstance(status[name], int):  rebooted.append(name)
                    else:                              failed.append(name)
                elif name not in proc:  # process died, no status received till now
                    if name in waiting: waiting.remove(name)
                    if not name in interrupted: interrupted.append(name)
        # show progress: Rebooted | Failed | Interrupted? | Waiting
        for (k, v) in [("Rebooted", rebooted), ('Failed', failed),
                ('Interrupted?', interrupted), ('Waiting', waiting)]:
            if v:
                if not progress:  progress = k + ': ' + ', '.join(v)
                else:             progress += sep + k + ': ' + ', '.join(v)
        print(progress)
        time.sleep(1)
    for name in queue:
        if not queue[name].empty():
            status[name] = queue[name].get()
    print "============== FINISHED ================"
    for server in servers:
        if not server.name in status:
            status[server.name] = 'interrupted?'
        print("{0}: {1}".format(server.name, status[server.name]))


def _reboot(server, queue):
    try:
        server.check_reboot()
    except Exception as e:
        pass
    finally:
        server.cleanup()
    if server.check_reboot_result is None:
        queue.put("reboot failed?")
    else:
        queue.put(server.check_reboot_result)


def exec_cmd():
    """Exec command on specified server interactively"""
    servername = hwswa2.config['servername']
    server = get_server_or_exit(servername)
    sshcmd = " ".join(hwswa2.config['sshcmd'])
    get_pty = hwswa2.config['tty']
    logger.debug("Executing `%s` on server %s" % (sshcmd, servername))
    if server.accessible():
        exitstatus = server.exec_cmd_i(sshcmd, get_pty=get_pty)
        sys.exit(exitstatus)
    else:
        log_error_and_print("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(255)


def ni_exec_cmd():
    """Exec command on specified server non-interactively"""
    servername = hwswa2.config['servername']
    server = get_server_or_exit(servername)
    sshcmd = " ".join(hwswa2.config['sshcmd'])
    logger.debug("Executing `%s` on server %s" % (sshcmd, servername))
    if server.accessible():
        stdout, stderr, exitstatus = server.exec_cmd(sshcmd)
        print(" = stdout = \n%s" % stdout)
        print(" = stderr = \n%s" % stderr)
        print("exitstatus = %s" % exitstatus)
    else:
        log_error_and_print("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def bulk_exec_cmd():
    """Exec command on specified server(s) non-interactively"""
    sshcmd = " ".join(hwswa2.config['sshcmd'])
    servers = get_servers_or_exit(skip_dontcheck=False) 
    logger.debug("Will execute %s on servers %s" % (sshcmd, servers))
    # process, status and queue for each server
    proc = {}; status = {}; queue = {}
    executed = []; waiting = []
    progress = ""; sep = "  |  "
    for server in servers:
        name = server.name
        queue[name] = SimpleQueue()
        proc[name] = Process(name=server.name, target=_exec, args=(server, sshcmd, queue[name]))
        proc[name].start()
        waiting.append(name)
    # while there is at least one alive child
    while next((p for p in proc.values() if p.is_alive()), None):
        # remove finished processes
        proc = dict([(n, p) for (n, p) in proc.items() if p.is_alive()])
        # receive new statuses
        for name in queue:
            if not queue[name].empty():
                status[name] = queue[name].get()
                waiting.remove(name)
                executed.append(name)
        if executed:  progress = "Executed: " + ', '.join(executed)
        if waiting:
            if progress:  progress += sep
            progress += "Waiting: " + ', '.join(waiting)
        print(progress)
        #TODO replace with configurable value
        time.sleep(1)
    # update statuses
    for name in queue:
        if not queue[name].empty():
            status[name] = queue[name].get()
    print "============== FINISHED ================"
    print "Server\tExit code"
    for server in servers:
        result = status[server.name]
        if result['accessible']:
            print("%s\t%s" %(server.name, result['exitstatus']))
        else:
            print("%s\t%s" %(server.name, result['conn_err']))
    for stream in ['stdout', 'stderr']:
        if hwswa2.config[stream]:
            print("============== %s ================" % stream)
            for server in servers:
                result = status[server.name]
                if result['accessible']:
                    if not result[stream]:
                        print("==== %s ==== Empty" % server.name)
                    else:
                        print("==== %s ====\n%s" % (server.name, result[stream]))
    print "See log file for stdout and stderr"


def _exec(server, cmd, resultsqueue):
    if server.accessible():
        try:
            stdout, stderr, exitstatus = server.exec_cmd(cmd)
        except TimeoutException as te:
            logger.info("%s: Timeout while executing command" % server)
            resultsqueue.put({'accessible': False,
                'conn_err': "Timeout while executing"})
        else:
            logger.info("%s\n  = stdout = \n%s-------\n  = stderr = \n%s-------\nexitstatus = %s"
                % (server, stdout, stderr, exitstatus))
            resultsqueue.put({'accessible': True, 'stdout': stdout,
                'stderr': stderr, 'exitstatus': exitstatus})
        finally:
            server.cleanup()
    else:
        resultsqueue.put({'accessible': False,
            'conn_err': server.last_connection_error()})


def put():
    """Copy file to server"""
    server = get_server_or_exit(hwswa2.config['servername'])
    localpath = hwswa2.config['localpath']
    remotepath = hwswa2.config['remotepath']
    logger.debug("Copying '%s' to '%s' on %s" % (localpath, remotepath, server))
    if server.accessible():
        server.put(localpath, remotepath)
    else:
        log_error_and_print("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def get():
    """Copy file from server"""
    server = get_server_or_exit(hwswa2.config['servername'])
    localpath = hwswa2.config['localpath']
    remotepath = hwswa2.config['remotepath']
    logger.debug("Copying to '%s' from '%s' on %s" % (localpath, remotepath, server))
    if server.accessible():
        server.get(remotepath, localpath)
    else:
        log_error_and_print("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def lastreport():
    server = get_server_or_exit(hwswa2.config['servername'])
    raw = hwswa2.config['raw']
    report = server.last_report()
    if report is None:
        log_info_and_print("%s has no reports" % server)
    else:
        report.show(raw=raw)


def show_report():
    server = get_server_or_exit(hwswa2.config['servername'])
    reportname = hwswa2.config['reportname']
    raw = hwswa2.config['raw']
    report = server.get_report(reportname)
    if report is None:
        log_error_and_print("%s has no report %s" % (server, reportname))
        sys.exit(1)
    report.show(raw=raw)


def reports():
    for server in get_servers_or_exit(skip_dontcheck=False):
        print "==== %s" % server
        server.list_reports()


def reportdiff():
    server = get_server_or_exit(hwswa2.config['servername'])
    r1name = hwswa2.config['oldreport']
    r2name = hwswa2.config['newreport']
    report1 = server.get_report(r1name)
    report2 = server.get_report(r2name)
    if report1 is None:
        log_error_and_print("%s has no report %s" % (server, r1name))
        sys.exit(1)
    if report2 is None:
        log_error_and_print("%s has no report %s" % (server, r2name))
        sys.exit(1)
    Report.print_diff(report1, report2)


def reportshistory():
    server = get_server_or_exit(hwswa2.config['servername'])
    max_reports = hwswa2.config['reportsnumber']
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
        roles_dir = hwswa2.config['rolesdir']
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
    server = get_server_or_exit(hwswa2.config['servername'])
    log_info_and_print("Opening agent console for server %s" % server.name)
    if server.accessible():
        server.agent_console()
    else:
        log_error_and_print("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def encrypt():
    from getpass import getpass
    key = getpass("Enter encryption key: ")
    password = getpass("Enter password to encrypt: ")
    print(aux.encrypt(key, password))


def decrypt():
    from getpass import getpass
    key = getpass("Enter encryption key: ")
    password = getpass("Enter encoded password to decrypt: ")
    print(aux.decrypt(key, password))
