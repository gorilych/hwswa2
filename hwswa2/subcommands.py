import logging
import threading
import Queue
import time
import sys

from hwswa2.globals import config
from hwswa2.server.factory import get_server, server_names
from hwswa2.server import FirewallException
from hwswa2.server.report import Report

logger = logging.getLogger(__name__)


def firewall():
    """Check connections between servers"""
    start_time = time.time()
    port_timeout = config['firewall']['send_timeout']
    report_period = config['firewall']['report_period']
    max_failures = config['firewall']['max_failures']
    max_closed_ports = config['firewall']['max_closed_ports']
    servers = []
    for name in config['servernames']:
        server = get_server(name)
        if server is None:
            logger.error("Cannot find server %s in servers list" % name)
            sys.exit(1)
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
            if not other_s.name == s.name:
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
    """Check only specified servers"""
    check_time = time.localtime()
    report_period = config['check']['report_period']
    logger.info("Checking servers: %s" % config['servernames'])
    servers = []
    for name in config['servernames']:
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
        server.prepare_and_save_report(config['networks'], check_time)
        logger.info("%s status: %s, report file: %s" %
                    (server.name, server.last_report().data['check_status'], server.last_report().yamlfile))


def _check(server, resultsqueue):
    name = server.name
    for progress in server.collect_parameters():
        resultsqueue.put({'name': name, 'progress': progress})


def checkall():
    """Check all servers"""
    logger.debug("Checking all servers")
    config['servernames'] = server_names()
    check()


def prepare():
    """Prepare only specified servers"""
    logger.debug("Preparing servers: %s" % config['servernames'])
    servers = []
    for name in config['servernames']:
        server = get_server(name)
        if server is None:
            logger.error("Cannot find server %s in servers list" % name)
            sys.exit(1)
        else:
            if server.dontcheck:
                logger.info("Skipping server %s because of dontcheck option" % name)
            else:
                servers.append(server)


def prepareall():
    """Prepare all servers"""
    logger.debug("Preparing all servers")
    config['servernames'] = server_names()
    prepare()


def shell():
    """Open interactive shell to specific server"""
    servername = config['servername']
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
    logger.info("Rebooting servers: %s" % config['servernames'])
    servers = []
    for name in config['servernames']:
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
    servername = config['servername']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    sshcmd = " ".join(config['sshcmd'])
    get_pty = config['tty']
    logger.debug("Executing `%s` on server %s" % (sshcmd, servername))
    if server.accessible():
        exitstatus = server.exec_cmd_i(sshcmd, get_pty=get_pty)
        logger.debug("exitstatus = %s" % exitstatus)
    else:
        logger.error("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def ni_exec_cmd():
    """Exec command on specified server non-interactively"""
    servername = config['servername']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    sshcmd = " ".join(config['sshcmd'])
    logger.debug("Executing `%s` on server %s" % (sshcmd, servername))
    if server.accessible():
        stdout, stderr, exitstatus = server.exec_cmd(sshcmd)
        print("stdout = %s" % stdout)
        print("stderr = %s" % stderr)
        print("exitstatus = %s" % exitstatus)
    else:
        logger.error("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def put():
    """Copy file to server"""
    servername = config['servername']
    localpath = config['localpath']
    remotepath = config['remotepath']
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
    servername = config['servername']
    localpath = config['localpath']
    remotepath = config['remotepath']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    logger.debug("Copying to '%s' from '%s' on %s" % (localpath, remotepath, server))
    if server.accessible():
        server.get(localpath, remotepath)
    else:
        logger.error("Failed to connect to %s: %s" % (server, server.last_connection_error()))
        sys.exit(1)


def lastreport():
    servername = config['servername']
    raw = config['raw']
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
    servername = config['servername']
    reportname = config['reportname']
    raw = config['raw']
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
    servername = config['servername']
    server = get_server(servername)
    if server is None:
        logger.error("Cannot find server %s in servers list" % servername)
        sys.exit(1)
    server.list_reports()


def reportdiff():
    servername = config['servername']
    r1name = config['oldreport']
    r2name = config['newreport']
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
