import logging

from contextlib import contextmanager

from hwswa2.server import Server
from hwswa2.server.linux import LinuxServer

logger = logging.getLogger(__name__)

# _servers = {name1: server1, name2: server2}
_servers = {}
# Some servers require postponed initialization
# _servers_to_init_later = {name1: {reason1: req1, reason2: req2}, name2: {reason1: req3}}
_servers_to_init_later = {}


def get_server(name):
    if name in _servers:
        return _servers[name]
    else:
        return None


def server_names():
    return [name for name in _servers]


@contextmanager
def servers_context(servers_list, roles_dir, reports_dir, remote_scripts_dir):
    srvrs = []
    for serverdict in servers_list:
        srvrs.append(server_factory(serverdict, roles_dir, reports_dir, remote_scripts_dir))
    yield srvrs
    # clean up in proper order, gateways last
    with_gw = []
    ordered_srvrs = []
    for srvr in srvrs:
        if srvr.gateway is None:
            ordered_srvrs.append(srvr)
        else:
            with_gw.append(srvr)
    while with_gw:
        for s in with_gw:
            if s.gateway in ordered_srvrs:
                ordered_srvrs.append(s)
        with_gw = [s for s in with_gw if s not in ordered_srvrs]
    ordered_srvrs.reverse()
    for s in ordered_srvrs:
        s.cleanup()


def server_factory(serverdict, roles_dir=None, reports_dir=None, remote_scripts_dir=None):
    global _servers, _servers_to_init_later

    name = serverdict['name']
    logger.debug("Trying to init server object %s" % name)

    if 'gateway' in serverdict:
        gwname = serverdict['gateway']
        if gwname in _servers:
            logger.debug("Already have gateway %s" % gwname)
            serverdict['gateway'] = _servers[gwname]
        else:
            logger.debug("Will postpone gateway setup, we are waiting for server %s" % gwname)
            if name not in _servers_to_init_later:
                _servers_to_init_later[name] = {}
            _servers_to_init_later[name]['gateway'] = gwname

    # fall back to linux - default ostype
    if 'ostype' not in serverdict:
        serverdict['ostype'] = 'linux'

    if serverdict['ostype'] == 'linux':
        server = LinuxServer.fromserverdict(serverdict, roles_dir, reports_dir, remote_scripts_dir)
    else:
        server = Server.fromserverdict(serverdict, roles_dir, reports_dir, remote_scripts_dir)

    _servers[name] = server
    if not name in _servers_to_init_later:
        logger.debug("Finished initialization of server %s" % name)

    # now check if new server blocks previous server initialization:
    for sname, reasons in _servers_to_init_later.iteritems():
        if 'gateway' in reasons:
            if reasons['gateway'] == name:
                logger.debug("We have found gateway %s for server %s" % (name, sname))
                so = _servers[sname]
                so.gateway = server
                del reasons['gateway']
        if not reasons:  # no more reasons?
            logger.debug("Finished initialization of server %s" % sname)

    # remove servers with empty reasons
    _servers_to_init_later = {n: r for n, r in _servers_to_init_later.iteritems() if r}

    return server
