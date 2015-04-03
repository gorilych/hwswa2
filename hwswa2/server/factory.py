import logging

from contextlib import contextmanager

from hwswa2.server import Server, ServerException
from hwswa2.server.linux import LinuxServer
from hwswa2.server.windows import WindowsServer
import hwswa2.server.role

__all__ = ['get_server', 'server_names', 'servers_context']

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
def servers_context(servers_list):
    srvrs = []
    for serverdict in servers_list:
        srvrs.append(server_factory(serverdict))
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


def server_factory(serverdict):
    global _servers, _servers_to_init_later

    name = serverdict['name']

    if 'gateway' in serverdict:
        gwname = serverdict['gateway']
        if gwname in _servers:
            serverdict['gateway'] = _servers[gwname]
        else:
            if name not in _servers_to_init_later:
                _servers_to_init_later[name] = {}
            _servers_to_init_later[name]['gateway'] = gwname

    if 'ostype' not in serverdict:
        # try to get ostype from roles
        rolenames = serverdict.get('role')
        if rolenames is not None:
            if not isinstance(rolenames, list):
                rolenames = [rolenames, ]
            for rolename in rolenames:
                role = hwswa2.server.role.role_factory(rolename)
                if role.ostype is not None:
                    serverdict['ostype'] = role.ostype
                    break
        if 'ostype' not in serverdict:  # didn't find in roles
            # fall back to linux - default ostype
            serverdict['ostype'] = 'linux'

    try:
        if serverdict['ostype'] == 'linux':
            server = LinuxServer.fromserverdict(serverdict)
        elif serverdict['ostype'] == 'windows':
            server = WindowsServer.fromserverdict(serverdict)
        else:
            server = Server.fromserverdict(serverdict)
    except ServerException as se:
        logger.debug("Server initialization fails for %s: %s" % (serverdict, se))
        return None

    _servers[name] = server

    # now check if new server blocks previous server initialization:
    for sname, reasons in _servers_to_init_later.iteritems():
        if 'gateway' in reasons:
            if reasons['gateway'] == name:
                logger.debug("We have found gateway %s for server %s" % (name, sname))
                so = _servers[sname]
                so.gateway = server
                del reasons['gateway']

    # remove servers with empty reasons
    _servers_to_init_later = dict([(n, r) for n, r in _servers_to_init_later.iteritems() if r])

    return server
