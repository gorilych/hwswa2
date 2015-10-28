import logging

from contextlib import contextmanager

from hwswa2.server import Server, ServerException
from hwswa2.server.linux import LinuxServer
from hwswa2.server.windows import WindowsServer
import hwswa2.server.role

__all__ = ['get_server', 'server_names', 'servers_context']

logger = logging.getLogger(__name__)

# _not_inited_servers = {name1: serverdict1, name2:.. }
_not_inited_servers = {}
# _servers = {name1: server1, name2: server2}
_servers = {}


def get_server(name):
    global _servers, _not_inited_servers
    if name in _not_inited_servers:
        logger.debug("Postponed initialization of server %s started" % name)
        server_factory(_not_inited_servers[name])
        del _not_inited_servers[name]
    if name in _servers:
        return _servers[name]
    else:
        return None


def server_names():
    return [name for name in _servers.keys() + _not_inited_servers.keys()]


@contextmanager
def servers_context(servers_list):
    global _servers
    for serverdict in servers_list:
        server_pre_init(serverdict)
    yield "finished"
    # clean up in proper order, gateways last
    with_gw = []
    ordered_srvrs = []
    for srvr in _servers.values():
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


def server_pre_init(serverdict):
    global _not_inited_servers
    name = serverdict['name']
    _not_inited_servers[name] = serverdict


def server_factory(serverdict):
    global _servers

    name = serverdict['name']

    if 'gateway' in serverdict:
        gwname = serverdict['gateway']
        logger.debug("Server %s uses server %s as a gateway" % (name, gwname))
        serverdict['gateway'] = get_server(gwname)

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

    return server
