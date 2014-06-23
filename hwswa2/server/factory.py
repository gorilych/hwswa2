import logging

from weakref import ref

from hwswa2.server import Server
from hwswa2.server.linux import LinuxServer

logger = logging.getLogger(__name__)

# We are using weak references to keep previously created servers
# _servers = {name1: ref1, name2: ref2}
_servers = {}
# Some servers require postponed initialization
# _servers_to_init_later = {name1: {reason1: req1, reason2: req2}, name2: {reason1: req3}}
_servers_to_init_later = {}


def server_factory(serverdict):
    global _servers, _servers_to_init_later
    # remove stale references
    _servers = {n: r for n, r in _servers.iteritems() if r() is not None}
    _servers_to_init_later = {n: r for n, r in _servers_to_init_later.iteritems() if n in _servers}

    name = serverdict['name']
    logger.debug("Trying to init server object %s" % name)

    if 'gateway' in serverdict:
        gwname = serverdict['gateway']
        if gwname in _servers:
            logger.debug("Already have gateway %s" % gwname)
            serverdict['gateway'] = _servers[gwname]()
        else:
            logger.debug("Will postpone gateway setup, we are waiting for server %s" % gwname)
            if name not in _servers_to_init_later:
                _servers_to_init_later[name] = {}
            _servers_to_init_later[name]['gateway'] = gwname

    # fall back to linux - default ostype
    if 'ostype' not in serverdict:
        serverdict['ostype'] = 'linux'

    if serverdict['ostype'] == 'linux':
        server = LinuxServer.fromserverdict(serverdict)
    else:
        server = Server.fromserverdict(serverdict)

    _servers[name] = ref(server)
    if not name in _servers_to_init_later:
        logger.debug("Finished initialization of server %s" % name)

    # now check if new server blocks previous server initialization:
    for sname, reasons in _servers_to_init_later.iteritems():
        if 'gateway' in reasons:
            if reasons['gateway'] == name:
                logger.debug("We have found gateway %s for server %s" % (name, sname))
                so = _servers[sname]()
                so.gateway = server
                del reasons['gateway']
        if not reasons:  # no more reasons?
            logger.debug("Finished initialization of server %s" % sname)

    # remove servers with empty reasons
    _servers_to_init_later = {n: r for n, r in _servers_to_init_later.iteritems() if r}

    return server
