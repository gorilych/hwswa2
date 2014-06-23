import logging

logger = logging.getLogger(__name__)

# default timeout value for all operations
TIMEOUT = 30

class Server(object):

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
        self.account = account
        self.address = address
        self.port = port
        self.dontcheck = dontcheck
        #gateway should be Server object
        self.gateway = gateway
        self.expect = expect
        self._last_connection_error = None
        self._accessible = None
        # list of temporary dirs/files
        self._tmp = []

    @classmethod
    def fromserverdict(cls, serverdict):
        """Instantiate from server dict which can be read from servers.yaml"""
        # these properties can be defined in servers.yaml
        properties = ['account', 'name', 'role', 'address', 'port', 'ostype', 'expect', 'dontcheck', 'gateway']
        initargs = {}
        for key in properties:
            if key in serverdict:
                initargs[key] = serverdict[key]
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

    def _connect(self, reconnect=False, timeout=None):
        """Initiates connection to the server.

            Returns true if connection was successful.
        """
        raise NotImplemented


class ServerException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)