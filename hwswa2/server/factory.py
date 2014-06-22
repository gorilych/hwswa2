from hwswa2.server.linux import LinuxServer

def server_factory(serverdict):
    if 'ostype' in serverdict:
        if serverdict['ostype'] == 'linux':
            return LinuxServer.fromserverdict(serverdict)
    else: # fall back to linux
        serverdict['ostype'] = 'linux'
        return LinuxServer.fromserverdict(serverdict)
