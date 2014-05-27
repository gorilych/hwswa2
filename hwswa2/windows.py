import ntpath
import os.path
import socket

from impacket.dcerpc.v5.transport import DCERPCStringBindingCompose, DCERPCTransportFactory
from impacket.dcerpc.v5 import scmr
from impacket.smbconnection import SessionError

import hwswa2.aux as aux
from hwswa2.globals import config
from logging import debug

win_timeout = 30

def connect(server, reconnect=False, timeout=win_timeout):
    '''Connects to server and returns (SMB)transport object'''
    if 'transport' in server:
        if reconnect:
            server['transport'].disconnect()
            del server['transport']
            debug("Will reconnect to server %s" % server['name'])
        else:
            return server['transport']
    debug("Trying to connect to server %s" % server['name'])
    hostname = server['address']
    username = server['account']['login']
    password = server['account']['password']
    strbinding = DCERPCStringBindingCompose(protocol_sequence='ncacn_np', 
                                            network_address=hostname, 
                                            endpoint='\pipe\svcctl')
    transport = DCERPCTransportFactory(strbinding)
    transport.set_credentials(username, password)
    transport.set_connect_timeout(timeout)
    dce = transport.get_dce_rpc()

    try:
        dce.connect()
    except SessionError, se:
        debug('Failed to establish connection with %s: %s'% (server['name'], se))
        server['lastConnectionError'] = 'SessionError raised while connecting: %s' % se
        return None
    except socket.error, serr:
        debug('socket.error raised while connecting to %s@%s: %s' % (username, hostname, serr))
        server['lastConnectionError'] = 'socket.error raised while connecting to %s@%s: %s' % (username, hostname, serr)
        return None
    else:
        dce.bind(scmr.MSRPC_UUID_SCMR)
        debug('Established connection with %s@%s' % (username, hostname))
        server['transport'] = transport
        return server['transport']


def shell(server, privileged=True):
    '''Opens remote cmd session'''
    raise NotImplementedError

def accessible(server, retry=False):
    '''Checks if server is accessible and manageable'''
    raise NotImplementedError


def pingable(server):
    '''Checks if server responds to ping'''
    raise NotImplementedError
    #command = "ping -w 1 -q -c 1 %s" % server['address']
    #return subprocess.call(command) == 0

def exec_cmd_i(server, sshcmd, privileged=True, timeout=win_timeout, get_pty=False):
    '''Executes command interactively'''
    raise NotImplementedError


def exec_cmd(server, sshcmd, input_data=None, timeout=win_timeout, privileged=True):
    '''Executes command and returns tuple of stdout, stderr and status'''
    raise NotImplementedError

def get_cmd_out(server, sshcmd, input_data=None, timeout=win_timeout, privileged=True):
    '''Returns command output (stdout)'''
    raise NotImplementedError


def remove(server, path, privileged=True):
    '''Removes file/directory'''
    raise NotImplementedError


def put(server, localpath, remotepath):
    '''Copies local file/directory to the server''' 
    debug("Copying %s to %s:%s" %(localpath, server['name'], remotepath))
    if not os.path.exists(localpath):
        raise Exception("Local path does not exist: %s" % localpath)
    transport = connect(server)
    smbconnection = transport.get_smb_connection()
    fh = open(localpath, 'rb')
    # remotepath = C:\somedir\somefile
    # => share = C$, sharepath = somedir\somefile
    share = remotepath[0] + '$'
    sharepath = remotepath[3:]
    smbconnection.putFile(share, sharepath, fh.read)
    

def mktemp(server, template='hwswa2.XXXXX', ftype='d', path='`pwd`'):
    '''Creates directory using mktemp and returns its name'''
    raise NotImplementedError


def mkdir(server, path):
    '''Creates directory'''
    debug("MKDIR %s on %s" %(path, server['name']))
    transport = connect(server)
    smbconnection = transport.get_smb_connection()
    share = path[0] + '$'
    sharepath = path[3:]
    smbconnection.createDirectory(share, sharepath)


def rmdir(server, path):
    '''Removes directory'''
    debug("RMDIR %s on %s" %(path, server['name']))
    transport = connect(server)
    smbconnection = transport.get_smb_connection()
    share = path[0] + '$'
    sharepath = path[3:]
    smbconnection.deleteDirectory(share, sharepath)

def exists(server, path):
    raise NotImplementedError


def write(server, path, data):
    raise NotImplementedError


def is_it_me(server):
    raise NotImplementedError


def check_reboot(server, timeout=300):
    '''Reboot the server and check the time it takes to come up'''
    raise NotImplementedError


def cleanup(server):
    if 'transport' in server:
        server['transport'].disconnect()
        del server['transport']
        debug("Closed connection to server %s" % server['name'])


def serverd_start(server):
    '''Starts serverd on server'''
    raise NotImplementedError


def serverd_stop(server):
    '''Stops serverd on server'''
    raise NotImplementedError


def serverd_cmd(server, cmd):
    '''Sends command to serverd and returns tuple (status_ok_or_not, result)'''
    raise NotImplementedError

