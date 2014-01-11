import signal
import time
import copy
from hwswa2.globals import config

def get_server(servername):
  return next((s for s in config['servers'] if s['name'] == servername), None)

def wait_for(condition_fn, args, timeout=60):
  """Waits for condition or timeout
  
  Returns True if condition is met within timeout period
  """
  starttime = time.time()
  while not condition_fn(*args):
    if time.time() - starttime > timeout:
      return False
  return True

def wait_for_not(condition_fn, args, timeout=60):
  """Waits while condition became false or timeout

  Returns True if condition become False within timeout period
  """
  starttime = time.time()
  while condition_fn(*args):
    if time.time() - starttime > timeout:
      return False
    time.sleep(5)
  return True

# decorator to make arguments to be passed by value
def passbyval(func):
  def _new_function_with_args_passed_by_value(*args, **kargs):
    cargs = [copy.deepcopy(arg) for arg in args]
    ckargs = {}
    for key in kargs:
      ckargs[key] = copy.deepcopy(kargs[key])
    return func(*cargs, **ckargs)
  return _new_function_with_args_passed_by_value


def threaded(f, daemon=False):
  """Decorator for threaded functions"""
  import Queue, threading

  def wrapped_f(q, *args, **kwargs):
    '''this function calls the decorated function and puts the 
       result in a queue'''
    ret = f(*args, **kwargs)
    q.put(ret)

  def wrap(*args, **kwargs):
    '''this is the function returned from the decorator. It fires off
       wrapped_f in a new thread and returns the thread object with
       the result queue attached'''

    q = Queue.Queue()

    t = threading.Thread(target=wrapped_f, args=(q,)+args, kwargs=kwargs)
    t.daemon = daemon
    t.start()
    t.result_queue = q        
    return t

  return wrap


def shell_escape(string):
    """
    Escape double quotes, backticks and dollar signs in given ``string``.

    For example::

        >>> _shell_escape('abc$')
        'abc\\\\$'
        >>> _shell_escape('"')
        '\\\\"'
    """
    for char in ('"', '$', '`'):
        string = string.replace(char, '\%s' % char)
    return string

def getTerminalSize():
  import os
  env = os.environ
  def ioctl_GWINSZ(fd):
    try:
      import fcntl, termios, struct, os
      cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
    except:
      return
    return cr
  cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
  if not cr:
    try:
      fd = os.open(os.ctermid(), os.O_RDONLY)
      cr = ioctl_GWINSZ(fd)
      os.close(fd)
    except:
      pass
  if not cr:
    cr = (env.get('LINES', 25), env.get('COLUMNS', 80))
    ### Use get(key[, default]) instead of a try/catch
    #try:
    #  cr = (env['LINES'], env['COLUMNS'])
    #except:
    #  cr = (25, 80)
  return (int(cr[0]), int(cr[1]))
