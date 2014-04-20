import signal
import time
import copy
import struct
import sys
import os
import fcntl
import termios
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
    except KeyboardInterrupt:
      raise
    except:
      return
    return cr
  cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
  if not cr:
    try:
      fd = os.open(os.ctermid(), os.O_RDONLY)
      cr = ioctl_GWINSZ(fd)
      os.close(fd)
    except KeyboardInterrupt:
      raise
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

def term_winsz():
  '''Return terminal window size (height, width)'''
  winsz_fmt = "HHHH"
  winsz_arg = " "*struct.calcsize(winsz_fmt)
  if not sys.stdin.isatty():
    #raise type("NotConnectToTTYDevice", (Exception,), {})()
    return (25,80)
  return struct.unpack(winsz_fmt, fcntl.ioctl(sys.stdin, termios.TIOCGWINSZ, winsz_arg))[:2]

def term_type():
  '''Return terminal type'''
  return os.environ.get('TERM', 'linux')

def range2list(rstr):
  '''Converts range to list, f.e. 1-3,5,7-9 -> [1,2,3,5,7,8,9]'''
  if rstr == '':
    return []
  ls = []
  for subrange in rstr.split(','):
    start, minus, end = subrange.partition('-')
    if minus == '': # single port
      ls.append(int(start))
    else: # port range start-end
      ls.extend(range(int(start),int(end)+1))
  return sorted(list(set(ls)))

def list2range(ls):
  '''Converts list ls to range string, f.e. [1,2,3,5,7,8,9] -> 1-3,5,7-9'''
  if len(ls) == 0:
    return ''
  sls = sorted(ls)
  previous = start = sls[0]
  result = '%s' % start
  for p in sls[1:]:
    if p == previous + 1:
      previous = p
    else:
      if start == previous:
        result = result + ',%s' % p
      else:
        result = result + '-%s,%s' % (previous, p)
      start = previous = p
  if previous > start:
    result = result + '-%s' % previous
  return result

def splitlist(ls, chunksize):
  '''Split list into chunks of maximum chunksize'''
  return [ls[i:i+chunksize] for i in range(0,len(ls),chunksize)]

def splitrange(rg, chunksize):
  '''Split range into chunks of maximum chunksize'''
  ls = range2list(rg)
  if len(ls) == 0:
    return ['',]
  return [list2range(e) for e in splitlist(ls, chunksize)]

def joinlists(ls1,ls2):
  return sorted(list(set(ls1 + ls2)))

def joinranges(rg1, rg2):
  return list2range(joinlists(range2list(rg1), range2list(rg2)))

def differenceranges(rg1, rg2):
  s1 = set(range2list(rg1))
  s2 = set(range2list(rg2))
  return list2range(list(s1.difference(s2)))
