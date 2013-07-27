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

