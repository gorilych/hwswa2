from hwswa2.globals import config

def get_server(servername):
  return next((s for s in config['servers'] if s['name'] == servername), None)
