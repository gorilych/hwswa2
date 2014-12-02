=====
ROLES
=====

.. contents::


Role files
==========

HWSWA2 uses roles to determine what parameters it should obtain for the server
asdfasf and what requirements it should satisfy.

Role files are stored in *checks/* directory.


Role files structure
====================

Role file should have `YAML <http://www.yaml.org/>`_ format and *yaml*
extension. When HWSWA2 reads role file it interprets it as a dictionary with
specifics keys which describe the role. While HWSWA2 accepts any key inside a
role, only few have the meaning. Let's call them sections.

**description**
  This section is ignored by HWSWA2 and used for readability. Example from 
  pvclin.yaml::

    description: Checks for PVCLIN role

**includes**
  The value specified in this section should be a sequence of included roles,
  from more specific to less specific. HWSWA2 will read included roles and merge
  their key values accordingly. Example from pvclin.yaml::

    includes: [ common ]

**parameters** 
  This section represents mapping between parameter names and the commands
  (sometime in a complex manner) HWSWA2 should execute on the server to obtain
  parameter value.

**firewall**
  This section contains all firewall requirements for the role. This section is
  used to check or print out firewall requirements between servers with
  different roles.
  
**requirements**
  In this section you can specify CPU/RAM/disk requirements for the role. It is
  possible to add requirement for some specific parameter.

We will cover **parameters**, **firewall** and **requirements** sections in more
details below.


Parameters
==========

String parameter
----------------

Simple parameter is mapped to a command which should be executed on a remote
server. Example from common.yaml::

  parameters:
    hostname:           hostname -f 2>/dev/null || hostname
    time:               LANG=C date
    umask:              umask
    uptime:             uptime
    architecture:       uname --machine

As you see from above example, command ``hostname -f 2>/dev/null || hostname``
will be executed on the server and its output will be saved in a report as a
value of parameter named **hostname**.

In a server report it will look like this::

  parameters:
    hostname: aser.lan
    time: Tue Nov 25 22:42:57 NOVT 2014
    umask: '0022'
    uptime: ' 22:42:57 up 16:30,  5 users,  load average: 0.12, 0.09, 0.07'
    architecture: x86_64


Complex parameters
------------------

Sometimes a parameter should be represented not by a single string but by a more
complex structure like a set of contained parameters or by a table.

For this purpose you need to describe parameter as a dictionary and put some
specific keys inside it, which should start with underscore.

``_type`` key determines the type of the parameter which can be: *dictionary*,
*list* or *table*. If ``_type`` is not specified, HWSWA2 assumes this parameter
is a *dictionary*.

``_command`` key says which command's output to use to obtain parameter's value.

``_script`` key is an alternative to a ``_command``: HWSWA2 will create
temporary executable file and will use output of this script's execution to
obtain parameter's value.

Dictionary parameter
++++++++++++++++++++

For *dictionary* parameter the logic is simple: took each other key as a
subparameter and obtain it with a specified command. Subparameter can be of a
different type its turn. Example of a *dictionary* parameter **processors** from
common.yaml::

  processors:
    _type: dictionary
    count:     grep --fixed-strings processor -c /proc/cpuinfo
    model:     grep --fixed-strings --max-count=1 'model name' /proc/cpuinfo | awk -F':' '{print $2}' | sed 's/^ //g'
    frequency(GHz): grep --fixed-strings --max-count=1 'cpu MHz' /proc/cpuinfo 
                    | awk '{printf("%.2f",$NF/1000)}' 
                    | sed -e 's/\.0*$//' -e 's/\(\.[0-9]*[1-9]\)0*$/\1/'

In a report::

  processors: {count: '1', frequency(GHz): '0.8', model: AMD Athlon(tm) II Neo K125 Processor}


Table parameter
+++++++++++++++

If parameter has a ``_type`` *table*, it should also contain: ``_fields``,
``_separator`` and ``_command`` (or alternatively ``_script``). Table is
generated from the output of a *command* (or *script*). Each line of output is
splitted by a *separator* to form table row with *fields*. Example of a *table*
parameter **partitions** from common.yaml::

  partitions:
    _type: table
    _fields: [device, size(GB), mountpoint, fs_type]
    _separator: '|'
    _command: lspartitions.sh

In a report::

  partitions:
  - {device: sda1, fs_type: ext4, mountpoint: /, size(GB): '489.976'}
  - {device: sda2, fs_type: swap, mountpoint: '-', size(GB): '4'}


List parameter
++++++++++++++

Value of list parameter is a sequence of dictionaries with subparameters.

There is a specific subparameter called generator. It is evaluated first and its
value is used as a replacement for a placeholder inside commands for other subparameters.

List parameter should have additional specific key ``_generator``. It should
have form ``{field: placeholder}`` where ``field`` says which subparameter will
be used as a generator and ``placeholder`` says which placeholder to replace in
other subparameters' commands. Replacement is done with python operation % (see
`Format String Syntax <https://docs.python.org/2/library/string.html#format-string-syntax>`_).

First HWSWA2 finds generator which should be a simple string parameter and
executes its command. HWSWA2 expects multiline output from this command.

Next, for each line of output, it uses this line as a generator value, finds out
other subparameters' values (by executing appropriate commands with substituted
placeholders). Resulting dictionary is added to the sequence. 

Example of list parameter from common.yaml::

    network_interfaces:
      _type: list
      _generator: {name: name}
      name:   /sbin/ip --oneline link show | grep --fixed-strings --invert-match 'link/loopback'
              | awk '{print $2}' | sed 's/:$//' | sed 's/@[^@]*$//'
      state:  /sbin/ip --oneline link show dev %(name)s 
              | grep --only-matching --extended-regexp ' state (UP|DOWN|UNKNOWN) ' 
              | awk '{print $2}'
      hwaddr: /sbin/ip --oneline link show dev %(name)s
              | grep --only-matching --extended-regexp ' link/.*'
              | awk '{print $2}'
      gateway: /sbin/ip route list dev %(name)s | grep ^default | awk '{print $3}'
      ip:
        _type: table
        _fields: [address, prefix]
        _separator: ' '
        _command: "{ /sbin/ip -family inet -oneline address list scope global dev %(name)s;
                     /sbin/ip -family inet6 -oneline address list scope global dev %(name)s; }
                   | awk '{print $4}' | tr '/' ' '"

Here we see that parameter **network_interfaces** is a list of network
interfaces. Generator is a subparameter **name**. Each other subparameter has a
placeholder **%(name)s** in its command.

HWSWA2 will execute first command of **name** subparameter which will produce
lines with nic names ('eth0', 'eth1', etc) and then for each name will find nic
properties by executing commands of other subparameters preliminary replacing
**%(name)s** with 'eth0', 'eth1' and so on.

In a report it will look like this::

    network_interfaces:
    - name: eth0
      hwaddr: 00:26:2d:ad:f7:23
      ip:
      - {address: 192.168.1.8, prefix: '24'}
      - {address: '2002:25c0:3110:1:226:2dff:fead:f723', prefix: '64'}
      gateway: 192.168.1.1
      state: UP
    - name: wlan0
      hwaddr: 78:e4:00:d4:b9:85
      ip: []
      gateway: ''
      state: DOWN


Firewall
========

Firewall section contains a list of rules with below properties:

name
  name of the rule



Example of simple rule::


  - name: Incoming_from_LinMN
    description: Allow SSH access and connections to pleskd from POA LinMN
    # policy: allow/deny
    policy: allow
    # direction: incoming/outgoing
    direction: incoming
    networks: [backnet]
    # proto: TCP/UDP/ICMP
    protos: [TCP]
    # ports: 22,53,80,443,2000-2100 - comma-separated, no spaces
    ports: 22,8352-8439,8441-8500
    # type: infra/internet
    type: infra
    connect_with:
      # roles are for type = infra
      roles: [linmn]
      # hosts are for type = internet, host can be IP/FQDN, like 8.8.8.8 or ya.ru
      hosts: []
      # smtprelay, dnsresolver, hwswa_host: yes/no, no by default
      #smtprelay: no
      #dnsresolver: no
      #hwswa_host: no


Requirements
============
