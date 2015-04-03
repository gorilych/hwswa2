=====
ROLES
=====

.. contents::


Role files
==========

HWSWA2 uses roles to determine what parameters it should obtain for the server
and what requirements it should satisfy.

Role files are stored in *checks/* directory.


Role files structure
====================

Role file should have `YAML <http://www.yaml.org/>`_ format and *yaml*
extension. When HWSWA2 reads role file it interprets it as a dictionary with
specific keys which describe the role. Let's call them sections. While HWSWA2
accepts any key inside a role, only few have the meaning

description
  This section is ignored by HWSWA2 and used for readability. Example from 
  pvclin.yaml::

    description: Checks for PVCLIN role

ostype
  Determines OS type for the server which can have this role. Can be either
  linux or windows. Example from common.yaml::

    ostype: linux

includes
  The value specified in this section should be a sequence of included roles,
  from more specific to less specific. HWSWA2 will read included roles and merge
  their sections accordingly. Example from pvclin.yaml::

    includes: [ common ]

parameters
  This section represents mapping between parameter names and the commands
  (sometime in a complex manner) HWSWA2 should execute on the server to obtain
  parameter value.

firewall
  This section (represented as a list) contains all firewall requirements for 
  the role. It is used to check or print out firewall requirements 
  between servers with different roles.
  
requirements
  In this section you can specify CPU/RAM/disk requirements for the role. It is
  possible to add requirement for arbitrary parameter as well.

We will cover **parameters**, **firewall** and **requirements** sections in more
details below.


Parameters
==========

String parameter
----------------

String parameter is simply mapped to a command which should be executed on a
remote server. Example from common.yaml::

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

For windows roles you can specify prefix 'ps|' to indicate that the command
should be executed in PowerShell    


Complex parameters
------------------

Sometimes a parameter should be represented by a more complex structure like a
set of contained parameters or by a table.

For this purpose you need to describe parameter as a dictionary and put some
specific keys inside it, which should start with underscore.

``_type`` key determines the type of the parameter which can be: *dictionary*,
*list* or *table*. If ``_type`` is not specified, HWSWA2 assumes this parameter
is a *dictionary*.

``_command`` key says which command's output to use to obtain parameter's value.

``_script`` key is an alternative to a ``_command``: HWSWA2 will create
temporary executable file and will use output of this script's execution to
obtain parameter's value. This key does not work for windows roles and
CAN BE DROPPED IN FUTURE VERSIONS

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

.. note::
   Subparameter names should not start with underscore!

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

List parameter should have additional specific key ``_generator`` with value of
form ``{field: placeholder}`` where ``field`` says which subparameter will be
used as a generator and ``placeholder`` says which placeholder to replace with
generator value in other subparameters' commands. Replacement is done with
python operation % (see `Format String Syntax
<https://docs.python.org/2/library/string.html#format-string-syntax>`_).

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
lines with nic names ('eth0', 'eth1', etc) and then for each name it will find
nic properties by executing commands of other subparameters preliminary
replacing **%(name)s** with 'eth0', 'eth1' and so on.

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

.. note::
   Subparameter names should not start with underscore!

Firewall
========

Firewall section contains a list of rules (or rule groups) with below properties:

name
  name of the rule

description
  rule description

policy
  rule policy, can be *allow* or *deny*

direction
  direction of connections affected by this rule, can be *incoming* or *outgoing*

networks
  list of network names in which this rule is effective

protos
  list of network protocols, can contain *TCP* and *UDP*

ports
  range of ports, comma separated. Continuos range can be specified with a dash
  as start-end

type
  can be *infra* (for connections between servers with particular roles) or
  *internet* (for connections from/to server and some outer host)

connect_with
  Dictionary that determines the *other* side of the connection. Can contain:
    roles
      list of roles (for **type** = *infra*)
    hosts
      list of outer hosts (for **type** = *internet*)
    
group
  *yes* or *no*. Rule group combines different rules with the same properties,
  for example all *incoming* rules can be joined into one rule group with
  **direction** set to *incoming*. Specific properties for each rule are 
  described in additional property **rules**

rules
  sequence of rules for rule group

Example of a simple rule::

  - name: Incoming_from_LinMN
    description: Allow SSH access and connections to pleskd from POA LinMN
    policy: allow
    direction: incoming
    networks: [backnet]
    protos: [TCP]
    ports: 22,8352-8439,8441-8500
    type: infra
    connect_with:
      roles: [linmn]

Example of rule group (all rules have the same **policy**, **direction**,
**networks**, **type** and **protos**)::

  firewall:
    - name: from_branding
      policy: allow
      group: yes
      direction: outgoing
      networks: [frontnet]
      type: infra
      protos: [TCP]
      rules:
        - name: to_file_manager
          ports: 1299
          connect_with: {roles: [filemanager]}
        - name: to_phppgadm
          ports: 9114
          connect_with: {roles: [phppgadm]}
        - name: to_webmail_sslpr_pba
          ports: 443
          connect_with: {roles: [atmail, impwebmail, winsslpr, pbalinfe, pbawinfe]}
        - name: to_awstats_mssqladm
          ports: 80
          connect_with: {roles: [awstats, mssqldataadm]}


Requirements
============

This section contains requirements which should be satisfied by the server
holding this role.

As with **parameters**, this section is a mapping between requirement **name** and
requirement properties.

Requirement properties are:

parameter
  Specifies which parameter from **parameters** is a subject to this requirement
  If **parameter** is not specified, HWSWA2 assumes it equals to requirement **name**
  Subparameter can be specified with a colon: ``param:subparam``.

value
  value to compare with. If **value** is not specified, this requirement is treated
  by HWSWA2 as a requirement template which can be used in roles which include
  this one (see short notation below).

type
  Determines how requiement *value* is compared against parameter value. Type can 
  be *eq* (equal), *neq* (not equal), *regex* (matches pattern), *lt* (less than),
  *le* (less or equal), *gt* (greater than), *ge* (greater or equal), *manual*,
  *networks* or *disk*. Default: *eq*.

  For type *disk*: **parameter** is a path and **value** is a minimum disk space in GB.

  Requirements of type *manual* will always fail with warning specified in **value**.
  This is useful in case some requirement check cannot be automated and should be
  checked manually.

  Requirement of type *networks* checks if server has nics with IP address from
  networks, specied as a list in a **value**.

  Also HWSWA2 can guess **type** as *disk* if **parameter** starts with '/'
  or 'C:', 'D:', etc.

join-rule
  Roles including this role can specify its own requirements with the same name.
  In this case HWSWA2 will merge current role requirement with included 
  requirements using **join-rule**. It can be *override* (current requirement
  remains only), *and* (both current and included requirements should be
  satisfied), *or* (either current or included), sum (resulting requirement
  value equals to sum of current and included values), *mul* (multiplication of 
  values), *avg* (average), *min*, *max*. Default: *override*. For **type**
  *disk* **join-rule** is always *sum*.

Example::

  requirements:
    OS: { type: regex, value: '(CentOS|RedHat).* 6\.', join-rule: and }
    ram(GB): { type: ge, value: 0.5, join-rule: sum }
    swap(GB): { type: ge, value: 1, join-rule: sum }
    cpu-cores: { parameter: processors:count, type: ge, value: 1, join-rule: max }
    root_partition: { parameter: /, value: 10 }
    networks: { type: networks, value: [backnet, frontnet] }
    checkSAN: { type: manual, value: "In case of cluster heartbeat is needed, check manually" }

Also HWSWA2 allows short notation for requirements, like this::

  requirements:
    OS: '(CentOS|RedHat).* 6\.'
    architecture: x86_64
    ram(GB): 0.5
    swap(GB): 1
    cpu-cores: 2
    cpu-frequency: 2
    /: 10
    networks: [backnet, frontnet]

In this case only **value** is specified and other properties are taken from
included requirement templates (or defaults are taken, or guessed).
