=============
Configuration
=============

.. contents::

Overview
========

There are 3 configuration files:

- **main.cfg**: main configuration file
- **servers.yaml**: file with servers (addresses, roles, login information)
- **networks.yaml**: file with network addresses (backnet, frontnet, ..)

Also, it is possible to change hwswa2 behaviour by command line options or
by setting environment variables.

main.cfg
========

This configuration file is parsed with ConfigObj_ Python library, and it's
format is quite simple. It supports sections and variables (starting with 
$ sign).

Command line options take precedence over options from configuration files.

By default, hwswa2 searches for main.cfg alongside with its binary, in the
same directory. Also, you can specify which configuration file to use with
-c/--config command line option.

General options
---------------

General parameters are not located in any section.

**serversfile**
+++++++++++++++

Location of servers.yaml_ (full or relative to hwswa2 path).

Default: config/servers.yaml

Command line option: -s/--servers file/path

**networksfile**
++++++++++++++++

Location of networks.yaml_ (full or relative to hwswa2 path).

Default: config/networks.yaml

Command line option: -n/--networks file/path

**logfile**
+++++++++++

Location of logging file (full or relative to hwswa2 path).

If directory for logging file does not exists, hwswa2 will create it.

Default: logs/hwswa2.log

Command line option: -l/--log file/path

**reportsdir**
++++++++++++++

Directory where check reports for servers are saved.

Default: logs/reports

Command line option: -r/--reports dir/path

**rolesdir**
++++++++++++

Directory where role files are stored (full or relative to hwswa2 path).

Better not to change.

Default: roles

**debug**
+++++++++

Enable debug mode for logging. Can be true/false.

Default: false

Command line option (to enable): -d/--debug

**remote_debug**
++++++++++++++++

Enable debug mode for logging of remote execution (on remote server).
Can be true/false.

Remote logs can be found in /tmp on remote server.

Default: false

**ssh_timeout**
+++++++++++++++

Timeout (in seconds) for SSH operations (+ establishing connection).

Default: 30

**win_timeout**
+++++++++++++++

Timeout (in seconds) for operations on Windows servers (+ establishing connection).

Default: 100

**reboot_timeout**
++++++++++++++++++

Time to wait for the server to shut down (one time) and go up (another time)
while checking reboot time with subcommand *reboot*.

Default: 300. So *reboot* can wait up to 600 seconds in total.

Section check
-------------

This section ``[check]`` includes parameters for subcommand *check*.

**report_period**
+++++++++++++++++

*check* will report progress every **report_period** seconds.

Default: 5

Section firewall
----------------

This section ``[firewall]`` includes parameters for subcommand *firewall*

**send_timeout**
++++++++++++++++

Timeout in seconds for send operation while checking connection to TCP port.

Default: 1

**max_open_sockets**
++++++++++++++++++++

Maximum number of concurrently open TCP/UDP ports for listening, limits number
of concurrently checked ports.

Default: 100

**report_period**
+++++++++++++++++

*firewall* will report progress every **report_period** seconds.

Default: 10

**max_failures**
++++++++++++++++

*firewall* will stop checking connections between two servers after this number of
failures (listen command failed). Rest of ports will be reported as not checked.

Default: 10. 0 means not to stop checking.

**max_closed_ports**
++++++++++++++++++++

*firewall* will stop checking connections between two servers after this number
of ports found to be filtered. Rest of ports will be reported as not checked.

Default: 500. 0 means not to stop checking.

Section role-aliases
--------------------

This section ``[role-aliases]`` sets which role aliases can be used for server
in servers.yaml.

This section is pre-populated in main.cfg provided in distribution.

Format is simple::

  role = alias1, alias2, alias3

.. _ConfigObj: https://wiki.python.org/moin/ConfigObj

servers.yaml
============

This configuration file is a YaML_ document. It contains information about
servers.

By default, hwswa2 searches for servers.yaml alongside with its binary, in the
same directory. You can specify custom location via main.cfg_ or with command
line option -s/--servers. 

From this document hwswa2 reads only one node_ - **servers**, which content
is supposed to be a sequence__.

Each element in **servers** is a mapping__, representing one server.

All child nodes in this element are optional except for the **name** node.

Example of server element::

  - { name: localhost, address: 127.0.0.1, role: PVCLIN, account: { login: root,
    password: secret }, expect: [{ip: 4.4.4.4, network: frontnet}, 
                                 {ip: 10.10.10.10, network: heartbeat}] }

Possible nodes in server element are:

**name**
--------

Name of the server. Used as argument in hwswa2 subcommands.

**dontcheck**
-------------

If this node is presented, this server won't be checked, but can be used as a
**gateway** for other servers.

**address**
-----------

IP address or hostname for connections.

**port**
--------

Port for connections. By default, it is 22 for linux servers and 5985
for Windows servers.

**gateway**
-----------

It is a **name** of another server which should be used as a gateway for
connections.

**role**
--------

Single role or sequence of roles of this server. If role does not match (case
insensitive) file names in roles directory (<role>.yaml) or is not mentioned in
any role file (in firewall rules) - it is ignored by hwswa2.

**account**
-----------

This node is a mapping__. It represents account used for connections. Included
nodes are:

**login** - account login name. Mandatory.

**key** - path to ssh key.

**password** - account password or key passphrase.

Either **key** or **password** or both should be specified.

Optionally, you can specify:

**su** or **sudo** - specifies the way to elevate priviliges for non-root
account. If these nodes are not empty, this value will be taken as a password
asked by su/sudo.

**encrypted** - if true, **password** and **su**/**sudo**  are specified in
encrypted form.

Encryption key can be specified via environment variable ``HWSWA2_ENC_PWD`` or with
command line option -a/--askpass.

**expect**
----------

Sequence__ of so called expectation you have for this server. Only one type of
expectation is supported for now: IP address. Such expectation is a *mapping*
with two nodes, **ip** and **network**. Subcommand **check** will verify that
server has specified IP address and it is resided in specified network.

.. _YaML: http://yaml.org/
.. _node: http://www.yaml.org/spec/1.2/spec.html#id2764044
.. _collections: http://yaml.org/spec/1.2/spec.html#id2759963
__ collections_
__ collections_
__ collections_
__ collections_

networks.yaml
=============

This configuration file is a YaML_ document. It contains information about
networks.

By default, hwswa2 searches for networks.yaml alongside with its binary, in the
same directory. You can specify custom location via main.cfg_ or with command
line option -n/--networks. 

From this document hwswa2 reads only one node_ - **networks**, which content
is supposed to be a sequence__.

Each element in **servers** is a mapping__, representing one **network**.

All child nodes, **name**, **network** and **prefix** in this element are mandatory.

**name** can be *frontnet*, *backnet*, *privnet*, *heartbeat*, *storagenet* and
so on.

**network**/**prefix** define network address in `CIDR notation`_.

If network has several network addreses, it can have several elements.

Example of network element::

  - {name: frontnet,  address: 10.200.200.0, prefix: 24}

.. _CIDR notation: https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation
__ collections_
__ collections_

Command line options
====================

Where are general options and separate options for each subcommand.

General options
---------------

``-h/--help``
+++++++++++++

Show usage screen::

  $ ./hwswa2.py -h
  usage: hwswa2 [-h] [--version] [-c CONFIGFILE] [-s SERVERSFILE]
                [-n NETWORKSFILE] [-k NETWORK] [-l LOGFILE] [-r REPORTSDIR] [-d]
                [-a]
                {encrypt,decrypt,list-roles,list-servers,ls,check,ck,show-reqs,
                sr,prepare,pr,shell,sh,reboot,exec,e,ni_exec,ne,bulk_exec,be,
                put,p,get,g,firewall,fw,show-firewall,sfw,lastreport,lr,report,
                r,reports,rs,reportdiff,rd,reports-history,rh,agent}
                ..
  
  HWSWA: tool for automatization of hardware/software check
  
  optional arguments:
    -h, --help            show this help message and exit
    --version             show program's version number and exit
    -c CONFIGFILE, --config CONFIGFILE
                          path to config file
    -s SERVERSFILE, --servers SERVERSFILE
                          path to servers file
    -n NETWORKSFILE, --networks NETWORKSFILE
                          path to networks file
    -k NETWORK, --network NETWORK
                          network in format name:addr/prefix
    -l LOGFILE, --log LOGFILE
                          path to log file
    -r REPORTSDIR, --reports REPORTSDIR
                          directory to store reports
    -d, --debug           enable debug
    -a, --askpass         ask encryption password
  
  Subcommands:
    {encrypt,decrypt,list-roles,list-servers,ls,check,ck,show-reqs,sr,prepare,
    pr,shell,sh,reboot,exec,e,ni_exec,ne,bulk_exec,be,put,p,get,g,firewall,fw,
    show-firewall,sfw,lastreport,lr,$eport,r,reports,rs,reportdiff,rd,
    reports-history,rh,agent}
                          Run `hwswa2 <subcommand> -h` for usage
      encrypt             encrypt password
      decrypt             decrypt password
      list-roles          show available roles
      list-servers (ls)   list servers
      check (ck)          check servers
      show-reqs (sr)      show requirements for servers
      prepare (pr)        prepare servers (not implemented)
      shell (sh)          open shell to server
      reboot              reboot server(s) and measure reboot time
      exec (e)            execute command interactively
      ni_exec (ne)        execute command non-interactively
      bulk_exec (be)      execute command non-interactively on few servers in
                          parallel
      put (p)             copy file to server
      get (g)             copy file from server
      firewall (fw)       check connections between servers
      show-firewall (sfw)
                          show firewall requirements for servers
      lastreport (lr)     show last report for the server
      report (r)          show particular report for server
      reports (rs)        list reports for server(s)
      reportdiff (rd)     show difference between reports
      reports-history (rh)
                          show history of reports, by diffs
      agent               open agent console

``--version``
+++++++++++++

Show hwswa2 version

``-c/--config``
+++++++++++++++

See main.cfg_

``-s/--servers``
++++++++++++++++

See serversfile_

``-n/--networks``
+++++++++++++++++

See networksfile_

``-k/--network``
++++++++++++++++

Allows to specify network in format ``name:addr/prefix`` in addition to records
in networks.yaml_

``-l/--log``
+++++++++++++

See logfile_

``-r/--reports``
+++++++++++++++++

See reportsdir_

``-d/--debug``
+++++++++++++++

See debug_

``-a/--askpass``
++++++++++++++++

See account_


Subcommands
-----------

Some subcommands have short aliases.

encrypt, decrypt
++++++++++++++++

Helper subcommands to encrypt password to store it in account_

Example of usage::

  $ ./hwswa2 encrypt
  Enter encryption key:
  Enter password to encrypt:
  siKdHeux44Xp90D9dK0WPNXk9smk5e4zmR2ng8rbcb6I023m5uTdhjwFor/OzWV+

list-roles
++++++++++

Shows role names which can be used in servers.yaml_

It shows:

1. Regular roles, which have files in roles directory
2. Auxiliary nodes, which are mentioned in firewall rules. Can be used in
   server definition.
3. Internal roles, used to separate, f.e., firewall rules description in a
   separate file. Not recommended for use in servers.yaml.

Example of usage::

  $ ./hwswa2 list-roles
  ==== Roles ====
  ad, awstats, balinbe, balinfe, balinos, bawinbe, bawinfe, bawinos, bes, besas,
  bessql, branding, cdiws, excas, exmbx, helb, henas, hewsl, lincustbackup,
  lindns, linmn, linmndb, linpgh, linpps, linwdg, lyncaeh, lyncamsqlbe,
  lyncamsqlbecl, lyncdirector, lyncedge, lyncmediation, lyncpoolfe, lyncrevprx,
  lyncsqlbe, lyncsqlbecl, lyncwac, misclin, mssql, mssqlcluster, mssqldataadm,
  mysql, o365aeh, oaci_bn_vz, oaci_im, oaci_imdb, oaci_vz, pgsql, sysbu, ui,
  vzlin, vzstorage_client, vzstorage_cs, vzstorage_mds, vzwin, vzwinbu, winbr,
  wincustbackup, windns, windp, winfm, winmn, winpps, winsslpr, winui, winwdg,
  winweb, wpedb, wpedbcl, wpesrv, wpesrvdb, wsng, wssbe, wssfe
  ==== Auxiliary roles (no yaml files, but mentioned in firewall rules) ====
  aeh, cf, exhub, filemanager, linmailcl, linmailldap, linmailnlb, linmailsh,
  mailsid, o365mssql, phpmyadm, phppgadm, vzlinbu, webmail_login, wincpnlb, wm
  ==== Internal roles ====
  ad.member.fw, bafe.fw, baos.fw, custbackup.fw, lin.oa.managed.fw, lincommon,
  lincommon-blockdevs, lincommon-partitions, lincommon-virtualization, mn.fw,
  ngwebserver.fw, oa.managed.fw, pps.fw, vz.fw, wdg.fw, webserver.pub.fw,
  win.oa.managed.fw, wincommon, wpe.managed.fw


list-servers
++++++++++++

Shows servers defined in servers.yaml_

Alias: ls

Example::

  $ ./hwswa2 list-servers
  server localhost, role PVCLIN, 127.0.0.1
  server localhost2, role PVCLIN, 127.0.0.1
  server localhost3, role ['PVCLIN', 'LINMN'], 127.0.0.1

check
+++++

Check servers. Options:

``-a/--all``

  Check all servers

``-s/--servers`` server1 server2 ...

  Check only specified servers (by name).

Check is performed in parallel with progress shown periodically. 

Alias: ck

Example::

  $ ./hwswa2.py check -s localhost
  Checking servers: ['localhost']
  Not started: localhost
  Waiting: localhost(8)
  Waiting: localhost(30)
  ============== FINISHED =============
  localhost status: finished, report file: 
  /hwswa2/logs/reports/localhost/2016-02-19.01h41m23s

show-reqs
+++++++++

Show requiremens for specified servers, selected by ``--all`` or ``--servers``
options like for check_.

Alias: sr

Example::

  $ ./hwswa2 show-reqs -s centos5su
  REQUIREMENTS
  ====== server centos5su, role balinos, 192.168.122.86
      /boot > 0.2GB, / > 100GB
      OS matches regex pattern (CentOS).* 6\.[567]
      swap(GB) >= 2
      processors:frequency(GHz) >= 2.3
      ram(GB) >= 1
      password_strength > 2
      yum_repos != ''
      tmp_noexec == OK
      is_admin == True
      architecture == x86_64
      network:dns_check == OK
      selinux == Disabled
      Required networks: backnet, frontnet
      Manual check for cert_baos: SSL certificate is needed for online store
  ==== END ====

prepare
+++++++

Not implemented. Supposed to prepare servers according to it's roles.

shell
+++++

Open interactive shell. Works only for linux servers.

Accepts additional swith -L for port forwarding, as openssh client:

-L [bind_address:]port:host:hostport

Alias: sh

Example::

  $ ./hwswa2.py --askpass shell -L localhost:8080:ya.ru:80 billing
  Servers.yaml encryption password:
  Opening interactive shell to server billing
  root@billing:~$

reboot
++++++
 
Reboots specified servers, selected by ``--all`` or ``--servers`` options like
for check_.

Reports reboot time for each server.

See also reboot_timeout_

exec
++++

Executes command on specified server.

Alias: e

Example::

  $ ./hwswa2.py exec billing hostname -f
  billing.provider.com

ni_exec
+++++++

Similar to exec_, but reports stdout, stderr and exit code separately.

Alias: ne

bulk_exec
+++++++++

Like ni_exec, executes command and collects stdout,stderr and exit code.
Does this in parallel on servers, selected by  ``--all`` or ``--servers``
options. In ``servers``, names should be specified in one string,
separated by comma, so it can find where command starts.

By default, **bulk_exec** shows only exit codes.

Options:

``-a/--all``, ``-s/--servers``

  Servers selection. Server names should be separated by commas!

``-o/--stdout``

  Show stdout

``-e/--stderr``

  Show stderr

Alias: be

Example::

  $ ./hwswa2.py -a bulk_exec -o -s server1,server2 hostname
  Servers.yaml encryption password:
  Waiting: server1, server2
  ============== FINISHED ================
  Server  Exit code
  server1         0
  server2         0
  ============== stdout ================
  ==== server1 ====
  server1.lan

  ==== server2 ====
  server2.lan

  See log file for stdout and stderr

put and get
+++++++++++

Copy file or directory to or from server.

If destination is not specified, file is copied into the current directory,
like scp does.

Aliases: p and g

Usage::

  hwswa2 put server localpath [remotepath]
  hwswa2 get server remotepath [localpath]

firewall
++++++++

Check intranet connections between selected servers and from servers to
Internet resources per firewall rules in corresponding roles.

Options for server selection are as for check_

Alias: fw

See also `Section firewall`_

Example::

  $ ./hwswa2.py -a fw -s localhost centos6root
  Servers.yaml encryption password:
  Checking localhost <- centos6root
  Checking centos6root <- localhost
  OK: 0 NOK: 100 Failed: 0 Left: 49
  OK: 0 NOK: 149 Failed: 0 Left: 0
  Start Internet access checks ...
  ============== FINISHED ================
  Below connections are OK:
  localhost <- centos6root tcp:80,8352-8439,8441-8500,16384 (backnet)
  Below connections are NOT OK:
  centos6root <- localhost tcp:22,8352-8439,8441-8500 (backnet)
  ============= INTERRUPTED ==============
  ==============  TOTALS  ================
  OK 150 NOK 149 Failed 0 Left 0
  =============  INTERNET  ===============
  OK: localhost -> ka.odin.com:5224,7050
  OK: localhost -> vzup2date.swsoft.com:80,443
  OK: localhost -> download.automation.odin.com:80,443
  OK: localhost -> vzup2date.parallels.com:80,443
  ========================================

show-firewall
+++++++++++++

Has the same syntax as firewall_, but only shows firewall requirements and does not check anything.

Additional options ``-c/--compact`` and ``-v/--csv`` will change output format, if specified.

Alias: sfw

Example::

  $ ./hwswa2.py sfw -c -s localhost centos6root
  =============BEGIN======================
  localhost -> centos6root tcp:22,8352-8439,8441-8500 (backnet)
  centos6root -> localhost tcp:80,8352-8439,8441-8500,16384 (backnet)
  ===== Internet access requirements =====
  localhost -> download.automation.odin.com:80,443
  localhost -> ka.odin.com:5224,7050
  localhost -> vzup2date.swsoft.com:80,443
  localhost -> vzup2date.parallels.com:80,443
  localhost TCP:5800-6800 <- any
  =============END========================

lastreport
++++++++++

Show last generated report for the server.

Usage: hwswa2 lastreport [-r/--raw] server

Option -r/--raw shows report file content (it's yaml). By default, it shows formatted and colored report.

Alias: lr

Example::

  $ ./hwswa2.py lr localhost
      name localhost
      role linpps, linpgh, oaci_vz
      check_status finished
      check_time Fri Feb 19 01:41:26 2016
        == Parameters ==
      hostname aser.lan
      hw_id
      OS Debian 8.0
      architecture x86_64
      processors 1x1.7GHz
      ram(GB) 3.624
      swap(GB) 4
      partitions sda1 ext4 / 489.976GB | sda2 swap - 4GB
      blockdevs disk sda 931.513GB
      time Fri Feb 19 01:41:26 NOVT 2016
      iptables no rejects
      selinux no selinux
      yum_repos no yum
      password_strength 0
      virtualization bare metal
      CPUVTfeatures AMD SVM, AMD Nested Page Tables
      is_admin false
        == Network parameters ==
      disable_ipv6 0
      dns_check OK
      name_servers 192.168.1.1
      nics br0(eth0) 192.168.1.8/backnet
        == Parameter FAILURES (parameter: failure) ==
      hw_id ExecutionException: Exit code: 1 |STDERR: cat: /sys/class/dmi/id/
                                product_uuid: Permission denied
      ntp_service_status ExecutionException: Exit code: 127 |STDERR:
        == Requirement FAILURES (role:req: reason) ==
      None and [<Req OS>, <Req OS>, <Req OS>] (joined from 
        ['linpps:OS regex (CentOS|Red Hat Enterprise Linux Server).* 6\\.',
         'linpgh:OS regex (CentOS|Red Hat Enterprise Linux Server).* 6\\.',
         'oaci_vz:OS regex Parallels Cloud Server 6\\.']): actual value: Debian 8.0
      swap(GB) ge 9 (joined from ['linpps:swap(GB) ge 1', 
               'linpgh:swap(GB) ge 4', 'oaci_vz:swap(GB) ge 4']): actual value: 4
      cpu-cores ge 2 (joined from ['linpps:cpu-cores ge 1',
                                       'linpgh:cpu-cores ge 2']): actual value: 1
      cpu-frequency ge 2.3 (joined from ['linpps:cpu-frequency ge 2', 
                     'linpgh:cpu-frequency ge 2.3',
                     'oaci_vz:cpu-frequency ge 1.5']): actual value: 1.7
      ram(GB) ge 4.5 (joined from ['linpps:ram(GB) ge 0.5',
                     'linpgh:ram(GB) ge 2',
                     'oaci_vz:ram(GB) ge 2']): actual value: 3.624
      lincommon:password_strength gt 2: actual value: 0
      lin.oa.managed.fw:selinux eq Disabled: actual value: no selinux
      networks(backnet, frontnet), joined from ['linpps:networks(backnet, frontnet)',
         'linpgh:networks(backnet, frontnet)',
         'oaci_vz:networks(backnet, frontnet)']: not found: frontnet
      oaci_vz:storage_roles manual: Be sure to use vzstorage roles servers.yaml
                                    if VZ storage cluster is used
        == Requirement successes (role:req) ==
      req disk: {'/vz': 88, '/': 57, '/usr': 70}
      lincommon:yum_repos neq
      vz.fw:CPUVTfeatures neq
      lincommon:tmp_noexec eq OK
      lincommon:is_admin eq True
      lincommon:architecture eq x86_64
      lincommon:dns eq OK
      oaci_vz:virtualization eq bare metal

report
++++++

The same as lastreport_, but you can specify arbitrary report (by file name).
File names can be shown by subcommand reports_

Alias: r

Usage: hwswa2 report [-r/--raw] server report

reports
+++++++

Show report names for selected servers (with ``--all`` option, like for check_)

Alias: rs

Usage: hwswa2 reports [-a/--all | -s/--servers server [server ...]]

reportdiff
++++++++++

Show recursive difference between two reports for one server

Alias: rd

Usage: hwswa2 reportdiff server oldreport newreport

Example::

  $ ./hwswa2.py rd localhost 2016-02-17.23h55m34s 2016-02-19.01h40m33s
  NEW
      check_time Fri Feb 19 01:40:36 2016
        == Parameters ==
      time Fri Feb 19 01:40:36 NOVT 2016
  OLD
      check_time Wed Feb 17 23:55:36 2016
        == Parameters ==
      time Wed Feb 17 23:55:36 NOVT 2016

reports-history
+++++++++++++++

Does the same as reportdiff_, but shows consequent diffs between last reports, 
starting from the oldest.

Usage: hwswa2 reports-history [-n/--reports-number REPORTSNUMBER] server

Alias: rh
