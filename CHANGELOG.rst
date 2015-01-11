
Version History
===============

0.5.0 (work in progress)
    - Added: documentation for role files
    - Added: remote_debug option in main.cfg
    - Added: guess requirement type as disk if it starts with slash
    - Improvement: command execution made via remote agent now
    - Improvement: logging reworked, now important messages are recorded
    - Fixed: disk requirement is false positieve if disk size is not integer
    - Fixed: remove empty failures from reports
    - Fixed: handle keyerror exceptions in hwswa2.functions.read_servers()
    - Fixed: reboot check improved, it could hang in previous version
    - Fixed: command execution timeout option works now

0.4.0 (2014-11-22)
    - Added: requirements (ram, disk, cpu, etc) in role files
    - Added: subcommand show-firewall
    - Added: put and get subcommands allow to omit remotepath and localpath, respectively
    - Added: subcommand list-roles
    - Added: check for virtualization
    - Added: role aliases
    - Added: role linwdg
    - Added: adjusted firewall checks for role linmn
    - Added: updated firewall rules in role pbalinfe
    - Added: check for pba account in pbalinfe
    - Added: check noexec for /tmp
    - Added: requirements for roles: helb hewsl wsng ui paci_pcs paci_sn_pcs pvclin
    - Fixed: multiply roles are not printed in report
    - Fixed: NameError: global name 'se' is not defined
    - Fixed: name is missing in report
    - Fixed: firewall does not work if role is not lowercase in servers.yaml
    - Fixed: incorrect vlan names in report
    - Fixed: exception is not handled in _new_sshclient()
    - Fixed: check fails for server with empty role

0.3.0 (2014-06-29)
    - Removed: check_reboot option. Use reboot subcommand instead
    - Fixed: firewall does not fail if server is not accessible
    - Added: check and checkall use the same time string for report file names of all servers
    - Fixed: dontcheck option is ignored sometimes
    - Fixed: check subcommand: timeout exception is not handled
    - Removed: ability to use keyword _uses in <role>.yaml
    - Added: --raw option for report and lastreport subcommands
    - Added: firewall will convert ip.add.re.ss/net.add.re.ss/prefix to ip.add.re.ss/networkname
      automatically if networks.yaml is updated, no need to rerun checks
    - Fixed: long remote output can be truncated by exec subcommand
    - Added: firewall subcommand: progress is reported every 10 seconds (configurable value)
    - Added: check subcommand: progress is reported every 5 seconds (configurable value)
    - Added: firewall subcommand: will stop after 10 failures or 500 closed/filtered ports discovered
      (per servers pair, configurable values)
    - Added: cli option to specify network (-k, --network)
    - Added: firewall subcommand: added checks for access to hosts on Internet
    - Added: PACI roles
    - Added: firewall subcommand: pre-generated reports are not required now

0.2.1 (2014-06-25)
    - Added: subcommand aliases
    - Added: subcommand get
    - Fixed: firewall subcommand does not work at all
    - Fixed: timeout value is not used by firewall
    - Added: in firewall: ability to specify number of concurrently checked ports
      in configuration (main.cfg: section [firewall], max_open_sockets)
    - Added: firewall rules for roles linpps, sysbu, ui, branding
    - Fixed: log messages show 'logging.info()' instead of 'calling-module.calling-function()'
    - Fixed: other minor bugs

0.2 (2014-06-08)
    - Added: dontcheck option for servers
    - Added: subcommand reboot: ability to specify more than one server
    - Fixed: reportdiff: unresolvable variable servername is used in error message
    - Added: subcommand check: --with-reboot/--wo-reboot options
    - Added: thread name is shown in log
    - Fixed: subcommand check: not found role is handled properly
    - Fixed: subcommand check: replaced waiting for active threads with waiting for alive threads
    - Fixed: subcommands lastreport, reports, lastreport: server is checked for existence in configuration
    - Fixed: subcommand check: size for swap partitions is not gathered
    - Fixed: subcommand firewall: handle properly case if no udp messages received
    - Added: SSH jump host (gateway) support
    - Added: subcommand report
    - Added: subcommand check: new roles henas, linmndb, linpps
    - Added: subcommand check: updated firewall rules in helb, hewsl, lindns, pbalinbe, pbalinfe, pbalinos, wsng

0.1 (2014-05-24)
    Initial release.

