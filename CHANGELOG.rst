
Version History
===============

0.4.0 (in progress)
    - Added: subcommand list-roles
    - Fixed: multiply roles are not printed in report
    - Fixed: NameError: global name 'se' is not defined
    - Added: role linwdg
    - Added: updated firewall rules in role pbalinfe
    - Fixed: name is missing in report
    - Added: put and get subcommands allow to omit remotepath and localpath, respectively

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

