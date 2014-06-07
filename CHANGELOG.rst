
Version History
===============

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

