====
ifup
====

-------------------------------------
network interface management commands 
-------------------------------------

:Author: roopa@cumulusnetworks.com
:Date:   2014-02-05
:Copyright: Copyright 2014 Cumulus Networks, Inc.  All rights reserved.
:Version: 0.1
:Manual section: 8

NAME
====
    **ifup** - bring a network interface up

    **ifdown** - take a network interface down

SYNOPSIS
========

    ifup [-h] [-a] [-v] [-d] [--allow CLASS] [--with-depends]
       **[-X EXCLUDEPATS] [-f] [-n] [--print-dependency {list,dot}]**
       **[IFACE [IFACE ...]]**

    ifdown [-h] [-a] [-v] [-d] [--allow CLASS] [--with-depends]
           **[-X EXCLUDEPATS] [-f] [-n] [--print-dependency {list,dot}]**
           **[IFACE [IFACE ...]]**

DESCRIPTION
===========
    **ifup** and **ifdown** commands can be used to configure (or, respectively,
    deconfigure) network interfaces based on interface definitions in the
    file **/etc/network/interfaces/** file.

    **ifquery(8)** maybe used in conjunction with **ifup** and **ifdown**
    commands to query and validate applied/running configuration.

    **ifup** always works on the current **interfaces(5)** file under
    **/etc/network/interfaces**. **ifdown** works on the last applied interface
    configuration.

    **ifup** on an already ifup'ed interface will re-apply the configuration,
    skipping already applied configuration whereever possible. In many cases
    where config commands are idempotent, you will see that ifup/ifdown will
    reapply the config even if the interface already has that config.

    **ifup** and **ifdown** understands interface dependency order.

    For logical devices like vlans, bridges, bonds **ifup** creates the
    interface and **ifdown** deletes the interface. Use **--no-scripts**
    option if you only want to administratively bring the interface up/down.

OPTIONS
=======
    positional arguments:

    **IFACE**  interface list separated by spaces. **IFACE** list and **'-a'**
    argument are mutually exclusive.

    optional arguments:

    -h, --help            show this help message and exit

    -a, --all             process all interfaces marked "auto"

    -v, --verbose         verbose

    -d, --debug           output debug info

    -l, --allow CLASS         ignore non-"allow-CLASS" interfaces

    -w, --with-depends        run with all dependent interfaces. This option
                          is redundant when -a is specified. When '-a' is
                          specified, interfaces are always executed in
                          dependency order.
                        
    -X EXCLUDEPATS, --exclude EXCLUDEPATS
                          Exclude interfaces from the list of interfaces to
                          operate on. Can be specified multiple times

    -f, --force           force run all operations

    -n, --no-act          print out what would happen,but don't do it

    -p, --print-dependency {list,dot} print iface dependency in list or dot format.

    --no-scripts, --no-addons dont run any addon modules/scripts. Only bring
                              the interface administratively up/down

EXAMPLES
========
    # bringing up all interfaces

        **ifup -a**

    # bringing up interface list

        **ifup swp1 swp2**

    # bringing up interface with its dependents

        **ifup br0 --with-depends**

    # bringing down all interfaces

        **ifdown -a**

    # bringing down a single interface

        **ifdown swp1**

    # excluding interfaces using -X option

        **ifdown -X eth0 -a**

        **ifup -X eth0 -a**

        **ifdown -X eth0 -X lo -a**

    # using verbose -v option to see what is going on

        **ifup -v -a**

    # using debug -d option to see more of what is going on

        **ifup -d -a**

    # ignore errors

        **ifup -a -f**

        **ifdown -a -f**

    # ifdown and ifup on all interfaces using service command/init script

        **service networking restart**

    # ifup on all interfaces using service command/init script

        **service networking start**

    # ifdown on all interfaces using service command/init script

        **service networking stop**

    # Also see **ifreload(8)**

SEE ALSO
========
    ifquery(8),
    ifreload(8),
    interfaces(5),
    ifupdownaddons-interfaces(5)
