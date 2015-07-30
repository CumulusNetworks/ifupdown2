====
ifup
====

-------------------------------------
network interface management commands 
-------------------------------------

:Author: Roopa Prabhu <roopa@cumulusnetworks.com>
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

    For logical interfaces like vlans, bridges, bonds, **ifup** creates the
    interface and **ifdown** deletes the interface. Use **--admin-state**
    option if you only want to administratively bring the interface up/down.

    When **ifup** and **ifdown** are used with interfaces on command line,
    they must be have a **iface** section in the **interfaces(5)** file.

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
    --allow CLASS         ignore non-"allow-CLASS" interfaces

    -w, --with-depends        run with all dependent interfaces. This option
                          is redundant when -a is specified. When '-a' is
                          specified, interfaces are always executed in
                          dependency order.
                        
    -X EXCLUDEPATS, --exclude EXCLUDEPATS
                          Exclude interfaces from the list of interfaces to
                          operate on. Can be specified multiple times
                          If the excluded interface has dependent interfaces,
                          (e.g. a bridge or a bond with multiple enslaved interfaces)
                          then each dependent interface must be specified in order
                          to be excluded.

    -i INTERFACESFILE, --interfaces INTERFACESFILE
                          Use interfaces file instead of default
                          /etc/network/interfaces

    -t {native,json}, --interfaces-format {native,json}
                          interfaces file format

    -f, --force           force run all operations

    -n, --no-act          print out what would happen, but don't do it

    -p, --print-dependency {list,dot}
                          print iface dependency in list or dot format

    -m, --admin-state, --no-scripts
                          dont run any addon modules/scripts. Only bring
                          the interface administratively up/down

    -u, --use-current-config
                          By default ifdown looks at the saved state for
                          interfaces to bring down. This option allows ifdown
                          to look at the current interfaces file. Useful when
                          your state file is corrupted or you want down to use
                          the latest from the interfaces file

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

    # run ifdown and ifup on all interfaces using service command/init script

        **service networking restart**

    # run ifup on all interfaces using service command/init script

        **service networking start**

    # ifdown on all interfaces using service command/init script

        **service networking stop**

    # To run ifup/ifdown on only interfaces that changed see **ifreload(8)**

SEE ALSO
========
    ifquery(8),
    ifreload(8),
    interfaces(5),
    ifupdown-addons-interfaces(5)
