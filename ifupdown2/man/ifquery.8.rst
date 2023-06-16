=======
ifquery
=======

-------------------------------------
query network interface configuration
-------------------------------------

:Author: Roopa Prabhu <roopa@cumulusnetworks.com>
:Date:   2014-02-05
:Copyright: Copyright 2014 Cumulus Networks, Inc.  All rights reserved.
:Version: 0.1
:Manual section: 8

SYNOPSIS
========

    **ifquery [-v] [--allow CLASS] [--with-depends] -a|IFACE...**

    **ifquery [-v] [-r|--running] [--allow CLASS] [--with-depends] -a|IFACE...**

    **ifquery [-v] [-c|--check] [--allow CLASS] [--with-depends] -a|IFACE...**

    **ifquery [-v] [-p|--print-dependency {list,dot}] [--allow CLASS] [--with-depends] -a|IFACE...**

    **ifquery [-v] -s|--syntax-help**

DESCRIPTION
===========
    **ifquery** can be used to parse interface configuration file, query
    running state or check running state of the interface with configuration
    in **/etc/network/interfaces** file.

    **ifquery** always works on the current **interfaces(5)** file
    **/etc/network/interfaces** unless an alternate interfaces file is
    defined in ifupdown2.conf or provided with the **-i** option.
    Note: the -i option is enabled by default in ifupdown2.conf.

OPTIONS
=======
    positional arguments:

    **IFACE**   interface list separated by spaces. **IFACE** list and **'-a'** argument are mutually exclusive.

    optional arguments:

    -h, --help            show this help message and exit

    -a, --all             process all interfaces marked "auto" or filtered by --allow
                          (already set by default if no interfaces list is provided)

    -v, --verbose         verbose

    -d, --debug           output debug info
    --allow CLASS         ignore non-"allow-CLASS" interfaces

    -w, --with-depends    run with all dependent interfaces. This option
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
                          defined in ifupdown2.conf (default /etc/network/interfaces)

    -t {native,json}, --interfaces-format {native,json}
                          interfaces file format

    -r, --running         print raw interfaces file entries

    -c, --check           check interface file contents against running state
                          of an interface. Returns exit code 0 on success and
                          1 on error

    -x, --raw             print raw config file entries

    -o {native,json}, --format {native,json}
                          interface display format

    -p, --print-dependency {list,dot}
                          print iface dependency in list or dot format

    -s, --syntax-help     print supported interface config syntax. Scans all
                          addon modules and dumps supported syntax from them
                          if provided by the module.

EXAMPLES
========
    # dump all or some interfaces config file entries
    # (pretty prints user provided entries)

        **ifquery -a**

        **ifquery br0**

    # Same as above but dump with dependencies

        **ifquery br0 --with-depends**

    # Check running state with the config in /etc/network/interfaces

        **ifquery --check br0**

        **ifquery --check --with-depends br0**

        **ifquery --check -a** 

    # dump running state of all interfaces in /etc/network/interfaces format

        **ifquery --running br0**

        **ifquery --running --with-depends br0**

        **ifquery --running -a**

    # print dependency info in list format

        **ifquery --print-dependency=list -a**

        **ifquery --print-dependency=list  br2000**

    # print dependency info in dot format

        **ifquery --print-dependency=dot -a**

        **ifquery --print-dependency=dot br2000**

    # Create an image (png) from the dot format

        **ifquery --print-dependency=dot -a > interfaces.dot**

        **dot -Tpng interfaces.dot > interfaces.png**

        (The above command only works on a system with dot installed)

KNOWN_ISSUES
============
    **ifquery --check** is currently experimental

    **ifquery --check** cannot validate usercommands given under pre-up, post-up etc
    There is currently no support to check/validate ethtool iface attributes

SEE ALSO
========
    ifup(8),
    ifdown(8),
    ifreload(8),
    interfaces(5),
    ifupdown-addons-interfaces(5)
