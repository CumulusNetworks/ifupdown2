========
ifreload
========

--------------------------------------
reload network interface configuration
--------------------------------------

:Author: roopa@cumulusnetworks.com
:Date:   2014-02-05
:Copyright: Copyright 2014 Cumulus Networks, Inc.  All rights reserved.
:Version: 0.1
:Manual section: 8

SYNOPSIS
========
    ifreload [-h] [-a] [-v] [-d] [--allow CLASS] [--with-depends]
             [-X EXCLUDEPATS] [-f] [-n] [--print-dependency {list,dot}]
             [--down-changediface]
             [IFACE [IFACE ...]]

DESCRIPTION
===========
    reloads network interfaces(5) file /etc/network/interfaces.

    runs ifdown on interfaces that were there previously but are no longer
    in the interfaces file and ifup on all interfaces in the current
    /etc/network/interfaces file.

OPTIONS
=======
    -h, --help            show this help message and exit

    -a, --all             process all interfaces marked "auto"

    -v, --verbose         verbose

    -d, --debug           output debug info

    -f, --force           force run all operations

    --down-changediface   run down and then up on interfaces that changed from
                          the last installed version of the interfaces file.
                          Without this option, ifup is executed on all
                          interfaces
                          

CHEATSHEET
==========
    # reload /etc/network/interfaces file
    ifreload -a

    # reload all interfaces using service command
    service networking reload

SEE ALSO
========
    ifup(8)
    ifdown(8)
    ifquery(8)
    interfaces(5)
    interfaces-addons(5)
