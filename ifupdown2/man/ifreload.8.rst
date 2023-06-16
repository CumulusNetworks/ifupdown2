========
ifreload
========

--------------------------------------
reload network interface configuration
--------------------------------------

:Author: Roopa Prabhu <roopa@cumulusnetworks.com>
:Date:   2014-02-05
:Copyright: Copyright 2014 Cumulus Networks, Inc.  All rights reserved.
:Version: 0.1
:Manual section: 8

SYNOPSIS
========
    ifreload [-h] (-a|-c) [-v] [-d] [-f] [-n] [-s]

DESCRIPTION
===========
    reloads network **interfaces(5)** file **/etc/network/interfaces**
    or config file defined in ifupdown2.conf file.

    Runs **ifdown** on interfaces that were removed from the file and
    subsequently runs **ifup** on all interfaces.

    ifreload is non-disruptive. It will fix running config to match what
    is configured in the interfaces file without bringing the interface
    down. There are some cases where on linux an interface config cannot
    be applied unless the interface is brought down...eg: change of mac
    address and a few bond attributes. For such attribute changes, it may
    flap the interface only if the linux kernel requires it to.

    When removing an interface (iface section) from the interfaces file
    please make sure all its references are removed as well. Similarly
    when renaming an interface, please make sure all references to the
    interface are changed to the new name. Renaming an interface
    in the interfaces file results in ifdown of the old and ifup
    of the interface with the new name.

    If you do not wish to execute **down** on any interfaces, but only **up** on
    interfaces that were already **up**, please see the **--currently-up**
    option below.

OPTIONS
=======
    -h, --help            show this help message and exit

    -a, --all             process all interfaces

    -v, --verbose         verbose

    -d, --debug           output debug info

    -f, --force           force run all operations

    -c, --currently-up    Reload the configuration for all interfaces which
                          are currently up regardless of whether an interface
                          has "auto <interface>" configuration within the
                          /etc/network/interfaces file.

    -X EXCLUDEPATS, --exclude EXCLUDEPATS
                          Exclude interfaces from the list of interfaces to
                          operate on. Can be specified multiple times
                          If the excluded interface has dependent interfaces,
                          (e.g. a bridge or a bond with multiple enslaved interfaces)
                          then each dependent interface must be specified in order
                          to be excluded.

    -s, --syntax-check    Only run the interfaces file parser


EXAMPLES
========
    # reload all auto interfaces in **interfaces(5)** file

    **ifreload -a**

    # reload all interfaces using service command

    **service networking reload**

    # reload all currently up interfaces without bringing any interfaces down

    **service networking reload-currently-up**

SEE ALSO
========
    ifup(8),
    ifdown(8),
    ifquery(8),
    interfaces(5),
    ifupdown-addons-interfaces(5)
