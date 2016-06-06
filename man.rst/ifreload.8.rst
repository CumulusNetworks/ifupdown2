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
<<<<<<< HEAD
    ifreload [-h] (-a|-c) [-v] [-d] [-f] [-n] 

DESCRIPTION
===========
    reloads network **interfaces(5)** file **/etc/network/interfaces**.
=======
    ifreload [-h] (-a|-c) [-v] [-d] [-f] [-n] [-s]

DESCRIPTION
===========
    reloads network **interfaces(5)** file **/etc/network/interfaces**
    or config file defined in ifupdown2.conf file.
>>>>>>> cumulus/dev

    Runs **ifdown** on interfaces that were removed from the file and
    subsequently runs **ifup** on all interfaces.

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

    -a, --all             process all interfaces marked "auto"

    -v, --verbose         verbose

    -d, --debug           output debug info

    -f, --force           force run all operations

    -c, --currently-up    only reload auto and other interfaces that are
                          currently up. This can be used as a non-disruptive
                          alternative to -a because it will not down any
                          interfaces

    -X EXCLUDEPATS, --exclude EXCLUDEPATS
                          Exclude interfaces from the list of interfaces to
                          operate on. Can be specified multiple times
<<<<<<< HEAD
=======
                          If the excluded interface has dependent interfaces,
                          (e.g. a bridge or a bond with multiple enslaved interfaces)
                          then each dependent interface must be specified in order
                          to be excluded.

    -s, --syntax-check    Only run the interfaces file parser
>>>>>>> cumulus/dev


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
