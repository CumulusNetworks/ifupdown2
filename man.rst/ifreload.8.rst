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
    ifreload [-h] (-a|-c) [-v] [-d] [-f] [-n] 

DESCRIPTION
===========
    reloads network **interfaces(5)** file **/etc/network/interfaces**.

    Runs **ifdown** on interfaces that changed in the interfaces file and
    subsequently runs **ifup** on all interfaces.

    **ifreload** is equivalent to **ifdown -a** followed by **ifup -a**
    but it skips **ifdown** for interfaces that did not change in the config
    file.

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
