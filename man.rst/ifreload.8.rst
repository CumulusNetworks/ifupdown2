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
    ifreload [-h] [-a] [-v] [-d] [-f] [-n] 

DESCRIPTION
===========
    reloads network **interfaces(5)** file **/etc/network/interfaces**.

    Runs **ifdown** on interfaces that changed in the interfaces file and
    subsequently runs **ifup** on all interfaces.

    **ifreload** is equivalent to **ifdown -a** followed by **ifup -a**
    but it skips **ifdown** for interfaces that did not change in the config
    file.


OPTIONS
=======
    -h, --help            show this help message and exit

    -a, --all             process all interfaces marked "auto"

    -v, --verbose         verbose

    -d, --debug           output debug info

    -f, --force           force run all operations

EXAMPLES
========
    # reload all auto interfaces in **interfaces(5)** file

    **ifreload -a**

    # reload all interfaces using service command

    **service networking reload**

SEE ALSO
========
    ifup(8),
    ifdown(8),
    ifquery(8),
    interfaces(5),
    ifupdown-addons-interfaces(5)
