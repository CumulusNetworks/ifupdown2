==========
interfaces
==========

--------------------------------------------
network interface configuration for ifupdown
--------------------------------------------

:Author: Roopa Prabhu <roopa@cumulusnetworks.com>
:Date:   2014-02-05
:Copyright: Copyright 2014 Cumulus Networks, Inc.  All rights reserved.
:Version: 0.1
:Manual section: 5 

DESCRIPTION
===========
    By default, ifupdown2.conf sets **/etc/network/interfaces** as the
    network interface configuration file.  This file contains information
    for the **ifup(8)**, **ifdown(8)** and **ifquery(8)** commands.

    This is where you configure how your system is connected to the network.

    Lines starting with # are ignored. Note that end-of-line comments are
    NOT supported, comments must be on a line of their own.

    A line may be extended across multiple lines by making the last character
    a backslash.

    The file consists of zero or more "iface", "auto",  "allow-"
    and "source" stanzas. Here is an example::

        auto lo eth0
        allow-hotplug eth1

        iface lo inet loopback

        source /etc/network/interfaces.d/bridges

        iface eth0 inet static
            address 192.168.1.1/24
            up flush-mail

        iface eth1 inet dhcp

    Lines beginning with the word "auto" are used to identify the physical
    interfaces to be brought up when ifup is run with the -a option.
    (This option is used by the system boot scripts.) Physical interface names
    should follow the word "auto" on the same line.  There can be  multiple
    "auto"  stanzas.

    Lines beginning with "allow-" are  used  to  identify  interfaces  that
    should  be  brought  up automatically by various subsytems. This may be
    done using a command such as "ifup --allow=hotplug  eth0  eth1",  which
    will  only  bring up eth0 or eth1 if it is listed in an "allow-hotplug"
    line. Note that "allow-auto" and "auto" are synonyms.

    Lines beginning with "source" are used to include  stanzas  from  other
    files, so configuration can be split into many files. The word "source"
    is followed by the path of file to be sourced. Shell wildcards  can  be
    used. Currently only supports absolute
    path names.

    iface is normally given a interface name as its first non-option
    argument. 

    The interface name is followed by the name of the address family that the
    interface uses. This will be "inet" for TCP/IP networking and inet6 for
    ipv6. Following that is the name of the method used to configure the
    interface.

    ifupdown supports iface stanzas without a family or a method. This enables
    using the same stanza for inet and inet6 family addresses. And the method
    defaults to "static"

    Additional interface options/attributes can be given on subsequent lines
    in the iface stanza. These options come from addon modules. see
    **ifupdown-addons-interfaces(5)** for these options.

    example bridge interface with additional attributes listed in the
    **ifupdown-addons-interfaces(5)** man page::

        auto br0
        iface br0
            address 12.0.0.4/24
            address 2000:1000:1000:1000:3::5/128
            bridge-ports swp1 swp2 swp3
            bridge-stp on

    ifupdown supports python-mako style templates in the interfaces file.
    See examples section for details.

    See **/usr/share/doc/python-ifupdown2/examples/** for **interfaces(5)**
    file examples and interfaces file generation scripts.

METHODS
=======
    Both **inet** and **inet6** address family interfaces can use the following
    methods (However they are not required):

    The loopback Method
           This method may be used to define the loopback interface.

    The static Method
           This method may be used to define ethernet interfaces with
           statically allocated addresses.

    The dhcp Method
           This method may be used to obtain an address via DHCP.

BUILTIN INTERFACES
==================
    **iface** sections for some interfaces like physical interfaces or vlan
    interfaces in dot notation (like eth1.100) are understood by ifupdown.
    These interfaces do not need an entry in the interfaces file if
    they are dependents of other interfaces and don't need any specific
    configurations like addresses etc.

EXAMPLES
========
    Sample /etc/network/interfaces file::

        auto lo
        iface lo
            address 192.168.2.0/24
            address 2001:dee:eeee:1::4/128

        auto eth0
        iface eth0 inet dhcp

        auto eth1
        iface eth1 inet manual
            address 192.168.2.0/24
            address 2001:dee:eeee:1::4/128

        # source files from a directory /etc/network/interfaces.d
        source /etc/network/interfaces.d/*

        # Using mako style templates
        % for v in [11,12]:
            auto vlan${v}
            iface vlan${v} inet static
                address 10.20.${v}.3/24
        % endfor

    For additional syntax and examples see **ifupdown-addons-interfaces(5)**

FILES
=====
    configuration file defined in ifupdown2.conf (default /etc/network/interfaces)

SEE ALSO
========
    ifupdown-addons-interfaces(5),
    ifup(8),
    ifquery(8),
    ifreload(8)
