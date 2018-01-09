#!/usr/bin/env python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
#
# Author: Scott Feldman, sfeldma@cumulusnetworks.com
#
#
# from /usr/include/linux/if.h
#

# Standard interface flags (netdevice->flags).

IFF_UP = 0x1                  # interface is up
IFF_BROADCAST = 0x2           # broadcast address valid
IFF_DEBUG = 0x4               # turn on debugging
IFF_LOOPBACK = 0x8            # is a loopback net
IFF_POINTOPOINT = 0x10        # interface is has p-p link
IFF_NOTRAILERS = 0x20         # avoid use of trailers
IFF_RUNNING = 0x40            # interface RFC2863 OPER_UP
IFF_NOARP = 0x80              # no ARP protocol
IFF_PROMISC = 0x100           # receive all packets
IFF_ALLMULTI = 0x200          # receive all multicast packets

IFF_MASTER = 0x400            # master of a load balancer
IFF_SLAVE = 0x800             # slave of a load balancer

IFF_MULTICAST = 0x1000        # Supports multicast

IFF_PORTSEL = 0x2000          # can set media type
IFF_AUTOMEDIA = 0x4000        # auto media select active
IFF_DYNAMIC = 0x8000          # dialup device with changing addresses

IFF_LOWER_UP = 0x10000        # driver signals L1 up
IFF_DORMANT = 0x20000         # driver signals dormant

IFF_ECHO = 0x40000            # echo sent packets
