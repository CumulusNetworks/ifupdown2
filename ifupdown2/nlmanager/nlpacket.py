# Copyright (c) 2009-2013, Exa Networks Limited
# Copyright (c) 2009-2013, Thomas Mangin
# Copyright (c) 2015-2020 Cumulus Networks, Inc.
#
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# The names of the Exa Networks Limited, Cumulus Networks, Inc. nor the names
# of its contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import socket
import logging
import struct
from binascii import hexlify
from pprint import pformat
from socket import AF_UNSPEC, AF_INET, AF_INET6, AF_BRIDGE, htons
from string import printable
from struct import pack, unpack, calcsize


from . import ipnetwork


log = logging.getLogger(__name__)
SYSLOG_EXTRA_DEBUG = 5

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD

INFINITY_LIFE_TIME = 0xFFFFFFFF

# Interface name buffer size #define IFNAMSIZ 16 (kernel source)
IF_NAME_SIZE = 15 # 15 because python doesn't have \0

# Netlink message types
NLMSG_NOOP    = 0x01
NLMSG_ERROR   = 0x02
NLMSG_DONE    = 0x03
NLMSG_OVERRUN = 0x04

RTM_NEWLINK   = 0x10  # Create a new network interface
RTM_DELLINK   = 0x11  # Destroy a network interface
RTM_GETLINK   = 0x12  # Retrieve information about a network interface(ifinfomsg)
RTM_SETLINK   = 0x13  #

RTM_NEWADDR   = 0x14
RTM_DELADDR   = 0x15
RTM_GETADDR   = 0x16

RTM_NEWNEIGH  = 0x1C
RTM_DELNEIGH  = 0x1D
RTM_GETNEIGH  = 0x1E

RTM_NEWROUTE  = 0x18
RTM_DELROUTE  = 0x19
RTM_GETROUTE  = 0x1A

RTM_NEWQDISC  = 0x24
RTM_DELQDISC  = 0x25
RTM_GETQDISC  = 0x26

RTM_NEWNETCONF = 80
RTM_DELNETCONF = 81
RTM_GETNETCONF = 82

RTM_NEWMDB = 84
RTM_DELMDB = 85
RTM_GETMDB = 86

# Netlink message flags
NLM_F_REQUEST = 0x01  # It is query message.
NLM_F_MULTI   = 0x02  # Multipart message, terminated by NLMSG_DONE
NLM_F_ACK     = 0x04  # Reply with ack, with zero or error code
NLM_F_ECHO    = 0x08  # Echo this query

# Modifiers to GET query
NLM_F_ROOT   = 0x100  # specify tree root
NLM_F_MATCH  = 0x200  # return all matching
NLM_F_DUMP   = NLM_F_ROOT | NLM_F_MATCH
NLM_F_ATOMIC = 0x400  # atomic GET

# Modifiers to NEW query
NLM_F_REPLACE = 0x100  # Override existing
NLM_F_EXCL    = 0x200  # Do not touch, if it exists
NLM_F_CREATE  = 0x400  # Create, if it does not exist
NLM_F_APPEND  = 0x800  # Add to end of list

NLA_F_NESTED        = 0x8000
NLA_F_NET_BYTEORDER = 0x4000
NLA_TYPE_MASK       = ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

# Groups
RTMGRP_LINK          = 0x1
RTMGRP_NOTIFY        = 0x2
RTMGRP_NEIGH         = 0x4
RTMGRP_TC            = 0x8
RTMGRP_IPV4_IFADDR   = 0x10
RTMGRP_IPV4_MROUTE   = 0x20
RTMGRP_IPV4_ROUTE    = 0x40
RTMGRP_IPV4_RULE     = 0x80
RTMGRP_IPV6_IFADDR   = 0x100
RTMGRP_IPV6_MROUTE   = 0x200
RTMGRP_IPV6_ROUTE    = 0x400
RTMGRP_IPV6_IFINFO   = 0x800
RTMGRP_DECnet_IFADDR = 0x1000
RTMGRP_DECnet_ROUTE  = 0x4000
RTMGRP_IPV6_PREFIX   = 0x20000
RTNLGRP_MDB          = 0x1A


def nl_mgrp(group):
    """
    The api is a reimplementation of "nl_mgrp" function from
    iproute2/include/utils.h
    """
    if group > 31:
        raise Exception("%d Invalid Group" % group)
    else:
        group = (1 << (group - 1)) if group else 0
        return group


RTNLGRP_IPV4_NETCONF = nl_mgrp(24)
RTNLGRP_IPV6_NETCONF = nl_mgrp(25)
RTNLGRP_MPLS_NETCONF = nl_mgrp(29)


RTMGRP_ALL = (RTMGRP_LINK | RTMGRP_NOTIFY | RTMGRP_NEIGH | RTMGRP_TC |
              RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_MROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_RULE |
              RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_MROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFINFO |
              RTMGRP_DECnet_IFADDR | RTMGRP_DECnet_ROUTE | nl_mgrp(RTNLGRP_MDB) |
              RTMGRP_IPV6_PREFIX | RTNLGRP_IPV4_NETCONF | RTNLGRP_IPV6_NETCONF | RTNLGRP_MPLS_NETCONF)

# /etc/iproute2/rt_scopes
RT_SCOPES = {
    "global": 0,
    "universe": 0,
    "nowhere": 255,
    "host": 254,
    "link": 253,
    "site": 200
}

AF_MPLS = 28

BOND_MAX_ARP_TARGETS = 16


AF_FAMILY = dict()

for family in [attr for attr in dir(socket) if attr.startswith('AF_')]:
    AF_FAMILY[getattr(socket, family)] = family

AF_FAMILY[AF_MPLS] = 'AF_MPLS'


def get_family_str(family):
    return AF_FAMILY.get(family, 'UNKNOWN')

# Colors for logging
red    = 91
green  = 92
yellow = 93
blue   = 94

value_to_bool_dict = {
    False: False,
    None: False,
    0: False,
    '0': False,
    'no': False,
    'off': False,
    'slow': False,
    'None': False,
    True: True,
    1: True,
    '1': True,
    'on': True,
    'yes': True,
    'fast': True
}


def set_log_level(level):
    log.setLevel(level)


def zfilled_hex(value, digits):
    return '0x' + hex(value)[2:].zfill(digits)


def remove_trailing_null(line):
    """
    Remove the last character if it is a NULL...having that NULL
    causes python to print a garbage character
    """
    if line[-1] == 0:
        line = line[:-1]

    return line


mac_int_to_str = lambda mac_int: ":".join(("%012x" % mac_int)[i:i + 2] for i in range(0, 12, 2))


def data_to_color_text(line_number, color, data, extra=''):
    (c1, c2, c3, c4) = unpack('BBBB', data[0:4])
    in_ascii = []

    for c in (c1, c2, c3, c4):
        char_c = chr(c)

        if char_c in printable[:-5]:
            in_ascii.append(char_c)
        else:
            in_ascii.append('.')

    if color:
        return '  %2d: \033[%dm0x%02x%02x%02x%02x\033[0m  %s  %s' % (line_number, color, c1, c2, c3, c4, ''.join(in_ascii), extra)

    return '  %2d: 0x%02x%02x%02x%02x  %s  %s' % (line_number, c1, c2, c3, c4, ''.join(in_ascii), extra)


def padded_length(length):
    return int((length + 3) // 4) * 4


class NetlinkPacket_IFLA_LINKINFO_Attributes:

    # =========================================
    # IFLA_LINKINFO attributes
    # =========================================
    IFLA_INFO_UNSPEC     = 0
    IFLA_INFO_KIND       = 1
    IFLA_INFO_DATA       = 2
    IFLA_INFO_XSTATS     = 3
    IFLA_INFO_SLAVE_KIND = 4
    IFLA_INFO_SLAVE_DATA = 5
    IFLA_INFO_MAX        = 6

    ifla_info_to_string = {
        IFLA_INFO_UNSPEC     : 'IFLA_INFO_UNSPEC',
        IFLA_INFO_KIND       : 'IFLA_INFO_KIND',
        IFLA_INFO_DATA       : 'IFLA_INFO_DATA',
        IFLA_INFO_XSTATS     : 'IFLA_INFO_XSTATS',
        IFLA_INFO_SLAVE_KIND : 'IFLA_INFO_SLAVE_KIND',
        IFLA_INFO_SLAVE_DATA : 'IFLA_INFO_SLAVE_DATA',
        IFLA_INFO_MAX        : 'IFLA_INFO_MAX'
    }

    # =========================================
    # IFLA_INFO_DATA attributes for vlan
    # =========================================
    IFLA_VLAN_UNSPEC      = 0
    IFLA_VLAN_ID          = 1
    IFLA_VLAN_FLAGS       = 2
    IFLA_VLAN_EGRESS_QOS  = 3
    IFLA_VLAN_INGRESS_QOS = 4
    IFLA_VLAN_PROTOCOL    = 5

    ifla_vlan_to_string = {
        IFLA_VLAN_UNSPEC      : 'IFLA_VLAN_UNSPEC',
        IFLA_VLAN_ID          : 'IFLA_VLAN_ID',
        IFLA_VLAN_FLAGS       : 'IFLA_VLAN_FLAGS',
        IFLA_VLAN_EGRESS_QOS  : 'IFLA_VLAN_EGRESS_QOS',
        IFLA_VLAN_INGRESS_QOS : 'IFLA_VLAN_INGRESS_QOS',
        IFLA_VLAN_PROTOCOL    : 'IFLA_VLAN_PROTOCOL'
    }

    ifla_vlan_protocol_dict = {
        '802.1Q':   0x8100,
        '802.1q':   0x8100,

        '802.1ad':  0x88A8,
        '802.1AD':  0x88A8,
        '802.1Ad':  0x88A8,
        '802.1aD':  0x88A8,

        0x8100:     '802.1Q',
        0x88A8:     '802.1ad'
    }

    VLAN_FLAG_REORDER_HDR    = 0x1
    VLAN_FLAG_GVRP           = 0x2
    VLAN_FLAG_LOOSE_BINDING  = 0x4
    VLAN_FLAG_MVRP           = 0x8
    VLAN_FLAG_BRIDGE_BINDING = 0x10

    vlan_flags_to_string = {
        VLAN_FLAG_REORDER_HDR    : "REORDER_HDR",
        VLAN_FLAG_GVRP           : "GVRP",
        VLAN_FLAG_LOOSE_BINDING  : "LOOSE_BINDING",
        VLAN_FLAG_MVRP           : "MVRP",
        VLAN_FLAG_BRIDGE_BINDING : "BRIDGE_BINDING",
    }

    # =========================================
    # IFLA_INFO_DATA attributes for macvlan
    # =========================================
    IFLA_MACVLAN_UNSPEC = 0
    IFLA_MACVLAN_MODE   = 1

    ifla_macvlan_to_string = {
        IFLA_MACVLAN_UNSPEC : 'IFLA_MACVLAN_UNSPEC',
        IFLA_MACVLAN_MODE   : 'IFLA_MACVLAN_MODE'
    }

    # enum macvlan_mode
    MACVLAN_MODE_PRIVATE    = 1  # don't talk to other macvlans */
    MACVLAN_MODE_VEPA       = 2  # talk to other ports through ext bridge */
    MACVLAN_MODE_BRIDGE     = 4  # talk to bridge ports directly */
    MACVLAN_MODE_PASSTHRU   = 8  # take over the underlying device */
    MACVLAN_MODE_SOURCE     = 16  # use source MAC address list to assign */

    macvlan_mode_to_string = {
        MACVLAN_MODE_PRIVATE  : 'MACVLAN_MODE_PRIVATE',
        MACVLAN_MODE_VEPA     : 'MACVLAN_MODE_VEPA',
        MACVLAN_MODE_BRIDGE   : 'MACVLAN_MODE_BRIDGE',
        MACVLAN_MODE_PASSTHRU : 'MACVLAN_MODE_PASSTHRU',
        MACVLAN_MODE_SOURCE   : 'MACVLAN_MODE_SOURCE'
    }

    # =========================================
    # IFLA_INFO_DATA attributes for xfrm
    # =========================================
    IFLA_XFRM_UNSPEC = 0
    IFLA_XFRM_LINK   = 1
    IFLA_XFRM_IF_ID  = 2

    ifla_xfrm_to_string = {
        IFLA_XFRM_UNSPEC: 'IFLA_XFRM_UNSPEC',
        IFLA_XFRM_LINK  : 'IFLA_XFRM_LINK',
        IFLA_XFRM_IF_ID : 'IFLA_XFRM_IF_ID'
    }

    # =========================================
    # IFLA_INFO_DATA attributes for vxlan
    # =========================================
    IFLA_VXLAN_UNSPEC            = 0
    IFLA_VXLAN_ID                = 1
    IFLA_VXLAN_GROUP             = 2
    IFLA_VXLAN_LINK              = 3
    IFLA_VXLAN_LOCAL             = 4
    IFLA_VXLAN_TTL               = 5
    IFLA_VXLAN_TOS               = 6
    IFLA_VXLAN_LEARNING          = 7
    IFLA_VXLAN_AGEING            = 8
    IFLA_VXLAN_LIMIT             = 9
    IFLA_VXLAN_PORT_RANGE        = 10
    IFLA_VXLAN_PROXY             = 11
    IFLA_VXLAN_RSC               = 12
    IFLA_VXLAN_L2MISS            = 13
    IFLA_VXLAN_L3MISS            = 14
    IFLA_VXLAN_PORT              = 15
    IFLA_VXLAN_GROUP6            = 16
    IFLA_VXLAN_LOCAL6            = 17
    IFLA_VXLAN_UDP_CSUM          = 18
    IFLA_VXLAN_UDP_ZERO_CSUM6_TX = 19
    IFLA_VXLAN_UDP_ZERO_CSUM6_RX = 20
    IFLA_VXLAN_REMCSUM_TX        = 21
    IFLA_VXLAN_REMCSUM_RX        = 22
    IFLA_VXLAN_GBP               = 23
    IFLA_VXLAN_REMCSUM_NOPARTIAL = 24
    IFLA_VXLAN_COLLECT_METADATA  = 25
    IFLA_VXLAN_REPLICATION_NODE  = 253
    IFLA_VXLAN_REPLICATION_TYPE  = 254

    ifla_vxlan_to_string = {
        IFLA_VXLAN_UNSPEC            : 'IFLA_VXLAN_UNSPEC',
        IFLA_VXLAN_ID                : 'IFLA_VXLAN_ID',
        IFLA_VXLAN_GROUP             : 'IFLA_VXLAN_GROUP',
        IFLA_VXLAN_LINK              : 'IFLA_VXLAN_LINK',
        IFLA_VXLAN_LOCAL             : 'IFLA_VXLAN_LOCAL',
        IFLA_VXLAN_TTL               : 'IFLA_VXLAN_TTL',
        IFLA_VXLAN_TOS               : 'IFLA_VXLAN_TOS',
        IFLA_VXLAN_LEARNING          : 'IFLA_VXLAN_LEARNING',
        IFLA_VXLAN_AGEING            : 'IFLA_VXLAN_AGEING',
        IFLA_VXLAN_LIMIT             : 'IFLA_VXLAN_LIMIT',
        IFLA_VXLAN_PORT_RANGE        : 'IFLA_VXLAN_PORT_RANGE',
        IFLA_VXLAN_PROXY             : 'IFLA_VXLAN_PROXY',
        IFLA_VXLAN_RSC               : 'IFLA_VXLAN_RSC',
        IFLA_VXLAN_L2MISS            : 'IFLA_VXLAN_L2MISS',
        IFLA_VXLAN_L3MISS            : 'IFLA_VXLAN_L3MISS',
        IFLA_VXLAN_PORT              : 'IFLA_VXLAN_PORT',
        IFLA_VXLAN_GROUP6            : 'IFLA_VXLAN_GROUP6',
        IFLA_VXLAN_LOCAL6            : 'IFLA_VXLAN_LOCAL6',
        IFLA_VXLAN_UDP_CSUM          : 'IFLA_VXLAN_UDP_CSUM',
        IFLA_VXLAN_UDP_ZERO_CSUM6_TX : 'IFLA_VXLAN_UDP_ZERO_CSUM6_TX',
        IFLA_VXLAN_UDP_ZERO_CSUM6_RX : 'IFLA_VXLAN_UDP_ZERO_CSUM6_RX',
        IFLA_VXLAN_REMCSUM_TX        : 'IFLA_VXLAN_REMCSUM_TX',
        IFLA_VXLAN_REMCSUM_RX        : 'IFLA_VXLAN_REMCSUM_RX',
        IFLA_VXLAN_GBP               : 'IFLA_VXLAN_GBP',
        IFLA_VXLAN_REMCSUM_NOPARTIAL : 'IFLA_VXLAN_REMCSUM_NOPARTIAL',
        IFLA_VXLAN_COLLECT_METADATA  : 'IFLA_VXLAN_COLLECT_METADATA',
        IFLA_VXLAN_REPLICATION_NODE  : 'IFLA_VXLAN_REPLICATION_NODE',
        IFLA_VXLAN_REPLICATION_TYPE  : 'IFLA_VXLAN_REPLICATION_TYPE'
    }

    # =========================================
    # IFLA_INFO_DATA attributes for bonds
    # =========================================
    IFLA_BOND_UNSPEC                    = 0
    IFLA_BOND_MODE                      = 1
    IFLA_BOND_ACTIVE_SLAVE              = 2
    IFLA_BOND_MIIMON                    = 3
    IFLA_BOND_UPDELAY                   = 4
    IFLA_BOND_DOWNDELAY                 = 5
    IFLA_BOND_USE_CARRIER               = 6
    IFLA_BOND_ARP_INTERVAL              = 7
    IFLA_BOND_ARP_IP_TARGET             = 8
    IFLA_BOND_ARP_VALIDATE              = 9
    IFLA_BOND_ARP_ALL_TARGETS           = 10
    IFLA_BOND_PRIMARY                   = 11
    IFLA_BOND_PRIMARY_RESELECT          = 12
    IFLA_BOND_FAIL_OVER_MAC             = 13
    IFLA_BOND_XMIT_HASH_POLICY          = 14
    IFLA_BOND_RESEND_IGMP               = 15
    IFLA_BOND_NUM_PEER_NOTIF            = 16
    IFLA_BOND_ALL_SLAVES_ACTIVE         = 17
    IFLA_BOND_MIN_LINKS                 = 18
    IFLA_BOND_LP_INTERVAL               = 19
    IFLA_BOND_PACKETS_PER_SLAVE         = 20
    IFLA_BOND_AD_LACP_RATE              = 21
    IFLA_BOND_AD_SELECT                 = 22
    IFLA_BOND_AD_INFO                   = 23
    IFLA_BOND_AD_ACTOR_SYS_PRIO         = 24
    IFLA_BOND_AD_USER_PORT_KEY          = 25
    IFLA_BOND_AD_ACTOR_SYSTEM           = 26
    IFLA_BOND_CL_START                  = 60
    IFLA_BOND_AD_LACP_BYPASS            = IFLA_BOND_CL_START


    ifla_bond_to_string = {
        IFLA_BOND_UNSPEC                    : 'IFLA_BOND_UNSPEC',
        IFLA_BOND_MODE                      : 'IFLA_BOND_MODE',
        IFLA_BOND_ACTIVE_SLAVE              : 'IFLA_BOND_ACTIVE_SLAVE',
        IFLA_BOND_MIIMON                    : 'IFLA_BOND_MIIMON',
        IFLA_BOND_UPDELAY                   : 'IFLA_BOND_UPDELAY',
        IFLA_BOND_DOWNDELAY                 : 'IFLA_BOND_DOWNDELAY',
        IFLA_BOND_USE_CARRIER               : 'IFLA_BOND_USE_CARRIER',
        IFLA_BOND_ARP_INTERVAL              : 'IFLA_BOND_ARP_INTERVAL',
        IFLA_BOND_ARP_IP_TARGET             : 'IFLA_BOND_ARP_IP_TARGET',
        IFLA_BOND_ARP_VALIDATE              : 'IFLA_BOND_ARP_VALIDATE',
        IFLA_BOND_ARP_ALL_TARGETS           : 'IFLA_BOND_ARP_ALL_TARGETS',
        IFLA_BOND_PRIMARY                   : 'IFLA_BOND_PRIMARY',
        IFLA_BOND_PRIMARY_RESELECT          : 'IFLA_BOND_PRIMARY_RESELECT',
        IFLA_BOND_FAIL_OVER_MAC             : 'IFLA_BOND_FAIL_OVER_MAC',
        IFLA_BOND_XMIT_HASH_POLICY          : 'IFLA_BOND_XMIT_HASH_POLICY',
        IFLA_BOND_RESEND_IGMP               : 'IFLA_BOND_RESEND_IGMP',
        IFLA_BOND_NUM_PEER_NOTIF            : 'IFLA_BOND_NUM_PEER_NOTIF',
        IFLA_BOND_ALL_SLAVES_ACTIVE         : 'IFLA_BOND_ALL_SLAVES_ACTIVE',
        IFLA_BOND_MIN_LINKS                 : 'IFLA_BOND_MIN_LINKS',
        IFLA_BOND_LP_INTERVAL               : 'IFLA_BOND_LP_INTERVAL',
        IFLA_BOND_PACKETS_PER_SLAVE         : 'IFLA_BOND_PACKETS_PER_SLAVE',
        IFLA_BOND_AD_LACP_RATE              : 'IFLA_BOND_AD_LACP_RATE',
        IFLA_BOND_AD_SELECT                 : 'IFLA_BOND_AD_SELECT',
        IFLA_BOND_AD_INFO                   : 'IFLA_BOND_AD_INFO',
        IFLA_BOND_AD_ACTOR_SYS_PRIO         : 'IFLA_BOND_AD_ACTOR_SYS_PRIO',
        IFLA_BOND_AD_USER_PORT_KEY          : 'IFLA_BOND_AD_USER_PORT_KEY',
        IFLA_BOND_AD_ACTOR_SYSTEM           : 'IFLA_BOND_AD_ACTOR_SYSTEM',
        IFLA_BOND_CL_START                  : 'IFLA_BOND_CL_START',
        IFLA_BOND_AD_LACP_BYPASS            : 'IFLA_BOND_AD_LACP_BYPASS'
    }

    IFLA_BOND_AD_INFO_UNSPEC            = 0
    IFLA_BOND_AD_INFO_AGGREGATOR        = 1
    IFLA_BOND_AD_INFO_NUM_PORTS         = 2
    IFLA_BOND_AD_INFO_ACTOR_KEY         = 3
    IFLA_BOND_AD_INFO_PARTNER_KEY       = 4
    IFLA_BOND_AD_INFO_PARTNER_MAC       = 5

    ifla_bond_ad_to_string = {
        IFLA_BOND_AD_INFO_UNSPEC            : 'IFLA_BOND_AD_INFO_UNSPEC',
        IFLA_BOND_AD_INFO_AGGREGATOR        : 'IFLA_BOND_AD_INFO_AGGREGATOR',
        IFLA_BOND_AD_INFO_NUM_PORTS         : 'IFLA_BOND_AD_INFO_NUM_PORTS',
        IFLA_BOND_AD_INFO_ACTOR_KEY         : 'IFLA_BOND_AD_INFO_ACTOR_KEY',
        IFLA_BOND_AD_INFO_PARTNER_KEY       : 'IFLA_BOND_AD_INFO_PARTNER_KEY',
        IFLA_BOND_AD_INFO_PARTNER_MAC       : 'IFLA_BOND_AD_INFO_PARTNER_MAC'
    }

    ifla_bond_mode_tbl = {
        'balance-rr': 0,
        'active-backup': 1,
        'balance-xor': 2,
        'broadcast': 3,
        '802.3ad': 4,
        'balance-tlb': 5,
        'balance-alb': 6,
        '0': 0,
        '1': 1,
        '2': 2,
        '3': 3,
        '4': 4,
        '5': 5,
        '6': 6,
        0: 0,
        1: 1,
        2: 2,
        3: 3,
        4: 4,
        5: 5,
        6: 6
    }

    ifla_bond_mode_pretty_tbl = {
        0: 'balance-rr',
        1: 'active-backup',
        2: 'balance-xor',
        3: 'broadcast',
        4: '802.3ad',
        5: 'balance-tlb',
        6: 'balance-alb'
    }

    ifla_bond_xmit_hash_policy_tbl = {
        'layer2': 0,
        'layer3+4': 1,
        'layer2+3': 2,
        'encap2+3': 3,
        'encap3+4': 4,
        'vlan+srcmac': 5,
        '0': 0,
        '1': 1,
        '2': 2,
        '3': 3,
        '4': 4,
        '5': 5,
        0: 0,
        1: 1,
        2: 2,
        3: 3,
        4: 4,
        5: 5,
    }

    ifla_bond_xmit_hash_policy_pretty_tbl = {
        0: 'layer2',
        1: 'layer3+4',
        2: 'layer2+3',
        3: 'encap2+3',
        4: 'encap3+4',
        5: 'vlan+srcmac',
    }

    ifla_bond_primary_reselect_tbl = {
        'always': 0,
        'better': 1,
        'failure': 2,
        0: 0,
        1: 1,
        2: 2,
    }

    ifla_bond_primary_reselect_pretty_tbl = {
        0: 'always',
        1: 'better',
        2: 'failure',
    }

    # =========================================
    # IFLA_INFO_SLAVE_DATA attributes for bonds
    # =========================================
    IFLA_BOND_SLAVE_UNSPEC                      = 0
    IFLA_BOND_SLAVE_STATE                       = 1
    IFLA_BOND_SLAVE_MII_STATUS                  = 2
    IFLA_BOND_SLAVE_LINK_FAILURE_COUNT          = 3
    IFLA_BOND_SLAVE_PERM_HWADDR                 = 4
    IFLA_BOND_SLAVE_QUEUE_ID                    = 5
    IFLA_BOND_SLAVE_AD_AGGREGATOR_ID            = 6
    IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE    = 7
    IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE  = 8
    IFLA_BOND_SLAVE_CL_START                    = 50
    IFLA_BOND_SLAVE_AD_RX_BYPASS                = IFLA_BOND_SLAVE_CL_START

    ifla_bond_slave_to_string = {
        IFLA_BOND_SLAVE_UNSPEC                      : 'IFLA_BOND_SLAVE_UNSPEC',
        IFLA_BOND_SLAVE_STATE                       : 'IFLA_BOND_SLAVE_STATE',
        IFLA_BOND_SLAVE_MII_STATUS                  : 'IFLA_BOND_SLAVE_MII_STATUS',
        IFLA_BOND_SLAVE_LINK_FAILURE_COUNT          : 'IFLA_BOND_SLAVE_LINK_FAILURE_COUNT',
        IFLA_BOND_SLAVE_PERM_HWADDR                 : 'IFLA_BOND_SLAVE_PERM_HWADDR',
        IFLA_BOND_SLAVE_QUEUE_ID                    : 'IFLA_BOND_SLAVE_QUEUE_ID',
        IFLA_BOND_SLAVE_AD_AGGREGATOR_ID            : 'IFLA_BOND_SLAVE_AD_AGGREGATOR_ID',
        IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE    : 'IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE',
        IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE  : 'IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE',
        IFLA_BOND_SLAVE_CL_START                    : 'IFLA_BOND_SLAVE_CL_START',
        IFLA_BOND_SLAVE_AD_RX_BYPASS                : 'IFLA_BOND_SLAVE_AD_RX_BYPASS'
    }

    # =========================================
    # IFLA_PROTINFO attributes for bridge ports
    # =========================================
    IFLA_BRPORT_UNSPEC              = 0
    IFLA_BRPORT_STATE               = 1
    IFLA_BRPORT_PRIORITY            = 2
    IFLA_BRPORT_COST                = 3
    IFLA_BRPORT_MODE                = 4
    IFLA_BRPORT_GUARD               = 5
    IFLA_BRPORT_PROTECT             = 6
    IFLA_BRPORT_FAST_LEAVE          = 7
    IFLA_BRPORT_LEARNING            = 8
    IFLA_BRPORT_UNICAST_FLOOD       = 9
    IFLA_BRPORT_PROXYARP            = 10
    IFLA_BRPORT_LEARNING_SYNC       = 11
    IFLA_BRPORT_PROXYARP_WIFI       = 12
    IFLA_BRPORT_ROOT_ID             = 13
    IFLA_BRPORT_BRIDGE_ID           = 14
    IFLA_BRPORT_DESIGNATED_PORT     = 15
    IFLA_BRPORT_DESIGNATED_COST     = 16
    IFLA_BRPORT_ID                  = 17
    IFLA_BRPORT_NO                  = 18
    IFLA_BRPORT_TOPOLOGY_CHANGE_ACK = 19
    IFLA_BRPORT_CONFIG_PENDING      = 20
    IFLA_BRPORT_MESSAGE_AGE_TIMER   = 21
    IFLA_BRPORT_FORWARD_DELAY_TIMER = 22
    IFLA_BRPORT_HOLD_TIMER          = 23
    IFLA_BRPORT_FLUSH               = 24
    IFLA_BRPORT_MULTICAST_ROUTER    = 25
    IFLA_BRPORT_PAD                 = 26
    IFLA_BRPORT_MCAST_FLOOD         = 27
    IFLA_BRPORT_MCAST_TO_UCAST      = 28
    IFLA_BRPORT_VLAN_TUNNEL         = 29
    IFLA_BRPORT_BCAST_FLOOD         = 30
    IFLA_BRPORT_GROUP_FWD_MASK      = 31
    IFLA_BRPORT_NEIGH_SUPPRESS      = 32
    IFLA_BRPORT_ISOLATED            = 33
    IFLA_BRPORT_BACKUP_PORT         = 34

    IFLA_BRPORT_PEER_LINK           = 60
    IFLA_BRPORT_DUAL_LINK           = 61
    IFLA_BRPORT_GROUP_FWD_MASKHI    = 62

    ifla_brport_to_string = {
        IFLA_BRPORT_UNSPEC              : 'IFLA_BRPORT_UNSPEC',
        IFLA_BRPORT_STATE               : 'IFLA_BRPORT_STATE',
        IFLA_BRPORT_PRIORITY            : 'IFLA_BRPORT_PRIORITY',
        IFLA_BRPORT_COST                : 'IFLA_BRPORT_COST',
        IFLA_BRPORT_MODE                : 'IFLA_BRPORT_MODE',
        IFLA_BRPORT_GUARD               : 'IFLA_BRPORT_GUARD',
        IFLA_BRPORT_PROTECT             : 'IFLA_BRPORT_PROTECT',
        IFLA_BRPORT_FAST_LEAVE          : 'IFLA_BRPORT_FAST_LEAVE',
        IFLA_BRPORT_LEARNING            : 'IFLA_BRPORT_LEARNING',
        IFLA_BRPORT_UNICAST_FLOOD       : 'IFLA_BRPORT_UNICAST_FLOOD',
        IFLA_BRPORT_PROXYARP            : 'IFLA_BRPORT_PROXYARP',
        IFLA_BRPORT_LEARNING_SYNC       : 'IFLA_BRPORT_LEARNING_SYNC',
        IFLA_BRPORT_PROXYARP_WIFI       : 'IFLA_BRPORT_PROXYARP_WIFI',
        IFLA_BRPORT_ROOT_ID             : 'IFLA_BRPORT_ROOT_ID',
        IFLA_BRPORT_BRIDGE_ID           : 'IFLA_BRPORT_BRIDGE_ID',
        IFLA_BRPORT_DESIGNATED_PORT     : 'IFLA_BRPORT_DESIGNATED_PORT',
        IFLA_BRPORT_DESIGNATED_COST     : 'IFLA_BRPORT_DESIGNATED_COST',
        IFLA_BRPORT_ID                  : 'IFLA_BRPORT_ID',
        IFLA_BRPORT_NO                  : 'IFLA_BRPORT_NO',
        IFLA_BRPORT_TOPOLOGY_CHANGE_ACK : 'IFLA_BRPORT_TOPOLOGY_CHANGE_ACK',
        IFLA_BRPORT_CONFIG_PENDING      : 'IFLA_BRPORT_CONFIG_PENDING',
        IFLA_BRPORT_MESSAGE_AGE_TIMER   : 'IFLA_BRPORT_MESSAGE_AGE_TIMER',
        IFLA_BRPORT_FORWARD_DELAY_TIMER : 'IFLA_BRPORT_FORWARD_DELAY_TIMER',
        IFLA_BRPORT_HOLD_TIMER          : 'IFLA_BRPORT_HOLD_TIMER',
        IFLA_BRPORT_FLUSH               : 'IFLA_BRPORT_FLUSH',
        IFLA_BRPORT_MULTICAST_ROUTER    : 'IFLA_BRPORT_MULTICAST_ROUTER',
        IFLA_BRPORT_PAD                 : 'IFLA_BRPORT_PAD',
        IFLA_BRPORT_MCAST_FLOOD         : 'IFLA_BRPORT_MCAST_FLOOD',
        IFLA_BRPORT_MCAST_TO_UCAST      : 'IFLA_BRPORT_MCAST_TO_UCAST',
        IFLA_BRPORT_VLAN_TUNNEL         : 'IFLA_BRPORT_VLAN_TUNNEL',
        IFLA_BRPORT_BCAST_FLOOD         : 'IFLA_BRPORT_BCAST_FLOOD',
        IFLA_BRPORT_GROUP_FWD_MASK      : 'IFLA_BRPORT_GROUP_FWD_MASK',
        IFLA_BRPORT_NEIGH_SUPPRESS      : 'IFLA_BRPORT_NEIGH_SUPPRESS',
        IFLA_BRPORT_ISOLATED            : 'IFLA_BRPORT_ISOLATED',
        IFLA_BRPORT_BACKUP_PORT         : 'IFLA_BRPORT_BACKUP_PORT',
        IFLA_BRPORT_PEER_LINK           : 'IFLA_BRPORT_PEER_LINK',
        IFLA_BRPORT_DUAL_LINK           : 'IFLA_BRPORT_DUAL_LINK',
        IFLA_BRPORT_GROUP_FWD_MASKHI    : 'IFLA_BRPORT_GROUP_FWD_MASKHI'
    }

    IFLA_BR_UNSPEC                     =  0
    IFLA_BR_FORWARD_DELAY              =  1
    IFLA_BR_HELLO_TIME                 =  2
    IFLA_BR_MAX_AGE                    =  3
    IFLA_BR_AGEING_TIME                =  4
    IFLA_BR_STP_STATE                  =  5
    IFLA_BR_PRIORITY                   =  6
    IFLA_BR_VLAN_FILTERING             =  7
    IFLA_BR_VLAN_PROTOCOL              =  8
    IFLA_BR_GROUP_FWD_MASK             =  9
    IFLA_BR_ROOT_ID                    = 10
    IFLA_BR_BRIDGE_ID                  = 11
    IFLA_BR_ROOT_PORT                  = 12
    IFLA_BR_ROOT_PATH_COST             = 13
    IFLA_BR_TOPOLOGY_CHANGE            = 14
    IFLA_BR_TOPOLOGY_CHANGE_DETECTED   = 15
    IFLA_BR_HELLO_TIMER                = 16
    IFLA_BR_TCN_TIMER                  = 17
    IFLA_BR_TOPOLOGY_CHANGE_TIMER      = 18
    IFLA_BR_GC_TIMER                   = 19
    IFLA_BR_GROUP_ADDR                 = 20
    IFLA_BR_FDB_FLUSH                  = 21
    IFLA_BR_MCAST_ROUTER               = 22
    IFLA_BR_MCAST_SNOOPING             = 23
    IFLA_BR_MCAST_QUERY_USE_IFADDR     = 24
    IFLA_BR_MCAST_QUERIER              = 25
    IFLA_BR_MCAST_HASH_ELASTICITY      = 26
    IFLA_BR_MCAST_HASH_MAX             = 27
    IFLA_BR_MCAST_LAST_MEMBER_CNT      = 28
    IFLA_BR_MCAST_STARTUP_QUERY_CNT    = 29
    IFLA_BR_MCAST_LAST_MEMBER_INTVL    = 30
    IFLA_BR_MCAST_MEMBERSHIP_INTVL     = 31
    IFLA_BR_MCAST_QUERIER_INTVL        = 32
    IFLA_BR_MCAST_QUERY_INTVL          = 33
    IFLA_BR_MCAST_QUERY_RESPONSE_INTVL = 34
    IFLA_BR_MCAST_STARTUP_QUERY_INTVL  = 35
    IFLA_BR_NF_CALL_IPTABLES           = 36
    IFLA_BR_NF_CALL_IP6TABLES          = 37
    IFLA_BR_NF_CALL_ARPTABLES          = 38
    IFLA_BR_VLAN_DEFAULT_PVID          = 39
    IFLA_BR_PAD                        = 40
    IFLA_BR_VLAN_STATS_ENABLED         = 41
    IFLA_BR_MCAST_STATS_ENABLED        = 42
    IFLA_BR_MCAST_IGMP_VERSION         = 43
    IFLA_BR_MCAST_MLD_VERSION          = 44

    ifla_br_to_string = {
        IFLA_BR_UNSPEC                     : 'IFLA_BR_UNSPEC',
        IFLA_BR_FORWARD_DELAY              : 'IFLA_BR_FORWARD_DELAY',
        IFLA_BR_HELLO_TIME                 : 'IFLA_BR_HELLO_TIME',
        IFLA_BR_MAX_AGE                    : 'IFLA_BR_MAX_AGE',
        IFLA_BR_AGEING_TIME                : 'IFLA_BR_AGEING_TIME',
        IFLA_BR_STP_STATE                  : 'IFLA_BR_STP_STATE',
        IFLA_BR_PRIORITY                   : 'IFLA_BR_PRIORITY',
        IFLA_BR_VLAN_FILTERING             : 'IFLA_BR_VLAN_FILTERING',
        IFLA_BR_VLAN_PROTOCOL              : 'IFLA_BR_VLAN_PROTOCOL',
        IFLA_BR_GROUP_FWD_MASK             : 'IFLA_BR_GROUP_FWD_MASK',
        IFLA_BR_ROOT_ID                    : 'IFLA_BR_ROOT_ID',
        IFLA_BR_BRIDGE_ID                  : 'IFLA_BR_BRIDGE_ID',
        IFLA_BR_ROOT_PORT                  : 'IFLA_BR_ROOT_PORT',
        IFLA_BR_ROOT_PATH_COST             : 'IFLA_BR_ROOT_PATH_COST',
        IFLA_BR_TOPOLOGY_CHANGE            : 'IFLA_BR_TOPOLOGY_CHANGE',
        IFLA_BR_TOPOLOGY_CHANGE_DETECTED   : 'IFLA_BR_TOPOLOGY_CHANGE_DETECTED',
        IFLA_BR_HELLO_TIMER                : 'IFLA_BR_HELLO_TIMER',
        IFLA_BR_TCN_TIMER                  : 'IFLA_BR_TCN_TIMER',
        IFLA_BR_TOPOLOGY_CHANGE_TIMER      : 'IFLA_BR_TOPOLOGY_CHANGE_TIMER',
        IFLA_BR_GC_TIMER                   : 'IFLA_BR_GC_TIMER',
        IFLA_BR_GROUP_ADDR                 : 'IFLA_BR_GROUP_ADDR',
        IFLA_BR_FDB_FLUSH                  : 'IFLA_BR_FDB_FLUSH',
        IFLA_BR_MCAST_ROUTER               : 'IFLA_BR_MCAST_ROUTER',
        IFLA_BR_MCAST_SNOOPING             : 'IFLA_BR_MCAST_SNOOPING',
        IFLA_BR_MCAST_QUERY_USE_IFADDR     : 'IFLA_BR_MCAST_QUERY_USE_IFADDR',
        IFLA_BR_MCAST_QUERIER              : 'IFLA_BR_MCAST_QUERIER',
        IFLA_BR_MCAST_HASH_ELASTICITY      : 'IFLA_BR_MCAST_HASH_ELASTICITY',
        IFLA_BR_MCAST_HASH_MAX             : 'IFLA_BR_MCAST_HASH_MAX',
        IFLA_BR_MCAST_LAST_MEMBER_CNT      : 'IFLA_BR_MCAST_LAST_MEMBER_CNT',
        IFLA_BR_MCAST_STARTUP_QUERY_CNT    : 'IFLA_BR_MCAST_STARTUP_QUERY_CNT',
        IFLA_BR_MCAST_LAST_MEMBER_INTVL    : 'IFLA_BR_MCAST_LAST_MEMBER_INTVL',
        IFLA_BR_MCAST_MEMBERSHIP_INTVL     : 'IFLA_BR_MCAST_MEMBERSHIP_INTVL',
        IFLA_BR_MCAST_QUERIER_INTVL        : 'IFLA_BR_MCAST_QUERIER_INTVL',
        IFLA_BR_MCAST_QUERY_INTVL          : 'IFLA_BR_MCAST_QUERY_INTVL',
        IFLA_BR_MCAST_QUERY_RESPONSE_INTVL : 'IFLA_BR_MCAST_QUERY_RESPONSE_INTVL',
        IFLA_BR_MCAST_STARTUP_QUERY_INTVL  : 'IFLA_BR_MCAST_STARTUP_QUERY_INTVL',
        IFLA_BR_NF_CALL_IPTABLES           : 'IFLA_BR_NF_CALL_IPTABLES',
        IFLA_BR_NF_CALL_IP6TABLES          : 'IFLA_BR_NF_CALL_IP6TABLES',
        IFLA_BR_NF_CALL_ARPTABLES          : 'IFLA_BR_NF_CALL_ARPTABLES',
        IFLA_BR_VLAN_DEFAULT_PVID          : 'IFLA_BR_VLAN_DEFAULT_PVID',
        IFLA_BR_PAD                        : 'IFLA_BR_PAD',
        IFLA_BR_VLAN_STATS_ENABLED         : 'IFLA_BR_VLAN_STATS_ENABLED',
        IFLA_BR_MCAST_STATS_ENABLED        : 'IFLA_BR_MCAST_STATS_ENABLED',
        IFLA_BR_MCAST_IGMP_VERSION         : 'IFLA_BR_MCAST_IGMP_VERSION',
        IFLA_BR_MCAST_MLD_VERSION          : 'IFLA_BR_MCAST_MLD_VERSION'
    }

    # =========================================
    # IFLA_INFO_DATA attributes for vrfs
    # =========================================
    IFLA_VRF_UNSPEC                         = 0
    IFLA_VRF_TABLE                          = 1

    ifla_vrf_to_string = {
        IFLA_VRF_UNSPEC                     : 'IFLA_VRF_UNSPEC',
        IFLA_VRF_TABLE                      : 'IFLA_VRF_TABLE'
    }

    # ================================================================
    # IFLA_INFO_DATA attributes for (ip6)gre, (ip6)gretap, (ip6)erspan
    # ================================================================
    IFLA_GRE_UNSPEC             = 0
    IFLA_GRE_LINK               = 1
    IFLA_GRE_IFLAGS             = 2
    IFLA_GRE_OFLAGS             = 3
    IFLA_GRE_IKEY               = 4
    IFLA_GRE_OKEY               = 5
    IFLA_GRE_LOCAL              = 6
    IFLA_GRE_REMOTE             = 7
    IFLA_GRE_TTL                = 8
    IFLA_GRE_TOS                = 9
    IFLA_GRE_PMTUDISC           = 10
    IFLA_GRE_ENCAP_LIMIT        = 11
    IFLA_GRE_FLOWINFO           = 12
    IFLA_GRE_FLAGS              = 13
    IFLA_GRE_ENCAP_TYPE         = 14
    IFLA_GRE_ENCAP_FLAGS        = 15
    IFLA_GRE_ENCAP_SPORT        = 16
    IFLA_GRE_ENCAP_DPORT        = 17
    IFLA_GRE_COLLECT_METADATA   = 18
    IFLA_GRE_IGNORE_DF          = 19
    IFLA_GRE_FWMARK             = 20
    IFLA_GRE_ERSPAN_INDEX       = 21
    IFLA_GRE_ERSPAN_VER         = 22
    IFLA_GRE_ERSPAN_DIR         = 23
    IFLA_GRE_ERSPAN_HWID        = 24

    ifla_gre_to_string = {
        IFLA_GRE_UNSPEC             : "IFLA_GRE_UNSPEC",
        IFLA_GRE_LINK               : "IFLA_GRE_LINK",
        IFLA_GRE_IFLAGS             : "IFLA_GRE_IFLAGS",
        IFLA_GRE_OFLAGS             : "IFLA_GRE_OFLAGS",
        IFLA_GRE_IKEY               : "IFLA_GRE_IKEY",
        IFLA_GRE_OKEY               : "IFLA_GRE_OKEY",
        IFLA_GRE_LOCAL              : "IFLA_GRE_LOCAL",
        IFLA_GRE_REMOTE             : "IFLA_GRE_REMOTE",
        IFLA_GRE_TTL                : "IFLA_GRE_TTL",
        IFLA_GRE_TOS                : "IFLA_GRE_TOS",
        IFLA_GRE_PMTUDISC           : "IFLA_GRE_PMTUDISC",
        IFLA_GRE_ENCAP_LIMIT        : "IFLA_GRE_ENCAP_LIMIT",
        IFLA_GRE_FLOWINFO           : "IFLA_GRE_FLOWINFO",
        IFLA_GRE_FLAGS              : "IFLA_GRE_FLAGS",
        IFLA_GRE_ENCAP_TYPE         : "IFLA_GRE_ENCAP_TYPE",
        IFLA_GRE_ENCAP_FLAGS        : "IFLA_GRE_ENCAP_FLAGS",
        IFLA_GRE_ENCAP_SPORT        : "IFLA_GRE_ENCAP_SPORT",
        IFLA_GRE_ENCAP_DPORT        : "IFLA_GRE_ENCAP_DPORT",
        IFLA_GRE_COLLECT_METADATA   : "IFLA_GRE_COLLECT_METADATA",
        IFLA_GRE_IGNORE_DF          : "IFLA_GRE_IGNORE_DF",
        IFLA_GRE_FWMARK             : "IFLA_GRE_FWMARK",
        IFLA_GRE_ERSPAN_INDEX       : "IFLA_GRE_ERSPAN_INDEX",
        IFLA_GRE_ERSPAN_VER         : "IFLA_GRE_ERSPAN_VER",
        IFLA_GRE_ERSPAN_DIR         : "IFLA_GRE_ERSPAN_DIR",
        IFLA_GRE_ERSPAN_HWID        : "IFLA_GRE_ERSPAN_HWID",
    }

    # ===============================================
    # IFLA_INFO_DATA attributes for ipip, sit, ip6tnl
    # ===============================================
    IFLA_IPTUN_UNSPEC                       = 0
    IFLA_IPTUN_LINK                         = 1
    IFLA_IPTUN_LOCAL                        = 2
    IFLA_IPTUN_REMOTE                       = 3
    IFLA_IPTUN_TTL                          = 4
    IFLA_IPTUN_TOS                          = 5
    IFLA_IPTUN_ENCAP_LIMIT                  = 6
    IFLA_IPTUN_FLOWINFO                     = 7
    IFLA_IPTUN_FLAGS                        = 8
    IFLA_IPTUN_PROTO                        = 9
    IFLA_IPTUN_PMTUDISC                     = 10
    IFLA_IPTUN_6RD_PREFIX                   = 11
    IFLA_IPTUN_6RD_RELAY_PREFIX             = 12
    IFLA_IPTUN_6RD_PREFIXLEN                = 13
    IFLA_IPTUN_6RD_RELAY_PREFIXLEN          = 14
    IFLA_IPTUN_ENCAP_TYPE                   = 15
    IFLA_IPTUN_ENCAP_FLAGS                  = 16
    IFLA_IPTUN_ENCAP_SPORT                  = 17
    IFLA_IPTUN_ENCAP_DPORT                  = 18
    IFLA_IPTUN_COLLECT_METADATA             = 19
    IFLA_IPTUN_FWMARK                       = 20

    ifla_iptun_to_string = {
        IFLA_IPTUN_UNSPEC                   : "IFLA_IPTUN_UNSPEC",
        IFLA_IPTUN_LINK                     : "IFLA_IPTUN_LINK",
        IFLA_IPTUN_LOCAL                    : "IFLA_IPTUN_LOCAL",
        IFLA_IPTUN_REMOTE                   : "IFLA_IPTUN_REMOTE",
        IFLA_IPTUN_TTL                      : "IFLA_IPTUN_TTL",
        IFLA_IPTUN_TOS                      : "IFLA_IPTUN_TOS",
        IFLA_IPTUN_ENCAP_LIMIT              : "IFLA_IPTUN_ENCAP_LIMIT",
        IFLA_IPTUN_FLOWINFO                 : "IFLA_IPTUN_FLOWINFO",
        IFLA_IPTUN_FLAGS                    : "IFLA_IPTUN_FLAGS",
        IFLA_IPTUN_PROTO                    : "IFLA_IPTUN_PROTO",
        IFLA_IPTUN_PMTUDISC                 : "IFLA_IPTUN_PMTUDISC",
        IFLA_IPTUN_6RD_PREFIX               : "IFLA_IPTUN_6RD_PREFIX",
        IFLA_IPTUN_6RD_RELAY_PREFIX         : "IFLA_IPTUN_6RD_RELAY_PREFIX",
        IFLA_IPTUN_6RD_PREFIXLEN            : "IFLA_IPTUN_6RD_PREFIXLEN",
        IFLA_IPTUN_6RD_RELAY_PREFIXLEN      : "IFLA_IPTUN_6RD_RELAY_PREFIXLEN",
        IFLA_IPTUN_ENCAP_TYPE               : "IFLA_IPTUN_ENCAP_TYPE",
        IFLA_IPTUN_ENCAP_FLAGS              : "IFLA_IPTUN_ENCAP_FLAGS",
        IFLA_IPTUN_ENCAP_SPORT              : "IFLA_IPTUN_ENCAP_SPORT",
        IFLA_IPTUN_ENCAP_DPORT              : "IFLA_IPTUN_ENCAP_DPORT",
        IFLA_IPTUN_COLLECT_METADATA         : "IFLA_IPTUN_COLLECT_METADATA",
        IFLA_IPTUN_FWMARK                   : "IFLA_IPTUN_FWMARK",
    }

    # =========================================
    # IFLA_INFO_DATA attributes for vti, vti6
    # =========================================
    IFLA_VTI_UNSPEC     = 0
    IFLA_VTI_LINK       = 1
    IFLA_VTI_IKEY       = 2
    IFLA_VTI_OKEY       = 3
    IFLA_VTI_LOCAL      = 4
    IFLA_VTI_REMOTE     = 5
    IFLA_VTI_FWMARK     = 6

    ifla_vti_to_string = {
        IFLA_VTI_UNSPEC     : "IFLA_VTI_UNSPEC",
        IFLA_VTI_LINK       : "IFLA_VTI_LINK",
        IFLA_VTI_IKEY       : "IFLA_VTI_IKEY",
        IFLA_VTI_OKEY       : "IFLA_VTI_OKEY",
        IFLA_VTI_LOCAL      : "IFLA_VTI_LOCAL",
        IFLA_VTI_REMOTE     : "IFLA_VTI_REMOTE",
        IFLA_VTI_FWMARK     : "IFLA_VTI_FWMARK",
    }

    # =========================================
    # IFLA_INFO_DATA attributes for wireguard
    # =========================================
    ifla_wireguard_to_string = {
    }


class Attribute(object):

    def __init__(self, atype, string, logger):
        self.atype = atype
        self.string = string
        self.HEADER_PACK = '=HH'
        self.HEADER_LEN = calcsize(self.HEADER_PACK)
        self.PACK = None
        self.LEN = None
        self.raw = None  # raw value (i.e. int for mac address)
        self.value = None
        self.nested = False
        self.net_byteorder = False
        self.log = logger

    def __str__(self):
        return self.string

    def set_value(self, value):
        self.value = value

    def set_nested(self, nested):
        self.nested = nested

    def set_net_byteorder(self, net_byteorder):
        self.net_byteorder = net_byteorder

    @staticmethod
    def pad_bytes_needed(length):
        """
        Return the number of bytes that should be added to align on a 4-byte boundry
        """
        remainder = length % 4

        if remainder:
            return 4 - remainder

        return 0

    def pad(self, length, raw):
        pad = self.pad_bytes_needed(length)

        if pad:
            raw += ("\0" * pad).encode("utf-8")

        return raw

    def encode(self):

        if not self.LEN:
            raise Exception('Please define an encode() method in your child attribute class, or do not use AttributeGeneric')

        length = self.HEADER_LEN + self.LEN
        attr_type_with_flags = self.atype

        if self.nested:
            attr_type_with_flags = attr_type_with_flags | NLA_F_NESTED

        if self.net_byteorder:
            attr_type_with_flags = attr_type_with_flags | NLA_F_NET_BYTEORDER

        raw = pack(self.HEADER_PACK, length, attr_type_with_flags) + pack(self.PACK, self.value)
        raw = self.pad(length, raw)
        return raw

    def decode_length_type(self, data):
        """
        The first two bytes of an attribute are the length, the next two bytes are the type
        """
        self.data = data
        prev_atype = self.atype
        (data1, data2) = unpack(self.HEADER_PACK, data[:self.HEADER_LEN])
        self.length = int(data1)
        self.atype = int(data2)
        self.attr_end = padded_length(self.length)

        self.nested = True if self.atype & NLA_F_NESTED else False
        self.net_byteorder = True if self.atype & NLA_F_NET_BYTEORDER else False
        self.atype = self.atype & NLA_TYPE_MASK

        # Should never happen
        assert self.atype == prev_atype, "This object changes attribute type from %d to %d, this is bad" % (prev_atype, self.atype)

    def dump_first_line(self, dump_buffer, line_number, color):
        """
        Add the "Length....Type..." line to the dump buffer
        """
        if self.attr_end == self.length:
            padded_to = ', '
        else:
            padded_to = ' padded to %d, ' % self.attr_end

        extra = 'Length %s (%d)%sType %s%s%s (%d) %s' % \
                 (zfilled_hex(self.length, 4), self.length,
                  padded_to,
                  zfilled_hex(self.atype, 4),
                  " (NLA_F_NESTED set)" if self.nested else "",
                  " (NLA_F_NET_BYTEORDER set)" if self.net_byteorder else "",
                  self.atype,
                  self)

        dump_buffer.append(data_to_color_text(line_number, color, self.data[0:4], extra))
        return line_number + 1

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)

        for x in range(1, self.attr_end//4):
            start = x * 4
            end = start + 4
            dump_buffer.append(data_to_color_text(line_number, color, self.data[start:end], ''))
            line_number += 1

        return line_number

    def get_pretty_value(self, obj=None):
        if obj and callable(obj):
            return obj(self.value)
        return self.value

    @staticmethod
    def decode_one_byte_attribute(data, _=None):
        # we don't need to use the unpack function because bytes are a list of ints
        return data[4]

    @staticmethod
    def decode_two_bytes_attribute(data, _=None):
        return unpack("=H", data[4:6])[0]

    @staticmethod
    def decode_two_bytes_network_byte_order_attribute(data, _=None):
        # The form '!' is available for those poor souls who claim they can't
        # remember whether network byte order is big-endian or little-endian.
        return unpack("!H", data[4:6])[0]

    @staticmethod
    def decode_four_bytes_attribute(data, _=None):
        return unpack("=L", data[4:8])[0]

    @staticmethod
    def decode_eight_bytes_attribute(data, _=None):
        return unpack("=Q", data[4:12])[0]

    @staticmethod
    def decode_mac_address_attribute(data, _=None):
        (data1, data2) = unpack(">LHxx", data[4:12])
        return mac_int_to_str(data1 << 16 | data2)

    @staticmethod
    def decode_ipv4_address_attribute(data, _=None):
        return ipnetwork.IPv4Address(unpack(">L", data[4:8])[0])

    @staticmethod
    def decode_ipv6_address_attribute(data, _=None):
        (data1, data2) = unpack(">QQ", data[4:20])
        return ipnetwork.IPv6Address(data1 << 64 | data2)

    @staticmethod
    def decode_bond_ad_info_attribute(data, info_data_end):
        ifla_bond_ad_info = {}
        ad_attr_data = data[4:info_data_end]

        while ad_attr_data:
            (ad_data_length, ad_data_type) = unpack("=HH", ad_attr_data[:4])
            ad_data_end = padded_length(ad_data_length)

            if ad_data_type == Link.IFLA_BOND_AD_INFO_PARTNER_MAC:
                (data1, data2) = unpack(">LHxx", ad_attr_data[4:12])
                ifla_bond_ad_info[ad_data_type] = mac_int_to_str(data1 << 16 | data2)

            ad_attr_data = ad_attr_data[ad_data_end:]

        return ifla_bond_ad_info

    @staticmethod
    def decode_bond_ad_arp_ip_target(data, info_data_end):
        ifla_bond_ad_arp_ip_target = []
        arp_attr_data = data[4:info_data_end]

        while arp_attr_data and len(arp_attr_data) >= 8:
            arp_ip = ipnetwork.IPv4Address(unpack('>L', arp_attr_data[4:8])[0])
            ifla_bond_ad_arp_ip_target.append(arp_ip)
            arp_attr_data = arp_attr_data[8:]

        return ifla_bond_ad_arp_ip_target

    @staticmethod
    def decode_vlan_protocol_attribute(data, _=None):
        return Link.ifla_vlan_protocol_dict.get(unpack(">H", data[4:6])[0])

    @staticmethod
    def decode_vlan_flags_attribute(data, _=None):
        vlan_flags = unpack('=I', data[4:8])[0]
        vlan_flags_dict = {}

        # iterate over bits set to 1
        def bits(n):
            while n:
                b = n & (~n + 1)
                yield b
                n ^= b

        for vlan_flag in bits(vlan_flags):
            if vlan_flag in Link.vlan_flags_to_string:
                vlan_flags_dict[vlan_flag] = True
            #else:
            #    self.log.warning('Unknown vlan flag %d in IFLA_VLAN_FLAGS' % vlan_flag)

        return vlan_flags_dict

    ############################################################################
    # encode methods
    ############################################################################

    @staticmethod
    def encode_one_byte_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        sub_attr_pack_layout.append("HH")
        sub_attr_payload.append(5)  # length
        sub_attr_payload.append(info_data_type)

        sub_attr_pack_layout.append("Bxxx")
        sub_attr_payload.append(info_data_value)

    @staticmethod
    def encode_bond_xmit_hash_policy_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        return Attribute.encode_one_byte_attribute(
            sub_attr_pack_layout,
            sub_attr_payload,
            info_data_type,
            Link.ifla_bond_xmit_hash_policy_tbl.get(info_data_value, 0),
        )

    @staticmethod
    def encode_bond_mode_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        return Attribute.encode_one_byte_attribute(
            sub_attr_pack_layout,
            sub_attr_payload,
            info_data_type,
            Link.ifla_bond_mode_tbl.get(info_data_value, 0),
        )

    @staticmethod
    def encode_bond_primary_reselect_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        return Attribute.encode_one_byte_attribute(
            sub_attr_pack_layout,
            sub_attr_payload,
            info_data_type,
            Link.ifla_bond_primary_reselect_tbl.get(info_data_value, 0),
        )

    @staticmethod
    def encode_two_bytes_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        sub_attr_pack_layout.append("HH")
        sub_attr_payload.append(6)  # length
        sub_attr_payload.append(info_data_type)

        sub_attr_pack_layout.append("Hxx")
        sub_attr_payload.append(info_data_value)

    @staticmethod
    def encode_four_bytes_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        sub_attr_pack_layout.append("HH")
        sub_attr_payload.append(8)  # length
        sub_attr_payload.append(info_data_type)

        sub_attr_pack_layout.append("L")
        sub_attr_payload.append(info_data_value)

    @staticmethod
    def encode_eight_bytes_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        sub_attr_pack_layout.append("HH")
        sub_attr_payload.append(12)  # length
        sub_attr_payload.append(info_data_type)

        sub_attr_pack_layout.append("Q")
        sub_attr_payload.append(info_data_value)

    @staticmethod
    def encode_ipv4_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        sub_attr_pack_layout.append("HH")
        sub_attr_payload.append(8)  # length
        sub_attr_payload.append(info_data_type)

        sub_attr_pack_layout.append("BBBB")

        if info_data_value:
            sub_attr_payload.extend(info_data_value.packed)
        else:
            sub_attr_payload.extend([0, 0, 0, 0])

    @staticmethod
    def encode_ipv6_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        """
            def decode_ipv6_address_attribute(data, _=None):
                (data1, data2) = unpack(">QQ", data[4:20])
                return IPv6Address(data1 << 64 | data2)
        """
        sub_attr_pack_layout.append("HH")
        sub_attr_payload.append(20)  # length
        sub_attr_payload.append(info_data_type)
        sub_attr_pack_layout.append("QQ")
        if info_data_value:
            data1, data2 = unpack("<QQ", info_data_value.packed)
            sub_attr_payload.append(data1)
            sub_attr_payload.append(data2)
        else:
            sub_attr_payload.extend([0, 0])

    @staticmethod
    def encode_vlan_protocol_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        sub_attr_pack_layout.append("HH")
        sub_attr_payload.append(6)  # length
        sub_attr_payload.append(info_data_type)

        # vlan protocol
        vlan_protocol = NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_vlan_protocol_dict.get(info_data_value)
        if not vlan_protocol:
            raise NotImplementedError('vlan protocol %s not implemented' % info_data_value)

        sub_attr_pack_layout.append("Hxx")
        sub_attr_payload.append(htons(vlan_protocol))

    @staticmethod
    def encode_vxlan_port_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        sub_attr_pack_layout.append("HH")
        sub_attr_payload.append(6)
        sub_attr_payload.append(info_data_type)

        sub_attr_pack_layout.append("Hxx")

        # byte swap
        swaped = pack(">H", info_data_value)

        sub_attr_payload.append(unpack("<H", swaped)[0])

    @staticmethod
    def encode_mac_address_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        sub_attr_pack_layout.append("HH")
        sub_attr_payload.append(10)  # length
        sub_attr_payload.append(info_data_type)

        sub_attr_pack_layout.append("6Bxx")
        for mbyte in info_data_value.replace(".", " ").replace(":", " ").split():
            sub_attr_payload.append(int(mbyte, 16))

    @staticmethod
    def encode_vlan_flags_attribute(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):
        sub_attr_pack_layout.append('HH')
        sub_attr_payload.append(12)
        sub_attr_payload.append(info_data_type)

        # vlan flags and mask
        sub_attr_pack_layout.append('II')
        vlan_flags = 0
        vlan_flags_mask = 0

        for (vlan_flag, flag_set) in info_data_value.items():
            vlan_flags_mask |= vlan_flag
            if flag_set:
                vlan_flags |= vlan_flag

        sub_attr_payload.append(vlan_flags)
        sub_attr_payload.append(vlan_flags_mask)

    @staticmethod
    def encode_bond_ad_arp_ip_target(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value):

        if len(info_data_value) > BOND_MAX_ARP_TARGETS:
            info_data_value = info_data_value[:BOND_MAX_ARP_TARGETS]

        sub_attr_pack_layout.append('HH')
        sub_attr_payload.append(8*len(info_data_value) + 4)  # length
        sub_attr_payload.append(info_data_type)

        counter = 0

        for ip in info_data_value:
            # Fix this pack
            sub_attr_pack_layout.append('HH')
            sub_attr_payload.append(8)  # length
            sub_attr_payload.append(counter)
            # The IP
            sub_attr_pack_layout.append('4s')
            sub_attr_payload.append(struct.pack('>L', int(ip.ip)))
            counter += 1


class AttributeCACHEINFO(Attribute):
    """
        struct ifa_cacheinfo {
            __u32	ifa_prefered;
            __u32	ifa_valid;
            __u32	cstamp; /* created timestamp, hundredths of seconds */
            __u32	tstamp; /* updated timestamp, hundredths of seconds */
        };
    """
    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = "=IIII"
        self.LEN = calcsize(self.PACK)

    def encode(self):
        ifa_prefered, ifa_valid, cstamp, tstamp = self.value
        return pack(self.HEADER_PACK, self.HEADER_LEN + self.LEN , self.atype) + pack(self.PACK, ifa_prefered, ifa_valid, cstamp, tstamp)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        try:
            self.value = unpack(self.PACK, self.data[4:])
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))


class AttributeFourByteList(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        wordcount = (self.attr_end - 4)//4
        self.PACK = '=%dL' % wordcount
        self.LEN = calcsize(self.PACK)

        try:
            self.value = unpack(self.PACK, self.data[4:])
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        idx = 1
        for val in self.value:
            dump_buffer.append(data_to_color_text(line_number, color, self.data[4*idx:4*(idx+1)], val))
            line_number += 1
            idx += 1
        return line_number


class AttributeFourByteValue(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = '=L'
        self.LEN = calcsize(self.PACK)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        assert self.attr_end == 8, "Attribute length for %s must be 8, it is %d" % (self, self.attr_end)

        try:
            self.value = int(unpack(self.PACK, self.data[4:])[0])
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
        return line_number + 1


class AttributeTwoByteValue(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = '=Hxx'
        self.LEN = calcsize(self.PACK)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        assert self.attr_end == 8, "Attribute length for %s must be 8, it is %d" % (self, self.attr_end)

        try:
            self.value = int(unpack(self.PACK, self.data[4:8])[0])
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:6])))
            raise

    def encode(self):
        length = self.HEADER_LEN + self.LEN
        raw = pack(self.HEADER_PACK, length-2, self.atype) + pack(self.PACK, self.value)
        raw = self.pad(length, raw)
        return raw

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
        return line_number + 1


class AttributeString(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = None
        self.LEN = None

    def encode(self):
        # some interface names come from JSON as unicode strings
        # and cannot be packed as is so we must convert them to strings
        if isinstance(self.value, str):
            self.value = str(self.value)
        self.PACK = '%ds' % len(self.value)
        self.LEN = calcsize(self.PACK)

        length = self.HEADER_LEN + self.LEN
        raw = pack(self.HEADER_PACK, length, self.atype) + pack(self.PACK, self.value.encode())
        raw = self.pad(length, raw)
        return raw

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        self.PACK = '%ds' % (self.length - 4)
        self.LEN = calcsize(self.PACK)

        try:
            self.value = remove_trailing_null(unpack(self.PACK, self.data[4:self.length])[0]).decode("utf-8")
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:self.length])))
            raise


class AttributeStringInterfaceName(AttributeString):

    def __init__(self, atype, string, family, logger):
        AttributeString.__init__(self, atype, string, family, logger)

    def set_value(self, value):
        if value and len(value) > IF_NAME_SIZE:
            raise Exception('interface name exceeds max length of %d' % IF_NAME_SIZE)
        self.value = value


class AttributeIPAddress(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.family = family

        if self.family == AF_INET:
            self.PACK = '>L'

        elif self.family == AF_INET6:
            self.PACK = '>QQ'

        elif self.family == AF_BRIDGE:
            self.PACK = '>L'

        else:
            raise Exception("%s is not a supported address family" % self.family)

        self.LEN = calcsize(self.PACK)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)

        try:
            try:
                prefixlen = parent_msg.prefixlen
            except AttributeError:
                prefixlen = None
            try:
                scope = parent_msg.scope
            except AttributeError:
                scope = 0

            if isinstance(parent_msg, Route):
                if self.atype == Route.RTA_SRC:
                    prefixlen = parent_msg.src_len
                elif self.atype == Route.RTA_DST:
                    prefixlen = parent_msg.dst_len

            if self.family in (AF_INET, AF_BRIDGE):
                self.value = ipnetwork.IPv4Network(unpack(self.PACK, self.data[4:])[0], prefixlen, scope)

            elif self.family == AF_INET6:
                (data1, data2) = unpack(self.PACK, self.data[4:])
                self.value = ipnetwork.IPv6Network(data1 << 64 | data2, prefixlen, scope)

            else:
                self.log.debug("AttributeIPAddress: decode: unsupported address family ({})".format(self.family))

        except struct.error:
            self.value = None
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise

    def encode(self):
        length = self.HEADER_LEN + self.LEN

        if self.family not in [AF_INET, AF_INET6, AF_BRIDGE]:
            raise Exception("%s is not a supported address family" % self.family)

        raw = pack(self.HEADER_PACK, length, self.atype) + self.value.packed
        raw = self.pad(length, raw)
        return raw

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)

        if self.family == AF_INET:
            dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
            line_number += 1

        elif self.family == AF_INET6:

            for x in range(1, self.attr_end//4):
                start = x * 4
                end = start + 4
                dump_buffer.append(data_to_color_text(line_number, color, self.data[start:end], self.value))
                line_number += 1

        elif self.family == AF_BRIDGE:
            dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
            line_number += 1

        return line_number


class AttributeIPAddressNoMask(AttributeIPAddress):
    def decode(self, *args, **kwargs):
        super(AttributeIPAddressNoMask, self).decode(*args, **kwargs)
        self.value = self.value.ip


class AttributeMACAddress(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = '>LHxx'
        self.LEN = calcsize(self.PACK)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)

        # IFLA_ADDRESS and IFLA_BROADCAST attributes for all interfaces has been a
        # 6-byte MAC address. But the GRE interface uses a 4-byte IP address and
        # GREv6 uses a 16-byte IPv6 address for this attribute.
        try:
            # GRE interface uses a 4-byte IP address for this attribute
            if self.length == 8:
                self.value = ipnetwork.IPv4Address(unpack('>L', self.data[4:])[0])

            # MAC Address
            elif self.length == 10:
                (data1, data2) = unpack(self.PACK, self.data[4:])
                self.raw = data1 << 16 | data2
                self.value = mac_int_to_str(self.raw)
            # GREv6 interface uses a 16-byte IP address for this attribute
            elif self.length == 20:
                self.value = ipnetwork.IPv6Address(unpack('>L', self.data[16:])[0])

            else:
                self.log.info("Length of MACAddress attribute not supported: %d" % self.length)
                self.value = None

        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise

    def encode(self):
        length = self.HEADER_LEN + self.LEN
        mac_raw = int(self.value.replace('.', '').replace(':', ''), 16)
        raw = pack(self.HEADER_PACK, length-2, self.atype) + pack(self.PACK, mac_raw >> 16, mac_raw & 0x0000FFFF)
        raw = self.pad(length, raw)
        return raw

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
        line_number += 1
        if len(self.data) >= 12:
            dump_buffer.append(data_to_color_text(line_number, color, self.data[8:12]))
            line_number += 1
        return line_number


class AttributeMplsLabel(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.family = family
        self.PACK = '>HBB'

    def decode(self, parent_msg, data):
        self.decode_length_type(data)

        try:
            (label_high, label_low_tc_s, self.ttl) = unpack(self.PACK, self.data[4:])
            self.s_bit = label_low_tc_s & 0x1
            self.traffic_class = ((label_low_tc_s & 0xf) >> 1)
            self.label = (label_high << 4) | (label_low_tc_s >> 4)
            self.value = self.label

        except struct.error:
            self.value = None
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8],
                                              'label %s, TC %s, bottom-of-stack %s, TTL %d' %
                                              (self.label, self.traffic_class, self.s_bit, self.ttl)))
        line_number += 1

        return line_number


class AttributeGeneric(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = None
        self.LEN = None

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        wordcount = (self.attr_end - 4)//4
        self.PACK = '=%dL' % wordcount
        self.LEN = calcsize(self.PACK)

        try:
            self.value = ''.join(map(str, unpack(self.PACK, self.data[4:])))
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise


class AttributeOneByteValue(AttributeGeneric):

    def __init__(self, atype, string, family, logger):
        AttributeGeneric.__init__(self, atype, string, family, logger)
        self.PACK = '=Bxxx'
        self.LEN = calcsize(self.PACK)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        assert self.attr_end == 8, "Attribute length for %s must be 8, it is %d" % (self, self.attr_end)

        try:
            self.value = int(unpack(self.PACK, self.data[4:8])[0])
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:5])))
            raise

    def encode(self):
        length = self.HEADER_LEN + self.LEN
        raw = pack(self.HEADER_PACK, length-3, self.atype) + pack(self.PACK, self.value)
        raw = self.pad(length, raw)
        return raw

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
        return line_number + 1


class AttributeIFLA_AF_SPEC(Attribute):
    """
    value will be a dictionary such as:
    {
        Link.IFLA_BRIDGE_FLAGS: flags,
        Link.IFLA_BRIDGE_VLAN_INFO: (vflags, vlanid)
    }
    """
    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.family = family

    def encode(self):
        pack_layout = [self.HEADER_PACK]
        payload = [0, self.atype | NLA_F_NESTED]
        attr_length_index = 0

        # For now this assumes that all data will be packed in the native endian
        # order (=). If a field is added that needs to be packed via network
        # order (>) then some smarts will need to be added to split the pack_layout
        # string at the >, split the payload and make the needed pack() calls.
        #
        # Until we cross that bridge though we will keep things nice and simple and
        # pack everything via a single pack() call.
        sub_attr_to_add = []

        for (sub_attr_type, sub_attr_value) in self.value.items():

            if sub_attr_type == Link.IFLA_BRIDGE_FLAGS:
                sub_attr_to_add.append((sub_attr_type, sub_attr_value))

            elif sub_attr_type == Link.IFLA_BRIDGE_VLAN_INFO:
                for (vlan_flag, vlan_id) in sub_attr_value:
                    sub_attr_to_add.append((sub_attr_type, (vlan_flag, vlan_id)))

            else:
                self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_AF_SPEC sub-attribute type %d' % sub_attr_type)
                continue

        for (sub_attr_type, sub_attr_value) in sub_attr_to_add:
            sub_attr_pack_layout = ['=', 'HH']
            sub_attr_payload = [0, sub_attr_type]
            sub_attr_length_index = 0

            if sub_attr_type == Link.IFLA_BRIDGE_FLAGS:
                sub_attr_pack_layout.append('H')
                sub_attr_payload.append(sub_attr_value)

            elif sub_attr_type == Link.IFLA_BRIDGE_VLAN_INFO:
                sub_attr_pack_layout.append('HH')
                sub_attr_payload.append(sub_attr_value[0])
                sub_attr_payload.append(sub_attr_value[1])

            sub_attr_length = calcsize(''.join(sub_attr_pack_layout))
            sub_attr_payload[sub_attr_length_index] = sub_attr_length

            # add padding
            for x in range(self.pad_bytes_needed(sub_attr_length)):
                sub_attr_pack_layout.append('x')

            # The [1:] is to remove the leading = so that when we do the ''.join() later
            # we do not end up with an = in the middle of the pack layout string. There
            # will be an = at the beginning via self.HEADER_PACK
            sub_attr_pack_layout = sub_attr_pack_layout[1:]

            # Now extend the ovarall attribute pack_layout/payload to include this sub-attribute
            pack_layout.extend(sub_attr_pack_layout)
            payload.extend(sub_attr_payload)

        pack_layout = ''.join(pack_layout)

        # Fill in the length field
        length = calcsize(pack_layout)
        payload[attr_length_index] = length

        raw = pack(pack_layout, *payload)
        raw = self.pad(length, raw)
        return raw

    def decode(self, parent_msg, data):
        """
        value is a dictionary such as:
        {
            Link.IFLA_BRIDGE_FLAGS: flags,
            Link.IFLA_BRIDGE_VLAN_INFO: (vflags, vlanid)
            Link.IFLA_BRIDGE_VLAN_TUNNEL_INFO: [
                    __u32 tunnel_id;
                    __u16 tunnel_vid;
                    __u16 tunnel_flags;
            ]
        }

        FROM: David Ahern
        The encoding of the IFLA_AF_SPEC attribute varies depending on the family
        used for the request (RTM_GETLINK) message. For AF_UNSPEC the encoding
        has another level of nesting for each address family with the type encoded
        first. i.e.,
            af_spec = nla_nest_start(skb, IFLA_AF_SPEC)
            for each family:
                af = nla_nest_start(skb, af_ops->family)
                af_ops->fill_link_af(skb, dev, ext_filter_mask)
                nest_end
            nest_end

        This allows the parser to find the address family by looking at the first
        type.

        Whereas AF_BRIDGE encoding is just:
            af_spec = nla_nest_start(skb, IFLA_AF_SPEC)
            br_fill_ifvlaninfo{_compressed}(skb, vg)
            nest_end

        which means the parser can not use the attribute itself to know the family
        to which the attribute belongs.

        /include/uapi/linux/if_link.h
        /*
         * IFLA_AF_SPEC
         *   Contains nested attributes for address family specific attributes.
         *   Each address family may create a attribute with the address family
         *   number as type and create its own attribute structure in it.
         *
         *   Example:
         *   [IFLA_AF_SPEC] = {
         *       [AF_INET] = {
         *           [IFLA_INET_CONF] = ...,
         *       },
         *       [AF_INET6] = {
         *           [IFLA_INET6_FLAGS] = ...,
         *           [IFLA_INET6_CONF] = ...,
         *       }
         *   }
         */

        """
        self.decode_length_type(data)
        self.value = {}

        data = self.data[4:]

        while data:
            (sub_attr_length, sub_attr_type) = unpack('=HH', data[:4])
            sub_attr_end = padded_length(sub_attr_length)

            if not sub_attr_length:
                self.log.error('parsed a zero length sub-attr')
                return

            sub_attr_data = data[4:sub_attr_end]

            if self.family == AF_BRIDGE:
                # /* Bridge management nested attributes
                #  * [IFLA_AF_SPEC] = {
                #  *     [IFLA_BRIDGE_FLAGS]
                #  *     [IFLA_BRIDGE_MODE]
                #  *     [IFLA_BRIDGE_VLAN_INFO]
                #  * }
                #  */
                if sub_attr_type == Link.IFLA_BRIDGE_FLAGS:
                    self.value[Link.IFLA_BRIDGE_FLAGS] = unpack("=H", sub_attr_data[0:2])[0]

                elif sub_attr_type == Link.IFLA_BRIDGE_VLAN_INFO:
                    if Link.IFLA_BRIDGE_VLAN_INFO not in self.value:
                        self.value[Link.IFLA_BRIDGE_VLAN_INFO] = []
                    self.value[Link.IFLA_BRIDGE_VLAN_INFO].append(tuple(unpack("=HH", sub_attr_data[0:4])))

                elif sub_attr_type == Link.IFLA_BRIDGE_VLAN_TUNNEL_INFO:
                    # Link.IFLA_BRIDGE_VLAN_TUNNEL_INFO: {
                    #     __u32 tunnel_id;
                    #     __u16 tunnel_vid;
                    #     __u16 tunnel_flags;
                    # }
                    # all the nested attributes are padded on 8 bytes

                    tunnel_id = 0
                    tunnel_vid = 0
                    tunnel_flags = 0

                    while sub_attr_data:
                        (s_sub_attr_length, s_sub_attr_type) = unpack("=HH", sub_attr_data[:4])
                        s_sub_attr_end = padded_length(s_sub_attr_length)
                        d = sub_attr_data[4:s_sub_attr_end]

                        if s_sub_attr_type == Link.IFLA_BRIDGE_VLAN_TUNNEL_ID:
                            tunnel_id = unpack("=L", d)[0]

                        elif s_sub_attr_type == Link.IFLA_BRIDGE_VLAN_TUNNEL_VID:
                            tunnel_vid = unpack("=L", d)[0]

                        elif s_sub_attr_type == Link.IFLA_BRIDGE_VLAN_TUNNEL_FLAGS:
                            tunnel_flags = unpack("=L", d)[0]

                        sub_attr_data = sub_attr_data[s_sub_attr_end:]

                    if Link.IFLA_BRIDGE_VLAN_TUNNEL_INFO not in self.value:
                        self.value[Link.IFLA_BRIDGE_VLAN_TUNNEL_INFO] = []

                    self.value[Link.IFLA_BRIDGE_VLAN_TUNNEL_INFO].append((tunnel_id, tunnel_vid, tunnel_flags))
                else:
                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_AF_SPEC sub-attribute '
                                                     'type %s (%d), length %d, padded to %d' %
                                 (parent_msg.get_ifla_bridge_af_spec_to_string(sub_attr_type),
                                  sub_attr_type, sub_attr_length, sub_attr_end))

            elif self.family == AF_UNSPEC:

                if sub_attr_type == AF_INET6:
                    inet6_attr = {}

                    while sub_attr_data:
                        (inet6_attr_length, inet6_attr_type) = unpack('=HH', sub_attr_data[:4])
                        inet6_attr_end = padded_length(inet6_attr_length)

                        # 1 byte attr
                        if inet6_attr_type == Link.IFLA_INET6_ADDR_GEN_MODE:
                            inet6_attr[inet6_attr_type] = self.decode_one_byte_attribute(sub_attr_data)

                            # nlmanager doesn't support multiple kernel version
                            # all the other attributes like IFLA_INET6_CONF are
                            # based on DEVCONF_MAX from _UAPI_IPV6_H.
                            # we can opti the code and break this loop once we
                            # found the attribute that we are interested in.
                            # It's not really worth going through all the other
                            # attributes to log that we don't support them yet
                            break
                        else:
                            self.log.log(
                                SYSLOG_EXTRA_DEBUG,
                                'Add support for decoding AF_INET6 IFLA_AF_SPEC '
                                'sub-attribute type %s (%d), length %d, padded to %d'
                                % (
                                    parent_msg.get_ifla_inet6_af_spec_to_string(inet6_attr_type),
                                    inet6_attr_type, inet6_attr_length, inet6_attr_end
                                )
                            )

                        sub_attr_data = sub_attr_data[inet6_attr_end:]
                    self.value[AF_INET6] = inet6_attr
                else:
                    self.value[sub_attr_type] = {}

                # Uncomment the following block to implement the AF_INET attributes
                # see Link.get_ifla_inet_af_spec_to_string (dict)
                #elif sub_attr_type == AF_INET:
                #    inet_attr = {}
                #
                #    while sub_attr_data:
                #        (inet_attr_length, inet_attr_type) = unpack('=HH', sub_attr_data[:4])
                #        inet_attr_end = padded_length(inet_attr_length)
                #
                #        self.log.error(
                #            # SYSLOG_EXTRA_DEBUG,
                #            'Add support for decoding AF_INET IFLA_AF_SPEC '
                #            'sub-attribute type %s (%d), length %d, padded to %d'
                #            % (
                #                parent_msg.get_ifla_inet_af_spec_to_string(inet_attr_type),
                #                inet_attr_type, inet_attr_length, inet_attr_end
                #            )
                #        )
                #
                #        sub_attr_data = sub_attr_data[inet_attr_end:]
                #
                #    self.value[AF_INET] = inet_attr
            else:
                self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_AF_SPEC sub-attribute '
                                                 'family %d, length %d, padded to %d'
                             % (self.family, sub_attr_length, sub_attr_end))

            data = data[sub_attr_end:]

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        extra = ''

        next_sub_attr_line = 0
        sub_attr_line = True

        for x in range(1, self.attr_end//4):
            start = x * 4
            end = start + 4

            if line_number == next_sub_attr_line:
                sub_attr_line = True

            if sub_attr_line:
                sub_attr_line = False

                (sub_attr_length, sub_attr_type) = unpack('=HH', self.data[start:start+4])
                sub_attr_end = padded_length(sub_attr_length)

                next_sub_attr_line = line_number + (sub_attr_end//4)

                if sub_attr_end == sub_attr_length:
                    padded_to = ','
                else:
                    padded_to = ' padded to %d,' % sub_attr_end

                if self.family == AF_BRIDGE:
                    extra = 'Nested Attribute - Length %s (%d)%s Type %s (%d) %s' % \
                            (zfilled_hex(sub_attr_length, 4), sub_attr_length,
                             padded_to,
                             zfilled_hex(sub_attr_type, 4), sub_attr_type,
                             Link.ifla_bridge_af_spec_to_string.get(sub_attr_type))
                elif self.family == AF_UNSPEC:
                    if sub_attr_type == AF_INET6:
                        family = 'AF_INET6'
                    elif sub_attr_type == AF_INET:
                        family = 'AF_INET'
                    else:
                        family = 'Unsupported family %d' % sub_attr_type

                    extra = 'Nested Attribute Structure for %s - Length %s (%d)%s Type %s (%d)' % (
                        family, zfilled_hex(sub_attr_length, 4), sub_attr_length, padded_to,
                        zfilled_hex(sub_attr_type, 4), sub_attr_type,
                    )
            else:
                extra = ''

            dump_buffer.append(data_to_color_text(line_number, color, self.data[start:end], extra))
            line_number += 1

        return line_number

    def get_pretty_value(self, obj=None):

        if obj and callable(obj):
            return obj(self.value)

        # We do this so we can print a more human readable dictionary
        # with the names of the nested keys instead of their numbers
        value_pretty = {}

        if self.family == AF_BRIDGE:
            for (sub_key, sub_value) in self.value.items():
                sub_key_pretty = "(%2d) %s" % (sub_key, Link.ifla_bridge_af_spec_to_string.get(sub_key))
                value_pretty[sub_key_pretty] = sub_value
        elif self.family == AF_UNSPEC:
            for (family, family_attr) in self.value.items():
                family_value_pretty = {}

                if family == AF_INET6:
                    family_af_spec_to_string = Link.ifla_inet6_af_spec_to_string
                elif family == AF_INET:
                    family_af_spec_to_string = Link.ifla_inet_af_spec_to_string
                else:
                    continue # log error?

                for (sub_key, sub_value) in family_attr.items():
                    sub_key_pretty = "(%2d) %s" % (sub_key, family_af_spec_to_string.get(sub_key))
                    family_value_pretty[sub_key_pretty] = sub_value
                value_pretty = family_value_pretty

        return value_pretty



class AttributeRTA_MULTIPATH(Attribute):
    """
/* RTA_MULTIPATH --- array of struct rtnexthop.
 *
 * "struct rtnexthop" describes all necessary nexthop information,
 * i.e. parameters of path to a destination via this nexthop.
 *
 * At the moment it is impossible to set different prefsrc, mtu, window
 * and rtt for different paths from multipath.
 */

struct rtnexthop {
    unsigned short rtnh_len;
    unsigned char  rtnh_flags;
    unsigned char  rtnh_hops;
    int            rtnh_ifindex;
};
    """

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.family = family
        self.PACK = None
        self.LEN = None
        self.RTNH_PACK = '=HBBL'  # rtnh_len, flags, hops, ifindex
        self.RTNH_LEN = calcsize(self.RTNH_PACK)
        self.IPV4_LEN = 4
        self.IPV6_LEN = 16

    def encode(self):

        # Calculate the length
        if self.family == AF_INET:
            ip_len = self.IPV4_LEN
        elif self.family == AF_INET6:
            ip_len = self.IPV6_LEN

        # Attribute header
        length = self.HEADER_LEN + ((self.RTNH_LEN + self.HEADER_LEN + ip_len) * len(self.value))
        raw = pack(self.HEADER_PACK, length, self.atype)

        rtnh_flags = 0
        rtnh_hops = 0
        rtnh_len = self.RTNH_LEN + self.HEADER_LEN + ip_len

        for (nexthop, rtnh_ifindex) in self.value:

            # rtnh structure
            raw += pack(self.RTNH_PACK, rtnh_len, rtnh_flags, rtnh_hops, rtnh_ifindex)

            # Gateway
            raw += pack(self.HEADER_PACK, self.HEADER_LEN + ip_len, Route.RTA_GATEWAY)

            if self.family == AF_INET:
                raw += pack('>L', nexthop)
            elif self.family == AF_INET6:
                raw += pack('>QQ', nexthop >> 64, nexthop & 0x0000000000000000FFFFFFFFFFFFFFFF)

        raw = self.pad(length, raw)
        return raw

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        self.value = []

        data = self.data[4:]

        while data:
            (rtnh_len, rtnh_flags, rtnh_hops, rtnh_ifindex) = unpack(self.RTNH_PACK, data[:self.RTNH_LEN])
            data = data[self.RTNH_LEN:]

            (attr_type, attr_length) = unpack(self.HEADER_PACK, self.data[:self.HEADER_LEN])
            data = data[self.HEADER_LEN:]

            if self.family == AF_INET:
                if len(data) < self.IPV4_LEN:
                    break
                nexthop = ipnetwork.IPv4Address(unpack('>L', data[:self.IPV4_LEN])[0])
                self.value.append((nexthop, rtnh_ifindex, rtnh_flags, rtnh_hops))

            elif self.family == AF_INET6:
                if len(data) < self.IPV6_LEN:
                    break
                (data1, data2) = unpack('>QQ', data[:self.IPV6_LEN])
                nexthop = ipnetwork.IPv6Address(data1 << 64 | data2)
                self.value.append((nexthop, rtnh_ifindex, rtnh_flags, rtnh_hops))

            data = data[(rtnh_len-self.RTNH_LEN-self.HEADER_LEN):]

        self.value = tuple(self.value)


class AttributeIFLA_LINKINFO(Attribute):
    """
    value is a dictionary such as:

    {
        Link.IFLA_INFO_KIND : 'vlan',
        Link.IFLA_INFO_DATA : {
            Link.IFLA_VLAN_ID : vlanid,
        }
    }
    """
    decode_ifla_info_nested_data_handlers = {
        NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_INFO_DATA: {
            "bridge": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_VLAN_FILTERING: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_TOPOLOGY_CHANGE: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_TOPOLOGY_CHANGE_DETECTED: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_ROUTER: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_SNOOPING: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_QUERY_USE_IFADDR: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_QUERIER: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_NF_CALL_IPTABLES: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_NF_CALL_IP6TABLES: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_NF_CALL_ARPTABLES: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_VLAN_STATS_ENABLED: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_STATS_ENABLED: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_IGMP_VERSION: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_MLD_VERSION: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_PRIORITY: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_GROUP_FWD_MASK: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_ROOT_PORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_VLAN_DEFAULT_PVID: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_AGEING_TIME: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_FORWARD_DELAY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_HELLO_TIME: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MAX_AGE: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_STP_STATE: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_ROOT_PATH_COST: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_HASH_ELASTICITY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_HASH_MAX: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_LAST_MEMBER_CNT: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_STARTUP_QUERY_CNT: Attribute.decode_four_bytes_attribute,

                # 8 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_MEMBERSHIP_INTVL: Attribute.decode_eight_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_QUERIER_INTVL: Attribute.decode_eight_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_LAST_MEMBER_INTVL: Attribute.decode_eight_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_QUERY_INTVL: Attribute.decode_eight_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL: Attribute.decode_eight_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_STARTUP_QUERY_INTVL: Attribute.decode_eight_bytes_attribute,

                # vlan-protocol attribute ######################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_VLAN_PROTOCOL: Attribute.decode_vlan_protocol_attribute
            },
            "bond": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_MODE: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_USE_CARRIER: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_AD_LACP_RATE: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_AD_LACP_BYPASS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_XMIT_HASH_POLICY: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_NUM_PEER_NOTIF: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_PRIMARY_RESELECT: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_AD_ACTOR_SYS_PRIO: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_MIIMON: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_UPDELAY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_DOWNDELAY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_MIN_LINKS: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_PRIMARY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_ARP_INTERVAL: Attribute.decode_four_bytes_attribute,

                # mac address attributes #######################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_AD_ACTOR_SYSTEM: Attribute.decode_mac_address_attribute,

                # bond ad info attribute #######################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_AD_INFO: Attribute.decode_bond_ad_info_attribute,

                # bond arp ip target attribute #######################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_ARP_IP_TARGET: Attribute.decode_bond_ad_arp_ip_target,
            },
            "vlan": {
                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VLAN_ID: Attribute.decode_two_bytes_attribute,

                # vlan-protocol attribute ######################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VLAN_PROTOCOL: Attribute.decode_vlan_protocol_attribute,

                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VLAN_FLAGS: Attribute.decode_vlan_flags_attribute
            },
            "macvlan": {
                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_MACVLAN_MODE: Attribute.decode_four_bytes_attribute,
            },
            "vxlan": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_TTL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_TOS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_LEARNING: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_PROXY: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_RSC: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_L2MISS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_L3MISS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_UDP_CSUM: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_UDP_ZERO_CSUM6_TX: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_UDP_ZERO_CSUM6_RX: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_REMCSUM_TX: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_REMCSUM_RX: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_REPLICATION_TYPE: Attribute.decode_one_byte_attribute,

                # 2 bytes network byte order attributes ########################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_PORT: Attribute.decode_two_bytes_network_byte_order_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_ID: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_LINK: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_AGEING: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_LIMIT: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_PORT_RANGE: Attribute.decode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_GROUP: Attribute.decode_ipv4_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_LOCAL: Attribute.decode_ipv4_address_attribute,

                # ipv6 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_GROUP6: Attribute.decode_ipv6_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_LOCAL6: Attribute.decode_ipv6_address_attribute,
            },
            "vrf": {
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VRF_TABLE: Attribute.decode_four_bytes_attribute
            },
            "xfrm": {
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_XFRM_IF_ID: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_XFRM_LINK: Attribute.decode_four_bytes_attribute
            },

            # Tunnels:
            # There's is a lot of copy paste here because most of the tunnels
            # share the same attribute key / attribute index value, but ipv6
            # tunnels needs special handling for their ipv6 attributes.
            #
            # "gre", "gretap", "erspan", "ip6gre", "ip6gretap", "ip6erspan" are
            # identical as well with special handling for LOCAL and REMOTE for
            # the ipv6 tunnels
            "gre": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.decode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.decode_ipv4_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.decode_ipv4_address_attribute
            },
            "gretap": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.decode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.decode_ipv4_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.decode_ipv4_address_attribute
            },
            "erspan": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.decode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.decode_ipv4_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.decode_ipv4_address_attribute
            },
            "ip6gre": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.decode_four_bytes_attribute,

                # ipv6 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.decode_ipv6_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.decode_ipv6_address_attribute
            },
            "ip6gretap": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.decode_four_bytes_attribute,

                # ipv6 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.decode_ipv6_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.decode_ipv6_address_attribute
            },
            "ip6erspan": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.decode_four_bytes_attribute,

                # ipv6 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.decode_ipv6_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.decode_ipv6_address_attribute
            },

            # "ipip", "sit", "ip6tnl" are identical as well except for some
            # special ipv6 handling for LOCAL and REMOTE.
            "ipip": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_TTL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_TOS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_PMTUDISC: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_TYPE: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_SPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_DPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_FLAGS: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_LINK: Attribute.decode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_LOCAL: Attribute.decode_ipv4_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_REMOTE: Attribute.decode_ipv4_address_attribute,
            },
            "sit": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_TTL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_TOS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_PMTUDISC: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_TYPE: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_SPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_DPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_FLAGS: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_LINK: Attribute.decode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_LOCAL: Attribute.decode_ipv4_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_REMOTE: Attribute.decode_ipv4_address_attribute,
            },
            "ip6tnl": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_TTL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_TOS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_PMTUDISC: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_TYPE: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_SPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_DPORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_ENCAP_FLAGS: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_LINK: Attribute.decode_four_bytes_attribute,

                # ipv6 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_LOCAL: Attribute.decode_ipv6_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_IPTUN_REMOTE: Attribute.decode_ipv6_address_attribute,
            },

            # Same story with "vti", "vti6"...
            "vti": {
                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VTI_LINK: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VTI_IKEY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VTI_OKEY: Attribute.decode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VTI_LOCAL: Attribute.decode_ipv4_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VTI_REMOTE: Attribute.decode_ipv4_address_attribute
            },
            "vti6": {
                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VTI_LINK: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VTI_IKEY: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VTI_OKEY: Attribute.decode_four_bytes_attribute,

                # ipv6 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VTI_LOCAL: Attribute.decode_ipv6_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VTI_REMOTE: Attribute.decode_ipv6_address_attribute
            },
            # wireguard is different and does not have IFLA. Keep empty record to not break global logic
            "wireguard": {
            }
        },
        NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_INFO_SLAVE_DATA: {
            "bridge": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_STATE: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_MODE: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_GUARD: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_PROTECT: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_FAST_LEAVE: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_LEARNING: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_UNICAST_FLOOD: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_PROXYARP: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_LEARNING_SYNC: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_PROXYARP_WIFI: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_TOPOLOGY_CHANGE_ACK: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_CONFIG_PENDING: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_MULTICAST_ROUTER: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_MCAST_FLOOD: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_BCAST_FLOOD: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_MCAST_TO_UCAST: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_VLAN_TUNNEL: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_PEER_LINK: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_DUAL_LINK: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_NEIGH_SUPPRESS: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_PRIORITY: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_DESIGNATED_PORT: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_DESIGNATED_COST: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_ID: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_NO: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_GROUP_FWD_MASK: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_GROUP_FWD_MASKHI: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_COST: Attribute.decode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_BACKUP_PORT: Attribute.decode_four_bytes_attribute,
            },
            "bond": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_SLAVE_STATE: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_SLAVE_MII_STATUS: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE: Attribute.decode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_SLAVE_AD_RX_BYPASS: Attribute.decode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_SLAVE_QUEUE_ID: Attribute.decode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_SLAVE_AD_AGGREGATOR_ID: Attribute.decode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_SLAVE_PERM_HWADDR: Attribute.decode_mac_address_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_SLAVE_LINK_FAILURE_COUNT: Attribute.decode_four_bytes_attribute,
            }
        }
    }

    encode_ifla_info_nested_data_handlers = {
        NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_INFO_DATA: {
            "vlan": {
                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VLAN_ID: Attribute.encode_two_bytes_attribute,

                # vlan-protocol attribute ######################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VLAN_PROTOCOL: Attribute.encode_vlan_protocol_attribute,

                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VLAN_FLAGS: Attribute.encode_vlan_flags_attribute,
            },
            "macvlan": {
                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_MACVLAN_MODE: Attribute.encode_four_bytes_attribute,
            },
            "vxlan": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_TTL: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_TOS: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_LEARNING: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_PROXY: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_RSC: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_L2MISS: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_L3MISS: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_UDP_CSUM: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_UDP_ZERO_CSUM6_TX: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_UDP_ZERO_CSUM6_RX: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_REMCSUM_TX: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_REMCSUM_RX: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_REPLICATION_TYPE: Attribute.encode_one_byte_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_ID: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_LINK: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_AGEING: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_LIMIT: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_PORT_RANGE: Attribute.encode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_GROUP: Attribute.encode_ipv4_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_LOCAL: Attribute.encode_ipv4_attribute,

                # ipv6 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_GROUP6: Attribute.encode_ipv6_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_LOCAL6: Attribute.encode_ipv6_attribute,

                # vxlan-port attribute #########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VXLAN_PORT: Attribute.encode_vxlan_port_attribute,
            },
            "bond": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_NUM_PEER_NOTIF: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_USE_CARRIER: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_AD_LACP_BYPASS: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_AD_LACP_RATE: Attribute.encode_one_byte_attribute,

                # bond-mode attribute ##########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_MODE: Attribute.encode_bond_mode_attribute,

                # bond-xmit-hash-policy attribute ##############################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_XMIT_HASH_POLICY: Attribute.encode_bond_xmit_hash_policy_attribute,

		# bond-primary-reselect attribute ##############################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_PRIMARY_RESELECT: Attribute.encode_bond_primary_reselect_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_AD_ACTOR_SYS_PRIO: Attribute.encode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_MIIMON: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_UPDELAY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_DOWNDELAY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_MIN_LINKS: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_PRIMARY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_ARP_INTERVAL: Attribute.encode_four_bytes_attribute,

                # mac address attribute ########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_AD_ACTOR_SYSTEM: Attribute.encode_mac_address_attribute,

                # arp ip target attribute #######################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BOND_ARP_IP_TARGET: Attribute.encode_bond_ad_arp_ip_target
            },
            "vrf": {
                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_VRF_TABLE: Attribute.encode_four_bytes_attribute
            },
            "bridge": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_VLAN_FILTERING: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_TOPOLOGY_CHANGE: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_TOPOLOGY_CHANGE_DETECTED: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_ROUTER: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_SNOOPING: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_QUERY_USE_IFADDR: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_QUERIER: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_NF_CALL_IPTABLES: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_NF_CALL_IP6TABLES: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_NF_CALL_ARPTABLES: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_VLAN_STATS_ENABLED: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_STATS_ENABLED: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_IGMP_VERSION: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_MLD_VERSION: Attribute.encode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_PRIORITY: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_GROUP_FWD_MASK: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_ROOT_PORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_VLAN_DEFAULT_PVID: Attribute.encode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_FORWARD_DELAY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_HELLO_TIME: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MAX_AGE: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_AGEING_TIME: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_STP_STATE: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_ROOT_PATH_COST: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_HASH_ELASTICITY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_HASH_MAX: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_LAST_MEMBER_CNT: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_STARTUP_QUERY_CNT: Attribute.encode_four_bytes_attribute,

                # 8 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_LAST_MEMBER_INTVL: Attribute.encode_eight_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_MEMBERSHIP_INTVL: Attribute.encode_eight_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_QUERIER_INTVL: Attribute.encode_eight_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_QUERY_INTVL: Attribute.encode_eight_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL: Attribute.encode_eight_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_MCAST_STARTUP_QUERY_INTVL: Attribute.encode_eight_bytes_attribute,

                # vlan-protocol attribute ######################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BR_VLAN_PROTOCOL: Attribute.encode_vlan_protocol_attribute
            },
            # Tunnels:
            # There's is a lot of copy paste here because most of the tunnels
            # share the same attribute key / attribute index value, but ipv6
            # tunnels needs special handling for their ipv6 attributes.
            #
            # "gre", "gretap", "erspan", "ip6gre", "ip6gretap", "ip6erspan" are
            # identical as well with special handling for LOCAL and REMOTE for
            # the ipv6 tunnels
            "gre": {  # == ("gre", "gretap", "erspan")
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.encode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.encode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.encode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.encode_ipv4_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.encode_ipv4_attribute,
            },
            "gretap": {  # == ("gre", "gretap", "erspan")
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.encode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.encode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.encode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.encode_ipv4_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.encode_ipv4_attribute,
            },
            "erspan": {  # == ("gre", "gretap", "erspan")
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.encode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.encode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.encode_four_bytes_attribute,

                # ipv4 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.encode_ipv4_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.encode_ipv4_attribute,
            },
            "ip6gre": {  # == ("ip6gre", "ip6gretap", "ip6erspan")
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.encode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.encode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.encode_four_bytes_attribute,

                # ipv6 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.encode_ipv6_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.encode_ipv6_attribute,
            },
            "ip6gretap": {  # == ("ip6gre", "ip6gretap", "ip6erspan")
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.encode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.encode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.encode_four_bytes_attribute,

                # ipv6 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.encode_ipv6_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.encode_ipv6_attribute,
            },
            "ip6erspan": {  # == ("ip6gre", "ip6gretap", "ip6erspan")
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TTL: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_TOS: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_PMTUDISC: Attribute.encode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OFLAGS: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_TYPE: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_SPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_DPORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_ENCAP_FLAGS: Attribute.encode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LINK: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_IKEY: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_OKEY: Attribute.encode_four_bytes_attribute,

                # ipv6 attributes ##############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_LOCAL: Attribute.encode_ipv6_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_GRE_REMOTE: Attribute.encode_ipv6_attribute,
            }
            # wireguard is different and does not have IFLA. Keep empty record to not break global logic
            "wireguard": {
            }
        },
        NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_INFO_SLAVE_DATA: {
            "bridge": {
                # 1 byte attributes ############################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_STATE: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_MODE: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_GUARD: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_PROTECT: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_FAST_LEAVE: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_LEARNING: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_UNICAST_FLOOD: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_PROXYARP: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_LEARNING_SYNC: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_PROXYARP_WIFI: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_TOPOLOGY_CHANGE_ACK: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_CONFIG_PENDING: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_MULTICAST_ROUTER: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_MCAST_FLOOD: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_MCAST_TO_UCAST: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_VLAN_TUNNEL: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_BCAST_FLOOD: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_PEER_LINK: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_DUAL_LINK: Attribute.encode_one_byte_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_NEIGH_SUPPRESS: Attribute.encode_one_byte_attribute,

                # 2 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_PRIORITY: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_DESIGNATED_PORT: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_DESIGNATED_COST: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_ID: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_NO: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_GROUP_FWD_MASK: Attribute.encode_two_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_GROUP_FWD_MASKHI: Attribute.encode_two_bytes_attribute,

                # 4 bytes attributes ###########################################
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_COST: Attribute.encode_four_bytes_attribute,
                NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_BRPORT_BACKUP_PORT: Attribute.encode_four_bytes_attribute,
            },
        }
    }

    ifla_info_nested_data_attributes_to_string_dict = {
        NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_INFO_DATA: {
            "bond": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_bond_to_string,
            "vlan": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_vlan_to_string,
            "vxlan": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_vxlan_to_string,
            "bridge": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_br_to_string,
            "macvlan": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_macvlan_to_string,
            "vrf": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_vrf_to_string,
            "gre": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_gre_to_string,
            "gretap": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_gre_to_string,
            "erspan": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_gre_to_string,
            "ip6gre": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_gre_to_string,
            "ip6gretap": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_gre_to_string,
            "ip6erspan": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_gre_to_string,
            "vti": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_vti_to_string,
            "vti6": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_vti_to_string,
            "ipip": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_iptun_to_string,
            "sit": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_iptun_to_string,
            "ip6tnl": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_iptun_to_string,
            "xfrm": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_xfrm_to_string,
            "wireguard": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_wireguard_to_string
        },
        NetlinkPacket_IFLA_LINKINFO_Attributes.IFLA_INFO_SLAVE_DATA: {
            "bridge": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_brport_to_string,
            "bond": NetlinkPacket_IFLA_LINKINFO_Attributes.ifla_bond_slave_to_string
        }
    }

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)

    def encode_ifla_info_nested_data(self, sub_attr_pack_layout, sub_attr_type, sub_attr_type_string, sub_attr_value, encode_handlers, ifla_info_nested_attr_to_str_dict, kind):
        sub_attr_payload = [0, sub_attr_type | NLA_F_NESTED]

        if not encode_handlers:
            self.log.log(
                SYSLOG_EXTRA_DEBUG,
                "Add support for encoding %s for %s link kind" % (sub_attr_type_string, kind)
            )
        else:
            for (info_data_type, info_data_value) in sub_attr_value.items():
                encode_handler = encode_handlers.get(info_data_type)

                if encode_handler:
                    encode_handler(sub_attr_pack_layout, sub_attr_payload, info_data_type, info_data_value)
                else:
                    self.log.log(
                        SYSLOG_EXTRA_DEBUG,
                        "Add support for encoding %s %s sub-attribute %s (%d)"
                        % (
                            sub_attr_type_string,
                            kind,
                            ifla_info_nested_attr_to_str_dict.get(info_data_type),
                            info_data_type
                        )
                    )

        return sub_attr_payload

    def encode(self):
        pack_layout = [self.HEADER_PACK]
        payload = [0, self.atype | NLA_F_NESTED]
        attr_length_index = 0

        kind        = self.value.get(Link.IFLA_INFO_KIND)
        slave_kind  = self.value.get(Link.IFLA_INFO_SLAVE_KIND)

        if not slave_kind and kind not in (
            "vrf",
            "vlan",
            "vxlan",
            "bond",
            "dummy",
            "bridge",
            "macvlan",
            "gre",
            "gretap",
            "erspan",
            "ip6gre",
            "ip6gretap",
            "ip6erspan",
            "vti",
            "vti6",
            "ipip",
            "sit",
            "ip6tnl",
            "ip6ip6",
            "ipip6",
            "xfrm",
            "openvswitch",
            "wireguard"

        ):
            self.log.debug('Unsupported IFLA_INFO_KIND %s' % kind)
            return

        elif not kind and slave_kind != 'bridge':
            # only support brport for now.
            raise Exception('Unsupported IFLA_INFO_SLAVE_KIND %s' % slave_kind)

        # For now this assumes that all data will be packed in the native endian
        # order (=). If a field is added that needs to be packed via network
        # order (>) then some smarts will need to be added to split the pack_layout
        # string at the >, split the payload and make the needed pack() calls.
        # Until we cross that bridge though we will keep things nice and simple and
        # pack everything via a single pack() call.

        for (sub_attr_type, sub_attr_value) in self.value.items():
            sub_attr_pack_layout = ['=', 'HH']
            sub_attr_payload = [0, sub_attr_type]
            sub_attr_length_index = 0

            if sub_attr_type in (Link.IFLA_INFO_KIND, Link.IFLA_INFO_SLAVE_KIND):
                sub_attr_pack_layout.append('%ds' % len(sub_attr_value))
                sub_attr_payload.append(sub_attr_value.encode("utf-8"))

            elif sub_attr_type == Link.IFLA_INFO_DATA:
                sub_attr_payload = self.encode_ifla_info_nested_data(
                    sub_attr_pack_layout,
                    sub_attr_type,
                    "IFLA_INFO_DATA",
                    sub_attr_value,
                    self.encode_ifla_info_nested_data_handlers.get(Link.IFLA_INFO_DATA, {}).get(kind),
                    self.ifla_info_nested_data_attributes_to_string_dict.get(Link.IFLA_INFO_DATA, {}).get(kind),
                    kind
                )

            elif sub_attr_type == Link.IFLA_INFO_SLAVE_DATA:
                sub_attr_payload = self.encode_ifla_info_nested_data(
                    sub_attr_pack_layout,
                    sub_attr_type,
                    "IFLA_INFO_SLAVE_DATA",
                    sub_attr_value,
                    self.encode_ifla_info_nested_data_handlers.get(Link.IFLA_INFO_SLAVE_DATA, {}).get(slave_kind),
                    self.ifla_info_nested_data_attributes_to_string_dict.get(Link.IFLA_INFO_SLAVE_DATA, {}).get(slave_kind),
                    slave_kind
                )

            else:
                self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_LINKINFO sub-attribute type %d' % sub_attr_type)
                continue

            sub_attr_length = calcsize(''.join(sub_attr_pack_layout))
            sub_attr_payload[sub_attr_length_index] = sub_attr_length

            # add padding
            sub_attr_pack_layout[-1] = "%s%s" % (sub_attr_pack_layout[-1], "x" * self.pad_bytes_needed(sub_attr_length))

            # The [1:] is to remove the leading = so that when we do the ''.join() later
            # we do not end up with an = in the middle of the pack layout string. There
            # will be an = at the beginning via self.HEADER_PACK
            sub_attr_pack_layout = sub_attr_pack_layout[1:]

            # Now extend the ovarall attribute pack_layout/payload to include this sub-attribute
            pack_layout.extend(sub_attr_pack_layout)
            payload.extend(sub_attr_payload)

        pack_layout = ''.join(pack_layout)

        # Fill in the length field
        length = calcsize(pack_layout)
        payload[attr_length_index] = length

        raw = pack(pack_layout, *payload)
        raw = self.pad(length, raw)
        return raw

    def get_bool_value(self, value, default=None):
        try:
            return value_to_bool_dict[value]
        except KeyError:
            self.log.debug('%s: unsupported boolean value' % value)
            return default

    def get_index(self, tbl, attr, value, default=None):
        try:
            return tbl[value]
        except KeyError:
            self.log.debug('unsupported %s value %s (%s)' % (attr, value, tbl.keys()))
            return default

    def decode_ifla_info_nested_data(self, kind, ifla_info_nested_kind_str, sub_attr_type, sub_attr_type_str, data, sub_attr_end):
        sub_attr_data = data[4:sub_attr_end]
        ifla_info_nested_data = {}

        if not kind:
            self.log.warning("%s is not known...we cannot parse %s" % (ifla_info_nested_kind_str, sub_attr_type_str))
        else:
            ifla_info_nested_data_handlers = self.decode_ifla_info_nested_data_handlers.get(sub_attr_type, {}).get(kind)
            ifla_info_nested_attr_to_str_dict = self.ifla_info_nested_data_attributes_to_string_dict.get(sub_attr_type, {}).get(kind)

            if not ifla_info_nested_data_handlers or not ifla_info_nested_attr_to_str_dict:
                self.log.log(
                    SYSLOG_EXTRA_DEBUG,
                    "%s: decode: unsupported %s %s"
                    % (sub_attr_type_str, ifla_info_nested_kind_str, kind)
                )
            else:
                while sub_attr_data:
                    (info_nested_data_length, info_nested_data_type) = unpack("=HH", sub_attr_data[:4])
                    info_nested_data_end = padded_length(info_nested_data_length)
                    handler = ifla_info_nested_data_handlers.get(info_nested_data_type)
                    try:
                        if handler:
                            ifla_info_nested_data[info_nested_data_type] = handler(sub_attr_data, info_nested_data_end)
                        else:
                            self.log.log(
                                SYSLOG_EXTRA_DEBUG,
                                "Add support for decoding %s %s, attribute %s (%s)"
                                % (
                                    ifla_info_nested_kind_str,
                                    kind,
                                    ifla_info_nested_attr_to_str_dict.get(info_nested_data_type, "UNKNOWN"),
                                    info_nested_data_type
                                )
                            )
                    except Exception as e:
                        self.log.warning(
                            "%s: %s: attribute %s: %s (%s)"
                            % (
                                ifla_info_nested_kind_str,
                                kind,
                                ifla_info_nested_attr_to_str_dict.get(info_nested_data_type, "UNKNOWN"),
                                info_nested_data_type,
                                str(e)
                            )
                        )

                    sub_attr_data = sub_attr_data[info_nested_data_end:]

        return ifla_info_nested_data

    def decode(self, parent_msg, data):
        """
        value is a dictionary such as:

        {
            Link.IFLA_INFO_KIND : 'vlan',
            Link.IFLA_INFO_DATA : {
                Link.IFLA_VLAN_ID : vlanid,
            }
        }
        """
        self.decode_length_type(data)
        self.value = {}

        data = self.data[4:]

        # IFLA_MACVLAN_MODE and IFLA_VLAN_ID both have a value of 1 and both are
        # valid IFLA_INFO_DATA entries :( The sender must TX IFLA_INFO_KIND
        # first in order for us to know if "1" is IFLA_MACVLAN_MODE vs IFLA_VLAN_ID.

        while data:
            (sub_attr_length, sub_attr_type) = unpack('=HH', data[:4])
            sub_attr_end = padded_length(sub_attr_length)

            if sub_attr_type & NLA_F_NESTED:
                sub_attr_type ^= NLA_F_NESTED

            if not sub_attr_length:
                self.log.error('parsed a zero length sub-attr')
                return

            if sub_attr_type in (Link.IFLA_INFO_KIND, Link.IFLA_INFO_SLAVE_KIND):
                self.value[sub_attr_type] = remove_trailing_null(unpack("%ds" % (sub_attr_length - 4), data[4:sub_attr_length])[0]).decode("utf-8")

            elif sub_attr_type == Link.IFLA_INFO_DATA:
                self.value[Link.IFLA_INFO_DATA] = self.decode_ifla_info_nested_data(
                    self.value.get(Link.IFLA_INFO_KIND), "IFLA_INFO_KIND",
                    Link.IFLA_INFO_DATA, "IFLA_INFO_DATA",
                    data, sub_attr_end,
                )

            elif sub_attr_type == Link.IFLA_INFO_SLAVE_DATA:
                self.value[Link.IFLA_INFO_SLAVE_DATA] = self.decode_ifla_info_nested_data(
                    self.value.get(Link.IFLA_INFO_SLAVE_KIND), "IFLA_INFO_SLAVE_KIND",
                    Link.IFLA_INFO_SLAVE_DATA, "IFLA_INFO_SLAVE_DATA",
                    data, sub_attr_end,
                )

            else:
                self.log.log(
                    SYSLOG_EXTRA_DEBUG,
                    'Add support for decoding IFLA_LINKINFO sub-attribute type %s (%d), length %d, padded to %d'
                    % (parent_msg.get_ifla_info_string(sub_attr_type), sub_attr_type, sub_attr_length, sub_attr_end)
                )

            data = data[sub_attr_end:]

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        extra = ''

        next_sub_attr_line = 0
        sub_attr_line = True

        for x in range(1, self.attr_end//4):
            start = x * 4
            end = start + 4

            if line_number == next_sub_attr_line:
                sub_attr_line = True

            if sub_attr_line:
                sub_attr_line = False

                (sub_attr_length, sub_attr_type) = unpack('=HH', self.data[start:start+4])
                sub_attr_end = padded_length(sub_attr_length)

                next_sub_attr_line = line_number + (sub_attr_end//4)

                if sub_attr_end == sub_attr_length:
                    padded_to = ', '
                else:
                    padded_to = ' padded to %d, ' % sub_attr_end

                if sub_attr_type & NLA_F_NESTED:
                    sub_attr_type ^= NLA_F_NESTED

                extra = 'Nested Attribute - Length %s (%d)%s Type %s (%d) %s (%s)' % \
                        (zfilled_hex(sub_attr_length, 4), sub_attr_length,
                         padded_to,
                         zfilled_hex(sub_attr_type, 4), sub_attr_type,
                         Link.ifla_info_to_string.get(sub_attr_type), sub_attr_type)
            else:
                extra = ''

            dump_buffer.append(data_to_color_text(line_number, color, self.data[start:end], extra))
            line_number += 1

        return line_number

    def get_pretty_value(self, obj=None):

        if obj and callable(obj):
            return obj(self.value)

        value_pretty            = self.value
        ifla_info_kind          = self.value.get(Link.IFLA_INFO_KIND)
        ifla_info_slave_kind    = self.value.get(Link.IFLA_INFO_SLAVE_KIND)

        kind_dict = {
            Link.IFLA_INFO_DATA: self.ifla_info_nested_data_attributes_to_string_dict.get(Link.IFLA_INFO_DATA, {}).get(ifla_info_kind),
            Link.IFLA_INFO_SLAVE_DATA: self.ifla_info_nested_data_attributes_to_string_dict.get(Link.IFLA_INFO_SLAVE_DATA, {}).get(ifla_info_slave_kind)
        }
        if ifla_info_kind or ifla_info_slave_kind:
            value_pretty = {}

            for (sub_key, sub_value) in self.value.items():
                sub_key_pretty = "(%2d) %s" % (sub_key, Link.ifla_info_to_string.get(sub_key, 'UNKNOWN'))
                sub_value_pretty = sub_value

                if sub_key in (Link.IFLA_INFO_DATA, Link.IFLA_INFO_SLAVE_DATA):
                    kind_to_string_dict = kind_dict.get(sub_key, {})
                    sub_value_pretty = {}

                    for (sub_sub_key, sub_sub_value) in sub_value.items():
                        sub_sub_key_pretty = "(%2d) %s" % (sub_sub_key, kind_to_string_dict.get(sub_sub_key, 'UNKNOWN'))
                        sub_value_pretty[sub_sub_key_pretty] = sub_sub_value

                value_pretty[sub_key_pretty] = sub_value_pretty

        return value_pretty


class AttributeIFLA_PROTINFO(Attribute):
    """
    IFLA_PROTINFO nested attributes.
    """
    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.family = family

    def encode(self):
        pack_layout = [self.HEADER_PACK]
        payload = [0, self.atype | NLA_F_NESTED]
        attr_length_index = 0

        if self.family not in (AF_BRIDGE,):
            raise Exception('Unsupported IFLA_PROTINFO family %d' % self.family)

        # For now this assumes that all data will be packed in the native endian
        # order (=). If a field is added that needs to be packed via network
        # order (>) then some smarts will need to be added to split the pack_layout
        # string at the >, split the payload and make the needed pack() calls.
        #
        # Until we cross that bridge though we will keep things nice and simple and
        # pack everything via a single pack() call.
        for (sub_attr_type, sub_attr_value) in self.value.items():
            sub_attr_pack_layout = ['=', 'HH']
            sub_attr_payload = [0, sub_attr_type]
            sub_attr_length_index = 0

            if self.family == AF_BRIDGE:
                # 1 Byte attributes
                if sub_attr_type in (Link.IFLA_BRPORT_STATE,
                                     Link.IFLA_BRPORT_MODE,
                                     Link.IFLA_BRPORT_GUARD,
                                     Link.IFLA_BRPORT_PROTECT,
                                     Link.IFLA_BRPORT_FAST_LEAVE,
                                     Link.IFLA_BRPORT_LEARNING,
                                     Link.IFLA_BRPORT_UNICAST_FLOOD,
                                     Link.IFLA_BRPORT_PROXYARP,
                                     Link.IFLA_BRPORT_LEARNING_SYNC,
                                     Link.IFLA_BRPORT_PROXYARP_WIFI,
                                     Link.IFLA_BRPORT_TOPOLOGY_CHANGE_ACK,
                                     Link.IFLA_BRPORT_CONFIG_PENDING,
                                     Link.IFLA_BRPORT_FLUSH,
                                     Link.IFLA_BRPORT_MULTICAST_ROUTER,
                                     Link.IFLA_BRPORT_PEER_LINK,
                                     Link.IFLA_BRPORT_DUAL_LINK,
                                     Link.IFLA_BRPORT_NEIGH_SUPPRESS):
                    sub_attr_pack_layout.append('B')
                    sub_attr_payload.append(sub_attr_value)

                # 2 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_PRIORITY,
                                       Link.IFLA_BRPORT_DESIGNATED_PORT,
                                       Link.IFLA_BRPORT_DESIGNATED_COST,
                                       Link.IFLA_BRPORT_ID,
                                       Link.IFLA_BRPORT_NO):
                    sub_attr_pack_layout.append('H')
                    sub_attr_payload.append(sub_attr_value)

                # 4 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_COST, Link.IFLA_BRPORT_BACKUP_PORT):
                    sub_attr_pack_layout.append('L')
                    sub_attr_payload.append(sub_attr_value)

                # 8 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_MESSAGE_AGE_TIMER,
                                       Link.IFLA_BRPORT_FORWARD_DELAY_TIMER,
                                       Link.IFLA_BRPORT_HOLD_TIMER):
                    sub_attr_pack_layout.append('Q')
                    sub_attr_payload.append(sub_attr_value)

                else:
                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_PROTINFO sub-attribute type %d' % sub_attr_type)

            sub_attr_length = calcsize(''.join(sub_attr_pack_layout))
            sub_attr_payload[sub_attr_length_index] = sub_attr_length

            # add padding
            sub_attr_pack_layout[-1] = "%s%s" % (sub_attr_pack_layout[-1], "x" * self.pad_bytes_needed(sub_attr_length))

            # The [1:] is to remove the leading = so that when we do the ''.join() later
            # we do not end up with an = in the middle of the pack layout string. There
            # will be an = at the beginning via self.HEADER_PACK
            sub_attr_pack_layout = sub_attr_pack_layout[1:]

            # Now extend the ovarall attribute pack_layout/payload to include this sub-attribute
            pack_layout.extend(sub_attr_pack_layout)
            payload.extend(sub_attr_payload)

        pack_layout = ''.join(pack_layout)

        # Fill in the length field
        length = calcsize(pack_layout)
        payload[attr_length_index] = length

        raw = pack(pack_layout, *payload)
        raw = self.pad(length, raw)
        return raw

    def decode(self, parent_msg, data):
        """
        value is a dictionary such as:
        {
            Link.IFLA_BRPORT_STATE : 3,
            Link.IFLA_BRPORT_PRIORITY : 8
            Link.IFLA_BRPORT_COST : 2
            ...
        }
        """
        self.decode_length_type(data)
        self.value = {}

        data = self.data[4:]

        while data:
            (sub_attr_length, sub_attr_type) = unpack('=HH', data[:4])
            sub_attr_end = padded_length(sub_attr_length)

            if not sub_attr_length:
                self.log.error('parsed a zero length sub-attr')
                return

            if self.family == AF_BRIDGE:

                # 1 Byte attributes
                if sub_attr_type in (Link.IFLA_BRPORT_STATE,
                                     Link.IFLA_BRPORT_MODE,
                                     Link.IFLA_BRPORT_GUARD,
                                     Link.IFLA_BRPORT_PROTECT,
                                     Link.IFLA_BRPORT_FAST_LEAVE,
                                     Link.IFLA_BRPORT_LEARNING,
                                     Link.IFLA_BRPORT_UNICAST_FLOOD,
                                     Link.IFLA_BRPORT_PROXYARP,
                                     Link.IFLA_BRPORT_LEARNING_SYNC,
                                     Link.IFLA_BRPORT_PROXYARP_WIFI,
                                     Link.IFLA_BRPORT_TOPOLOGY_CHANGE_ACK,
                                     Link.IFLA_BRPORT_CONFIG_PENDING,
                                     Link.IFLA_BRPORT_FLUSH,
                                     Link.IFLA_BRPORT_MULTICAST_ROUTER,
                                     Link.IFLA_BRPORT_PEER_LINK,
                                     Link.IFLA_BRPORT_DUAL_LINK,
                                     Link.IFLA_BRPORT_NEIGH_SUPPRESS):
                    self.value[sub_attr_type] = self.decode_one_byte_attribute(data)

                # 2 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_PRIORITY,
                                       Link.IFLA_BRPORT_DESIGNATED_PORT,
                                       Link.IFLA_BRPORT_DESIGNATED_COST,
                                       Link.IFLA_BRPORT_ID,
                                       Link.IFLA_BRPORT_NO):
                    self.value[sub_attr_type] = unpack('=H', data[4:6])[0]

                # 4 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_COST, Link.IFLA_BRPORT_BACKUP_PORT):
                    self.value[sub_attr_type] = unpack('=L', data[4:8])[0]

                # 8 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_MESSAGE_AGE_TIMER,
                                       Link.IFLA_BRPORT_FORWARD_DELAY_TIMER,
                                       Link.IFLA_BRPORT_HOLD_TIMER):
                    self.value[sub_attr_type] = unpack('=Q', data[4:12])[0]

                else:
                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_PROTINFO sub-attribute type %s (%d), length %d, padded to %d' %
                                (parent_msg.get_ifla_brport_string(sub_attr_type), sub_attr_type, sub_attr_length, sub_attr_end))

            data = data[sub_attr_end:]

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        extra = ''

        next_sub_attr_line = 0
        sub_attr_line = True

        for x in range(1, self.attr_end//4):
            start = x * 4
            end = start + 4

            if line_number == next_sub_attr_line:
                sub_attr_line = True

            if sub_attr_line:
                sub_attr_line = False

                (sub_attr_length, sub_attr_type) = unpack('=HH', self.data[start:start+4])
                sub_attr_end = padded_length(sub_attr_length)

                next_sub_attr_line = line_number + (sub_attr_end//4)

                if sub_attr_end == sub_attr_length:
                    padded_to = ', '
                else:
                    padded_to = ' padded to %d, ' % sub_attr_end

                extra = 'Nested Attribute - Length %s (%d)%s Type %s (%d) %s' % \
                        (zfilled_hex(sub_attr_length, 4), sub_attr_length,
                         padded_to,
                         zfilled_hex(sub_attr_type, 4), sub_attr_type,
                         Link.ifla_brport_to_string.get(sub_attr_type))
            else:
                extra = ''

            dump_buffer.append(data_to_color_text(line_number, color, self.data[start:end], extra))
            line_number += 1

        return line_number

    def get_pretty_value(self, obj=None):

        if obj and callable(obj):
            return obj(self.value)

        value_pretty = {}

        for (sub_key, sub_value) in self.value.items():
            sub_key_pretty = "(%2d) %s" % (sub_key, Link.ifla_brport_to_string.get(sub_key, 'UNKNOWN'))
            sub_value_pretty = sub_value
            value_pretty[sub_key_pretty] = sub_value_pretty

        return value_pretty



class NetlinkPacket(object):
    """
    Netlink Header

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Length                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Type              |           Flags              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Process ID (PID)                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    header_PACK = 'IHHII'
    header_LEN  = calcsize(header_PACK)

    # Netlink packet types
    # /usr/include/linux/rtnetlink.h
    type_to_string = {
        NLMSG_NOOP    : 'NLMSG_NOOP',
        NLMSG_ERROR   : 'NLMSG_ERROR',
        NLMSG_DONE    : 'NLMSG_DONE',
        NLMSG_OVERRUN : 'NLMSG_OVERRUN',
        RTM_NEWLINK   : 'RTM_NEWLINK',
        RTM_DELLINK   : 'RTM_DELLINK',
        RTM_GETLINK   : 'RTM_GETLINK',
        RTM_SETLINK   : 'RTM_SETLINK',
        RTM_NEWADDR   : 'RTM_NEWADDR',
        RTM_DELADDR   : 'RTM_DELADDR',
        RTM_GETADDR   : 'RTM_GETADDR',
        RTM_NEWNEIGH  : 'RTM_NEWNEIGH',
        RTM_DELNEIGH  : 'RTM_DELNEIGH',
        RTM_GETNEIGH  : 'RTM_GETNEIGH',
        RTM_NEWROUTE  : 'RTM_NEWROUTE',
        RTM_DELROUTE  : 'RTM_DELROUTE',
        RTM_GETROUTE  : 'RTM_GETROUTE',
        RTM_NEWQDISC  : 'RTM_NEWQDISC',
        RTM_DELQDISC  : 'RTM_DELQDISC',
        RTM_GETQDISC  : 'RTM_GETQDISC',
        RTM_NEWNETCONF: 'RTM_NEWNETCONF',
        RTM_GETNETCONF: 'RTM_GETNETCONF',
        RTM_DELNETCONF: 'RTM_DELNETCONF',
        RTM_NEWMDB    : 'RTM_NEWMDB',
        RTM_DELMDB    : 'RTM_DELMDB',
        RTM_GETMDB    : 'RTM_GETMDB'
    }

    af_family_to_string = {
        AF_INET     : 'inet',
        AF_INET6    : 'inet6'
    }

    def __init__(self, msgtype, debug, owner_logger=None, use_color=True, rx=False, tx=False):
        self.msgtype     = msgtype
        self.attributes  = {}
        self.dump_buffer = ['']
        self.line_number = 1
        self.debug       = debug
        self.message     = None
        self.use_color   = use_color
        self.family      = None
        self.rx          = rx
        self.tx          = tx
        self.priv_flags  = 0

        if owner_logger:
            self.log = owner_logger
        else:
            self.log = log

    def __str__(self):
        return self.get_type_string()

    def get_string(self, to_string, index):
        """
        Used to do lookups in all of the various FOO_to_string dictionaries
        but returns 'UNKNOWN' if the key is bogus
        """
        if index in to_string:
            return to_string[index]
        return 'UNKNOWN'

    def get_type_string(self, msgtype=None):
        if not msgtype:
            msgtype = self.msgtype
        return self.get_string(self.type_to_string, msgtype)

    def get_flags_string(self):
        foo = []

        for (flag, flag_string) in self.flag_to_string.items():
            if self.flags & flag:
                foo.append(flag_string)

        return ', '.join(foo)

    def decode_packet(self, length, flags, seq, pid, data):
        self.length      = length
        self.flags       = flags
        self.seq         = seq
        self.pid         = pid
        self.header_data = data[0:self.header_LEN]
        self.msg_data    = data[self.header_LEN:length]

        self.decode_netlink_header()
        self.decode_service_header()

        # NLMSG_ERROR is special case, it does not have attributes to decode
        if self.msgtype != NLMSG_ERROR:
            self.decode_attributes()

    def get_netlink_header_flags_string(self, msg_type, flags):
        foo = []

        if flags & NLM_F_REQUEST:
            foo.append('NLM_F_REQUEST')

        if flags & NLM_F_MULTI:
            foo.append('NLM_F_MULTI')

        if flags & NLM_F_ACK:
            foo.append('NLM_F_ACK')

        if flags & NLM_F_ECHO:
            foo.append('NLM_F_ECHO')

        # Modifiers to GET query
        if msg_type in (RTM_GETLINK, RTM_GETADDR, RTM_GETNEIGH, RTM_GETROUTE, RTM_GETQDISC, RTM_GETNETCONF, RTM_GETMDB):
            if flags & NLM_F_DUMP:
                foo.append('NLM_F_DUMP')
            else:
                if flags & NLM_F_MATCH:
                    foo.append('NLM_F_MATCH')

                if flags & NLM_F_ROOT:
                    foo.append('NLM_F_ROOT')

            if flags & NLM_F_ATOMIC:
                foo.append('NLM_F_ATOMIC')

        # Modifiers to NEW query
        elif msg_type in (RTM_NEWLINK, RTM_NEWADDR, RTM_NEWNEIGH, RTM_NEWROUTE, RTM_NEWQDISC, RTM_NEWMDB):
            if flags & NLM_F_REPLACE:
                foo.append('NLM_F_REPLACE')

            if flags & NLM_F_EXCL:
                foo.append('NLM_F_EXCL')

            if flags & NLM_F_CREATE:
                foo.append('NLM_F_CREATE')

            if flags & NLM_F_APPEND:
                foo.append('NLM_F_APPEND')

        return ', '.join(foo)

    # When we first RXed the netlink message we had to decode the header to
    # determine what type of netlink message we were dealing with.  So the
    # header has actually already been decoded...what we do here is
    # populate the dump_buffer lines with the header content.
    def decode_netlink_header(self):

        if not self.debug:
            return

        header_data = self.header_data

        # Print the netlink header in red
        netlink_header_length = 16
        color = red if self.use_color else None
        color_start = "\033[%dm" % color if color else ""
        color_end = "\033[0m" if color else ""
        self.dump_buffer.append("  %sNetlink Header%s" % (color_start, color_end))

        for x in range(0, netlink_header_length // 4):
            start = x * 4
            end = start + 4

            if self.line_number == 1:
                data = unpack('=L', header_data[start:end])[0]
                extra = "Length %s (%d)" % (zfilled_hex(data, 8), data)

            elif self.line_number == 2:
                (data1, data2) = unpack('HH', header_data[start:end])
                extra = "Type %s (%d - %s), Flags %s (%s)" % \
                    (zfilled_hex(data1, 4), data1, self.get_type_string(data1),
                     zfilled_hex(data2, 4), self.get_netlink_header_flags_string(data1, data2))

            elif self.line_number == 3:
                data = unpack('=L', header_data[start:end])[0]
                extra = "Sequence Number %s (%d)" % (zfilled_hex(data, 8), data)

            elif self.line_number == 4:
                data = unpack('=L', header_data[start:end])[0]
                extra = "Process ID %s (%d)" % (zfilled_hex(data, 8), data)
            else:
                extra = "Unexpected line number %d" % self.line_number

            self.dump_buffer.append(data_to_color_text(self.line_number, color, header_data[start:end], extra))
            self.line_number += 1

    def decode_attributes(self):
        """
        Decode the attributes and populate the dump_buffer
        """

        if self.debug:
            self.dump_buffer.append("  Attributes")
            color = green if self.use_color else None

        data = self.msg_data[self.LEN:]

        while data:
            (length, attr_type) = unpack('=HH', data[:4])

            # If this is zero we will stay in this loop for forever
            if not length:
                self.log.error('Length is zero')
                return

            if len(data) < length:
                self.log.error("Buffer underrun %d < %d" % (len(data), length))
                return

            attr = self.add_attribute(attr_type, None)

            # Find the end of 'data' for this attribute and decode our section
            # of 'data'. attributes are padded for alignment thus the attr_end.
            #
            # How the attribute is decoded/unpacked is specific per AttributeXXXX class.
            attr_end = padded_length(length)
            attr.decode(self, data[0:attr_end])

            if self.debug:
                self.line_number = attr.dump_lines(self.dump_buffer, self.line_number, color)

                # Alternate back and forth between green and blue
                if self.use_color:
                    if color == green:
                        color = blue
                    else:
                        color = green

            data = data[attr_end:]

    def add_attribute(self, attr_type, value):
        nested = True if attr_type & NLA_F_NESTED else False
        net_byteorder = True if attr_type & NLA_F_NET_BYTEORDER else False
        attr_type = attr_type & NLA_TYPE_MASK

        # Given an attr_type (say RTA_DST) find the type of AttributeXXXX class
        # that we will use to store this attribute...AttributeIPAddress in the
        # case of RTA_DST.
        if attr_type in self.attribute_to_class:
            (attr_string, attr_class) = self.attribute_to_class[attr_type]

            '''
            attribute_to_class is a dictionary where the key is the attr_type, it doesn't
            take the family into account. For now we'll handle this as a special case for
            MPLS but long term we may need to make key a tuple of the attr_type and family.
            '''
            if self.msgtype not in (RTM_NEWNETCONF, RTM_GETNETCONF, RTM_DELNETCONF) and attr_type == Route.RTA_DST and self.family == AF_MPLS:
                attr_string = 'RTA_DST'
                attr_class = AttributeMplsLabel

        else:
            attr_string = "UNKNOWN_ATTRIBUTE_%d" % attr_type
            attr_class = AttributeGeneric
            self.log.debug("Attribute %d is not defined in %s.attribute_to_class, assuming AttributeGeneric" %
                           (attr_type, self.__class__.__name__))

        attr = attr_class(attr_type, attr_string, self.family, self.log)

        attr.set_value(value)
        attr.set_nested(nested)
        attr.set_net_byteorder(net_byteorder)

        # self.attributes is a dictionary keyed by the attribute type where
        # the value is an instance of the corresponding AttributeXXXX class.
        self.attributes[attr_type] = attr

        return attr

    def get_attribute_value(self, attr_type, default=None):
        if attr_type not in self.attributes:
            return default

        return self.attributes[attr_type].value

    def get_attr_string(self, attr_type):
        """
        Example: If attr_type is Address.IFA_CACHEINFO return the string 'IFA_CACHEINFO'
        """
        if attr_type in self.attribute_to_class:
            (attr_string, attr_class) = self.attribute_to_class[attr_type]
            return attr_string
        return str(attr_type)

    def build_message(self, seq, pid):
        self.seq = seq
        self.pid = pid
        attrs = bytes()

        for attr in self.attributes.values():
            attrs += attr.encode()

        self.length = self.header_LEN + len(self.body) + len(attrs)
        self.header_data = pack(self.header_PACK, self.length, self.msgtype, self.flags, self.seq, self.pid)

        if not attrs:
            self.msg_data = self.body
        else:
            self.msg_data = self.body + attrs

        self.message = self.header_data + self.msg_data

        if self.debug:
            self.decode_netlink_header()
            self.decode_service_header()
            self.decode_attributes()
            self.dump("TXed %s, length %d, seq %d, pid %d, flags 0x%x (%s)" %
                      (self, self.length, self.seq, self.pid, self.flags,
                       self.get_netlink_header_flags_string(self.msgtype, self.flags)))

    def pretty_display_dict(self, dic, level):
        for k,v in dic.items():
            if isinstance(v, dict):
                self.log.debug(' '*level + str(k) + ':')
                self.pretty_display_dict(v, level+5)
            else:
                self.log.debug(' '*level + str(k) + ': ' + str(v))

    # Print the netlink message in hex. This is only used for debugging.
    def dump(self, desc=None):
        attr_string = {}

        if desc is None:
            desc = "RXed %s, length %d, seq %d, pid %d, flags 0x%x" % (self, self.length, self.seq, self.pid, self.flags)

        for (attr_type, attr_obj) in self.attributes.items():
            key_string = "(%2d) %s" % (attr_type, self.get_attr_string(attr_type))
            attr_string[key_string] = attr_obj.get_pretty_value()

        if self.use_color:
            self.log.debug("%s\n%s\n\nAttributes Summary\n%s\n" %
                           (desc, '\n'.join(self.dump_buffer), pformat(attr_string)))
        else:
            # Assume if we are not allowing color output we also don't want embedded
            # newline characters in the output. Output each line individually.
            self.log.debug(desc)
            for line in self.dump_buffer:
                self.log.debug(line)
            self.log.debug("")
            self.log.debug("Attributes Summary")
            self.pretty_display_dict(attr_string, 1)


class Address(NetlinkPacket):
    """
    Service Header
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Family    |     Length    |     Flags     |    Scope      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Interface Index                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    # Address attributes
    # /usr/include/linux/if_addr.h
    IFA_UNSPEC    = 0x00
    IFA_ADDRESS   = 0x01
    IFA_LOCAL     = 0x02
    IFA_LABEL     = 0x03
    IFA_BROADCAST = 0x04
    IFA_ANYCAST   = 0x05
    IFA_CACHEINFO = 0x06
    IFA_MULTICAST = 0x07
    IFA_FLAGS     = 0x08
    IFA_RT_PRIORITY = 0x09  # 32, priority / metricfor prefix route

    attribute_to_class = {
        IFA_UNSPEC    : ('IFA_UNSPEC', AttributeGeneric),
        IFA_ADDRESS   : ('IFA_ADDRESS', AttributeIPAddress),
        IFA_LOCAL     : ('IFA_LOCAL', AttributeIPAddress),
        IFA_LABEL     : ('IFA_LABEL', AttributeString),
        IFA_BROADCAST : ('IFA_BROADCAST', AttributeIPAddress),
        IFA_ANYCAST   : ('IFA_ANYCAST', AttributeIPAddress),
        IFA_CACHEINFO : ('IFA_CACHEINFO', AttributeCACHEINFO),
        IFA_MULTICAST : ('IFA_MULTICAST', AttributeIPAddress),
        IFA_FLAGS     : ('IFA_FLAGS', AttributeFourByteValue),
        IFA_RT_PRIORITY : ('IFA_RT_PRIORITY', AttributeFourByteValue)
    }

    # Address flags
    # /usr/include/linux/if_addr.h
    IFA_F_SECONDARY   = 0x01
    IFA_F_NODAD       = 0x02
    IFA_F_OPTIMISTIC  = 0x04
    IFA_F_DADFAILED   = 0x08
    IFA_F_HOMEADDRESS = 0x10
    IFA_F_DEPRECATED  = 0x20
    IFA_F_TENTATIVE   = 0x40
    IFA_F_PERMANENT   = 0x80

    flag_to_string = {
        IFA_F_SECONDARY   : 'IFA_F_SECONDARY',
        IFA_F_NODAD       : 'IFA_F_NODAD',
        IFA_F_OPTIMISTIC  : 'IFA_F_OPTIMISTIC',
        IFA_F_DADFAILED   : 'IFA_F_DADFAILED',
        IFA_F_HOMEADDRESS : 'IFA_F_HOMEADDRESS',
        IFA_F_DEPRECATED  : 'IFA_F_DEPRECATED',
        IFA_F_TENTATIVE   : 'IFA_F_TENTATIVE',
        IFA_F_PERMANENT   : 'IFA_F_PERMANENT'
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = '4Bi'
        self.LEN = calcsize(self.PACK)

    def decode_service_header(self):

        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.family, self.prefixlen, self.flags, self.scope,
         self.ifindex) = \
            unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN//4):
                if self.line_number == 5:
                    extra = "Family %s (%s:%d), Length %s (%d), Flags %s, Scope %s (%d)" % \
                            (zfilled_hex(self.family, 2), get_family_str(self.family), self.family,
                             zfilled_hex(self.prefixlen, 2), self.prefixlen,
                             zfilled_hex(self.flags, 2),
                             zfilled_hex(self.scope, 2), self.scope)
                elif self.line_number == 6:
                    extra = "Interface Index %s (%d)" % (zfilled_hex(self.ifindex, 8), self.ifindex)
                else:
                    extra = "Unexpected line number %d" % self.line_number

                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1


class Error(NetlinkPacket):

    # Error codes
    # /include/netlink/errno.h
    NLE_SUCCESS           = 0x00
    NLE_FAILURE           = 0x01
    NLE_INTR              = 0x02
    NLE_BAD_SOCK          = 0x03
    NLE_AGAIN             = 0x04
    NLE_NOMEM             = 0x05
    NLE_EXIST             = 0x06
    NLE_INVAL             = 0x07
    NLE_RANGE             = 0x08
    NLE_MSGSIZE           = 0x09
    NLE_OPNOTSUPP         = 0x0A
    NLE_AF_NOSUPPORT      = 0x0B
    NLE_OBJ_NOTFOUND      = 0x0C
    NLE_NOATTR            = 0x0D
    NLE_MISSING_ATTR      = 0x0E
    NLE_AF_MISMATCH       = 0x0F
    NLE_SEQ_MISMATCH      = 0x10
    NLE_MSG_OVERFLOW      = 0x11
    NLE_MSG_TRUNC         = 0x12
    NLE_NOADDR            = 0x13
    NLE_SRCRT_NOSUPPORT   = 0x14
    NLE_MSG_TOOSHORT      = 0x15
    NLE_MSGTYPE_NOSUPPORT = 0x16
    NLE_OBJ_MISMATCH      = 0x17
    NLE_NOCACHE           = 0x18
    NLE_BUSY              = 0x19
    NLE_PROTO_MISMATCH    = 0x1A
    NLE_NOACCESS          = 0x1B
    NLE_PERM              = 0x1C
    NLE_PKTLOC_FILE       = 0x1D
    NLE_PARSE_ERR         = 0x1E
    NLE_NODEV             = 0x1F
    NLE_IMMUTABLE         = 0x20
    NLE_DUMP_INTR         = 0x21
    NLE_ATTRSIZE          = 0x22

    error_to_string = {
        NLE_SUCCESS           : 'NLE_SUCCESS',
        NLE_FAILURE           : 'NLE_FAILURE',
        NLE_INTR              : 'NLE_INTR',
        NLE_BAD_SOCK          : 'NLE_BAD_SOCK',
        NLE_AGAIN             : 'NLE_AGAIN',
        NLE_NOMEM             : 'NLE_NOMEM',
        NLE_EXIST             : 'NLE_EXIST',
        NLE_INVAL             : 'NLE_INVAL',
        NLE_RANGE             : 'NLE_RANGE',
        NLE_MSGSIZE           : 'NLE_MSGSIZE',
        NLE_OPNOTSUPP         : 'NLE_OPNOTSUPP',
        NLE_AF_NOSUPPORT      : 'NLE_AF_NOSUPPORT',
        NLE_OBJ_NOTFOUND      : 'NLE_OBJ_NOTFOUND',
        NLE_NOATTR            : 'NLE_NOATTR',
        NLE_MISSING_ATTR      : 'NLE_MISSING_ATTR',
        NLE_AF_MISMATCH       : 'NLE_AF_MISMATCH',
        NLE_SEQ_MISMATCH      : 'NLE_SEQ_MISMATCH',
        NLE_MSG_OVERFLOW      : 'NLE_MSG_OVERFLOW',
        NLE_MSG_TRUNC         : 'NLE_MSG_TRUNC',
        NLE_NOADDR            : 'NLE_NOADDR',
        NLE_SRCRT_NOSUPPORT   : 'NLE_SRCRT_NOSUPPORT',
        NLE_MSG_TOOSHORT      : 'NLE_MSG_TOOSHORT',
        NLE_MSGTYPE_NOSUPPORT : 'NLE_MSGTYPE_NOSUPPORT',
        NLE_OBJ_MISMATCH      : 'NLE_OBJ_MISMATCH',
        NLE_NOCACHE           : 'NLE_NOCACHE',
        NLE_BUSY              : 'NLE_BUSY',
        NLE_PROTO_MISMATCH    : 'NLE_PROTO_MISMATCH',
        NLE_NOACCESS          : 'NLE_NOACCESS',
        NLE_PERM              : 'NLE_PERM',
        NLE_PKTLOC_FILE       : 'NLE_PKTLOC_FILE',
        NLE_PARSE_ERR         : 'NLE_PARSE_ERR',
        NLE_NODEV             : 'NLE_NODEV',
        NLE_IMMUTABLE         : 'NLE_IMMUTABLE',
        NLE_DUMP_INTR         : 'NLE_DUMP_INTR',
        NLE_ATTRSIZE          : 'NLE_ATTRSIZE'
    }

    error_to_human_readable_string = {
        NLE_SUCCESS:           "Success",
        NLE_FAILURE:           "Unspecific failure",
        NLE_INTR:              "Interrupted system call",
        NLE_BAD_SOCK:          "Bad socket",
        NLE_AGAIN:             "Try again",
        NLE_NOMEM:             "Out of memory",
        NLE_EXIST:             "Object exists",
        NLE_INVAL:             "Invalid input data or parameter",
        NLE_RANGE:             "Input data out of range",
        NLE_MSGSIZE:           "Message size not sufficient",
        NLE_OPNOTSUPP:         "Operation not supported",
        NLE_AF_NOSUPPORT:      "Address family not supported",
        NLE_OBJ_NOTFOUND:      "Object not found",
        NLE_NOATTR:            "Attribute not available",
        NLE_MISSING_ATTR:      "Missing attribute",
        NLE_AF_MISMATCH:       "Address family mismatch",
        NLE_SEQ_MISMATCH:      "Message sequence number mismatch",
        NLE_MSG_OVERFLOW:      "Kernel reported message overflow",
        NLE_MSG_TRUNC:         "Kernel reported truncated message",
        NLE_NOADDR:            "Invalid address for specified address family",
        NLE_SRCRT_NOSUPPORT:   "Source based routing not supported",
        NLE_MSG_TOOSHORT:      "Netlink message is too short",
        NLE_MSGTYPE_NOSUPPORT: "Netlink message type is not supported",
        NLE_OBJ_MISMATCH:      "Object type does not match cache",
        NLE_NOCACHE:           "Unknown or invalid cache type",
        NLE_BUSY:              "Object busy",
        NLE_PROTO_MISMATCH:    "Protocol mismatch",
        NLE_NOACCESS:          "No Access",
        NLE_PERM:              "Operation not permitted",
        NLE_PKTLOC_FILE:       "Unable to open packet location file",
        NLE_PARSE_ERR:         "Unable to parse object",
        NLE_NODEV:             "No such device",
        NLE_IMMUTABLE:         "Immutable attribute",
        NLE_DUMP_INTR:         "Dump inconsistency detected, interrupted",
        NLE_ATTRSIZE:          "Attribute max length exceeded",
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = '=iLHHLL'
        self.LEN = calcsize(self.PACK)

    def decode_service_header(self):

        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.negative_errno, self.bad_msg_len, self.bad_msg_type,
         self.bad_msg_flag, self.bad_msg_seq, self.bad_msg_pid) =\
            unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN//4):

                if self.line_number == 5:
                    error_number = abs(self.negative_errno)
                    extra = "Error Number %s is %s (%s)" % (self.negative_errno, self.error_to_string.get(error_number), self.error_to_human_readable_string.get(error_number))
                    # zfilled_hex(self.negative_errno, 2)

                elif self.line_number == 6:
                    extra = "Length %s (%d)" % (zfilled_hex(self.bad_msg_len, 8), self.bad_msg_len)

                elif self.line_number == 7:
                    extra = "Type %s (%d - %s), Flags %s (%s)" % \
                        (zfilled_hex(self.bad_msg_type, 4), self.bad_msg_type, self.get_type_string(self.bad_msg_type),
                         zfilled_hex(self.bad_msg_flag, 4), self.get_netlink_header_flags_string(self.bad_msg_type, self.bad_msg_flag))

                elif self.line_number == 8:
                    extra = "Sequence Number %s (%d)" % (zfilled_hex(self.bad_msg_seq, 8), self.bad_msg_seq)

                elif self.line_number == 9:
                    extra = "Process ID %s (%d)" % (zfilled_hex(self.bad_msg_pid, 8), self.bad_msg_pid)

                else:
                    extra = "Unexpected line number %d" % self.line_number

                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1


class Link(NetlinkPacket, NetlinkPacket_IFLA_LINKINFO_Attributes):
    """
    Service Header

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Family    |   Reserved  |          Device Type              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Interface Index                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Device Flags                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Change Mask                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    # Link attributes
    # /usr/include/linux/if_link.h
    IFLA_UNSPEC          = 0
    IFLA_ADDRESS         = 1
    IFLA_BROADCAST       = 2
    IFLA_IFNAME          = 3
    IFLA_MTU             = 4
    IFLA_LINK            = 5
    IFLA_QDISC           = 6
    IFLA_STATS           = 7
    IFLA_COST            = 8
    IFLA_PRIORITY        = 9
    IFLA_MASTER          = 10
    IFLA_WIRELESS        = 11
    IFLA_PROTINFO        = 12
    IFLA_TXQLEN          = 13
    IFLA_MAP             = 14
    IFLA_WEIGHT          = 15
    IFLA_OPERSTATE       = 16
    IFLA_LINKMODE        = 17
    IFLA_LINKINFO        = 18
    IFLA_NET_NS_PID      = 19
    IFLA_IFALIAS         = 20
    IFLA_NUM_VF          = 21
    IFLA_VFINFO_LIST     = 22
    IFLA_STATS64         = 23
    IFLA_VF_PORTS        = 24
    IFLA_PORT_SELF       = 25
    IFLA_AF_SPEC         = 26
    IFLA_GROUP           = 27
    IFLA_NET_NS_FD       = 28
    IFLA_EXT_MASK        = 29
    IFLA_PROMISCUITY     = 30
    IFLA_NUM_TX_QUEUES   = 31
    IFLA_NUM_RX_QUEUES   = 32
    IFLA_CARRIER         = 33
    IFLA_PHYS_PORT_ID    = 34
    IFLA_CARRIER_CHANGES = 35
    IFLA_PHYS_SWITCH_ID  = 36
    IFLA_LINK_NETNSID    = 37
    IFLA_PHYS_PORT_NAME  = 38
    IFLA_PROTO_DOWN      = 39
    IFLA_GSO_MAX_SEGS    = 40
    IFLA_GSO_MAX_SIZE    = 41
    IFLA_PAD             = 42
    IFLA_XDP             = 43
    IFLA_EVENT           = 44
    IFLA_NEW_NETNSID     = 45
    IFLA_IF_NETNSID      = 46
    IFLA_CARRIER_UP_COUNT   = 47
    IFLA_CARRIER_DOWN_COUNT = 48
    IFLA_NEW_IFINDEX        = 49
    IFLA_MIN_MTU            = 50
    IFLA_MAX_MTU            = 51

    attribute_to_class = {
        IFLA_UNSPEC          : ('IFLA_UNSPEC', AttributeGeneric),
        IFLA_ADDRESS         : ('IFLA_ADDRESS', AttributeMACAddress),
        IFLA_BROADCAST       : ('IFLA_BROADCAST', AttributeMACAddress),
        IFLA_IFNAME          : ('IFLA_IFNAME', AttributeStringInterfaceName),
        IFLA_MTU             : ('IFLA_MTU', AttributeFourByteValue),
        IFLA_LINK            : ('IFLA_LINK', AttributeFourByteValue),
        IFLA_QDISC           : ('IFLA_QDISC', AttributeString),
        IFLA_STATS           : ('IFLA_STATS', AttributeGeneric),
        IFLA_COST            : ('IFLA_COST', AttributeGeneric),
        IFLA_PRIORITY        : ('IFLA_PRIORITY', AttributeGeneric),
        IFLA_MASTER          : ('IFLA_MASTER', AttributeFourByteValue),
        IFLA_WIRELESS        : ('IFLA_WIRELESS', AttributeGeneric),
        IFLA_PROTINFO        : ('IFLA_PROTINFO', AttributeIFLA_PROTINFO),
        IFLA_TXQLEN          : ('IFLA_TXQLEN', AttributeFourByteValue),
        IFLA_MAP             : ('IFLA_MAP', AttributeGeneric),
        IFLA_WEIGHT          : ('IFLA_WEIGHT', AttributeGeneric),
        IFLA_OPERSTATE       : ('IFLA_OPERSTATE', AttributeOneByteValue),
        IFLA_LINKMODE        : ('IFLA_LINKMODE', AttributeOneByteValue),
        IFLA_LINKINFO        : ('IFLA_LINKINFO', AttributeIFLA_LINKINFO),
        IFLA_NET_NS_PID      : ('IFLA_NET_NS_PID', AttributeGeneric),
        IFLA_IFALIAS         : ('IFLA_IFALIAS', AttributeString),
        IFLA_NUM_VF          : ('IFLA_NUM_VF', AttributeGeneric),
        IFLA_VFINFO_LIST     : ('IFLA_VFINFO_LIST', AttributeGeneric),
        IFLA_STATS64         : ('IFLA_STATS64', AttributeGeneric),
        IFLA_VF_PORTS        : ('IFLA_VF_PORTS', AttributeGeneric),
        IFLA_PORT_SELF       : ('IFLA_PORT_SELF', AttributeGeneric),
        IFLA_AF_SPEC         : ('IFLA_AF_SPEC', AttributeIFLA_AF_SPEC),
        IFLA_GROUP           : ('IFLA_GROUP', AttributeFourByteValue),
        IFLA_NET_NS_FD       : ('IFLA_NET_NS_FD', AttributeGeneric),
        IFLA_EXT_MASK        : ('IFLA_EXT_MASK', AttributeFourByteValue),
        IFLA_PROMISCUITY     : ('IFLA_PROMISCUITY', AttributeGeneric),
        IFLA_NUM_TX_QUEUES   : ('IFLA_NUM_TX_QUEUES', AttributeGeneric),
        IFLA_NUM_RX_QUEUES   : ('IFLA_NUM_RX_QUEUES', AttributeGeneric),
        IFLA_CARRIER         : ('IFLA_CARRIER', AttributeGeneric),
        IFLA_PHYS_PORT_ID    : ('IFLA_PHYS_PORT_ID', AttributeGeneric),
        IFLA_CARRIER_CHANGES : ('IFLA_CARRIER_CHANGES', AttributeGeneric),
        IFLA_PHYS_SWITCH_ID  : ('IFLA_PHYS_SWITCH_ID', AttributeGeneric),
        IFLA_LINK_NETNSID    : ('IFLA_LINK_NETNSID', AttributeGeneric),
        IFLA_PHYS_PORT_NAME  : ('IFLA_PHYS_PORT_NAME', AttributeGeneric),
        IFLA_PROTO_DOWN      : ('IFLA_PROTO_DOWN', AttributeOneByteValue),
        IFLA_GSO_MAX_SEGS    : ('IFLA_GSO_MAX_SEGS', AttributeFourByteValue),
        IFLA_GSO_MAX_SIZE    : ('IFLA_GSO_MAX_SIZE', AttributeFourByteValue),
        IFLA_PAD             : ('IFLA_PAD', AttributeGeneric),
        IFLA_XDP             : ('IFLA_XDP', AttributeGeneric),
        IFLA_EVENT           : ('IFLA_EVENT', AttributeFourByteValue),
        IFLA_NEW_NETNSID     : ('IFLA_NEW_NETNSID', AttributeFourByteValue),
        IFLA_IF_NETNSID      : ('IFLA_IF_NETNSID', AttributeFourByteValue),
        IFLA_CARRIER_UP_COUNT   : ('IFLA_CARRIER_UP_COUNT', AttributeFourByteValue),
        IFLA_CARRIER_DOWN_COUNT : ('IFLA_CARRIER_DOWN_COUNT', AttributeFourByteValue),
        IFLA_NEW_IFINDEX        : ('IFLA_NEW_IFINDEX', AttributeFourByteValue),
        IFLA_MIN_MTU            : ('IFLA_MIN_MTU', AttributeFourByteValue),
        IFLA_MAX_MTU            : ('IFLA_MAX_MTU', AttributeFourByteValue),
    }

    # Link flags
    # /usr/include/linux/if.h
    IFF_UP          = 0x0001     # Interface is administratively up.
    IFF_BROADCAST   = 0x0002     # Valid broadcast address set.
    IFF_DEBUG       = 0x0004     # Internal debugging flag.
    IFF_LOOPBACK    = 0x0008     # Interface is a loopback interface.
    IFF_POINTOPOINT = 0x0010     # Interface is a point-to-point link.
    IFF_NOTRAILERS  = 0x0020     # Avoid use of trailers.
    IFF_RUNNING     = 0x0040     # Interface is operationally up.
    IFF_NOARP       = 0x0080     # No ARP protocol needed for this interface.
    IFF_PROMISC     = 0x0100     # Interface is in promiscuous mode.
    IFF_ALLMULTI    = 0x0200     # Receive all multicast packets.
    IFF_MASTER      = 0x0400     # Master of a load balancing bundle.
    IFF_SLAVE       = 0x0800     # Slave of a load balancing bundle.
    IFF_MULTICAST   = 0x1000     # Supports multicast.
    IFF_PORTSEL     = 0x2000     # Is able to select media type via ifmap.
    IFF_AUTOMEDIA   = 0x4000     # Auto media selection active.
    IFF_DYNAMIC     = 0x8000     # Interface was dynamically created.
    IFF_LOWER_UP    = 0x10000    # driver signals L1 up
    IFF_DORMANT     = 0x20000    # driver signals dormant
    IFF_ECHO        = 0x40000    # echo sent packet
    IFF_PROTO_DOWN  = 0x1000000  # protocol is down on the interface

    flag_to_string = {
        IFF_UP          : 'IFF_UP',
        IFF_BROADCAST   : 'IFF_BROADCAST',
        IFF_DEBUG       : 'IFF_DEBUG',
        IFF_LOOPBACK    : 'IFF_LOOPBACK',
        IFF_POINTOPOINT : 'IFF_POINTOPOINT',
        IFF_NOTRAILERS  : 'IFF_NOTRAILERS',
        IFF_RUNNING     : 'IFF_RUNNING',
        IFF_NOARP       : 'IFF_NOARP',
        IFF_PROMISC     : 'IFF_PROMISC',
        IFF_ALLMULTI    : 'IFF_ALLMULTI',
        IFF_MASTER      : 'IFF_MASTER',
        IFF_SLAVE       : 'IFF_SLAVE',
        IFF_MULTICAST   : 'IFF_MULTICAST',
        IFF_PORTSEL     : 'IFF_PORTSEL',
        IFF_AUTOMEDIA   : 'IFF_AUTOMEDIA',
        IFF_DYNAMIC     : 'IFF_DYNAMIC',
        IFF_LOWER_UP    : 'IFF_LOWER_UP',
        IFF_DORMANT     : 'IFF_DORMANT',
        IFF_ECHO        : 'IFF_ECHO',
        IFF_PROTO_DOWN  : 'IFF_PROTO_DOWN'
    }

    # RFC 2863 operational status
    IF_OPER_UNKNOWN        = 0
    IF_OPER_NOTPRESENT     = 1
    IF_OPER_DOWN           = 2
    IF_OPER_LOWERLAYERDOWN = 3
    IF_OPER_TESTING        = 4
    IF_OPER_DORMANT        = 5
    IF_OPER_UP             = 6

    oper_to_string = {
        IF_OPER_UNKNOWN        : 'IF_OPER_UNKNOWN',
        IF_OPER_NOTPRESENT     : 'IF_OPER_NOTPRESENT',
        IF_OPER_DOWN           : 'IF_OPER_DOWN',
        IF_OPER_LOWERLAYERDOWN : 'IF_OPER_LOWERLAYERDOWN',
        IF_OPER_TESTING        : 'IF_OPER_TESTING',
        IF_OPER_DORMANT        : 'IF_OPER_DORMANT',
        IF_OPER_UP             : 'IF_OPER_UP'
    }

    # Link types
    # /usr/include/linux/if_arp.h
    # ARP protocol HARDWARE identifiers
    ARPHRD_NETROM             = 0      # from KA9Q: NET/ROM pseudo
    ARPHRD_ETHER              = 1      # Ethernet 10Mbps
    ARPHRD_EETHER             = 2      # Experimental Ethernet
    ARPHRD_AX25               = 3      # AX.25 Level 2
    ARPHRD_PRONET             = 4      # PROnet token ring
    ARPHRD_CHAOS              = 5      # Chaosnet
    ARPHRD_IEEE802            = 6      # IEEE 802.2 Ethernet/TR/TB
    ARPHRD_ARCNET             = 7      # ARCnet
    ARPHRD_APPLETLK           = 8      # APPLEtalk
    ARPHRD_DLCI               = 15     # Frame Relay DLCI
    ARPHRD_ATM                = 19     # ATM
    ARPHRD_METRICOM           = 23     # Metricom STRIP (new IANA id)
    ARPHRD_IEEE1394           = 24     # IEEE 1394 IPv4 - RFC 2734
    ARPHRD_EUI64              = 27     # EUI-64
    ARPHRD_INFINIBAND         = 32     # InfiniBand
    # Dummy types for non ARP hardware
    ARPHRD_SLIP               = 256
    ARPHRD_CSLIP              = 257
    ARPHRD_SLIP6              = 258
    ARPHRD_CSLIP6             = 259
    ARPHRD_RSRVD              = 260    # Notional KISS type
    ARPHRD_ADAPT              = 264
    ARPHRD_ROSE               = 270
    ARPHRD_X25                = 271    # CCITT X.25
    ARPHRD_HWX25              = 272    # Boards with X.25 in firmware
    ARPHRD_CAN                = 280    # Controller Area Network
    ARPHRD_PPP                = 512
    ARPHRD_CISCO              = 513    # Cisco HDLC
    ARPHRD_HDLC               = ARPHRD_CISCO
    ARPHRD_LAPB               = 516    # LAPB
    ARPHRD_DDCMP              = 517    # Digital's DDCMP protocol
    ARPHRD_RAWHDLC            = 518    # Raw HDLC
    ARPHRD_TUNNEL             = 768    # IPIP tunnel
    ARPHRD_TUNNEL6            = 769    # IP6IP6 tunnel
    ARPHRD_FRAD               = 770    # Frame Relay Access Device
    ARPHRD_SKIP               = 771    # SKIP vif
    ARPHRD_LOOPBACK           = 772    # Loopback device
    ARPHRD_LOCALTLK           = 773    # Localtalk device
    ARPHRD_FDDI               = 774    # Fiber Distributed Data Interface
    ARPHRD_BIF                = 775    # AP1000 BIF
    ARPHRD_SIT                = 776    # sit0 device - IPv6-in-IPv4
    ARPHRD_IPDDP              = 777    # IP over DDP tunneller
    ARPHRD_IPGRE              = 778    # GRE over IP
    ARPHRD_PIMREG             = 779    # PIMSM register interface
    ARPHRD_HIPPI              = 780    # High Performance Parallel Interface
    ARPHRD_ASH                = 781    # Nexus 64Mbps Ash
    ARPHRD_ECONET             = 782    # Acorn Econet
    ARPHRD_IRDA               = 783    # Linux-IrDA
    ARPHRD_FCPP               = 784    # Point to point fibrechannel
    ARPHRD_FCAL               = 785    # Fibrechannel arbitrated loop
    ARPHRD_FCPL               = 786    # Fibrechannel public loop
    ARPHRD_FCFABRIC           = 787    # Fibrechannel fabric
    # 787->799 reserved for fibrechannel media types
    ARPHRD_IEEE802_TR         = 800    # Magic type ident for TR
    ARPHRD_IEEE80211          = 801    # IEEE 802.11
    ARPHRD_IEEE80211_PRISM    = 802    # IEEE 802.11 + Prism2 header
    ARPHRD_IEEE80211_RADIOTAP = 803    # IEEE 802.11 + radiotap header
    ARPHRD_IEEE802154         = 804
    ARPHRD_PHONET             = 820    # PhoNet media type
    ARPHRD_PHONET_PIPE        = 821    # PhoNet pipe header
    ARPHRD_CAIF               = 822    # CAIF media type
    ARPHRD_VOID               = 0xFFFF  # Void type, nothing is known
    ARPHRD_NONE               = 0xFFFE  # zero header length

    link_type_to_string = {
        ARPHRD_NETROM             : 'ARPHRD_NETROM',
        ARPHRD_ETHER              : 'ARPHRD_ETHER',
        ARPHRD_EETHER             : 'ARPHRD_EETHER',
        ARPHRD_AX25               : 'ARPHRD_AX25',
        ARPHRD_PRONET             : 'ARPHRD_PRONET',
        ARPHRD_CHAOS              : 'ARPHRD_CHAOS',
        ARPHRD_IEEE802            : 'ARPHRD_IEEE802',
        ARPHRD_ARCNET             : 'ARPHRD_ARCNET',
        ARPHRD_APPLETLK           : 'ARPHRD_APPLETLK',
        ARPHRD_DLCI               : 'ARPHRD_DLCI',
        ARPHRD_ATM                : 'ARPHRD_ATM',
        ARPHRD_METRICOM           : 'ARPHRD_METRICOM',
        ARPHRD_IEEE1394           : 'ARPHRD_IEEE1394',
        ARPHRD_EUI64              : 'ARPHRD_EUI64',
        ARPHRD_INFINIBAND         : 'ARPHRD_INFINIBAND',
        ARPHRD_SLIP               : 'ARPHRD_SLIP',
        ARPHRD_CSLIP              : 'ARPHRD_CSLIP',
        ARPHRD_SLIP6              : 'ARPHRD_SLIP6',
        ARPHRD_CSLIP6             : 'ARPHRD_CSLIP6',
        ARPHRD_RSRVD              : 'ARPHRD_RSRVD',
        ARPHRD_ADAPT              : 'ARPHRD_ADAPT',
        ARPHRD_ROSE               : 'ARPHRD_ROSE',
        ARPHRD_X25                : 'ARPHRD_X25',
        ARPHRD_HWX25              : 'ARPHRD_HWX25',
        ARPHRD_CAN                : 'ARPHRD_CAN',
        ARPHRD_PPP                : 'ARPHRD_PPP',
        ARPHRD_CISCO              : 'ARPHRD_CISCO',
        ARPHRD_HDLC               : 'ARPHRD_HDLC',
        ARPHRD_LAPB               : 'ARPHRD_LAPB',
        ARPHRD_DDCMP              : 'ARPHRD_DDCMP',
        ARPHRD_RAWHDLC            : 'ARPHRD_RAWHDLC',
        ARPHRD_TUNNEL             : 'ARPHRD_TUNNEL',
        ARPHRD_TUNNEL6            : 'ARPHRD_TUNNEL6',
        ARPHRD_FRAD               : 'ARPHRD_FRAD',
        ARPHRD_SKIP               : 'ARPHRD_SKIP',
        ARPHRD_LOOPBACK           : 'ARPHRD_LOOPBACK',
        ARPHRD_LOCALTLK           : 'ARPHRD_LOCALTLK',
        ARPHRD_FDDI               : 'ARPHRD_FDDI',
        ARPHRD_BIF                : 'ARPHRD_BIF',
        ARPHRD_SIT                : 'ARPHRD_SIT',
        ARPHRD_IPDDP              : 'ARPHRD_IPDDP',
        ARPHRD_IPGRE              : 'ARPHRD_IPGRE',
        ARPHRD_PIMREG             : 'ARPHRD_PIMREG',
        ARPHRD_HIPPI              : 'ARPHRD_HIPPI',
        ARPHRD_ASH                : 'ARPHRD_ASH',
        ARPHRD_ECONET             : 'ARPHRD_ECONET',
        ARPHRD_IRDA               : 'ARPHRD_IRDA',
        ARPHRD_FCPP               : 'ARPHRD_FCPP',
        ARPHRD_FCAL               : 'ARPHRD_FCAL',
        ARPHRD_FCPL               : 'ARPHRD_FCPL',
        ARPHRD_FCFABRIC           : 'ARPHRD_FCFABRIC',
        ARPHRD_IEEE802_TR         : 'ARPHRD_IEEE802_TR',
        ARPHRD_IEEE80211          : 'ARPHRD_IEEE80211',
        ARPHRD_IEEE80211_PRISM    : 'ARPHRD_IEEE80211_PRISM',
        ARPHRD_IEEE80211_RADIOTAP : 'ARPHRD_IEEE80211_RADIOTAP',
        ARPHRD_IEEE802154         : 'ARPHRD_IEEE802154',
        ARPHRD_PHONET             : 'ARPHRD_PHONET',
        ARPHRD_PHONET_PIPE        : 'ARPHRD_PHONET_PIPE',
        ARPHRD_CAIF               : 'ARPHRD_CAIF',
        ARPHRD_VOID               : 'ARPHRD_VOID',
        ARPHRD_NONE               : 'ARPHRD_NONE'
    }

    # Subtype attributes for IFLA_AF_SPEC
    IFLA_INET6_UNSPEC           = 0
    IFLA_INET6_FLAGS            = 1  # link flags
    IFLA_INET6_CONF             = 2  # sysctl parameters
    IFLA_INET6_STATS            = 3  # statistics
    IFLA_INET6_MCAST            = 4  # MC things. What of them?
    IFLA_INET6_CACHEINFO        = 5  # time values and max reasm size
    IFLA_INET6_ICMP6STATS       = 6  # statistics (icmpv6)
    IFLA_INET6_TOKEN            = 7  # device token
    IFLA_INET6_ADDR_GEN_MODE    = 8  # implicit address generator mode
    __IFLA_INET6_MAX            = 9

    ifla_inet6_af_spec_to_string = {
        IFLA_INET6_UNSPEC           : 'IFLA_INET6_UNSPEC',
        IFLA_INET6_FLAGS            : 'IFLA_INET6_FLAGS',
        IFLA_INET6_CONF             : 'IFLA_INET6_CONF',
        IFLA_INET6_STATS            : 'IFLA_INET6_STATS',
        IFLA_INET6_MCAST            : 'IFLA_INET6_MCAST',
        IFLA_INET6_CACHEINFO        : 'IFLA_INET6_CACHEINFO',
        IFLA_INET6_ICMP6STATS       : 'IFLA_INET6_ICMP6STATS',
        IFLA_INET6_TOKEN            : 'IFLA_INET6_TOKEN',
        IFLA_INET6_ADDR_GEN_MODE    : 'IFLA_INET6_ADDR_GEN_MODE',
    }

    # IFLA_INET6_ADDR_GEN_MODE values
    IN6_ADDR_GEN_MODE_EUI64 = 0
    IN6_ADDR_GEN_MODE_NONE = 1
    IN6_ADDR_GEN_MODE_STABLE_PRIVACY = 2
    IN6_ADDR_GEN_MODE_RANDOM = 3

    ifla_inet6_addr_gen_mode_dict = {
        IN6_ADDR_GEN_MODE_EUI64: "eui64",
        IN6_ADDR_GEN_MODE_NONE: "none",
        IN6_ADDR_GEN_MODE_STABLE_PRIVACY: "stable_secret",
        IN6_ADDR_GEN_MODE_RANDOM: "random"
    }

    # Subtype attrbutes AF_INET
    IFLA_INET_UNSPEC    = 0
    IFLA_INET_CONF      = 1
    __IFLA_INET_MAX     = 2

    ifla_inet_af_spec_to_string = {
        IFLA_INET_UNSPEC    : 'IFLA_INET_UNSPEC',
        IFLA_INET_CONF      : 'IFLA_INET_CONF',
    }

    # /* Bridge Flags */
    BRIDGE_FLAGS_MASTER = 1  # /* Bridge command to/from master */
    BRIDGE_FLAGS_SELF = 2  # /* Bridge command to/from lowerdev */

    bridge_flags_to_string = {
        BRIDGE_FLAGS_MASTER : "BRIDGE_FLAGS_MASTER",
        BRIDGE_FLAGS_SELF   : "BRIDGE_FLAGS_SELF"
    }

    BRIDGE_MODE_VEB = 0  # /* Default loopback mode */
    BRIDGE_MODE_VEPA = 1  # /* 802.1Qbg defined VEPA mode */
    BRIDGE_MODE_UNDEF = 0xFFFF  # /* mode undefined */

    # /* Bridge management nested attributes
    #  * [IFLA_AF_SPEC] = {
    #  *     [IFLA_BRIDGE_FLAGS]
    #  *     [IFLA_BRIDGE_MODE]
    #  *     [IFLA_BRIDGE_VLAN_INFO]
    #  * }
    #  */

    # BRIDGE IFLA_AF_SPEC attributes
    IFLA_BRIDGE_FLAGS     = 0
    IFLA_BRIDGE_MODE      = 1
    IFLA_BRIDGE_VLAN_INFO = 2
    IFLA_BRIDGE_VLAN_TUNNEL_INFO = 3

    ifla_bridge_af_spec_to_string = {
        IFLA_BRIDGE_FLAGS     : 'IFLA_BRIDGE_FLAGS',
        IFLA_BRIDGE_MODE      : 'IFLA_BRIDGE_MODE',
        IFLA_BRIDGE_VLAN_INFO : 'IFLA_BRIDGE_VLAN_INFO',
        IFLA_BRIDGE_VLAN_TUNNEL_INFO : "IFLA_BRIDGE_VLAN_TUNNEL_INFO"
    }

    # BRIDGE_VLAN_INFO flags
    BRIDGE_VLAN_INFO_MASTER      = 1 << 0  # Operate on Bridge device as well
    BRIDGE_VLAN_INFO_PVID        = 1 << 1  # VLAN is PVID, ingress untagged
    BRIDGE_VLAN_INFO_UNTAGGED    = 1 << 2  # VLAN egresses untagged
    BRIDGE_VLAN_INFO_RANGE_BEGIN = 1 << 3  # VLAN is start of vlan range
    BRIDGE_VLAN_INFO_RANGE_END   = 1 << 4  # VLAN is end of vlan range
    BRIDGE_VLAN_INFO_BRENTRY     = 1 << 5  # Global bridge VLAN entry

    bridge_vlan_to_string = {
        BRIDGE_VLAN_INFO_MASTER      : 'BRIDGE_VLAN_INFO_MASTER',
        BRIDGE_VLAN_INFO_PVID        : 'BRIDGE_VLAN_INFO_PVID',
        BRIDGE_VLAN_INFO_UNTAGGED    : 'BRIDGE_VLAN_INFO_UNTAGGED',
        BRIDGE_VLAN_INFO_RANGE_BEGIN : 'BRIDGE_VLAN_INFO_RANGE_BEGIN',
        BRIDGE_VLAN_INFO_RANGE_END   : 'BRIDGE_VLAN_INFO_RANGE_END',
        BRIDGE_VLAN_INFO_BRENTRY     : 'BRIDGE_VLAN_INFO_BRENTRY'
    }

    # struct bridge_vlan_info {
    # 	__u16 flags;
    # 	__u16 vid;
    # };

    IFLA_BRIDGE_VLAN_TUNNEL_UNSPEC = 0
    IFLA_BRIDGE_VLAN_TUNNEL_ID = 1
    IFLA_BRIDGE_VLAN_TUNNEL_VID = 2
    IFLA_BRIDGE_VLAN_TUNNEL_FLAGS = 3

    bridge_vlan_tunnel_to_string = {
        IFLA_BRIDGE_VLAN_TUNNEL_UNSPEC: "IFLA_BRIDGE_VLAN_TUNNEL_UNSPEC",
        IFLA_BRIDGE_VLAN_TUNNEL_ID: "IFLA_BRIDGE_VLAN_TUNNEL_ID",
        IFLA_BRIDGE_VLAN_TUNNEL_VID: "IFLA_BRIDGE_VLAN_TUNNEL_VID",
        IFLA_BRIDGE_VLAN_TUNNEL_FLAGS: "IFLA_BRIDGE_VLAN_TUNNEL_FLAGS",
    }

    # struct bridge_vlan_xstats {
    # 	__u64 rx_bytes;
    # 	__u64 rx_packets;
    # 	__u64 tx_bytes;
    # 	__u64 tx_packets;
    # 	__u16 vid;
    # 	__u16 flags;
    # 	__u32 pad2;
    # };

    # filters for IFLA_EXT_MASK
    RTEXT_FILTER_VF                = 1 << 0
    RTEXT_FILTER_BRVLAN            = 1 << 1
    RTEXT_FILTER_BRVLAN_COMPRESSED = 1 << 2
    RTEXT_FILTER_SKIP_STATS        = 1 << 3

    rtext_to_string = {
        RTEXT_FILTER_VF                : 'RTEXT_FILTER_VF',
        RTEXT_FILTER_BRVLAN            : 'RTEXT_FILTER_BRVLAN',
        RTEXT_FILTER_BRVLAN_COMPRESSED : 'RTEXT_FILTER_BRVLAN_COMPRESSED',
        RTEXT_FILTER_SKIP_STATS        : 'RTEXT_FILTER_SKIP_STATS'
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = 'BxHiII'
        self.LEN  = calcsize(self.PACK)

    def get_link_type_string(self, index):
        return self.get_string(self.link_type_to_string, index)

    def get_ifla_inet6_af_spec_to_string(self, index):
        return self.get_string(self.ifla_inet6_af_spec_to_string, index)

    def get_ifla_inet_af_spec_to_string(self, index):
        return self.get_string(self.ifla_inet_af_spec_to_string, index)

    def get_ifla_bridge_af_spec_to_string(self, index):
        return self.get_string(self.ifla_bridge_af_spec_to_string, index)

    def get_ifla_info_string(self, index):
        return self.get_string(self.ifla_info_to_string, index)

    def get_ifla_vlan_string(self, index):
        return self.get_string(self.ifla_vlan_to_string, index)

    def get_ifla_vxlan_string(self, index):
        return self.get_string(self.ifla_vxlan_to_string, index)

    def get_ifla_vrf_string(self, index):
        return self.get_string(self.ifla_vrf_to_string, index)

    def get_ifla_bond_slave_string(self, index):
        return self.get_string(self.ifla_bond_slave_to_string, index)

    def get_ifla_macvlan_string(self, index):
        return self.get_string(self.ifla_macvlan_to_string, index)

    def get_macvlan_mode_string(self, index):
        return self.get_string(self.macvlan_mode_to_string, index)

    def get_ifla_gre_string(self, index):
        return self.get_string(self.ifla_gre_to_string, index)

    def get_ifla_vti_string(self, index):
        return self.get_string(self.ifla_vti_to_string, index)

    def get_ifla_iptun_string(self, index):
        return self.get_string(self.ifla_iptun_to_string, index)

    def get_ifla_bond_string(self, index):
        return self.get_string(self.ifla_bond_to_string, index)

    def get_ifla_bond_ad_string(self, index):
        return self.get_string(self.ifla_bond_ad_to_string, index)

    def get_ifla_brport_string(self, index):
        return self.get_string(self.ifla_brport_to_string, index)

    def get_ifla_br_string(self, index):
        return self.get_string(self.ifla_br_to_string, index)

    def get_bridge_vlan_string(self, index):
        return self.get_string(self.bridge_vlan_to_string, index)

    def get_bridge_flags_string(self, index):
        return self.get_string(self.bridge_flags_to_string, index)

    def decode_service_header(self):

        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.family, self.device_type,
         self.ifindex,
         self.flags,
         self.change_mask) = \
            unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN//4):
                if self.line_number == 5:
                    extra = "Family %s (%s:%d), Device Type %s (%d - %s)" % \
                            (zfilled_hex(self.family, 2), get_family_str(self.family), self.family,
                             zfilled_hex(self.device_type, 4), self.device_type, self.get_link_type_string(self.device_type))
                elif self.line_number == 6:
                    extra = "Interface Index %s (%d)" % (zfilled_hex(self.ifindex, 8), self.ifindex)
                elif self.line_number == 7:
                    extra = "Device Flags %s (%s)" % (zfilled_hex(self.flags, 8), self.get_flags_string())
                elif self.line_number == 8:
                    extra = "Change Mask %s" % zfilled_hex(self.change_mask, 8)
                else:
                    extra = "Unexpected line number %d" % self.line_number

                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1

    def is_up(self):
        if self.flags & Link.IFF_UP:
            return True
        return False


class AttributeMDBA_MDB(Attribute):
    """
    /* Bridge multicast database attributes
     * [MDBA_MDB] = {
     *     [MDBA_MDB_ENTRY] = {
     *         [MDBA_MDB_ENTRY_INFO] {
     *                struct br_mdb_entry
     *                [MDBA_MDB_EATTR attributes]
     *         }
     *     }
     * }
    """
    """
    Current we support only MDB Dump and no MDB_GET.
    The code has been written to handle multiple entries in a single msg.
    data -- alignment
    MDBA_MDB ===> data[0:4]
    MDBA_MDB_ENTRY ===> data[4:8]
    MDBA_MDB_ENTRY_INFO ===> data[8:12]
    br_mdb_entry -- ===> ifindex data[12:16]
                 -- ===> state,flags,vide data[16:20]
                  -- ===> ip_addr data[20:36]
                 -- ===> proto data[36:40]
                 -- ===> MDB_MDB_EATTR_TIMER data[40:44]
                 -- Timer Value data[44:48]
    """

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)

        data = self.data[4:]
        if parent_msg.msgtype == RTM_GETMDB:
            self.value = []
            while data:
                (sub_attr_length, sub_attr_type) = unpack('=HH', data[:4])
                sub_attr_end = padded_length(sub_attr_length)
                sub_attr_data = data[4:sub_attr_end]

                mdb_entry = {}
                mdb_entry[MDB.MDBA_MDB_ENTRY] = []
                if not sub_attr_length:
                    self.log.error('parsed a zero length sub-attr')
                    return

                if sub_attr_type == MDB.MDBA_MDB_ENTRY:
                    while sub_attr_data:
                        nested_mdb_entry = {}
                        (nested_attr_length,nested_attr_type) = unpack('=HH',sub_attr_data[:4])
                        nested_attr_end = padded_length(nested_attr_length)
                        if nested_attr_type == MDB.MDBA_MDB_ENTRY_INFO:
                            (ifindex, state, flags, vid) = unpack('=LBBH',sub_attr_data[4:12])
                            info = [ifindex,state,flags,vid]
                            proto = unpack('=H',sub_attr_data[28:30])[0]
                            if proto == htons(ETH_P_IP):
                                ip_addr = ipnetwork.IPv4Address(unpack('>L', sub_attr_data[12:16])[0])
                            else:
                                (data1, data2) = unpack('>QQ',sub_attr_data[12:28])
                                ip_addr        = ipnetwork.IPv6Address(data1 << 64 | data2)

                            info.append(ip_addr)

                            try:
                                (timer_attr_length,timer_attr_type) = unpack('=HH',sub_attr_data[32:36])
                                if(timer_attr_type ) == MDB.MDBA_MDB_EATTR_TIMER:
                                    info.append({MDB.MDBA_MDB_EATTR_TIMER: (unpack('=I',sub_attr_data[36:40])[0])*0.01})
                            except struct.error:
                                self.log.error('No TimerAttribute')
                            nested_mdb_entry[MDB.MDBA_MDB_ENTRY] = info
                            mdb_entry[MDB.MDBA_MDB_ENTRY].append(nested_mdb_entry)
                        sub_attr_data = sub_attr_data[nested_attr_end:]
                self.value.append(mdb_entry)
                data = data[sub_attr_end:]

        else:
            self.value = {}
            while data:
                (sub_attr_length, sub_attr_type) = unpack('=HH', data[:4])
                sub_attr_end = padded_length(sub_attr_length)
                sub_attr_data = data[4:]
                if not sub_attr_length:
                    self.log.error('parsed a zero length sub-attr')
                    return

                if sub_attr_type == MDB.MDBA_MDB_ENTRY:
                    (nested_attr_length,nested_attr_type) = unpack('=HH',sub_attr_data[:4])
                    if nested_attr_type == MDB.MDBA_MDB_ENTRY_INFO:
                        self.value[MDB.MDBA_MDB_ENTRY] = {}
                        (ifindex,state,flags,vid) = unpack('=LBBH',sub_attr_data[4:12])
                        info = (ifindex,state,flags,vid)
                        info = list(info)
                        proto = unpack('=H',sub_attr_data[28:30])[0]
                        if proto == 8:
                            ip_addr = ipnetwork.IPv4Address(unpack('>L', sub_attr_data[12:16])[0])
                        else:
                            (data1, data2) = unpack('>QQ',sub_attr_data[12:28])
                            ip_addr        = ipnetwork.IPv6Address(data1 << 64 | data2)

                        info.append(ip_addr)
                        self.value[MDB.MDBA_MDB_ENTRY][MDB.MDBA_MDB_ENTRY_INFO] = info
                data = data[sub_attr_end:]

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)

        dump_buffer.append(data_to_color_text(line_number, color, self.data[0:4], self.value))
        return line_number + 1



class AttributeMDBA_ROUTER(Attribute):
    """
    /*
     * [MDBA_ROUTER] = {
     *    [MDBA_ROUTER_PORT] = {
     *        u32 ifindex
     *        [MDBA_ROUTER_PATTR attributes]
     *    }
     * }
     */
     """

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        data = self.data[4:]
        if parent_msg.msgtype == RTM_GETMDB:
            self.value = []
            while data:
                (sub_attr_length, sub_attr_type) = unpack('=HH', data[:4])
                sub_attr_end = padded_length(sub_attr_length)
                sub_attr_data = data[4:sub_attr_end]
                router_entry = {}

                if not sub_attr_length:
                    self.log.error('parsed a zero length sub-attr')
                    return

                if sub_attr_type == MDB.MDBA_ROUTER_PORT:
                    ifindex = unpack('=I',sub_attr_data[:4])[0]
                    sub_attr_data = sub_attr_data[4:]
                    timer_info = {}
                    type_info  = {}
                    while sub_attr_data:
                        (nested_sub_attr_length, nested_sub_attr_type) = unpack('=HH',sub_attr_data[:4])
                        nested_sub_attr_data = sub_attr_data[4:]
                        nested_sub_attr_end = padded_length(nested_sub_attr_length)
                        if nested_sub_attr_type == MDB.MDBA_ROUTER_PATTR_TIMER:
                            timer_info[MDB.MDBA_ROUTER_PATTR_TIMER] = (unpack('=L',nested_sub_attr_data[ :4])[0])*0.01
                        elif nested_sub_attr_type == MDB.MDBA_ROUTER_PATTR_TYPE:
                            type_info[MDB.MDBA_ROUTER_PATTR_TYPE] = unpack('=B',nested_sub_attr_data[:1])[0]
                        else:
                            raise Exception("Invalid Router Port Attribute")
                        sub_attr_data = sub_attr_data[nested_sub_attr_end:]
                    router_entry[MDB.MDBA_ROUTER_PORT] = [ifindex,timer_info,type_info]

                self.value.append(router_entry)
                data = data[sub_attr_end:]

        else:
            self.value = {}
            while data:
                (sub_attr_length, sub_attr_type) = unpack('=HH', data[:4])
                sub_attr_end = padded_length(sub_attr_length)
                sub_attr_data = data[4:]

                if not sub_attr_length:
                    self.log.error('parsed a zero length sub-attr')
                    return

                if sub_attr_type == MDB.MDBA_ROUTER_PORT:
                    ifindex = unpack('=L',sub_attr_data[:4])[0]
                self.value[MDB.MDBA_ROUTER_PORT] = ifindex
                data = data[sub_attr_end:]

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)

        dump_buffer.append(data_to_color_text(line_number, color, self.data[0:4], self.value))
        return line_number + 1


class AttributeMDBA_SET_ENTRY(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = None
        self.LEN  = None

    def set_value(self, value):
        self.value = value


    def encode(self):
        if self.value:
            (ifindex, flags, state,vid, ip, proto) = self.value
            if proto == htons(ETH_P_IP):
                self.PACK = '=IBBHLxxxxxxxxxxxxHxx'
                reorder = unpack('<L', ip.packed)[0]
                ip = ipnetwork.IPv4Address(reorder)

                self.LEN = calcsize(self.PACK)
                length = self.HEADER_LEN + self.LEN
                #TODO Please check the encoding for Ipv6
                raw = pack(self.HEADER_PACK, length, self.atype) + pack(self.PACK, ifindex, flags, state, vid, ip, proto)
            elif proto == htons(ETH_P_IPV6):
                self.PACK = '=IBBHQQHxx'
                (data1, data2) = unpack('<QQ', ip.packed)
                self.LEN = calcsize(self.PACK)
                length = self.HEADER_LEN + self.LEN
                raw = pack(self.HEADER_PACK, length, self.atype) + pack(self.PACK, ifindex, flags, state, vid, data1,data2, proto)

            else:
                raise Exception("%d Invalid Proto" % proto)
            raw = self.pad(length, raw)
            return raw


    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        if self.length == 32:
            proto = unpack('=H', data[28:30])[0]
            if proto == htons(ETH_P_IP):
                self.PACK = '=IBBHLxxxxxxxxxxxxHxx'
                (ifindex, flags, state,vid, ip, proto) = unpack(self.PACK, self.data[4:])
            elif proto == htons(ETH_P_IPV6):
                self.PACK = '=IBBHQQHxx'
                (ifindex, flags, state,vid, data1,data2, proto) = unpack(self.PACK, self.data[4:])
                ip = ipnetwork.IPv6Address(data1 << 64 | data2)
            else:
                raise Exception("%d Invalid Proto" % proto)
            self.LEN = calcsize(self.PACK)
            self.value = (ifindex, flags, state,vid, ip, proto)
        else:
            raise Exception("Invalid Attribute Length")



class MDB(NetlinkPacket):
    """
    Service Header
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Family    |    Reserved1  |           Reserved2           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Interface Index                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    struct br_port_msg {
    __u8  family;
    __u32 ifindex;
    };

    RTM_GETMDB - Service Header

    /* Bridge multicast database attributes
     * [MDBA_MDB] = {
     *     [MDBA_MDB_ENTRY] = {
     *         [MDBA_MDB_ENTRY_INFO] {
     *                struct br_mdb_entry
     *                [MDBA_MDB_EATTR attributes]
     *         }
     *     }
     * }
     * [MDBA_ROUTER] = {
     *    [MDBA_ROUTER_PORT] = {
     *        u32 ifindex
     *        [MDBA_ROUTER_PATTR attributes]
     *    }
     * }
     */

     struct br_mdb_entry {
            __u32 ifindex;
        #define MDB_TEMPORARY 0
        #define MDB_PERMANENT 1
            __u8 state;
        #define MDB_FLAGS_OFFLOAD      (1 << 0)
        #define MDB_FLAGS_FAST_LEAVE   (1 << 1)
            __u8 flags;
            __u16 vid;
            struct {
                union {
                    __be32    ip4;
                    struct in6_addr ip6;
                } u;
                __be16        proto;
            } addr;
        };
    """
    MDBA_UNSPEC = 0
    MDBA_MDB    = 1
    MDBA_ROUTER = 2
    __MDBA_MAX  = 3
    MDBA_MAX    = (__MDBA_MAX - 1)

    #MDBA Set Attributes
    MDBA_SET_ENTRY_UNSPEC  = 0
    MDBA_SET_ENTRY         = 1
    __MDBA_SET_ENTRY_MAX   = 2
    MDBA_SET_ENTRY_MAX = (__MDBA_SET_ENTRY_MAX - 1)

    #MDBA flags
    MDB_FLAGS_OFFLOAD       = 1 << 0
    MDB_FLAGS_FAST_LEAVE    = 1 << 1

    #MDBA Attributes
    MDBA_MDB_UNSPEC = 0
    MDBA_MDB_ENTRY  = 1
    __MDBA_MDB_MAX  = 2
    MDBA_MDB_MAX    = (__MDBA_MDB_MAX - 1)

    MDBA_MDB_ENTRY_UNSPEC   = 0
    MDBA_MDB_ENTRY_INFO     = 1
    __MDBA_MDB_ENTRY_MAX    = 2
    MDBA_MDB_ENTRY_MAX      = (__MDBA_MDB_ENTRY_MAX - 1)

    MDBA_MDB_EATTR_UNSPEC   = 0
    MDBA_MDB_EATTR_TIMER    = 1
    __MDBA_MDB_EATTR_MAX    = 2
    MDBA_MDB_ENTRY_MAX            = (__MDBA_MDB_EATTR_MAX -1)

    # router port attributes
    MDBA_ROUTER_UNSPEC  = 0
    MDBA_ROUTER_PORT    = 1
    __MDBA_ROUTER_MAX   = 2
    MDBA_ROUTER_MAX     = (__MDBA_ROUTER_MAX - 1)


    MDBA_ROUTER_PATTR_UNSPEC    = 0
    MDBA_ROUTER_PATTR_TIMER     = 1
    MDBA_ROUTER_PATTR_TYPE      = 2
    __MDBA_ROUTER_PATTR_MAX     = 3
    MDBA_ROUTER_PATTR_MAX       = (__MDBA_ROUTER_PATTR_MAX - 1)

    MDB_RTR_TYPE_DISABLED = 0
    MDB_RTR_TYPE_TEMP_QUERY = 1
    MDB_RTR_TYPE_PERM = 2
    MDB_RTR_TYPE_TEMP = 3


    def __init__(self, msgtype, debug=False, logger=None, use_color=True, rx=False, tx=False):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color, rx, tx)
        if self.tx and msgtype in (RTM_NEWMDB, RTM_DELMDB):
            self.attribute_to_class = {
                self.MDBA_UNSPEC: ('MDBA_SET_ENTRY_UNSPEC', AttributeGeneric),
                self.MDBA_SET_ENTRY: ('MDBA_SET_ENTRY', AttributeMDBA_SET_ENTRY),
        }
        else:
            self.attribute_to_class = {
                self.MDBA_UNSPEC: ('MDBA_UNSPEC', AttributeGeneric),
                self.MDBA_MDB: ('MDBA_MDB', AttributeMDBA_MDB),
                self.MDBA_ROUTER: ('MDBA_ROUTER', AttributeMDBA_ROUTER),
            }

        self.PACK = 'Bxxxi'
        self.LEN  = calcsize(self.PACK)

    def decode_service_header(self):
        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.family,self.ifindex) = unpack(self.PACK, self.msg_data[:self.LEN])
        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))
            self.dump_buffer.append(self.msg_data)
            self.dump_buffer.append(data_to_color_text(1, color, bytearray(struct.pack('!I', self.family)),
                                              "Family %s (%d)" % (zfilled_hex(self.family, 2), self.family)))
            self.dump_buffer.append(data_to_color_text(2, color, bytearray(struct.pack('i', self.ifindex)),
                                              "Ifindex %s (%d)" % (zfilled_hex(self.ifindex, 8), self.ifindex)))

class Netconf(Link):
    """
    RTM_NEWNETCONF - Service Header

    0               1
    0 1 2 3 4 5 6 7 8
    +-+-+-+-+-+-+-+-+
    |   Family      |
    +-+-+-+-+-+-+-+-+

    RTM_GETNETCONF - Service Header

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Family    |   Reserved  |          Device Type              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Interface Index                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Device Flags                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Change Mask                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    # Netconf attributes
    # /usr/include/linux/netconf.h
    NETCONFA_UNSPEC                         = 0
    NETCONFA_IFINDEX                        = 1
    NETCONFA_FORWARDING                     = 2
    NETCONFA_RP_FILTER                      = 3
    NETCONFA_MC_FORWARDING                  = 4
    NETCONFA_PROXY_NEIGH                    = 5
    NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN    = 6
    NETCONFA_INPUT                          = 7
    NETCONFA_BC_FORWARDING                  = 8
    __NETCONFA_MAX                          = 9

    NETCONFA_MAX                            = (__NETCONFA_MAX - 1)

    NETCONFA_ALL                            = -1
    NETCONFA_IFINDEX_ALL                    = -1
    NETCONFA_IFINDEX_DEFAULT                = -2

    NETCONF_ATTR_FAMILY = 0x0001
    NETCONF_ATTR_IFINDEX = 0x0002
    NETCONF_ATTR_RP_FILTER = 0x0004
    NETCONF_ATTR_FWDING	= 0x0008
    NETCONF_ATTR_MC_FWDING = 0x0010
    NETCONF_ATTR_PROXY_NEIGH = 0x0020
    NETCONF_ATTR_IGNORE_RT_LINKDWN = 0x0040

    attribute_to_class = {
        NETCONFA_UNSPEC                         : ('NETCONFA_UNSPEC', AttributeGeneric),
        NETCONFA_IFINDEX                        : ('NETCONFA_IFINDEX', AttributeFourByteValue),
        NETCONFA_FORWARDING                     : ('NETCONFA_FORWARDING', AttributeFourByteValue),
        NETCONFA_RP_FILTER                      : ('NETCONFA_RP_FILTER', AttributeFourByteValue),
        NETCONFA_MC_FORWARDING                  : ('NETCONFA_MC_FORWARDING', AttributeFourByteValue),
        NETCONFA_PROXY_NEIGH                    : ('NETCONFA_PROXY_NEIGH', AttributeFourByteValue),
        NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN    : ('NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN', AttributeFourByteValue),
        NETCONFA_INPUT                          : ('NETCONFA_INPUT', AttributeFourByteValue),
        NETCONFA_BC_FORWARDING                  : ('NETCONFA_BC_FORWARDING', AttributeFourByteValue),
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        if msgtype == RTM_GETNETCONF:  # same as RTM_GETLINK
            self.PACK = 'BxHiII'
            self.LEN  = calcsize(self.PACK)
        else:
            # RTM_NEWNETCONF
            # RTM_DELNETCONF
            self.PACK = 'Bxxx'
            self.LEN  = calcsize(self.PACK)

    def decode_service_header(self):
        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        if self.msgtype == RTM_GETNETCONF:
            super(Netconf, self).decode_service_header()

        else:
            # RTM_NEWNETCONF
            # RTM_DELNETCONF
            (self.family,) = unpack(self.PACK, self.msg_data[:self.LEN])

            if self.debug:
                color = yellow if self.use_color else None
                color_start = "\033[%dm" % color if color else ""
                color_end = "\033[0m" if color else ""
                self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))
                self.dump_buffer.append(data_to_color_text(1, color, bytearray(struct.pack('!I', self.family)), "Family %s (%s:%d)" % (zfilled_hex(self.family, 2), get_family_str(self.family), self.family)))


class Neighbor(NetlinkPacket):
    """
    Service Header

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Family    |    Reserved1  |           Reserved2           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Interface Index                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           State             |     Flags     |     Type      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    # Neighbor attributes
    # /usr/include/linux/neighbour.h
    NDA_UNSPEC       = 0x00  # Unknown type
    NDA_DST          = 0x01  # A neighbour cache network. layer destination address
    NDA_LLADDR       = 0x02  # A neighbor cache link layer address.
    NDA_CACHEINFO    = 0x03  # Cache statistics
    NDA_PROBES       = 0x04
    NDA_VLAN         = 0x05
    NDA_PORT         = 0x06
    NDA_VNI          = 0x07
    NDA_IFINDEX      = 0x08
    NDA_MASTER       = 0x09
    NDA_LINK_NETNSID = 0x0A

    attribute_to_class = {
        NDA_UNSPEC       : ('NDA_UNSPEC', AttributeGeneric),
        NDA_DST          : ('NDA_DST', AttributeIPAddressNoMask),
        NDA_LLADDR       : ('NDA_LLADDR', AttributeMACAddress),
        NDA_CACHEINFO    : ('NDA_CACHEINFO', AttributeFourByteList),
        NDA_PROBES       : ('NDA_PROBES', AttributeFourByteValue),
        NDA_VLAN         : ('NDA_VLAN', AttributeTwoByteValue),
        NDA_PORT         : ('NDA_PORT', AttributeGeneric),
        NDA_VNI          : ('NDA_VNI', AttributeFourByteValue),
        NDA_IFINDEX      : ('NDA_IFINDEX', AttributeFourByteValue),
        NDA_MASTER       : ('NDA_MASTER', AttributeFourByteValue),
        NDA_LINK_NETNSID : ('NDA_LINK_NETNSID', AttributeGeneric)
    }

    # Neighbor flags
    # /usr/include/linux/neighbour.h
    NTF_USE         = 0x01
    NTF_SELF        = 0x02
    NTF_MASTER      = 0x04
    NTF_PROXY       = 0x08  # A proxy ARP entry
    NTF_EXT_LEARNED = 0x10  # neigh entry installed by an external APP
    NTF_ROUTER      = 0x80  # An IPv6 router

    flag_to_string = {
        NTF_USE          : 'NTF_USE',
        NTF_SELF         : 'NTF_SELF',
        NTF_MASTER       : 'NTF_MASTER',
        NTF_PROXY        : 'NTF_PROXY',
        NTF_EXT_LEARNED  : 'NTF_EXT_LEARNED',
        NTF_ROUTER       : 'NTF_ROUTER'
    }

    # Neighbor states
    # /usr/include/linux/neighbour.h
    NUD_NONE       = 0x00
    NUD_INCOMPLETE = 0x01  # Still attempting to resolve
    NUD_REACHABLE  = 0x02  # A confirmed working cache entry
    NUD_STALE      = 0x04  # an expired cache entry
    NUD_DELAY      = 0x08  # Neighbor no longer reachable.  Traffic sent, waiting for confirmatio.
    NUD_PROBE      = 0x10  # A cache entry that is currently being re-solicited
    NUD_FAILED     = 0x20  # An invalid cache entry
    NUD_NOARP      = 0x40  # A device which does not do neighbor discovery(ARP)
    NUD_PERMANENT  = 0x80  # A static entry

    state_to_string = {
        NUD_NONE       : 'NUD_NONE',
        NUD_INCOMPLETE : 'NUD_INCOMPLETE',
        NUD_REACHABLE  : 'NUD_REACHABLE',
        NUD_STALE      : 'NUD_STALE',
        NUD_DELAY      : 'NUD_DELAY',
        NUD_PROBE      : 'NUD_PROBE',
        NUD_FAILED     : 'NUD_FAILED',
        NUD_NOARP      : 'NUD_NOARP',
        NUD_PERMANENT  : 'NUD_PERMANENT'
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = 'BxxxiHBB'
        self.LEN = calcsize(self.PACK)

    def get_state_string(self, index):
        return self.get_string(self.state_to_string, index)

    def get_states_string(self, states):
        for_string = []

        if states & Neighbor.NUD_INCOMPLETE:
            for_string.append('NUD_INCOMPLETE')

        if states & Neighbor.NUD_REACHABLE:
            for_string.append('NUD_REACHABLE')

        if states & Neighbor.NUD_STALE:
            for_string.append('NUD_STALE')

        if states & Neighbor.NUD_DELAY:
            for_string.append('NUD_DELAY')

        if states & Neighbor.NUD_PROBE:
            for_string.append('NUD_PROBE')

        if states & Neighbor.NUD_FAILED:
            for_string.append('NUD_FAILED')

        if states & Neighbor.NUD_NOARP:
            for_string.append('NUD_NOARP')

        if states & Neighbor.NUD_PERMANENT:
            for_string.append('NUD_PERMANENT')

        return ', '.join(for_string)

    def get_flags_string(self, flags):
        for_string = []

        if flags & Neighbor.NTF_USE:
            for_string.append('NTF_USE')

        if flags & Neighbor.NTF_SELF:
            for_string.append('NTF_SELF')

        if flags & Neighbor.NTF_MASTER:
            for_string.append('NTF_MASTER')

        if flags & Neighbor.NTF_PROXY:
            for_string.append('NTF_PROXY')

        if flags & Neighbor.NTF_ROUTER:
            for_string.append('NTF_ROUTER')

        return ', '.join(for_string)

    def decode_service_header(self):

        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.family,
         self.ifindex,
         self.state, self.flags, self.neighbor_type) = \
            unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN//4):
                if self.line_number == 5:
                    extra = "Family %s (%s:%d)" % (zfilled_hex(self.family, 2), get_family_str(self.family), self.family)
                elif self.line_number == 6:
                    extra = "Interface Index %s (%d)" % (zfilled_hex(self.ifindex, 8), self.ifindex)
                elif self.line_number == 7:
                    extra = "State %s (%d) %s, Flags %s (%s) %s, Type %s (%d)" % \
                        (zfilled_hex(self.state, 4), self.state, self.get_states_string(self.state),
                         zfilled_hex(self.flags, 2), self.flags, self.get_flags_string(self.flags),
                         zfilled_hex(self.neighbor_type, 4), self.neighbor_type)
                else:
                    extra = "Unexpected line number %d" % self.line_number

                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1


class Route(NetlinkPacket):
    """
    Service Header

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Family    |  Dest length  |   Src length  |     TOS       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Table ID   |   Protocol    |     Scope     |     Type      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Flags                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    # Route attributes
    # /usr/include/linux/rtnetlink.h
    RTA_UNSPEC    = 0x00  # Ignored.
    RTA_DST       = 0x01  # Protocol address for route destination address.
    RTA_SRC       = 0x02  # Protocol address for route source address.
    RTA_IIF       = 0x03  # Input interface index.
    RTA_OIF       = 0x04  # Output interface index.
    RTA_GATEWAY   = 0x05  # Protocol address for the gateway of the route
    RTA_PRIORITY  = 0x06  # Priority of broker.
    RTA_PREFSRC   = 0x07  # Preferred source address in cases where more than one source address could be used.
    RTA_METRICS   = 0x08  # Route metrics attributed to route and associated protocols(e.g., RTT, initial TCP window, etc.).
    RTA_MULTIPATH = 0x09  # Multipath route next hop's attributes.
    RTA_PROTOINFO = 0x0A  # Firewall based policy routing attribute.
    RTA_FLOW      = 0x0B  # Route realm.
    RTA_CACHEINFO = 0x0C  # Cached route information.
    RTA_SESSION   = 0x0D
    RTA_MP_ALGO   = 0x0E
    RTA_TABLE     = 0x0F
    RTA_MARK      = 0x10
    RTA_MFC_STATS = 0x11
    RTA_VIA       = 0x12
    RTA_NEWDST    = 0x13
    RTA_PREF      = 0x14
    RTA_ENCAP_TYPE= 0x15
    RTA_ENCAP     = 0x16

    attribute_to_class = {
        RTA_UNSPEC    : ('RTA_UNSPEC', AttributeGeneric),
        RTA_DST       : ('RTA_DST', AttributeIPAddress),
        RTA_SRC       : ('RTA_SRC', AttributeIPAddress),
        RTA_IIF       : ('RTA_IIF', AttributeFourByteValue),
        RTA_OIF       : ('RTA_OIF', AttributeFourByteValue),
        RTA_GATEWAY   : ('RTA_GATEWAY', AttributeIPAddress),
        RTA_PRIORITY  : ('RTA_PRIORITY', AttributeFourByteValue),
        RTA_PREFSRC   : ('RTA_PREFSRC', AttributeIPAddress),
        RTA_METRICS   : ('RTA_METRICS', AttributeGeneric),
        RTA_MULTIPATH : ('RTA_MULTIPATH', AttributeRTA_MULTIPATH),
        RTA_PROTOINFO : ('RTA_PROTOINFO', AttributeGeneric),
        RTA_FLOW      : ('RTA_FLOW', AttributeGeneric),
        RTA_CACHEINFO : ('RTA_CACHEINFO', AttributeGeneric),
        RTA_SESSION   : ('RTA_SESSION', AttributeGeneric),
        RTA_MP_ALGO   : ('RTA_MP_ALGO', AttributeGeneric),
        RTA_TABLE     : ('RTA_TABLE', AttributeFourByteValue),
        RTA_MARK      : ('RTA_MARK', AttributeGeneric),
        RTA_MFC_STATS : ('RTA_MFC_STATS', AttributeGeneric),
        RTA_VIA       : ('RTA_VIA', AttributeGeneric),
        RTA_NEWDST    : ('RTA_NEWDST', AttributeGeneric),
        RTA_PREF      : ('RTA_PREF', AttributeGeneric),
        RTA_ENCAP_TYPE: ('RTA_ENCAP_TYPE', AttributeGeneric),
        RTA_ENCAP     : ('RTA_ENCAP', AttributeGeneric)
    }

    # Route tables
    # /usr/include/linux/rtnetlink.h
    RT_TABLE_UNSPEC  = 0x00  # An unspecified routing table
    RT_TABLE_COMPAT  = 0xFC
    RT_TABLE_DEFAULT = 0xFD  # The default table
    RT_TABLE_MAIN    = 0xFE  # The main table
    RT_TABLE_LOCAL   = 0xFF  # The local table

    table_to_string = {
        RT_TABLE_UNSPEC  : 'RT_TABLE_UNSPEC',
        RT_TABLE_COMPAT  : 'RT_TABLE_COMPAT',
        RT_TABLE_DEFAULT : 'RT_TABLE_DEFAULT',
        RT_TABLE_MAIN    : 'RT_TABLE_MAIN',
        RT_TABLE_LOCAL   : 'RT_TABLE_LOCAL'
    }

    # Route scope
    # /usr/include/linux/rtnetlink.h
    RT_SCOPE_UNIVERSE = 0x00  # Global route
    RT_SCOPE_SITE     = 0xC8  # Interior route in the local autonomous system
    RT_SCOPE_LINK     = 0xFD  # Route on this link
    RT_SCOPE_HOST     = 0xFE  # Route on the local host
    RT_SCOPE_NOWHERE  = 0xFF  # Destination does not exist

    scope_to_string = {
        RT_SCOPE_UNIVERSE : 'RT_SCOPE_UNIVERSE',
        RT_SCOPE_SITE     : 'RT_SCOPE_SITE',
        RT_SCOPE_LINK     : 'RT_SCOPE_LINK',
        RT_SCOPE_HOST     : 'RT_SCOPE_HOST',
        RT_SCOPE_NOWHERE  : 'RT_SCOPE_NOWHERE'
    }

    # Route scope to string
    # iproute2/lib/rt_names.c
    rtnl_rtscope_tab = {
        RT_SCOPE_UNIVERSE: 'global',
        RT_SCOPE_NOWHERE: 'nowhere',
        RT_SCOPE_HOST: 'host',
        RT_SCOPE_LINK: 'link',
        RT_SCOPE_SITE: 'site'
    }

    # Routing stack
    # /usr/include/linux/rtnetlink.h
    RT_PROT_UNSPEC   = 0x00  # Identifies what/who added the route
    RT_PROT_REDIRECT = 0x01  # By an ICMP redirect
    RT_PROT_KERNEL   = 0x02  # By the kernel
    RT_PROT_BOOT     = 0x03  # During bootup
    RT_PROT_STATIC   = 0x04  # By the administrator
    RT_PROT_GATED    = 0x08  # GateD
    RT_PROT_RA       = 0x09  # RDISC/ND router advertissements
    RT_PROT_MRT      = 0x0A  # Merit MRT
    RT_PROT_ZEBRA    = 0x0B  # ZEBRA
    RT_PROT_BIRD     = 0x0C  # BIRD
    RT_PROT_DNROUTED = 0x0D  # DECnet routing daemon
    RT_PROT_XORP     = 0x0E  # XORP
    RT_PROT_NTK      = 0x0F  # Netsukuku
    RT_PROT_DHCP     = 0x10  # DHCP client
    RT_PROT_EXABGP   = 0x11  # Exa Networks ExaBGP

    prot_to_string = {
        RT_PROT_UNSPEC   : 'RT_PROT_UNSPEC',
        RT_PROT_REDIRECT : 'RT_PROT_REDIRECT',
        RT_PROT_KERNEL   : 'RT_PROT_KERNEL',
        RT_PROT_BOOT     : 'RT_PROT_BOOT',
        RT_PROT_STATIC   : 'RT_PROT_STATIC',
        RT_PROT_GATED    : 'RT_PROT_GATED',
        RT_PROT_RA       : 'RT_PROT_RA',
        RT_PROT_MRT      : 'RT_PROT_MRT',
        RT_PROT_ZEBRA    : 'RT_PROT_ZEBRA',
        RT_PROT_BIRD     : 'RT_PROT_BIRD',
        RT_PROT_DNROUTED : 'RT_PROT_DNROUTED',
        RT_PROT_XORP     : 'RT_PROT_XORP',
        RT_PROT_NTK      : 'RT_PROT_NTK',
        RT_PROT_DHCP     : 'RT_PROT_DHCP',
        RT_PROT_EXABGP   : 'RT_PROT_EXABGP'
    }

    # Route types
    # /usr/include/linux/rtnetlink.h
    RTN_UNSPEC      = 0x00  # Unknown broker.
    RTN_UNICAST     = 0x01  # A gateway or direct broker.
    RTN_LOCAL       = 0x02  # A local interface broker.
    RTN_BROADCAST   = 0x03  # A local broadcast route(sent as a broadcast).
    RTN_ANYCAST     = 0x04  # An anycast broker.
    RTN_MULTICAST   = 0x05  # A multicast broker.
    RTN_BLACKHOLE   = 0x06  # A silent packet dropping broker.
    RTN_UNREACHABLE = 0x07  # An unreachable destination.  Packets dropped and
                            # host unreachable ICMPs are sent to the originator.
    RTN_PROHIBIT    = 0x08  # A packet rejection broker.  Packets are dropped and
                            # communication prohibited ICMPs are sent to the originator.
    RTN_THROW       = 0x09  # When used with policy routing, continue routing lookup
                            # in another table.  Under normal routing, packets are
                            # dropped and net unreachable ICMPs are sent to the originator.
    RTN_NAT         = 0x0A  # A network address translation rule.
    RTN_XRESOLVE    = 0x0B  # Refer to an external resolver(not implemented).

    rt_type_to_string = {
        RTN_UNSPEC      : 'RTN_UNSPEC',
        RTN_UNICAST     : 'RTN_UNICAST',
        RTN_LOCAL       : 'RTN_LOCAL',
        RTN_BROADCAST   : 'RTN_BROADCAST',
        RTN_ANYCAST     : 'RTN_ANYCAST',
        RTN_MULTICAST   : 'RTN_MULTICAST',
        RTN_BLACKHOLE   : 'RTN_BLACKHOLE',
        RTN_UNREACHABLE : 'RTN_UNREACHABLE',
        RTN_PROHIBIT    : 'RTN_PROHIBIT',
        RTN_THROW       : 'RTN_THROW',
        RTN_NAT         : 'RTN_NAT',
        RTN_XRESOLVE    : 'RTN_XRESOLVE'
    }

    # Route flags
    # /usr/include/linux/rtnetlink.h
    RTM_F_NOTIFY   = 0x100  # If the route changes, notify the user
    RTM_F_CLONED   = 0x200  # Route is cloned from another route
    RTM_F_EQUALIZE = 0x400  # Allow randomization of next hop path in multi-path routing(currently not implemented)
    RTM_F_PREFIX   = 0x800  # Prefix Address

    flag_to_string = {
        RTM_F_NOTIFY   : 'RTM_F_NOTIFY',
        RTM_F_CLONED   : 'RTM_F_CLONED',
        RTM_F_EQUALIZE : 'RTM_F_EQUALIZE',
        RTM_F_PREFIX   : 'RTM_F_PREFIX'
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = '=8BI'  # or is it 8Bi ?
        self.LEN = calcsize(self.PACK)

    def get_prefix_string(self):
        dst = self.get_attribute_value(self.RTA_DST)

        if dst:
            return "%s" % dst
        else:
            if self.family == AF_INET:
                return "0.0.0.0/0"
            elif self.family == AF_INET6:
                return "::/0"

    def get_protocol_string(self, index=None):
        if index is None:
            index = self.protocol
        return self.get_string(self.prot_to_string, index)

    def get_rt_type_string(self, index=None):
        if index is None:
            index = self.route_type
        return self.get_string(self.rt_type_to_string, index)

    def get_scope_string(self, index=None):
        if index is None:
            index = self.scope
        return self.get_string(self.scope_to_string, index)

    def get_table_id_string(self, index=None):
        if index is None:
            index = self.table_id
        return self.get_string(self.table_to_string, index)

    def _get_ifname_from_index(self, ifindex, ifname_by_index):
        if ifindex:
            ifname = ifname_by_index.get(ifindex)

            if ifname is None:
                ifname = str(ifindex)
        else:
            ifname = None

        return ifname

    def get_nexthops(self, ifname_by_index={}):
        nexthop = self.get_attribute_value(self.RTA_GATEWAY)
        multipath = self.get_attribute_value(self.RTA_MULTIPATH)
        nexthops = []

        if nexthop:
            rta_oif = self.get_attribute_value(self.RTA_OIF)
            ifname = self._get_ifname_from_index(rta_oif, ifname_by_index)
            nexthops.append((nexthop, ifname))

        elif multipath:
            for (nexthop, rtnh_ifindex, rtnh_flags, rtnh_hops) in multipath:
                ifname = self._get_ifname_from_index(rtnh_ifindex, ifname_by_index)
                nexthops.append((nexthop, ifname))

        return nexthops

    def get_nexthops_string(self, ifname_by_index={}):
        output = []

        for (nexthop, ifname) in self.get_nexthops(ifname_by_index):
            output.append(" via %s on %s" % (nexthop, ifname))

        return ",".join(output)

    def decode_service_header(self):

        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.family, self.src_len, self.dst_len, self.tos,
         self.table_id, self.protocol, self.scope, self.route_type,
         self.flags) = \
            unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN//4):
                if self.line_number == 5:
                    extra = "Family %s (%s:%d), Source Length %s (%d), Destination Length %s (%d), TOS %s (%d)" % \
                            (zfilled_hex(self.family, 2), get_family_str(self.family), self.family,
                             zfilled_hex(self.src_len, 2), self.src_len,
                             zfilled_hex(self.dst_len, 2), self.dst_len,
                             zfilled_hex(self.tos, 2), self.tos)
                elif self.line_number == 6:
                    extra = "Table ID %s (%d - %s), Protocol %s (%d - %s), Scope %s (%d - %s), Type %s (%d - %s)" % \
                            (zfilled_hex(self.table_id, 2), self.table_id, self.get_table_id_string(),
                             zfilled_hex(self.protocol, 2), self.protocol, self.get_protocol_string(),
                             zfilled_hex(self.scope, 2), self.scope, self.get_scope_string(),
                             zfilled_hex(self.route_type, 2), self.route_type, self.get_rt_type_string())
                elif self.line_number == 7:
                    extra = "Flags %s" % zfilled_hex(self.flags, 8)
                else:
                    extra = "Unexpected line number %d" % self.line_number

                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1


class Done(NetlinkPacket):
    """
    NLMSG_DONE

    Service Header
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             TBD                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = 'i'
        self.LEN = calcsize(self.PACK)

    def decode_service_header(self):
        foo = unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN//4):
                extra = ''
                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1
