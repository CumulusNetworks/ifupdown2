#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import re
import json
import time
import itertools
from collections import Counter

try:
    from ifupdown2.lib.addon import Bridge, AddonException

    import ifupdown2.ifupdown.exceptions as exceptions
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    from ifupdown2.ifupdown.statemanager import statemanager_api as statemanager

    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdown.iface import ifaceRole, ifaceLinkKind, ifaceLinkPrivFlags, ifaceLinkType, ifaceDependencyType, ifaceStatus, iface
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    from lib.addon import Bridge, AddonException

    import ifupdown.exceptions as exceptions
    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags
    from ifupdown.statemanager import statemanager_api as statemanager

    from nlmanager.nlmanager import Link

    from ifupdown.iface import ifaceRole, ifaceLinkKind, ifaceLinkPrivFlags, ifaceLinkType, ifaceDependencyType, ifaceStatus, iface
    from ifupdown.utils import utils

    from ifupdownaddons.modulebase import moduleBase


class BridgeFlags:
    PORT_PROCESSED = 0x1
    PORT_PROCESSED_OVERRIDE = 0x2


class BridgeVlanVniMapError(Exception):
    pass


class bridge(Bridge, moduleBase):
    """  ifupdown2 addon module to configure linux bridges """

    _modinfo = {
        "mhelp": "Bridge configuration module. Supports both vlan aware and non "
                 "vlan aware bridges. For the vlan aware bridge, the port "
                 "specific attributes must be specified under the port. And for "
                 "vlan unaware bridge port specific attributes must be specified "
                 "under the bridge.",
        "attrs": {
            "bridge-vlan-aware": {
                "help": "vlan aware bridge. Setting this "
                        "attribute to yes enables vlan filtering"
                        " on the bridge",
                "validvals": ["yes", "no"],
                "example": ["bridge-vlan-aware yes/no"],
                "default": "no"
            },
            "bridge-ports": {
                "help": "bridge ports",
                "multivalue": True,
                "required": True,
                "validvals": ["<interface-list>", "none"],
                "example": [
                    "bridge-ports swp1.100 swp2.100 swp3.100",
                    "bridge-ports glob swp1-3.100",
                    "bridge-ports regex (swp[1|2|3].100)"
                ]
            },
            "bridge-stp": {
                "help": "bridge-stp yes/no",
                "example": ["bridge-stp no"],
                "validvals": ["yes", "on", "off", "no"],
                "default": "no"
            },
            "bridge-bridgeprio": {
                "help": "bridge priority",
                "validrange": ["0", "65535"],
                "example": ["bridge-bridgeprio 32768"],
                "default": "32768"
            },
            "bridge-ageing": {
                "help": "bridge ageing",
                "validrange": ["0", "65535"],
                "example": ["bridge-ageing 300"],
                "default": "300"
            },
            "bridge-fd": {
                "help": "bridge forward delay",
                "validrange": ["2", "255"],
                "example": ["bridge-fd 15"],
                "default": "15"
            },
            # XXX: recheck values
            "bridge-gcint": {
                "help": "bridge garbage collection interval in secs",
                "validrange": ["0", "255"],
                "example": ["bridge-gcint 4"],
                "default": "4",
                "compat": True,
                "deprecated": True
            },
            "bridge-hello": {
                "help": "bridge set hello time",
                "validrange": ["0", "255"],
                "example": ["bridge-hello 2"],
                "default": "2"
            },
            "bridge-maxage": {
                "help": "bridge set maxage",
                "validrange": ["0", "255"],
                "example": ["bridge-maxage 20"],
                "default": "20"
            },
            "bridge-pathcosts": {
                "help": "bridge set port path costs",
                "validvals": ["<interface-range-list>"],
                "validrange": ["0", "65535"],
                "example": [
                    "under the port (for vlan aware bridge): bridge-pathcosts 100",
                    "under the bridge (for vlan unaware bridge): bridge-pathcosts swp1=100 swp2=100"
                ],
                "default": "100"
            },
            "bridge-portprios": {
                "help": "bridge port prios",
                "validvals": ["<interface-range-list>"],
                "validrange": ["0", "65535"],
                "example": [
                    "under the port (for vlan aware bridge): bridge-portprios 32",
                    "under the bridge (for vlan unaware bridge): bridge-portprios swp1=32 swp2=32"
                ],
            },
            "bridge-mclmc": {
                "help": "set multicast last member count",
                "validrange": ["0", "255"],
                "example": ["bridge-mclmc 2"],
                "default": "2"
            },
            "bridge-mcrouter": {
                "help": "Set bridge multicast routers: 0 - disabled - no, 1 - automatic (queried), 2 - permanently enabled - yes",
                "validvals": ["yes", "no", "0", "1", "2"],
                "example": ["bridge-mcrouter 1"],
                "default": "yes"
            },
            "bridge-mcsnoop": {
                "help": "set multicast snooping",
                "validvals": ["yes", "no", "0", "1"],
                "default": "yes",
                "example": ["bridge-mcsnoop yes"]
            },
            "bridge-mcsqc": {
                "help": "set multicast startup query count",
                "validrange": ["0", "255"],
                "default": "2",
                "example": ["bridge-mcsqc 2"]
            },
            "bridge-mcqifaddr": {
                "help": "set multicast query to use ifaddr",
                "validvals": ["yes", "no", "0", "1"],
                "default": "no",
                "example": ["bridge-mcqifaddr no"]
            },
            "bridge-mcquerier": {
                "help": "set multicast querier",
                "validvals": ["yes", "no", "0", "1"],
                "default": "no",
                "example": ["bridge-mcquerier no"]
            },
            "bridge-hashel": {
                "help": "Set multicast database hash elasticity, It is the maximum chain length in the "
                        "multicast hash table. This attribute is deprecated and the value is always 16.",
                "validval": ["16"],
                "default": "16",
                "example": ["bridge-hashel 16"],
                "deprecated": True
            },
            "bridge-hashmax": {
                "help": "set hash max",
                "validrange": ["0", "65536"],
                "default": "512",
                "example": ["bridge-hashmax 4096"]
            },
            "bridge-mclmi": {
                "help": "set multicast last member interval (in secs)",
                "validrange": ["0", "255"],
                "default": "1",
                "example": ["bridge-mclmi 1"]
            },
            "bridge-mcmi": {
                "help": "set multicast membership interval (in secs)",
                "default": "260",
                "example": ["bridge-mcmi 260"]
            },
            "bridge-mcqpi": {
                "help": "set multicast querier interval (in secs)",
                "validrange": ["0", "255"],
                "default": "255",
                "example": ["bridge-mcqpi 255"]
            },
            "bridge-mcqi": {
                "help": "set multicast query interval (in secs)",
                "validrange": ["0", "255"],
                "default": "125",
                "example": ["bridge-mcqi 125"]
            },
            "bridge-mcqri": {
                "help": "set multicast query response interval (in secs)",
                "validrange": ["0", "255"],
                "default": "10",
                "example": ["bridge-mcqri 10"]
            },
            "bridge-mcsqi": {
                "help": "set multicast startup query interval (in secs)",
                "validrange": ["0", "255"],
                "default": "31",
                "example": ["bridge-mcsqi 31"]
            },
            "bridge-mcqv4src": {
                "help": "set per VLAN v4 multicast querier source address",
                "validvals": ["<number-ipv4-list>", ],
                "multivalue": True,
                "compat": True,
                "example": ["bridge-mcqv4src 100=172.16.100.1 101=172.16.101.1"]
            },
            "bridge-portmcrouter": {
                "help": "Set port multicast routers: 0 - disabled, 1 - automatic (queried), 2 - permanently enabled",
                "validvals": ["<interface-disabled-automatic-enabled>"],
                "default": "1",
                "example": [
                    "under the port (for vlan aware bridge): bridge-portmcrouter 0",
                    "under the port (for vlan aware bridge): bridge-portmcrouter 1",
                    "under the port (for vlan aware bridge): bridge-portmcrouter 2",
                    "under the port (for vlan aware bridge): bridge-portmcrouter disabled",
                    "under the port (for vlan aware bridge): bridge-portmcrouter automatic",
                    "under the port (for vlan aware bridge): bridge-portmcrouter enabled",
                    "under the bridge (for vlan unaware bridge): bridge-portmcrouter swp1=0 swp2=1 swp2=2",
                    "under the bridge (for vlan unaware bridge): bridge-portmcrouter swp1=disabled swp2=automatic swp3=enabled",
                    "under the bridge (for vlan unaware bridge): bridge-portmcrouter swp1=2 swp2=disabled swp3=1",
                ]
            },
            "bridge-portmcfl": {
                "help": "port multicast fast leave.",
                "validvals": ["<interface-yes-no-0-1-list>"],
                "default": "no",
                "example": [
                    "under the port (for vlan aware bridge): bridge-portmcfl no",
                    "under the bridge (for vlan unaware bridge): bridge-portmcfl swp1=no swp2=no"
                ]
            },
            "bridge-waitport": {
                "help": "wait for a max of time secs for the"
                        " specified ports to become available,"
                        "if no ports are specified then those"
                        " specified on bridge-ports will be"
                        " used here. Specifying no ports here "
                        "should not be used if we are using "
                        "regex or \"all\" on bridge_ports,"
                        "as it wouldnt work.",
                "default": "0",
                "validvals": ["<number-interface-list>"],
                "example": ["bridge-waitport 4 swp1 swp2"]
            },
            "bridge-maxwait": {
                "help": "forces to time seconds the maximum time "
                        "that the Debian bridge setup scripts will "
                        "wait for the bridge ports to get to the "
                        "forwarding status, doesn\"t allow factional "
                        "part. If it is equal to 0 then no waiting"
                        " is done",
                "validrange": ["0", "255"],
                "default": "0",
                "example": ["bridge-maxwait 3"]
            },
            "bridge-vids": {
                "help": "bridge port vids. Can be specified "
                        "under the bridge or under the port. "
                        "If specified under the bridge the ports "
                        "inherit it unless overridden by a "
                        "bridge-vids attribute under the port",
                "multivalue": True,
                "validvals": ["<number-comma-range-list>"],
                "example": [
                    "bridge-vids 4000",
                    "bridge-vids 2000 2200-3000"
                ],
                "aliases": ["bridge-trunk"]
            },
            "bridge-pvid": {
                "help": "bridge port pvid. Must be specified under"
                        " the bridge port",
                "validrange": ["0", "4096"],
                "example": ["bridge-pvid 1"]
            },
            "bridge-access": {
                "help": "bridge port access vlan. Must be "
                        "specified under the bridge port",
                "validrange": ["1", "4094"],
                "example": ["bridge-access 300"]
            },
            "bridge-allow-untagged": {
                "help": "indicate if the bridge port accepts "
                        "untagged packets or not.  Must be "
                        "specified under the bridge port. "
                        "Default is \"yes\"",
                "validvals": ["yes", "no"],
                "example": ["bridge-allow-untagged yes"],
                "default": "yes"
            },
            "bridge-port-vids": {
                "help": "bridge vlans",
                "compat": True,
                "example": ["bridge-port-vids bond0=1-1000,1010-1020"]
            },
            "bridge-port-pvids": {
                "help": "bridge port vlans",
                "compat": True,
                "example": ["bridge-port-pvids bond0=100 bond1=200"]
            },
            "bridge-learning": {
                "help": "bridge port learning flag",
                "validvals": ["on", "off", "<interface-on-off-list>"],
                "default": "on",
                "example": ["bridge-learning off"]
            },
            "bridge-igmp-version": {
                "help": "mcast igmp version",
                "validvals": ["2", "3"],
                "default": "2",
                "example": ["bridge-igmp-version 2"]
            },
            "bridge-mld-version": {
                "help": "mcast mld version",
                "validvals": ["1", "2"],
                "default": "1",
                "example": ["bridge-mld-version 1"]
            },
            "bridge-unicast-flood": {
                "help": "bridge port unicast flood flag",
                "validvals": ["on", "off", "<interface-on-off-list>"],
                "default": "on",
                "example": ["under the port (for vlan aware bridge): bridge-unicast-flood on",
                            "under the bridge (for vlan unaware bridge): bridge-unicast-flood swp1=on swp2=on"]
            },
            "bridge-multicast-flood": {
                "help": "bridge port multicast flood flag",
                "validvals": ["on", "off", "<interface-on-off-list>"],
                "default": "on",
                "example": [
                    "under the port (for vlan aware bridge): bridge-multicast-flood on",
                    "under the bridge (for vlan unaware bridge): bridge-multicast-flood swp1=on swp2=on"
                ]
            },
            "bridge-broadcast-flood": {
                "help": "bridge port broadcast flood flag",
                "validvals": ["on", "off", "<interface-on-off-list>"],
                "default": "on",
                "example": [
                    "under the port (for vlan aware bridge): bridge-broadcast-flood on",
                    "under the bridge (for vlan unaware bridge): bridge-broadcast-flood swp1=on swp2=on"
                ]
            },
            "bridge-vlan-protocol": {
                "help": "bridge vlan protocol",
                "default": "802.1q",
                "validvals": ["802.1q", "802.1ad"],
                "example": ["bridge-vlan-protocol 802.1q"]
            },
            "bridge-vlan-stats": {
                "help": "bridge vlan stats",
                "default": "off",
                "validvals": ["on", "off"],
                "example": ["bridge-vlan-stats off"]
            },
            "bridge-arp-nd-suppress": {
                "help": "bridge port arp nd suppress flag",
                "validvals": ["on", "off", "<interface-on-off-list>"],
                "default": "off",
                "example": [
                    "under the port (for vlan aware bridge): bridge-arp-nd-suppress on",
                    "under the bridge (for vlan unaware bridge): bridge-arp-nd-suppress swp1=on swp2=on"
                ]
            },
            "bridge-mcstats": {
                "help": "bridge multicast stats",
                "default": "off",
                "validvals": ["on", "off", "1", "0", "yes", "no"],
                "example": ["bridge-mcstats off"]
            },
            "bridge-l2protocol-tunnel": {
                "help": "layer 2 protocol tunneling",
                "validvals": [  # XXX: lists all combinations, should move to
                    # a better representation
                    "all",
                    "cdp",
                    "cdp lacp",
                    "cdp lacp lldp",
                    "cdp lacp lldp pvst",
                    "cdp lacp lldp stp",
                    "cdp lacp pvst",
                    "cdp lacp pvst stp",
                    "cdp lacp stp",
                    "cdp lldp",
                    "cdp lldp pvst",
                    "cdp lldp pvst stp",
                    "cdp lldp stp",
                    "cdp pvst",
                    "cdp pvst stp",
                    "cdp stp",
                    "lacp",
                    "lacp lldp",
                    "lacp lldp pvst",
                    "lacp lldp pvst stp",
                    "lacp lldp stp",
                    "lacp pvst",
                    "lacp pvst stp",
                    "lacp stp",
                    "lldp",
                    "lldp pvst",
                    "lldp pvst stp",
                    "lldp stp",
                    "pvst",
                    "pvst stp",
                    "stp",
                    "<interface-l2protocol-tunnel-list>"],
                "example": [
                    "under the bridge (for vlan unaware bridge): bridge-l2protocol-tunnel swpX=lacp,stp swpY=cdp swpZ=all",
                    "under the port (for vlan aware bridge): bridge-l2protocol-tunnel lacp stp lldp cdp pvst",
                    "under the port (for vlan aware bridge): bridge-l2protocol-tunnel lldp pvst",
                    "under the port (for vlan aware bridge): bridge-l2protocol-tunnel stp",
                    "under the port (for vlan aware bridge): bridge-l2protocol-tunnel all"
                ]
            },
            "bridge-ports-condone-regex": {
                    "help": "bridge ports to ignore/condone when reloading config / removing interfaces",
                    "required": False,
                    "example": ["bridge-ports-condone-regex ^[a-zA-Z0-9]+_v[0-9]{1,4}$"]
            },
            "bridge-vlan-vni-map": {
                "help": "Single vxlan support",
                "example": ["bridge-vlan-vni-map 1000-1001=1000-1001"],
            },
            "bridge-always-up": {
                "help": "Enabling this attribute on a bridge will enslave a dummy interface to the bridge",
                "required": False,
                "validvals": ["yes", "no", "on", "off"]
            }
        }
    }

    bridge_utils_missing_warning = True

    # Netlink attributes not associated with ifupdown2
    # attributes are left commented-out for a future use
    # and kept in order :)
    _ifla_br_attributes_map = {
        # Link.IFLA_BR_UNSPEC,
        'bridge-fd': Link.IFLA_BR_FORWARD_DELAY,
        'bridge-hello': Link.IFLA_BR_HELLO_TIME,
        'bridge-maxage': Link.IFLA_BR_MAX_AGE,
        'bridge-ageing': Link.IFLA_BR_AGEING_TIME,
        'bridge-stp': Link.IFLA_BR_STP_STATE,
        # 'bridge-bridgeprio': Link.IFLA_BR_PRIORITY,
        'bridge-vlan-aware': Link.IFLA_BR_VLAN_FILTERING,
        'bridge-vlan-protocol': Link.IFLA_BR_VLAN_PROTOCOL,
        # Link.IFLA_BR_GROUP_FWD_MASK,
        # Link.IFLA_BR_ROOT_ID,
        # Link.IFLA_BR_BRIDGE_ID,
        # Link.IFLA_BR_ROOT_PORT,
        # (Link.IFLA_BR_ROOT_PATH_COST,,
        # Link.IFLA_BR_TOPOLOGY_CHANGE,
        # Link.IFLA_BR_TOPOLOGY_CHANGE_DETECTED,
        # Link.IFLA_BR_HELLO_TIMER,
        # Link.IFLA_BR_TCN_TIMER,
        # Link.IFLA_BR_TOPOLOGY_CHANGE_TIMER,
        # Link.IFLA_BR_GC_TIMER,
        # Link.IFLA_BR_GROUP_ADDR,
        # Link.IFLA_BR_FDB_FLUSH,
        'bridge-mcrouter': Link.IFLA_BR_MCAST_ROUTER,
        #('bridge-mcsnoop', Link.IFLA_BR_MCAST_SNOOPING), # requires special handling so we won't loop on this attr
        'bridge-mcqifaddr': Link.IFLA_BR_MCAST_QUERY_USE_IFADDR,
        'bridge-mcquerier': Link.IFLA_BR_MCAST_QUERIER,
        'bridge-hashel': Link.IFLA_BR_MCAST_HASH_ELASTICITY,
        'bridge-hashmax': Link.IFLA_BR_MCAST_HASH_MAX,
        'bridge-mclmc': Link.IFLA_BR_MCAST_LAST_MEMBER_CNT,
        'bridge-mcsqc': Link.IFLA_BR_MCAST_STARTUP_QUERY_CNT,
        'bridge-mclmi': Link.IFLA_BR_MCAST_LAST_MEMBER_INTVL,
        'bridge-mcmi': Link.IFLA_BR_MCAST_MEMBERSHIP_INTVL,
        'bridge-mcqpi': Link.IFLA_BR_MCAST_QUERIER_INTVL,
        'bridge-mcqi': Link.IFLA_BR_MCAST_QUERY_INTVL,
        'bridge-mcqri': Link.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL,
        'bridge-mcsqi': Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL,
        # Link.IFLA_BR_NF_CALL_IPTABLES,
        # Link.IFLA_BR_NF_CALL_IP6TABLES,
        # Link.IFLA_BR_NF_CALL_ARPTABLES,
        # Link.IFLA_BR_VLAN_DEFAULT_PVID,
        # Link.IFLA_BR_PAD,
        # (Link.IFLA_BR_VLAN_STATS_ENABLED, 'bridge-vlan-stats'), #  already dealt with, in a separate loop
        'bridge-igmp-version': Link.IFLA_BR_MCAST_IGMP_VERSION,
        'bridge-mcstats': Link.IFLA_BR_MCAST_STATS_ENABLED,
        'bridge-mld-version': Link.IFLA_BR_MCAST_MLD_VERSION
    }
    # 'bridge-vlan-stats & bridge-mcstat are commented out even though, today
    # they are supported. It is done this way because this dictionary is used
    # in a loop, but these attributes require additional work. Thus they are
    # excluded from this loop without overhead.

    _ifla_br_attributes_translate_user_config_to_netlink_map = dict(
        (
            # Link.IFLA_BR_UNSPEC,
            (Link.IFLA_BR_FORWARD_DELAY, lambda x: int(x) * 100),
            (Link.IFLA_BR_HELLO_TIME, lambda x: int(x) * 100),
            (Link.IFLA_BR_MAX_AGE, lambda x: int(x) * 100),
            (Link.IFLA_BR_AGEING_TIME, lambda x: int(x) * 100),
            # Link.IFLA_BR_STP_STATE, #  STP is treated outside the loop
            (Link.IFLA_BR_PRIORITY, int),
            (Link.IFLA_BR_VLAN_FILTERING, utils.get_boolean_from_string),
            (Link.IFLA_BR_VLAN_PROTOCOL, str.upper),
            # Link.IFLA_BR_GROUP_FWD_MASK,
            # Link.IFLA_BR_ROOT_ID,
            # Link.IFLA_BR_BRIDGE_ID,
            # Link.IFLA_BR_ROOT_PORT,
            # Link.IFLA_BR_ROOT_PATH_COST,
            # Link.IFLA_BR_TOPOLOGY_CHANGE,
            # Link.IFLA_BR_TOPOLOGY_CHANGE_DETECTED,
            # Link.IFLA_BR_HELLO_TIMER,
            # Link.IFLA_BR_TCN_TIMER,
            # Link.IFLA_BR_TOPOLOGY_CHANGE_TIMER,
            # Link.IFLA_BR_GC_TIMER,
            # Link.IFLA_BR_GROUP_ADDR,
            # Link.IFLA_BR_FDB_FLUSH,
            (Link.IFLA_BR_MCAST_ROUTER, utils.get_int_from_boolean_and_string),
            (Link.IFLA_BR_MCAST_SNOOPING, utils.get_boolean_from_string),
            (Link.IFLA_BR_MCAST_QUERY_USE_IFADDR, utils.get_boolean_from_string),
            (Link.IFLA_BR_MCAST_QUERIER, utils.get_boolean_from_string),
            (Link.IFLA_BR_MCAST_HASH_ELASTICITY, int),
            (Link.IFLA_BR_MCAST_HASH_MAX, int),
            (Link.IFLA_BR_MCAST_LAST_MEMBER_CNT, int),
            (Link.IFLA_BR_MCAST_STARTUP_QUERY_CNT, int),
            (Link.IFLA_BR_MCAST_LAST_MEMBER_INTVL, lambda x: int(x) * 100),
            (Link.IFLA_BR_MCAST_MEMBERSHIP_INTVL, lambda x: int(x) * 100),
            (Link.IFLA_BR_MCAST_QUERIER_INTVL, lambda x: int(x) * 100),
            (Link.IFLA_BR_MCAST_QUERY_INTVL, lambda x: int(x) * 100),
            (Link.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL, lambda x: int(x) * 100),
            (Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL, lambda x: int(x) * 100),
            # Link.IFLA_BR_NF_CALL_IPTABLES,
            # Link.IFLA_BR_NF_CALL_IP6TABLES,
            # Link.IFLA_BR_NF_CALL_ARPTABLES,
            # Link.IFLA_BR_VLAN_DEFAULT_PVID,
            # Link.IFLA_BR_PAD,
            (Link.IFLA_BR_VLAN_STATS_ENABLED, utils.get_boolean_from_string),
            (Link.IFLA_BR_MCAST_IGMP_VERSION, int),
            (Link.IFLA_BR_MCAST_STATS_ENABLED, utils.get_boolean_from_string),
            (Link.IFLA_BR_MCAST_MLD_VERSION, int)
        )
    )

    _ifla_brport_attributes_map = {
        # Link.IFLA_BRPORT_UNSPEC,
        # Link.IFLA_BRPORT_STATE,
        'bridge-portprios': Link.IFLA_BRPORT_PRIORITY,
        'bridge-pathcosts': Link.IFLA_BRPORT_COST,
        # Link.IFLA_BRPORT_MODE,
        # Link.IFLA_BRPORT_GUARD,
        # Link.IFLA_BRPORT_PROTECT,
        'bridge-portmcfl': Link.IFLA_BRPORT_FAST_LEAVE,
        'bridge-learning': Link.IFLA_BRPORT_LEARNING,
        'bridge-unicast-flood': Link.IFLA_BRPORT_UNICAST_FLOOD,
        # Link.IFLA_BRPORT_PROXYARP,
        # Link.IFLA_BRPORT_LEARNING_SYNC,
        # Link.IFLA_BRPORT_PROXYARP_WIFI,
        # Link.IFLA_BRPORT_ROOT_ID,
        # Link.IFLA_BRPORT_BRIDGE_ID,
        # Link.IFLA_BRPORT_DESIGNATED_PORT,
        # Link.IFLA_BRPORT_DESIGNATED_COST,
        # Link.IFLA_BRPORT_ID,
        # Link.IFLA_BRPORT_NO,
        # Link.IFLA_BRPORT_TOPOLOGY_CHANGE_ACK,
        # Link.IFLA_BRPORT_CONFIG_PENDING,
        # Link.IFLA_BRPORT_MESSAGE_AGE_TIMER,
        # Link.IFLA_BRPORT_FORWARD_DELAY_TIMER,
        # Link.IFLA_BRPORT_HOLD_TIMER,
        # Link.IFLA_BRPORT_FLUSH,
        'bridge-portmcrouter': Link.IFLA_BRPORT_MULTICAST_ROUTER,
        # Link.IFLA_BRPORT_PAD,
        'bridge-multicast-flood': Link.IFLA_BRPORT_MCAST_FLOOD,
        # Link.IFLA_BRPORT_MCAST_TO_UCAST,
        # Link.IFLA_BRPORT_VLAN_TUNNEL,
        'bridge-broadcast-flood': Link.IFLA_BRPORT_BCAST_FLOOD,
        'bridge-l2protocol-tunnel': Link.IFLA_BRPORT_GROUP_FWD_MASK,
        # Link.IFLA_BRPORT_PEER_LINK,
        # Link.IFLA_BRPORT_DUAL_LINK,
        'bridge-arp-nd-suppress': Link.IFLA_BRPORT_NEIGH_SUPPRESS,
    }

    _ifla_brport_multicast_router_dict_to_int = {
        'disabled': 0,
        '0': 0,
        'no': 0,
        'automatic': 1,
        '1': 1,
        'yes': 1,
        'enabled': 2,
        '2': 2,
    }

    _ifla_brport_multicast_router_dict_int_to_str = {
        0: "disabled",
        1: "automatic",
        2: "enabled"
    }

    # callable to translate <interface-yes-no-0-1-list> to netlink value
    _ifla_brport_attributes_translate_user_config_to_netlink_map = dict(
        (
            (Link.IFLA_BRPORT_PRIORITY, int),
            (Link.IFLA_BRPORT_COST, int),
            (Link.IFLA_BRPORT_MULTICAST_ROUTER, lambda x: bridge._ifla_brport_multicast_router_dict_to_int.get(x, 0)),
            (Link.IFLA_BRPORT_FAST_LEAVE, utils.get_boolean_from_string),
            (Link.IFLA_BRPORT_LEARNING, utils.get_boolean_from_string),
            (Link.IFLA_BRPORT_UNICAST_FLOOD, utils.get_boolean_from_string),
            (Link.IFLA_BRPORT_MCAST_FLOOD, utils.get_boolean_from_string),
            (Link.IFLA_BRPORT_BCAST_FLOOD, utils.get_boolean_from_string),
            (Link.IFLA_BRPORT_GROUP_FWD_MASK, lambda x: x),
            (Link.IFLA_BRPORT_NEIGH_SUPPRESS, utils.get_boolean_from_string)
        )
    )

    def __init__(self, *args, **kargs):
        Bridge.__init__(self)
        moduleBase.__init__(self, *args, **kargs)
        self.name = self.__class__.__name__
        self._resv_vlan_range =  self._get_reserved_vlan_range()
        self.logger.debug('%s: using reserved vlan range %s' % (self.__class__.__name__, str(self._resv_vlan_range)))

        self.default_stp_on = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__,
                attr='bridge-stp'
            )
        )

        self.default_vlan_stats = policymanager.policymanager_api.get_attr_default(
            module_name=self.__class__.__name__,
            attr='bridge-vlan-stats'
        )

        self.warn_on_untagged_bridge_absence = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr='warn_on_untagged_bridge_absence'
            )
        )
        self.logger.debug('bridge: init: warn_on_untagged_bridge_absence=%s'
                         % self.warn_on_untagged_bridge_absence)

        self._vxlan_bridge_default_igmp_snooping = policymanager.policymanager_api.get_module_globals(
            self.__class__.__name__,
            'vxlan_bridge_default_igmp_snooping'
        )
        self.logger.debug('bridge: init: vxlan_bridge_default_igmp_snooping=%s'
                          % self._vxlan_bridge_default_igmp_snooping)

        self.arp_nd_suppress_only_on_vxlan = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr='allow_arp_nd_suppress_only_on_vxlan'
            )
        )
        self.logger.debug('bridge: init: arp_nd_suppress_only_on_vxlan=%s' % self.arp_nd_suppress_only_on_vxlan)

        self.bridge_always_up_dummy_brport = policymanager.policymanager_api.get_module_globals(
            module_name=self.__class__.__name__,
            attr='bridge_always_up_dummy_brport'
        )
        self.logger.debug('bridge: init: bridge_always_up_dummy_brport=%s' % self.bridge_always_up_dummy_brport)

        try:
            self.bridge_allow_multiple_vlans = utils.get_boolean_from_string(
                self.sysctl_get('net.bridge.bridge-allow-multiple-vlans')
            )
        except Exception:
            # Cumulus Linux specific variable. Failure probably means that
            # ifupdown2 is running a a different system.
            self.bridge_allow_multiple_vlans = True
        self.logger.debug('bridge: init: multiple vlans allowed %s' % self.bridge_allow_multiple_vlans)

        self.bridge_mac_iface_list = policymanager.policymanager_api.get_module_globals(self.__class__.__name__, 'bridge_mac_iface') or []
        # each bridge should have it's own tuple (ifname, mac)
        self.bridge_mac_iface = {}

        self.bridge_set_static_mac_from_port = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                self.__class__.__name__, 'bridge_set_static_mac_from_port'
            )
        )

        self.vxlan_bridge_igmp_snooping_enable_port_mcrouter = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr="vxlan_bridge_igmp_snooping_enable_port_mcrouter"
            ),
            default=True
        )

        self.allow_vlan_sub_interface_in_vlan_aware_bridge = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr="allow-vlan-sub-interface-in-vlan-aware-bridge"
            ),
            default=True
        )

        self.bridge_vxlan_arp_nd_suppress = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr="bridge-vxlan-arp-nd-suppress"
            ),
            default=False
        )
        self.bridge_vxlan_arp_nd_suppress_int = int(self.bridge_vxlan_arp_nd_suppress)

        self.l2protocol_tunnel_callback = {
            'all': self._l2protocol_tunnel_set_all,
            'stp': self._l2protocol_tunnel_set_stp,
            'cdp': self._l2protocol_tunnel_set_cdp,
            'pvst': self._l2protocol_tunnel_set_pvst,
            'lldp': self._l2protocol_tunnel_set_lldp,
            'lacp': self._l2protocol_tunnel_set_lacp
        }

        self.query_check_l2protocol_tunnel_callback = {
            'all': self._query_check_l2protocol_tunnel_all,
            'stp': self._query_check_l2protocol_tunnel_stp,
            'cdp': self._query_check_l2protocol_tunnel_cdp,
            'pvst': self._query_check_l2protocol_tunnel_pvst,
            'lldp': self._query_check_l2protocol_tunnel_lldp,
            'lacp': self._query_check_l2protocol_tunnel_lacp
        }

        self._bridge_attribute_query_check_handler = {
            "bridge-maxwait": (self._query_check_br_attr_wait, None),
            "bridge-waitport": (self._query_check_br_attr_wait, None),

            "bridge-stp": (self._query_check_br_attr_stp, Link.IFLA_BR_STP_STATE),

            "bridge-mcstats": (self._query_check_br_attr_boolean_on_off, Link.IFLA_BR_MCAST_STATS_ENABLED),
            "bridge-vlan-stats": (self._query_check_br_attr_boolean_on_off, Link.IFLA_BR_VLAN_STATS_ENABLED),

            "bridge-vlan-aware": (self._query_check_br_attr_boolean, Link.IFLA_BR_VLAN_FILTERING),
            "bridge-mcqifaddr": (self._query_check_br_attr_boolean, Link.IFLA_BR_MCAST_QUERY_USE_IFADDR),
            "bridge-mcsnoop": (self._query_check_br_attr_boolean, Link.IFLA_BR_MCAST_SNOOPING),
            "bridge-mcquerier": (self._query_check_br_attr_boolean, Link.IFLA_BR_MCAST_QUERIER),
            "bridge-mcrouter": (self._query_check_br_attr_boolean, Link.IFLA_BR_MCAST_ROUTER),

            "bridge-vlan-protocol": (self._query_check_br_attr_string, Link.IFLA_BR_VLAN_PROTOCOL),

            "bridge-mcsqc": (self._query_check_br_attr_int, Link.IFLA_BR_MCAST_STARTUP_QUERY_CNT),
            "bridge-mclmc": (self._query_check_br_attr_int, Link.IFLA_BR_MCAST_LAST_MEMBER_CNT),
            "bridge-hashmax": (self._query_check_br_attr_int, Link.IFLA_BR_MCAST_HASH_MAX),
            "bridge-hashel": (self._query_check_br_attr_int, Link.IFLA_BR_MCAST_HASH_ELASTICITY),
            "bridge-bridgeprio": (self._query_check_br_attr_int, Link.IFLA_BR_PRIORITY),
            "bridge-igmp-version": (self._query_check_br_attr_int, Link.IFLA_BR_MCAST_IGMP_VERSION),
            "bridge-mld-version": (self._query_check_br_attr_int, Link.IFLA_BR_MCAST_MLD_VERSION),

            "bridge-maxage": (self._query_check_br_attr_int_divided100, Link.IFLA_BR_MAX_AGE),
            "bridge-fd": (self._query_check_br_attr_int_divided100, Link.IFLA_BR_FORWARD_DELAY),
            "bridge-hello": (self._query_check_br_attr_int_divided100, Link.IFLA_BR_HELLO_TIME),
            "bridge-ageing": (self._query_check_br_attr_int_divided100, Link.IFLA_BR_AGEING_TIME),
            "bridge-mcmi": (self._query_check_br_attr_int_divided100, Link.IFLA_BR_MCAST_MEMBERSHIP_INTVL),
            "bridge-mcsqi": (self._query_check_br_attr_int_divided100, Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL),
            "bridge-mclmi": (self._query_check_br_attr_int_divided100, Link.IFLA_BR_MCAST_LAST_MEMBER_INTVL),
            "bridge-mcqri": (self._query_check_br_attr_int_divided100, Link.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL),
            "bridge-mcqpi": (self._query_check_br_attr_int_divided100, Link.IFLA_BR_MCAST_QUERIER_INTVL),
            "bridge-mcqi": (self._query_check_br_attr_int_divided100, Link.IFLA_BR_MCAST_QUERY_INTVL),
        }

        self._brport_attribute_query_check_handler = {
            "bridge-pathcosts": self._query_check_brport_attr_int,
            "bridge-portprios": self._query_check_brport_attr_int,
            "bridge-portmcfl": self._query_check_brport_attr_boolean_yes_no,
            "bridge-learning": self._query_check_brport_attr_boolean_on_off,
            "bridge-arp-nd-suppress": self._query_check_brport_attr_boolean_on_off,
            "bridge-unicast-flood": self._query_check_brport_attr_boolean_on_off,
            "bridge-multicast-flood": self._query_check_brport_attr_boolean_on_off,
            "bridge-broadcast-flood": self._query_check_brport_attr_boolean_on_off,
            "bridge-portmcrouter": self._query_check_brport_attr_portmcrouter,
        }

        self.bridge_vxlan_port_learning = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                self.__class__.__name__,
                "bridge_vxlan_port_learning"
            ),
            default=True
        )

        # To avoid disabling ipv6 on SVD we need to keep track of them
        self.svd_list = set()

        # user defined limit of VNI per vlan on the same bridge
        # -1 = no limit
        self.bridge_vni_per_svi = {}
        try:
            self.bridge_vni_per_svi_limit = int(policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr="bridge_vni_per_svi_limit"
            ))
        except Exception:
            self.bridge_vni_per_svi_limit = -1

        # There can only one vlan-aware bridge if PVRST mode is enabled
        self.pvrst_vlan_aware_bridge = None

        # Cumulus-check
        try:
            self.cumulus = "cumulus" in utils.exec_commandl(["lsb_release", "-a"]).lower()
        except:
            self.cumulus = False

    @staticmethod
    def _l2protocol_tunnel_set_pvst(ifla_brport_group_mask, ifla_brport_group_maskhi):
        if not ifla_brport_group_maskhi:
            ifla_brport_group_maskhi = 0x1
        else:
            ifla_brport_group_maskhi |= 0x1
        return ifla_brport_group_mask, ifla_brport_group_maskhi

    @staticmethod
    def _l2protocol_tunnel_set_cdp(ifla_brport_group_mask, ifla_brport_group_maskhi):
        if not ifla_brport_group_maskhi:
            ifla_brport_group_maskhi = 0x2
        else:
            ifla_brport_group_maskhi |= 0x2
        return ifla_brport_group_mask, ifla_brport_group_maskhi

    @staticmethod
    def _l2protocol_tunnel_set_stp(ifla_brport_group_mask, ifla_brport_group_maskhi):
        if not ifla_brport_group_mask:
            ifla_brport_group_mask = 0x1
        else:
            ifla_brport_group_mask |= 0x1
        return ifla_brport_group_mask, ifla_brport_group_maskhi

    @staticmethod
    def _l2protocol_tunnel_set_lacp(ifla_brport_group_mask, ifla_brport_group_maskhi):
        if not ifla_brport_group_mask:
            ifla_brport_group_mask = 0x4
        else:
            ifla_brport_group_mask |= 0x4
        return ifla_brport_group_mask, ifla_brport_group_maskhi

    @staticmethod
    def _l2protocol_tunnel_set_lldp(ifla_brport_group_mask, ifla_brport_group_maskhi):
        if not ifla_brport_group_mask:
            ifla_brport_group_mask = 0x4000
        else:
            ifla_brport_group_mask |= 0x4000
        return ifla_brport_group_mask, ifla_brport_group_maskhi

    @staticmethod
    def _l2protocol_tunnel_set_all(ifla_brport_group_mask, ifla_brport_group_maskhi):
        # returns new values for ifla_brport_group_mask and ifla_brport_group_maskhi
        return 0x1 | 0x4 | 0x4000, 0x1 | 0x2

    @staticmethod
    def _query_check_l2protocol_tunnel_stp(ifla_brport_group_mask, ifla_brport_group_maskhi):
        return ifla_brport_group_mask and ifla_brport_group_mask & 0x1

    @staticmethod
    def _query_check_l2protocol_tunnel_cdp(ifla_brport_group_mask, ifla_brport_group_maskhi):
        return ifla_brport_group_maskhi and ifla_brport_group_maskhi & 0x2

    @staticmethod
    def _query_check_l2protocol_tunnel_pvst(ifla_brport_group_mask, ifla_brport_group_maskhi):
        return ifla_brport_group_maskhi and ifla_brport_group_maskhi & 0x1

    @staticmethod
    def _query_check_l2protocol_tunnel_lldp(ifla_brport_group_mask, ifla_brport_group_maskhi):
        return ifla_brport_group_mask and ifla_brport_group_mask & 0x4000

    @staticmethod
    def _query_check_l2protocol_tunnel_lacp(ifla_brport_group_mask, ifla_brport_group_maskhi):
        return ifla_brport_group_mask and ifla_brport_group_mask & 0x4

    @staticmethod
    def _query_check_l2protocol_tunnel_all(ifla_brport_group_mask, ifla_brport_group_maskhi):
        return ifla_brport_group_mask == (0x1 | 0x4 | 0x4000) and ifla_brport_group_maskhi == (0x1 | 0x2)

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        retval = self.check_bridge_vlan_aware_port(ifaceobj, ifaceobj_getfunc)
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT and not self.check_bridge_port_vid_attrs(ifaceobj):
            retval = False
        c1 = self.syntax_check_vxlan_in_vlan_aware_br(ifaceobj, ifaceobj_getfunc)
        c2 = self.syntax_check_bridge_allow_multiple_vlans(ifaceobj, ifaceobj_getfunc)
        c3 = self.syntax_check_learning_l2_vni_evpn(ifaceobj)
        c4 = self.syntax_check_bridge_arp_vni_vlan(ifaceobj, ifaceobj_getfunc)
        c5 = self.syntax_check_bridge_vni_svi_limit(ifaceobj, ifaceobj_getfunc)
        c6 = self.check_bridge_single_vxlan(ifaceobj)
        return retval and c1 and c2 and c3 and c4 and c5 and c6

    def syntax_check_bridge_vni_svi_limit(self, ifaceobj, ifaceobj_getfunc):
        if self.bridge_vni_per_svi_limit > 0 and ifaceobj.link_kind & ifaceLinkKind.VXLAN:
            vni_name = ifaceobj.name
            bridge_name = self.__get_vxlan_bridge_name(ifaceobj, ifaceobj_getfunc)

            if not bridge_name:
                return True

            svi = ifaceobj.get_attr_value_first("bridge-access")

            if not svi:
                return True

            vni_per_svi = self.bridge_vni_per_svi.get(bridge_name, {}).get(svi)

            def err():
                self.logger.error(
                    "%s: misconfiguration detected: maximum vni allowed per bridge (%s) svi (%s) is limited to %s (policy: 'bridge_vni_per_svi_limit')" %
                    (vni_name,
                    bridge_name,
                    svi,
                    self.bridge_vni_per_svi_limit)
                )

            if vni_per_svi:
                err()
                return False
            else:
                if bridge_name not in self.bridge_vni_per_svi:
                    self.bridge_vni_per_svi[bridge_name] = {
                        svi: vni_name
                    }

                elif svi not in self.bridge_vni_per_svi[bridge_name]:
                    self.bridge_vni_per_svi[bridge_name][svi] = vni_name

                else:
                    err()
                    return False

        return True

    def __get_vxlan_bridge_name(self, ifaceobj, ifaceobj_getfunc):
        try:
            for intf in ifaceobj.upperifaces:
                for obj in ifaceobj_getfunc(intf):
                    if obj.link_kind & ifaceLinkKind.BRIDGE:
                        return obj.name
        except Exception:
            pass
        return None

    def syntax_check_bridge_arp_vni_vlan(self, ifaceobj, ifaceobj_getfunc):
        """
        Detect and warn when arp suppression is enabled and there is no vlan configured

        :param ifaceobj:
        :param ifaceobj_getfunc:
        :return boolean:
        """
        if ifaceobj.link_kind & ifaceLinkKind.VXLAN \
            and ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT \
            and utils.get_boolean_from_string(ifaceobj.get_attr_value_first("bridge-arp-nd-suppress")) \
            and not ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN:

            bridge_access = ifaceobj.get_attr_value_first("bridge-access")

            if not bridge_access:
                return True

            for obj in ifaceobj_getfunc(ifaceobj.upperifaces[0]) or []:
                for upper_ifname in obj.upperifaces or []:
                    for upper_obj in ifaceobj_getfunc(upper_ifname) or []:
                        if upper_obj.link_kind & ifaceLinkKind.VLAN and str(self._get_vlan_id(upper_obj)) == bridge_access:
                            return True

            self.logger.warning(
                "%s: ARP suppression configured on %s and associated vlan %s not configured. "
                "This may result in unexpected behavior"
                % (ifaceobj.name, ifaceobj.name, bridge_access)
            )
            return False

        return True

    def syntax_check_learning_l2_vni_evpn(self, ifaceobj):
        result = True
        if (
            ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT and ifaceobj.link_kind & ifaceLinkKind.VXLAN
            and utils.get_boolean_from_string(ifaceobj.get_attr_value_first("bridge-learning"))
            and not ifaceobj.get_attr_value_first("vxlan-remoteip") and not ifaceobj.get_attr_value_first("vxlan-remoteip-map")
        ):
            self.logger.warning(
                "%s: possible mis-configuration detected: l2-vni configured with bridge-learning ON "
                "while EVPN is also configured - these two parameters conflict with each other."
                % ifaceobj.name
            )
            result = False
        return result

    def syntax_check_bridge_allow_multiple_vlans(self, ifaceobj, ifaceobj_getfunc):
        result = True
        if not self.bridge_allow_multiple_vlans and ifaceobj.link_kind & ifaceLinkKind.BRIDGE and ifaceobj.lowerifaces:
            vlan_id = None
            for brport_name in ifaceobj.lowerifaces:
                for obj in ifaceobj_getfunc(brport_name) or []:
                    if obj.link_kind & ifaceLinkKind.VLAN:
                        sub_intf_vlan_id = self._get_vlan_id(obj)
                        if vlan_id and vlan_id != sub_intf_vlan_id:
                            self.logger.error('%s: ignore %s: multiple vlans not allowed under bridge '
                                              '(sysctl net.bridge.bridge-allow-multiple-vlans not set)'
                                              % (ifaceobj.name, brport_name))
                            result = False
                            continue
                        vlan_id = sub_intf_vlan_id
        return result

    def check_bridge_port_vid_attrs(self, ifaceobj):
        if (ifaceobj.get_attr_value('bridge-access') and
            (self.get_ifaceobj_bridge_vids_value(ifaceobj) or
             ifaceobj.get_attr_value('bridge-pvid'))):
            self.logger.warning('%s: bridge-access given, bridge-vids and bridge-pvid '
                             'will be ignored' % ifaceobj.name)
            return False
        return True

    def check_bridge_single_vxlan(self, ifaceobj):
        if (ifaceobj.link_privflags &
            (ifaceLinkPrivFlags.SINGLE_VXLAN | ifaceLinkPrivFlags.L3VXI) and
                ifaceobj.get_attr_value_first('bridge-pvid')):
                self.logger.warning("%s: bridge-pvid conflicts with single-vxlan device, bridge-pvid will be ignored" % ifaceobj.name)
                return False
        return True

    def check_bridge_vlan_aware_port(self, ifaceobj, ifaceobj_getfunc):
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE:
            ports = self._get_bridge_port_list(ifaceobj)
            if not ports:
                return True
            result = True
            for port_name in ports:
                port_obj_l = ifaceobj_getfunc(port_name)
                if not self.allow_vlan_sub_interface_in_vlan_aware_bridge:
                    if port_obj_l and port_obj_l[0].link_kind & ifaceLinkKind.VLAN:
                        self.logger.error('%s: %s: vlan sub-interface is not '
                                          'supported in a vlan-aware bridge'
                                          % (ifaceobj.name, port_name))
                        result = False
                if (port_obj_l and
                    port_obj_l[0].get_attr_value('bridge-arp-nd-suppress') and
                    self.arp_nd_suppress_only_on_vxlan and
                    not port_obj_l[0].link_kind & ifaceLinkKind.VXLAN):
                    self.log_error('\'bridge-arp-nd-suppress\' is not '
                                   'supported on a non-vxlan port %s'
                                   %port_obj_l[0].name)
                    result = False
            return result
        return True

    def _error_vxlan_in_vlan_aware_br(self, ifaceobj, bridgename):
        if not ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN:
            self.log_error('`bridge-access` attribute is mandatory when vxlan '
                           'device (%s) is part of vlan aware bridge (%s)'
                           % (ifaceobj.name, bridgename), ifaceobj)
            return False
        return True

    def syntax_check_vxlan_in_vlan_aware_br(self, ifaceobj, ifaceobj_getfunc):
        if not ifaceobj_getfunc:
            return True
        if (ifaceobj.link_kind & ifaceLinkKind.VXLAN and ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT):
            if ifaceobj.get_attr_value('bridge-access'):
                return True
            for iface in ifaceobj.upperifaces if ifaceobj.upperifaces else []:
                ifaceobj_upper_list = ifaceobj_getfunc(iface)
                if not ifaceobj_upper_list:
                    continue
                ifaceobj_upper = ifaceobj_upper_list[0]
                bridge_vids = self._get_bridge_vids(iface, ifaceobj_getfunc)
                if ifaceobj_upper.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE:
                    vids = self.get_ifaceobj_bridge_vids_value(ifaceobj)
                    pvid = ifaceobj.get_attr_value_first('bridge-pvid')
                    if (not vids
                        or not pvid
                        or not utils.compare_ids(bridge_vids,
                                                  vids,
                                                  pvid=pvid)):
                        if not self._error_vxlan_in_vlan_aware_br(ifaceobj, ifaceobj_upper.name):
                            return False
        return True

    @staticmethod
    def _is_bridge(ifaceobj):
        return (ifaceobj.link_kind & ifaceLinkKind.BRIDGE or
                ifaceobj.get_attr_value_first('bridge-ports') or
                ifaceobj.get_attr_value_first('bridge-vlan-aware'))

    def check_valid_bridge(self, ifaceobj, ifname):
        if self.cache.link_exists(ifname) and not self.cache.link_is_bridge(ifname):
            self.log_error('misconfiguration of bridge attribute(s) on existing non-bridge interface (%s)' % ifname, ifaceobj=ifaceobj)
            return False
        return True

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None, old_ifaceobjs=False):

        if not old_ifaceobjs and (ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN or ifaceobj.get_attr_value_first("bridge-vlan-vni-map")):
            self.svd_list.add(ifaceobj.name)

        if not self._is_bridge(ifaceobj) or not self.check_valid_bridge(ifaceobj, ifaceobj.name):
            return None
        if ifaceobj.link_type != ifaceLinkType.LINK_NA:
           ifaceobj.link_type = ifaceLinkType.LINK_MASTER
        ifaceobj.link_kind |= ifaceLinkKind.BRIDGE
        # for special vlan aware bridges, we need to add another bit
        if utils.get_boolean_from_string(ifaceobj.get_attr_value_first('bridge-vlan-aware')):
            ifaceobj.link_kind |= ifaceLinkKind.BRIDGE
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE

            if not old_ifaceobjs:
                # store the name of all bridge vlan aware in a global list
                self.bridge_vlan_aware_list.add(ifaceobj.name)

        ifaceobj.role |= ifaceRole.MASTER
        ifaceobj.dependency_type = ifaceDependencyType.MASTER_SLAVE

        return self.parse_port_list(ifaceobj.name,
                                    self._get_ifaceobj_bridge_ports(ifaceobj),
                                    ifacenames_all)

    def get_dependent_ifacenames_running(self, ifaceobj):
        if not self.cache.bridge_exists(ifaceobj.name):
            return None
        return self.cache.get_slaves(ifaceobj.name)

    def _get_bridge_port_list_user_ordered(self, ifaceobj):
        # When enslaving bridge-ports we need to return the exact user
        # configured bridge ports list (bridge will inherit the mac of the
        # first device.
        ports = self._get_ifaceobj_bridge_ports(ifaceobj)
        return self.parse_port_list(ifaceobj.name, ports) if ports else None

    def _get_bridge_port_condone_regex(self, ifaceobj, get_string = False):
        bridge_port_condone_regex = ifaceobj.get_attr_value_first('bridge-ports-condone-regex')
        # If bridge-ports-ignore-regex is configured, do NOT use the parse_port_list()
        # function to gather a list of ports matching the regex here and now but set
        # up a compiled regex to be used in a match later. This way we try to avoid
        # a race condition where an (possibly VM) interface is created after this
        # function has been called but before the bridgeports are validated.
        if bridge_port_condone_regex:
            if get_string:
                return bridge_port_condone_regex
            return re.compile (r"%s" % bridge_port_condone_regex)
        return None

    def _process_bridge_waitport(self, ifaceobj, portlist):
        waitport_value = ifaceobj.get_attr_value_first('bridge-waitport')
        if not waitport_value: return
        try:
            waitportvals = re.split(r'[\s\t]\s*', waitport_value, 1)
            if not waitportvals: return
            try:
                waitporttime = int(waitportvals[0])
            except Exception:
                self.log_warn('%s: invalid waitport value \'%s\''
                        %(ifaceobj.name, waitportvals[0]))
                return
            if waitporttime <= 0: return
            try:
                waitportlist = self.parse_port_list(ifaceobj.name,
                                                    waitportvals[1])
            except IndexError as e:
                # ignore error and use all bridge ports
                waitportlist = portlist
            if not waitportlist: return
            self.logger.info('%s: waiting for ports %s to exist ...'
                    %(ifaceobj.name, str(waitportlist)))
            starttime = time.time()
            while ((time.time() - starttime) < waitporttime):
                if all([False for p in waitportlist
                        if not self.cache.link_exists(p)]):
                    break;
                time.sleep(1)
        except Exception as e:
            self.log_warn('%s: unable to process waitport: %s'
                    %(ifaceobj.name, str(e)))

    def _enable_disable_ipv6(self, port, enable='1'):
        try:
            self.write_file('/proc/sys/net/ipv6/conf/%s/disable_ipv6' % port, enable)
        except Exception as e:
            self.logger.info(str(e))

    def handle_ipv6(self, ports, state):
        for p in ports:
            self._enable_disable_ipv6(p, state)

    def _pretty_print_add_ports_error(self, errstr, bridgeifaceobj, bridgeports):
        """ pretty print bridge port add errors.
            since the commands are batched and the kernel only returns error
            codes, this function tries to interpret some error codes
            and prints clearer errors """

        if re.search('RTNETLINK answers: Invalid argument', errstr):
            # Cumulus Linux specific error checks
            try:
                if self.sysctl_get('net.bridge.bridge-allow-multiple-vlans') == '0':
                    vlanid = None
                    for bport in bridgeports:
                        currvlanid = self._get_vlan_id_from_ifacename(bport)
                        if vlanid and currvlanid != vlanid:
                            self.log_error(
                                "%s: net.bridge.bridge-allow-multiple-vlans not set, multiple vlans not allowed"
                                % bridgeifaceobj.name, bridgeifaceobj
                            )
                            break
                        if currvlanid:
                            vlanid = currvlanid
            except Exception as e:
                errstr += '\n%s' % str(e)
        self.log_error(bridgeifaceobj.name + ': ' + errstr, bridgeifaceobj)

    def _add_ports(self, ifaceobj, ifaceobj_getfunc):
        bridgeports = self._get_bridge_port_list(ifaceobj)
        bridgeportscondoneregex = self._get_bridge_port_condone_regex(ifaceobj)
        runningbridgeports = []

        # bridge-always-up #####################################################
        bridge_always_up = ifaceobj.get_attr_value_first("bridge-always-up")
        dummy_brport = None

        if utils.get_boolean_from_string(bridge_always_up):
            # the dummy port will be added to the bridgeports list so the
            # following code don't de-enslave the dummy device.
            dummy_brport = self.bridge_always_up(ifaceobj.name, bridgeports)

        ########################################################################

        self._process_bridge_waitport(ifaceobj, bridgeports)
        # Delete active ports not in the new port list
        if not ifupdownflags.flags.PERFMODE:
            runningbridgeports = self.cache.get_slaves(ifaceobj.name)
            if runningbridgeports:
                for bport in runningbridgeports:
                    if not bridgeports or bport not in bridgeports:
                        if bridgeportscondoneregex and bridgeportscondoneregex.match(bport):
                            self.logger.info("%s: port %s will stay enslaved as it matches with bridge-ports-condone-regex" % (ifaceobj.name, bport))
                            continue
                        self.netlink.link_set_nomaster(bport)
                        # set admin DOWN on all removed ports
                        # that don't have config outside bridge
                        if not ifaceobj_getfunc(bport):
                            self.netlink.link_down(bport)
                        # enable ipv6 for ports that were removed
                        self.handle_ipv6([bport], '0')
            else:
                runningbridgeports = []
        if not bridgeports:
            return []
        err = 0
        newbridgeports = set(bridgeports).difference(set(runningbridgeports))
        newly_enslaved_ports = []

        newbridgeports_ordered = []
        for br_port in self._get_bridge_port_list_user_ordered(ifaceobj) or []:
            if br_port in newbridgeports:
                newbridgeports_ordered.append(br_port)

        if dummy_brport:
            # add the dummy port to the list of interface to enslave
            # link_set_master should make sure that the device is not
            # already enslaved.
            newbridgeports_ordered.append(dummy_brport)

        self.iproute2.batch_start()

        for bridgeport in newbridgeports_ordered:
            try:
                if (not ifupdownflags.flags.DRYRUN and
                    not self.cache.link_exists(bridgeport)):
                    self.log_error('%s: bridge port %s does not exist'
                                   %(ifaceobj.name, bridgeport), ifaceobj, raise_error=False)
                    err += 1
                    continue
                hwaddress = self.cache.get_link_address(bridgeport)
                if not ifupdownflags.flags.DRYRUN and not self._valid_ethaddr(hwaddress):
                    self.log_warn('%s: skipping port %s, ' %(ifaceobj.name,
                                  bridgeport) + 'invalid ether addr %s'
                                  %hwaddress)
                    continue
                self.iproute2.link_set_master(bridgeport, ifaceobj.name)
                newly_enslaved_ports.append(bridgeport)

                # dont disable ipv6 for SVD
                if bridgeport not in self.svd_list:
                    self.handle_ipv6([bridgeport], '1')

                self.iproute2.addr_flush(bridgeport)
            except Exception as e:
                self.logger.error(str(e))

        self.iproute2.batch_commit()
        self.cache.force_add_slave_list(ifaceobj.name, newly_enslaved_ports)

        if err:
            self.log_error('bridge configuration failed (missing ports)')

        try:
            # to avoid any side effect we remove the dummy brport from the
            # list of supposedly newly configured ports.
            newly_enslaved_ports.remove(dummy_brport)
        except Exception:
            pass

        return newly_enslaved_ports

    def get_dummy_brport_name_for_bridge(self, bridge_name):
        """
            dummy brport will have user provided name if it's defined in 'bridge_always_up_dummy_brport' policy
            Otherwise dummy brport will have pre-formated name: brport-if$BRIDGE_IFINDEX
            That way we can avoid collision with existing interfaces
        """
        if self.bridge_always_up_dummy_brport:
            return self.bridge_always_up_dummy_brport
        # this can raise: NetlinkCacheIfnameNotFoundError
        return "brport-if%d" % self.cache.get_ifindex(bridge_name)

    def bridge_always_up(self, bridge_name, newbridgeports_ordered):
        dummy_brport = self.get_dummy_brport_name_for_bridge(bridge_name)

        if not self.cache.link_exists(dummy_brport):
            self.logger.info("%s: bridge-always-up yes: enslaving dummy port: %s" % (bridge_name, dummy_brport))
            self.netlink.link_add(ifname=dummy_brport, kind="dummy")
            self.netlink.link_up_force(dummy_brport)

        newbridgeports_ordered.append(dummy_brport)
        return dummy_brport

    def _process_bridge_maxwait(self, ifaceobj, portlist):
        maxwait = ifaceobj.get_attr_value_first('bridge-maxwait')
        if not maxwait: return
        try:
            maxwait = int(maxwait)
        except Exception:
            self.log_warn('%s: invalid maxwait value \'%s\'' %(ifaceobj.name,
                    maxwait))
            return
        if not maxwait: return
        self.logger.info('%s: waiting for ports to go to fowarding state ..'
                %ifaceobj.name)
        try:
            starttime = time.time()
            while ((time.time() - starttime) < maxwait):
                if all([False for p in portlist
                    if self.read_file_oneline(
                            '/sys/class/net/%s/brif/%s/state'
                            %(ifaceobj.name, p)) != '3']):
                    break;
                time.sleep(1)
        except Exception as e:
            self.log_warn('%s: unable to process maxwait: %s'
                    %(ifaceobj.name, str(e)))

    def _set_bridge_mcqv4src_compat(self, ifaceobj):
        #
        # Sets old style igmp querier
        #
        attrval = ifaceobj.get_attr_value_first('bridge-mcqv4src')
        if attrval:
            running_mcqv4src = {}
            if not ifupdownflags.flags.PERFMODE:
                running_mcqv4src = self.sysfs.bridge_get_mcqv4src(ifaceobj.name)
            mcqs = {}
            srclist = attrval.split()
            for s in srclist:
                k, v = s.split('=')
                mcqs[k] = v

            k_to_del = set(list(running_mcqv4src.keys())).difference(list(mcqs.keys()))
            for v in k_to_del:
                self.iproute2.bridge_del_mcqv4src(ifaceobj.name, v)
            for v in list(mcqs.keys()):
                self.iproute2.bridge_set_mcqv4src(ifaceobj.name, v, mcqs[v])
        elif not ifupdownflags.flags.PERFMODE:
            running_mcqv4src = self.sysfs.bridge_get_mcqv4src(ifaceobj.name)
            if running_mcqv4src:
                for v in list(running_mcqv4src.keys()):
                    self.iproute2.bridge_del_mcqv4src(ifaceobj.name, v)

    def _set_bridge_vidinfo_compat(self, ifaceobj):
        #
        # Supports old style vlan vid info format
        # for compatibility
        #
        bridge_port_pvids = ifaceobj.get_attr_value_first('bridge-port-pvids')
        bridge_port_vids = ifaceobj.get_attr_value_first('bridge-port-vids')
        if not bridge_port_pvids and not bridge_port_vids:
            return

        # Handle bridge vlan attrs
        # Install pvids
        if bridge_port_pvids:
            portlist = self.parse_port_list(ifaceobj.name, bridge_port_pvids)
            if not portlist:
                self.log_warn('%s: could not parse \'%s %s\''
                              %(ifaceobj.name, 'bridge-port-pvids',
                                bridge_port_pvids))
                return
            for p in portlist:
                try:
                    (port, pvid) = p.split('=')
                    pvid = int(pvid)
                    running_pvid = self.cache.get_pvid(port)
                    if running_pvid:
                        if running_pvid == pvid:
                            continue
                        else:
                            self.iproute2.bridge_vlan_del_pvid(port, running_pvid)
                    self.iproute2.bridge_vlan_add_pvid(port, pvid)
                except Exception as e:
                    self.log_warn('%s: failed to set pvid `%s` (%s)'
                            %(ifaceobj.name, p, str(e)))

        # install port vids
        if bridge_port_vids:
            portlist = self.parse_port_list(ifaceobj.name, bridge_port_vids)
            if not portlist:
                self.log_warn('%s: could not parse \'%s %s\'' %(ifaceobj.name,
                              'bridge-port-vids', bridge_port_vids))
                return
            for p in portlist:
                try:
                    (port, val) = p.split('=')
                    vids = val.split(',')
                    vids_int =  utils.ranges_to_ints(vids)
                    _, running_vids = self.cache.get_pvid_and_vids(port)
                    if running_vids:
                        (vids_to_del, vids_to_add) = \
                                utils.diff_ids(vids_int, running_vids)
                        if vids_to_del:
                            self.iproute2.bridge_vlan_del_vid_list(port,
                                    utils.compress_into_ranges(vids_to_del))
                        if vids_to_add:
                            self.iproute2.bridge_vlan_add_vid_list(port,
                                    utils.compress_into_ranges(vids_to_add))
                    else:
                        self.iproute2.bridge_vlan_add_vid_list(port, vids_int)
                except Exception as e:
                    self.log_warn('%s: failed to set vid `%s` (%s)'
                        %(ifaceobj.name, p, str(e)))

    def _is_running_stp_state_on(self, bridgename):
        """ Returns True if running stp state is on, else False """

        stp_state_file = '/sys/class/net/%s/bridge/stp_state' %bridgename
        try:
            running_stp_state = self.read_file_oneline(stp_state_file)
            return running_stp_state and running_stp_state != '0'
        except Exception:
            return False

    def _is_config_stp_state_on(self, ifaceobj):
        """ Returns true if user specified stp state is on, else False """

        stp_attr = ifaceobj.get_attr_value_first('bridge-stp')
        if not stp_attr:
            return self.default_stp_on
        return utils.get_boolean_from_string(stp_attr)

    def get_bridge_mcsnoop_value(self, ifaceobj):
        mcsnoop = ifaceobj.get_attr_value_first('bridge-mcsnoop')

        if mcsnoop:
            return mcsnoop

        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VXLAN and self._vxlan_bridge_default_igmp_snooping is not None:
            return self._vxlan_bridge_default_igmp_snooping

        return self.get_attr_default_value("bridge-mcsnoop")

    def fill_ifla_info_data_with_ifla_br_attribute(self,
                                                   ifla_info_data,
                                                   link_just_created,
                                                   ifname,
                                                   nl_attr,
                                                   attr_name,
                                                   user_config,
                                                   cached_value):
        try:
            translate_func = self._ifla_br_attributes_translate_user_config_to_netlink_map.get(nl_attr)

            if not callable(translate_func):
                return

            if not user_config:
                user_config = policymanager.policymanager_api.get_iface_default(
                    module_name=self.__class__.__name__,
                    ifname=ifname,
                    attr=attr_name
                )

            if not link_just_created and cached_value is None:
                # the link already exists but we don't have any value
                # cached for this attr, it probably means that the
                # capability is not available on this system (i.e old kernel)
                self.logger.debug("%s: ignoring %s %s: capability probably not supported on this system"
                                  % (ifname, attr_name, user_config))
                return

            if not user_config and not link_just_created and cached_value is not None:
                # there is no user configuration for this attribute
                # if the bridge existed before we need to check if
                # this attribute needs to be reset to default value
                default_value = self.get_attr_default_value(attr_name)

                if default_value:
                    # the attribute has a default value, we need to convert it to
                    # netlink format to compare it with the cache value
                    default_value_nl = translate_func(default_value)  # default_value.lower()

                    if default_value_nl != cached_value:
                        # the running value difers from the default value
                        # but the user didn't specify any config
                        # resetting attribute to default
                        ifla_info_data[nl_attr] = default_value_nl
                        self.logger.info('%s: reset %s to default: %s' % (ifname, attr_name, default_value))
            elif user_config:
                user_config_nl = translate_func(user_config)  # user_config.lower()

                if user_config_nl != cached_value:
                    ifla_info_data[nl_attr] = user_config_nl

                    if cached_value is not None:
                        self.logger.info('%s: set %s %s (cache %s)' % (ifname, attr_name, user_config, cached_value))
                    else:
                        self.logger.info('%s: set %s %s' % (ifname, attr_name, user_config))
        except Exception as e:
            self.logger.warning('%s: %s: %s' % (ifname, attr_name, str(e)))

    def up_apply_bridge_settings(self, ifaceobj, link_just_created, bridge_vlan_aware):
        ifla_info_data = dict()
        ifname = ifaceobj.name

        self.logger.info('%s: applying bridge settings' % ifname)

        cached_ifla_info_data = self.cache.get_link_info_data(ifname)

        try:
            # we compare the user value (or policy value) with the current running state
            # we need to divide the cached value by 100 to ignore small difference.
            # i.e. our default value is 31 but the kernel default seems to be 3125
            cached_ifla_info_data[Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL] //= 100
            cached_ifla_info_data[Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL] *= 100
        except Exception:
            pass

        for attr_name, nl_attr in self._ifla_br_attributes_map.items():
            self.fill_ifla_info_data_with_ifla_br_attribute(
                ifla_info_data=ifla_info_data,
                link_just_created=link_just_created,
                ifname=ifname,
                nl_attr=nl_attr,
                attr_name=attr_name,
                user_config=ifaceobj.get_attr_value_first(attr_name),
                cached_value=cached_ifla_info_data.get(nl_attr)
            )

        # special cases ########################################################

        # bridge-bridgeprio
        # if mstpctl-treeprio is configured on the bridge
        # do not reset the bridge-bridgeprio to the default value
        # NOTE: this is the case for every bridge/mstpctl attribute pairs.
        # TODO: more code should be added to handle this in the future.
        mstpctl_treeprio = ifaceobj.get_attr_value_first("mstpctl-treeprio")
        bridge_bridgeprio = ifaceobj.get_attr_value_first("bridge-bridgeprio")

        if mstpctl_treeprio:
            self.logger.info("%s: mstpctl-treeprio attribute is set - ignorning bridge-bridgeprio" % ifname)
        else:
            self.fill_ifla_info_data_with_ifla_br_attribute(
                ifla_info_data=ifla_info_data,
                link_just_created=link_just_created,
                ifname=ifname,
                nl_attr=Link.IFLA_BR_PRIORITY,
                attr_name='bridge-bridgeprio',
                user_config=bridge_bridgeprio,
                cached_value=cached_ifla_info_data.get(Link.IFLA_BR_PRIORITY)
            )

        # bridge-mcsnoop
        self.fill_ifla_info_data_with_ifla_br_attribute(
            ifla_info_data=ifla_info_data,
            link_just_created=link_just_created,
            ifname=ifname,
            nl_attr=Link.IFLA_BR_MCAST_SNOOPING,
            attr_name='bridge-mcsnoop',
            user_config=self.get_bridge_mcsnoop_value(ifaceobj),
            cached_value=cached_ifla_info_data.get(Link.IFLA_BR_MCAST_SNOOPING)

        )

        # bridge-vlan-stats
        if bridge_vlan_aware:
            self.fill_ifla_info_data_with_ifla_br_attribute(
                ifla_info_data=ifla_info_data,
                link_just_created=link_just_created,
                ifname=ifname,
                nl_attr=Link.IFLA_BR_VLAN_STATS_ENABLED,
                attr_name='bridge-vlan-stats',
                user_config=ifaceobj.get_attr_value_first('bridge-vlan-stats') or self.default_vlan_stats,
                cached_value=cached_ifla_info_data.get(Link.IFLA_BR_VLAN_STATS_ENABLED)
            )

        try:
            if self._is_config_stp_state_on(ifaceobj):
                if not self._is_running_stp_state_on(ifname):
                    ifla_info_data[Link.IFLA_BR_STP_STATE] = 1
                    self.logger.info('%s: stp state reset, reapplying port settings' % ifname)
                    ifaceobj.module_flags[ifaceobj.name] = \
                        ifaceobj.module_flags.setdefault(self.name, 0) | \
                        BridgeFlags.PORT_PROCESSED_OVERRIDE
            else:
                # If stp not specified and running stp state on, set it to off
                if self._is_running_stp_state_on(ifname):
                    self.logger.info('%s: bridge-stp not specified but running: turning stp off')
                    ifla_info_data[Link.IFLA_BR_STP_STATE] = 0
        except Exception as e:
            self.logger.warning('%s: bridge stp: %s' % (ifname, str(e)))

        if ifla_info_data:
            self.netlink.link_set_bridge_info_data(ifname, ifla_info_data)

    def _check_vids(self, ifaceobj, vids):
        ret = True
        for v in vids:
            try:
                if '-' in v:
                    va, vb = v.split('-')
                    va, vb = int(va), int(vb)
                    self._handle_reserved_vlan(va, ifaceobj.name, end=vb)
                else:
                    va = int(v)
                    self._handle_reserved_vlan(va, ifaceobj.name)
            except exceptions.ReservedVlanException as e:
                raise e
            except Exception:
                self.logger.warning('%s: unable to parse vid \'%s\''
                                 %(ifaceobj.name, v))
        return ret

    def _get_running_vids_n_pvid_str(self, ifacename):
        pvid, vids = self.cache.get_pvid_and_vids(ifacename)

        if vids:
            ret_vids = utils.compress_into_ranges(vids)
        else:
            ret_vids = None

        if pvid:
            ret_pvid = '%s' %pvid
        else:
            ret_pvid = None
        return (ret_vids, ret_pvid)

    def config_check_bridge_vni_svi_limit(self, vxlan_brport_obj, ifaceobj_getfunc, pvid):
        """
        Multiple VXLANs can't be added to the same VLAN
        """
        ifname = vxlan_brport_obj.name

        for intf in vxlan_brport_obj.upperifaces:
            # find the bridge object to access the brport list

            for obj in ifaceobj_getfunc(intf):
                if obj.link_kind & ifaceLinkKind.BRIDGE:

                    for brport_name in self._get_bridge_port_list(obj):
                        # loop through the brports

                        if ifname == brport_name:
                            # ignore current brport
                            continue

                        for brport_obj in ifaceobj_getfunc(brport_name):
                            # loop through brport ifaceobjs and check for vxlan bridge-access value

                            if not brport_obj.link_kind & ifaceLinkKind.VXLAN:
                                continue

                            access = brport_obj.get_attr_value_first("bridge-access")
                            if access == pvid:
                                raise AddonException(
                                    "%s: misconfiguration detected: vlan \"%s\" added to two or more VXLANS (%s, %s)" % (
                                        ifname,
                                        access,
                                        ifname,
                                        brport_obj.name
                                    )
                                )

    def _apply_bridge_vids_and_pvid(self, bportifaceobj, ifaceobj_getfunc, vids, pvid,
                                    isbridge):
        """ This method is a combination of methods _apply_bridge_vids and
            _apply_bridge_port_pvids above. A combined function is
            found necessary to do the deletes first and the adds later
            because kernel does honor vid info flags during deletes.

        """
        if not isbridge and (bportifaceobj.link_kind & ifaceLinkKind.VXLAN and not bportifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN):
            self.config_check_bridge_vni_svi_limit(bportifaceobj, ifaceobj_getfunc, pvid)

            if not vids or not pvid or len(vids) > 1 or vids[0] != pvid:
                self._error_vxlan_in_vlan_aware_br(bportifaceobj,
                                                   bportifaceobj.upperifaces[0])
                return

        vids_int =  utils.ranges_to_ints(vids)
        try:
            pvid_int = int(pvid) if pvid else 0
        except Exception:
            self.logger.warning('%s: unable to parse pvid \'%s\''
                             %(bportifaceobj.name, pvid))
            pvid_int = 0

        vids_to_del = []
        vids_to_add = vids_int
        pvid_to_del = None
        pvid_to_add = pvid_int

        try:
            if not self._check_vids(bportifaceobj, vids):
               return

            running_pvid, running_vids = self.cache.get_pvid_and_vids(bportifaceobj.name)

            if not running_vids and not running_pvid:
                # There cannot be a no running pvid.
                # It might just not be in our cache:
                # this can happen if at the time we were
                # creating the bridge vlan cache, the port
                # was not part of the bridge. And we need
                # to make sure both vids and pvid is not in
                # the cache, to declare that our cache may
                # be stale.
                running_pvid = 1
                running_vids = [1]

            if running_vids:
                (vids_to_del, vids_to_add) = \
                    utils.diff_ids(vids_to_add, running_vids)

            if running_pvid and running_pvid != pvid_int and running_pvid != 0:
                pvid_to_del = running_pvid

            if (pvid_to_del and (pvid_to_del in vids_int) and
                (pvid_to_del not in vids_to_add)):
                # kernel deletes dont take into account
                # bridge vid flags and its possible that
                # the pvid deletes we do end up deleting
                # the vids. Be proactive and add the pvid
                # to the vid add list if it is in the vids
                # and not already part of vids_to_add.
                # This helps with a small corner case:
                #   - running
                #       pvid 100
                #       vid 101 102
                #   - new change is going to move the state to
                #       pvid 101
                #       vid 100 102
                vids_to_add.add(pvid_to_del)
        except exceptions.ReservedVlanException as e:
            raise e
        except Exception as e:
            self.log_error('%s: failed to process vids/pvids'
                           %bportifaceobj.name + ' vids = %s' %str(vids) +
                           'pvid = %s ' %pvid + '(%s)' %str(e),
                           bportifaceobj, raise_error=False)
        try:
            if vids_to_del:
               if pvid_to_add in vids_to_del:
                   vids_to_del.remove(pvid_to_add)

               vids_to_del = sorted(list(self.remove_bridge_vlans_mapped_to_vnis_from_vids_list(None, bportifaceobj, vids_to_del)))

               self.iproute2.batch_start()
               self.iproute2.bridge_vlan_del_vid_list_self(bportifaceobj.name,
                                          utils.compress_into_ranges(
                                          vids_to_del), isbridge)
               self.iproute2.batch_commit()
        except Exception as e:
                self.log_warn('%s: failed to del vid `%s` (%s)'
                        %(bportifaceobj.name, str(vids_to_del), str(e)))

        try:
            if pvid_to_del:
               self.iproute2.bridge_vlan_del_pvid(bportifaceobj.name,
                                               pvid_to_del)
        except Exception as e:
                self.log_warn('%s: failed to del pvid `%s` (%s)'
                        %(bportifaceobj.name, pvid_to_del, str(e)))

        try:

            if vids_to_add:
                self.iproute2.batch_start()
                self.iproute2.bridge_vlan_add_vid_list_self(
                    bportifaceobj.name,
                    utils.compress_into_ranges(sorted(list(vids_to_add))),
                    isbridge
                )
                self.iproute2.batch_commit()
        except Exception as e:
                self.log_error('%s: failed to set vid `%s` (%s)'
                               %(bportifaceobj.name, str(vids_to_add),
                                 str(e)), bportifaceobj, raise_error=False)

        try:
            if pvid_to_add and pvid_to_add != running_pvid:
                self.iproute2.bridge_vlan_add_pvid(bportifaceobj.name,
                                                pvid_to_add)
        except Exception as e:
                self.log_error('%s: failed to set pvid `%s` (%s)'
                               %(bportifaceobj.name, pvid_to_add, str(e)),
                               bportifaceobj)

    def get_bridge_vlans_mapped_to_vnis_as_integer_list(self, ifaceobj):
        """
            Get all vlans that the user wants to configured in vlan-vni maps
        """
        try:
            vids = []

            for vlans_vnis_map in ifaceobj.get_attr_value("bridge-vlan-vni-map"):
                for vlans_vni_map in vlans_vnis_map.split():
                    vids.extend(utils.ranges_to_ints([vlans_vni_map.split("=")[0]]))

            return vids
        except Exception as e:
            self.logger.debug("get_bridge_vlans_mapped_to_vnis_as_integer_list: %s" % str(e))
            return []

    def remove_bridge_vlans_mapped_to_vnis_from_vids_list(self, bridge_ifaceobj, vxlan_ifaceobj, vids_list):
        """
            For single vxlan we need to remove the vlans mapped to vnis
            from the vids list otherwise they will get removed from the brport
        """
        if not (vxlan_ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN):
            return vids_list

        user_config_vids = []

        if bridge_ifaceobj:
            for vid in self.get_bridge_vlans_mapped_to_vnis_as_integer_list(bridge_ifaceobj):
                user_config_vids.append(vid)

        if vxlan_ifaceobj:
            for vid in self.get_bridge_vlans_mapped_to_vnis_as_integer_list(vxlan_ifaceobj):
                user_config_vids.append(vid)

        for vlan in user_config_vids:
            try:
                vids_list.remove(vlan)
            except Exception:
                pass

        return vids_list

    def _apply_bridge_vlan_aware_port_settings_all(self, bportifaceobj, ifaceobj_getfunc,
                                                   bridge_vids=None,
                                                   bridge_pvid=None):
        vids = None
        pvids = None
        vids_final = []
        pvid_final = None
        bport_access = bportifaceobj.get_attr_value_first('bridge-access')
        if bport_access:
            vids = re.split(r'[\s\t]\s*', bport_access)
            pvids = vids
            allow_untagged = 'yes'
            self.check_bridge_port_vid_attrs(bportifaceobj)
        else:
            allow_untagged = bportifaceobj.get_attr_value_first('bridge-allow-untagged') or 'yes'

            bport_vids = self.get_ifaceobj_bridge_vids_value(bportifaceobj)
            if bport_vids:
                vids = re.split(r'[\s\t,]\s*', bport_vids)

            bport_pvids = bportifaceobj.get_attr_value_first('bridge-pvid')
            if bport_pvids:
                pvids = re.split(r'[\s\t]\s*', bport_pvids)

        if vids:
            vids_final =  vids
        elif bridge_vids:
            vids_final = bridge_vids

        self.check_bridge_single_vxlan(bportifaceobj)

        vxlan_in_collect_metadata_mode = (
            bportifaceobj.link_privflags &
            (ifaceLinkPrivFlags.SINGLE_VXLAN | ifaceLinkPrivFlags.L3VXI))
        if allow_untagged == 'yes' and not vxlan_in_collect_metadata_mode:
            if pvids:
                pvid_final = pvids[0]
            elif bridge_pvid:
                pvid_final = bridge_pvid
            else:
                pvid_final = '1'
        else:
            pvid_final = None

        self._apply_bridge_vids_and_pvid(bportifaceobj, ifaceobj_getfunc, vids_final,
                                         pvid_final, False)

    def _apply_bridge_port_settings_all(self, ifaceobj, ifaceobj_getfunc, bridge_vlan_aware):
        err = False

        if (ifaceobj.get_attr_value_first('bridge-port-vids') and
                ifaceobj.get_attr_value_first('bridge-port-pvids')):
            # Old style bridge port vid info
            # skip new style setting on ports
            return
        self.logger.info('%s: applying bridge configuration '
                         %ifaceobj.name + 'specific to ports')

        bridge_vids = self.get_ifaceobj_bridge_vids_value(ifaceobj)
        if bridge_vids:
           bridge_vids = re.split(r'[\s\t,]\s*', bridge_vids)
        else:
           bridge_vids = None

        bridge_pvid = ifaceobj.get_attr_value_first('bridge-pvid')
        if bridge_pvid:
           bridge_pvid = re.split(r'[\s\t]\s*', bridge_pvid)[0]
        else:
           bridge_pvid = None

        if (ifaceobj.module_flags.get(self.name, 0x0) &
                BridgeFlags.PORT_PROCESSED_OVERRIDE):
            port_processed_override = True
        else:
            port_processed_override = False

        bridgeports = self._get_bridge_port_list(ifaceobj)
        if not bridgeports:
           self.logger.debug('%s: cannot find bridgeports' %ifaceobj.name)
           return
        self.iproute2.batch_start()
        for bport in bridgeports:
            # on link_set_master we need to wait until we cache the correct
            # notification and register the brport as slave
            if not self.cache.bridge_port_exists(ifaceobj.name, bport):
                self.logger.info('%s: skipping bridge config' %ifaceobj.name +
                        ' for port %s (missing port)' %bport)
                continue
            self.logger.info('%s: processing bridge config for port %s'
                             %(ifaceobj.name, bport))
            bportifaceobjlist = ifaceobj_getfunc(bport)
            if not bportifaceobjlist:
                continue
            for bportifaceobj in bportifaceobjlist:
                # Dont process bridge port if it already has been processed
                # and there is no override on port_processed
                if (not port_processed_override and
                    (bportifaceobj.module_flags.get(self.name,0x0) &
                     BridgeFlags.PORT_PROCESSED)):
                    continue
                try:
                    # Add attributes specific to the vlan aware bridge
                    if bridge_vlan_aware:
                        self._apply_bridge_vlan_aware_port_settings_all(
                                bportifaceobj, ifaceobj_getfunc, bridge_vids, bridge_pvid)
                    elif self.warn_on_untagged_bridge_absence:
                        self._check_untagged_bridge(ifaceobj.name, bportifaceobj, ifaceobj_getfunc)
                except exceptions.ReservedVlanException as e:
                    raise e
                except Exception as e:
                    err = True
                    self.logger.warning('%s: %s' %(ifaceobj.name, str(e)))
        self.iproute2.batch_commit()
        if err:
           raise AddonException('%s: errors applying port settings' %ifaceobj.name)

    def _check_untagged_bridge(self, bridgename, bridgeportifaceobj, ifaceobj_getfunc):
        if bridgeportifaceobj.link_kind & ifaceLinkKind.VLAN:
            lower_ifaceobj_list = ifaceobj_getfunc(bridgeportifaceobj.lowerifaces[0])
            if lower_ifaceobj_list and lower_ifaceobj_list[0] and \
                    not lower_ifaceobj_list[0].link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT:
                self.logger.warning('%s: untagged bridge not found. Please configure a bridge with untagged bridge ports to avoid Spanning Tree Interoperability issue.' % bridgename)
                self.warn_on_untagged_bridge_absence = False

    def bridge_port_get_bridge_name(self, ifaceobj):
        bridgename = self.cache.get_bridge_name_from_port(ifaceobj.name)
        if not bridgename:
            # bridge port is not enslaved to a bridge we need to find
            # the bridge in it's upper ifaces then enslave it
            for u in ifaceobj.upperifaces:
                if self.cache.link_is_bridge(u):
                    return True, u
            return False, None
        # return should_enslave port, bridgename
        return False, bridgename

    def up_bridge_port_vlan_aware_bridge(self, ifaceobj, ifaceobj_getfunc, bridge_name, should_enslave_port):
        if should_enslave_port:
            self.netlink.link_set_master(ifaceobj.name, bridge_name)

            if ifaceobj.name not in self.svd_list:
                self.handle_ipv6([ifaceobj.name], '1')

        bridge_vids = self._get_bridge_vids(bridge_name, ifaceobj_getfunc)
        bridge_pvid = self._get_bridge_pvid(bridge_name, ifaceobj_getfunc)
        try:
            self._apply_bridge_vlan_aware_port_settings_all(ifaceobj, ifaceobj_getfunc, bridge_vids, bridge_pvid)
        except Exception as e:
            self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj)
            return

    def up_bridge_port(self, ifaceobj, ifaceobj_getfunc):
        should_enslave_port, bridge_name = self.bridge_port_get_bridge_name(ifaceobj)

        if not bridge_name:
            # bridge doesn't exist
            return

        if not should_enslave_port and not self.cumulus:
            self.cycle_vxlan_brport_on_vni_change(bridge_name, ifaceobj)

        # check for bridge-learning on l2 vni in evpn setup
        self.syntax_check_learning_l2_vni_evpn(ifaceobj)

        # detect and warn when arp suppression is enabled and there is no vlan configured
        self.syntax_check_bridge_arp_vni_vlan(ifaceobj, ifaceobj_getfunc)

        vlan_aware_bridge = self.cache.bridge_is_vlan_aware(bridge_name)
        if vlan_aware_bridge:
            self.up_bridge_port_vlan_aware_bridge(ifaceobj,
                                                  ifaceobj_getfunc,
                                                  bridge_name,
                                                  should_enslave_port)

        bridge_ifaceobj = ifaceobj_getfunc(bridge_name)[0]

        self.up_apply_brports_attributes(target_ports=[ifaceobj.name],
                                         ifaceobj=bridge_ifaceobj,
                                         ifaceobj_getfunc=ifaceobj_getfunc,
                                         bridge_vlan_aware=vlan_aware_bridge)

        ifaceobj.module_flags[self.name] = ifaceobj.module_flags.setdefault(self.name, 0) | BridgeFlags.PORT_PROCESSED

    def up_check_bridge_vlan_aware(self, ifaceobj, ifaceobj_getfunc, link_just_created):
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE:
            if not self.check_bridge_vlan_aware_port(ifaceobj, ifaceobj_getfunc):
                return False
            if not link_just_created and not self.cache.bridge_is_vlan_aware(ifaceobj.name):
                # if bridge-vlan-aware was added on a existing old-bridge, we need to reprocess all ports
                ifaceobj.module_flags[self.name] = ifaceobj.module_flags.setdefault(self.name, 0) | BridgeFlags.PORT_PROCESSED_OVERRIDE
            return True
        return False

    @staticmethod
    def parse_interface_list_value(user_config):
        config = dict()
        for entry in user_config.split():
            ifname, value = entry.split('=')
            config[ifname] = value
        return config

    def sync_bridge_learning_to_vxlan_brport(self, bridge_name, brport_ifaceobj, brport_name, brport_ifla_info_slave_data, user_config_brport_learning_nl, cached_brport_learning):
        """
            brport_ifaceobj.link_kind & ifaceLinkKind.VXLAN
            and
            brport_ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT

            Checks are not performed in this function and must be verified
             before. This is done this way to avoid calling this method on
             non vlan & bridge port interfaces thus wasting a bit less time
        """
        kind = None
        ifla_info_data = {}

        if user_config_brport_learning_nl is None:
            user_config_brport_learning_nl = self.bridge_vxlan_port_learning
            # bridge-learning is not configured by the user or by a policy
            # use "bridge-vxlan-port-learning" policy to set bridge-learning (default on)

        if user_config_brport_learning_nl != cached_brport_learning:
            brport_ifla_info_slave_data[Link.IFLA_BRPORT_LEARNING] \
                = cached_brport_learning \
                = user_config_brport_learning_nl

            self.logger.info(
                "%s: %s: set bridge-learning %s"
                % (bridge_name, brport_name, "on" if user_config_brport_learning_nl else "off")
            )
        else:
            # in this case, the current bridge-learning value is properly configured and
            # doesn't need to be reset. We need to make sure that BRPORT_LEARNING is not
            # part of ifla_info_slave_data.
            try:
                del brport_ifla_info_slave_data[Link.IFLA_BRPORT_LEARNING]
            except Exception:
                pass

        #
        # vxlan-learning sync:
        #
        user_brport_vxlan_learning_config = brport_ifaceobj.get_attr_value_first("vxlan-learning")

        if not user_brport_vxlan_learning_config:
            # if vxlan-learning is not defined on the brport

            if user_config_brport_learning_nl is not None:
                # if bridge-learning is defined on the brport use it's value to sync vxlan-learning
                user_brport_vxlan_learning_config_nl = user_config_brport_learning_nl

            else:
                # if bridge-learning is not defined, we check for policy and convert it into netlink format
                brport_vxlan_learning_config = policymanager.policymanager_api.get_attr_default("vxlan", "vxlan-learning")

                if brport_vxlan_learning_config is not None:
                    user_brport_vxlan_learning_config_nl = utils.get_boolean_from_string(brport_vxlan_learning_config)

                else:
                    # None = no policy set, default to the current brport learning
                    user_brport_vxlan_learning_config_nl = cached_brport_learning

        else:
            # if vxlan-learning is set we need to honor the user config
            user_brport_vxlan_learning_config_nl = utils.get_boolean_from_string(user_brport_vxlan_learning_config)

        if user_brport_vxlan_learning_config_nl != self.cache.get_link_info_data_attribute(
            brport_name,
            Link.IFLA_VXLAN_LEARNING
        ):
            self.logger.info(
                "%s: %s: vxlan learning and bridge learning out of sync: set vxlan-learning %s"
                % (bridge_name, brport_name, "on" if user_brport_vxlan_learning_config_nl else "off")
            )
            ifla_info_data = {Link.IFLA_VXLAN_LEARNING: user_brport_vxlan_learning_config_nl}
            kind = "vxlan"
        # if kind and ifla_info_data are set they will be added to the
        # netlink request on the VXLAN brport, to sync IFLA_VXLAN_LEARNING
        return kind, ifla_info_data

    def up_apply_brports_attributes(self, ifaceobj, ifaceobj_getfunc, bridge_vlan_aware, target_ports=[], newly_enslaved_ports=[]):
        ifname = ifaceobj.name
        single_vxlan_device_ifaceobj = None

        try:
            brports_ifla_info_slave_data    = dict()
            brport_ifaceobj_dict            = dict()
            brport_name_list                = []

            cache_brports_ifla_info_slave_data = {}

            port_processed_override = ifaceobj.module_flags.get(self.name, 0x0) & BridgeFlags.PORT_PROCESSED_OVERRIDE

            running_brports = self.cache.get_slaves(ifname)

            # If target_ports is specified we want to configure only this
            # sub-list of port, we need to check if these ports are already
            # enslaved, if not they will be ignored.
            # If target_ports is not populated we will apply the brport
            # attributes on all running brport.
            if target_ports:
                new_targets = []
                for brport_name in target_ports:
                    if brport_name not in running_brports:
                        self.logger.info('%s: not enslaved to bridge %s: ignored for now' % (brport_name, ifname))
                    else:
                        new_targets.append(brport_name)
                running_brports = new_targets

            for port in running_brports:
                brport_list = ifaceobj_getfunc(port)
                if brport_list:
                    port_already_processed = False

                    # ports just added to the bridge have to be processed
                    if port not in newly_enslaved_ports:
                        # check if brport was already processed
                        for brportifaceobj in brport_list:
                            if not port_processed_override and brportifaceobj.module_flags.get(self.name, 0x0) & BridgeFlags.PORT_PROCESSED:
                                # skip port if already processed (probably by `up_bridge_port`)
                                port_already_processed = True
                                self.logger.info("%s: port %s: already processed" % (ifname, port))
                                break

                    if not port_already_processed:
                        brport_name_list.append(port)
                        brport_ifaceobj_dict[port] = brport_list[0]
                        brports_ifla_info_slave_data[port] = dict()

                        if not ifupdownflags.flags.PERFMODE and port not in newly_enslaved_ports:
                            # if the port has just been enslaved, info_slave_data is not cached yet
                            cache_brports_ifla_info_slave_data[port] = self.cache.get_link_info_slave_data(port)
                        else:
                            cache_brports_ifla_info_slave_data[port] = {}

            if not brport_name_list:
                self.bridge_process_vidinfo_mcqv4src_maxwait(ifaceobj)
                return

            self.logger.info('%s: applying bridge port configuration: %s' % (ifname, brport_name_list))

            cached_bridge_mcsnoop = self.cache.get_bridge_multicast_snooping(ifname)

            bridge_ports_learning = {}
            bridge_ports_vxlan_arp_suppress = {}
            cached_bridge_ports_learning = {}

            # we iterate through all IFLA_BRPORT supported attributes
            for attr_name, nl_attr in self._ifla_brport_attributes_map.items():
                br_config = ifaceobj.get_attr_value_first(attr_name)
                translate_func = self._ifla_brport_attributes_translate_user_config_to_netlink_map.get(nl_attr)

                if not translate_func:
                    # if no translation function is found,
                    # we ignore this attribute and continue
                    continue

                if not br_config:
                    # user didn't specify any value for this attribute
                    # looking at policy overrides
                    br_config = policymanager.policymanager_api.get_iface_default(
                        module_name=self.__class__.__name__,
                        ifname=ifname,
                        attr=attr_name
                    )

                if br_config and "=" in br_config:
                    # if bridge_vlan_aware:
                    #    self.logger.info('%s: is a vlan-aware bridge, "%s %s" '
                    #                     'should be configured under the ports'
                    #                     % (ifname, attr_name, br_config))

                    # convert the <interface-yes-no-0-1-list> and <interface-range-list> value to subdict
                    # brport_name: { attr: value }
                    # example:
                    #   bridge-portprios swp1=5 swp2=32
                    # swp1: { bridge-portprios: 5 } swp2: { bridge-portprios: 32}
                    try:
                        br_config = self.parse_interface_list_value(br_config)
                    except Exception:
                        self.log_error("error while parsing '%s %s'" % (attr_name, br_config))
                        continue

                for brport_ifaceobj in list(brport_ifaceobj_dict.values()):
                    brport_config = brport_ifaceobj.get_attr_value_first(attr_name)
                    brport_name = brport_ifaceobj.name

                    if not ifupdownflags.flags.PERFMODE:
                        cached_value = cache_brports_ifla_info_slave_data.get(brport_name, {}).get(nl_attr, None)
                    else:
                        cached_value = None

                    if not brport_config:
                        # if a brport attribute was specified under the bridge and not under the port
                        # we assign the bridge value to the port. If an attribute is both defined under
                        # the bridge and the brport we keep the value of the port and ignore the br val.
                        if type(br_config) == dict:
                            # if the attribute value was in the format interface-list-value swp1=XX swp2=YY
                            # br_config is a dictionary, example:
                            # bridge-portprios swp1=5 swp2=32 = {swp1: 5, swp2: 32}
                            brport_config = br_config.get(brport_name)
                        else:
                            brport_config = br_config

                    if not brport_config:
                        brport_config = policymanager.policymanager_api.get_iface_default(
                            module_name=self.__class__.__name__,
                            ifname=brport_name,
                            attr=attr_name
                        )

                    user_config = brport_config

                    # attribute specific work
                    # This shouldn't be here but we don't really have a choice otherwise this
                    # will require too much code duplication and will make the code very complex
                    if nl_attr == Link.IFLA_BRPORT_NEIGH_SUPPRESS:
                        bridge_ports_vxlan_arp_suppress[brport_name] = user_config
                        try:
                            if user_config:
                                if self.arp_nd_suppress_only_on_vxlan and not brport_ifaceobj.link_kind & ifaceLinkKind.VXLAN:
                                    self.logger.warning('%s: %s: \'bridge-arp-nd-suppress\' '
                                                        'is not supported on a non-vxlan port'
                                                        % (ifaceobj.name, brport_name))
                                    continue
                            elif bridge_vlan_aware:
                                if not self.arp_nd_suppress_only_on_vxlan:
                                    user_config = self.get_mod_subattr('bridge-arp-nd-suppress', 'default')
                                elif self.arp_nd_suppress_only_on_vxlan and brport_ifaceobj.link_kind & ifaceLinkKind.VXLAN:
                                    # ignore the case of VXLAN brport - handled later in the code
                                    continue
                        except Exception:
                            continue
                    elif nl_attr == Link.IFLA_BRPORT_GROUP_FWD_MASK:
                        # special handking for group_fwd_mask because Cisco proprietary
                        # protocol needs to be set via a private netlink attribute
                        self.ifla_brport_group_fwd_mask(ifname, brport_name,
                                                        brports_ifla_info_slave_data,
                                                        user_config, cached_value)
                        continue

                    #if brport_config:
                    #    if not bridge_vlan_aware:
                    #        self.logger.info('%s: %s: is not a vlan-aware bridge, "%s %s" '
                    #                         'should be configured under the bridge'
                    #                         % (ifname, brport_name,
                    #                            attr_name, brport_config))

                    if user_config:
                        user_config_nl = translate_func(user_config)
                        # check config value against running value
                        if user_config_nl != cached_value:
                            brports_ifla_info_slave_data[brport_name][nl_attr] = user_config_nl
                            self.logger.info('%s: %s: set %s %s' % (ifname, brport_name, attr_name, user_config))
                            self.logger.debug('(cache %s)' % cached_value)

                        if nl_attr == Link.IFLA_BRPORT_LEARNING:
                            # for vxlan-learning sync purposes we need to save the user config for each brports.
                            # The dictionary 'brports_ifla_info_slave_data' might not contain any value for
                            # IFLA_BRPORT_LEARNING if the user value is already configured and running
                            # nevertheless we still need to check if the vxlan-learning is rightly synced with
                            # the brport since it might go out of sync for X and Y reasons.
                            # we also store the cached value to avoid an extra cache lookup.
                            bridge_ports_learning[brport_name] = user_config_nl
                            cached_bridge_ports_learning[brport_name] = cached_value

                    elif cached_value is not None:
                        # no config found, do we need to reset to default?
                        default = self.get_attr_default_value(attr_name)
                        if default:
                            default_netlink = translate_func(default)

                            if nl_attr == Link.IFLA_BRPORT_LEARNING:
                                # for vxlan-learning sync purposes we need to save the user config for each brports.
                                # The dictionary 'brports_ifla_info_slave_data' might not contain any value for
                                # IFLA_BRPORT_LEARNING if the user value is already configured and running
                                # nevertheless we still need to check if the vxlan-learning is rightly synced with
                                # the brport since it might go out of sync for X and Y reasons.
                                # we also store the cached value to avoid an extra cache lookup.
                                cached_bridge_ports_learning[brport_name] = cached_value
                                bridge_ports_learning[brport_name] = self.bridge_vxlan_port_learning

                                if brport_ifaceobj.link_kind & ifaceLinkKind.VXLAN:
                                    # bridge-learning for vxlan device is handled separatly in sync_bridge_learning_to_vxlan_brport
                                    continue

                                if not ifupdownflags.flags.PERFMODE and brport_name not in newly_enslaved_ports:
                                    # We don't query new slaves and not during boot
                                    try:
                                        if self.cache.get_link_info_slave_data_attribute(brport_name, Link.IFLA_BRPORT_PEER_LINK):
                                            if default_netlink != cached_value:
                                                self.logger.debug('%s: %s: bridge port peerlink: ignoring bridge-learning'
                                                                  % (ifname, brport_name))
                                            continue
                                    except Exception as e:
                                        self.logger.debug('%s: %s: peerlink check: %s' % (ifname, brport_name, str(e)))

                            if (
                                nl_attr == Link.IFLA_BRPORT_MULTICAST_ROUTER
                                and cached_value == 2
                                and brport_ifaceobj.link_kind & ifaceLinkKind.VXLAN
                                and brport_ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT) \
                                and (
                                (
                                    self.vxlan_bridge_igmp_snooping_enable_port_mcrouter and utils.get_boolean_from_string(
                                    self.get_bridge_mcsnoop_value(ifaceobj))
                                ) or cached_bridge_mcsnoop
                            ):
                                # if policy "vxlan_bridge_igmp_snooping_enable_port_mcrouter" is on and mcsnoop is
                                # on (or mcsnoop is already enabled on the bridge, keep 'bridge-portmcrouter 2'
                                # on vxlan ports (if not set by the user)
                                continue

                            if default_netlink != cached_value:
                                self.logger.info('%s: %s: %s: no configuration detected, resetting to default %s'
                                                 % (ifname, brport_name, attr_name, default))
                                self.logger.debug('(cache %s)' % cached_value)
                                brports_ifla_info_slave_data[brport_name][nl_attr] = default_netlink

            # is the current bridge (ifaceobj) a QinQ bridge?
            # This variable is initialized to None and will be
            # change to True/False, so that the check is only
            # performed once
            qinq_bridge = None

            # applying bridge port configuration via netlink
            for brport_name, brport_ifla_info_slave_data in list(brports_ifla_info_slave_data.items()):

                brport_ifaceobj = brport_ifaceobj_dict.get(brport_name)
                if (brport_ifaceobj
                    and brport_ifaceobj.link_kind & ifaceLinkKind.VXLAN
                    and brport_ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT):
                    # if the brport is a VXLAN, we might need to sync the VXLAN learning with the brport_learning val
                    # we use the same netlink request, by specfying kind=vxlan and ifla_info_data={vxlan_learning=0/1}
                    kind, ifla_info_data = self.sync_bridge_learning_to_vxlan_brport(ifaceobj.name,
                                                                                     brport_ifaceobj,
                                                                                     brport_name,
                                                                                     brport_ifla_info_slave_data,
                                                                                     bridge_ports_learning.get(brport_name),
                                                                                     cached_bridge_ports_learning.get(brport_name))

                    if (self.vxlan_bridge_igmp_snooping_enable_port_mcrouter and utils.get_boolean_from_string(
                            self.get_bridge_mcsnoop_value(ifaceobj)
                    )) or cached_bridge_mcsnoop:
                        # if policy "vxlan_bridge_igmp_snooping_enable_port_mcrouter"
                        # is on and mcsnoop is on (or mcsnoop is already enabled on the
                        # bridge, set 'bridge-portmcrouter 2' on vxlan ports (if not set by the user)
                        if not brport_ifla_info_slave_data.get(Link.IFLA_BRPORT_MULTICAST_ROUTER) \
                                and self.cache.get_bridge_port_multicast_router(brport_name) != 2:
                            brport_ifla_info_slave_data[Link.IFLA_BRPORT_MULTICAST_ROUTER] = 2
                            self.logger.info("%s: %s: vxlan bridge igmp snooping: enable port multicast router" % (ifname, brport_name))

                    #
                    # handling attribute: bridge-arp-nd-suppress
                    # defaults to bridge-vxlan-arp-nd-suppress policy (default False)
                    #
                    user_config_neigh_suppress = bridge_ports_vxlan_arp_suppress.get(brport_name)

                    if user_config_neigh_suppress is None:

                        if qinq_bridge is None:
                            # QinQ bridge hasn't been checked yet
                            qinq_bridge = self.is_qinq_bridge(
                                ifaceobj,
                                brport_name,
                                running_brports,
                                brport_ifaceobj_dict,
                                ifaceobj_getfunc
                            )

                        if qinq_bridge:
                            # exclude QinQ bridge from arp-nd-suppress default policy on
                            config_neigh_suppress = 0
                            self.logger.info("%s: QinQ bridge detected: %s: set bridge-arp-nd-suppress off" % (ifname, brport_name))
                        else:
                            config_neigh_suppress = self.bridge_vxlan_arp_nd_suppress_int
                    else:
                        config_neigh_suppress = int(utils.get_boolean_from_string(user_config_neigh_suppress))

                    brport_neigh_suppress_cached_value = self.cache.get_link_info_slave_data_attribute(
                        brport_name,
                        Link.IFLA_BRPORT_NEIGH_SUPPRESS
                    )

                    if config_neigh_suppress != brport_neigh_suppress_cached_value:
                        brport_ifla_info_slave_data[Link.IFLA_BRPORT_NEIGH_SUPPRESS] = config_neigh_suppress

                        if not user_config_neigh_suppress:
                            # if the configuration is not explicitely defined by the user
                            # we need report that the default behavior is enabled by policy
                            self.logger.info(
                                "%s: set bridge-arp-nd-suppress %s by default on vxlan port (%s)"
                                % (ifname, "on" if self.bridge_vxlan_arp_nd_suppress else "off", brport_name)
                            )
                    else:
                        # the user configuration (or policy) is already configured and running
                        # we need to remove this attribute from the request dictionary
                        try:
                            del brport_ifla_info_slave_data[Link.IFLA_BRPORT_NEIGH_SUPPRESS]
                        except Exception:
                            pass

                    #
                    # SINGLE VXLAN - enable IFLA_BRPORT_VLAN_TUNNEL
                    #

                    if brport_ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN:
                        single_vxlan_device_ifaceobj = brport_ifaceobj
                        brport_vlan_tunnel_cached_value = self.cache.get_link_info_slave_data_attribute(
                            brport_name,
                            Link.IFLA_BRPORT_VLAN_TUNNEL
                        )

                        if not brport_vlan_tunnel_cached_value:
                            self.logger.info("%s: %s: enabling vlan_tunnel on single vxlan device" % (ifname, brport_name))
                            brport_ifla_info_slave_data[Link.IFLA_BRPORT_VLAN_TUNNEL] = 1

                else:
                    kind = None
                    ifla_info_data = {}

                if brport_ifla_info_slave_data or ifla_info_data:
                    try:
                        self.netlink.link_set_brport_with_info_slave_data(
                            ifname=brport_name,
                            kind=kind,
                            ifla_info_data=ifla_info_data,
                            ifla_info_slave_data=brport_ifla_info_slave_data
                        )
                    except Exception as e:
                        self.logger.warning('%s: %s: %s' % (ifname, brport_name, str(e)))

            self.bridge_process_vidinfo_mcqv4src_maxwait(ifaceobj)

        except Exception as e:
            self.log_error(str(e), ifaceobj)

        if single_vxlan_device_ifaceobj:
            self.apply_bridge_port_vlan_vni_map(ifaceobj, single_vxlan_device_ifaceobj)

    @staticmethod
    def range_to_string(range_start, range_end):
        return "%s" % range_start if range_start == range_end else "%s-%s" % (range_start, range_end)

    def range_list_to_string(self, ifname, vni_list):
        range_list = [v for v in utils.ints_to_ranges(vni_list)]

        if len(range_list) != 1 and len(range_list[0]) > 0:
            self.logger.debug("%s: vlan-vni-map has duplicated ranges: %s" % (ifname, json.dumps(range_list, indent=4)))
            self.log_error("misconfiguration detected - see debug output for details")

        return self.range_to_string(range_list[0][0], range_list[0][1])

    def check_duplicate_vnis(self, ifaceobj, vlan_vni_dict):
        rev = {}

        for key, value in vlan_vni_dict.items():
            rev.setdefault(value, set()).add(key)

        duplicates = [(key, values) for key, values in rev.items() if len(values) > 1]

        if duplicates:
            err_msg = ["duplicate vnis detected - see details below"]

            for vni, vlans in duplicates:
                err_msg.append("\tvni %s assigned to vlans: %s" % (vni, ", ".join(map(str, vlans))))

            self.log_error("\n".join(err_msg), ifaceobj)
            return False

        return True

    def get_vlan_vni_ranges_from_dict(self, ifname, vlan_vni_dict):
        """
        Since bridge-vlan-vni-map is a multiline attribute, we expend all the ranges
        and have all the vlan-vni mapping in vlan_vni_dict. We need to reconstruct the
        ranges to execute iproute2 commands.

        i.e. for a multiline vlan-vni configuration:
            bridge-vlan-vni-map 1=1
            bridge-vlan-vni-map 2=2
            bridge-vlan-vni-map 3=3
            bridge-vlan-vni-map 4=4

        we will only execute a single ranged-command: vlan add dev vxlan48 vid 1-4 tunnel_info id 1-4

        If we find duplicated vlan/vnis in ranges we raise an exception
        """
        vlan_vni_ranges = {}

        def list_to_range(vlan_list, vni_list, range_dict):
            if not vlan_list and not vni_list:
                return
            vlans = self.range_list_to_string(ifname, vlan_list)
            vnis = self.range_list_to_string(ifname, vni_list)
            range_dict[vlans] = vnis

        current_vlan_range = []
        current_vni_range = []

        for vlan in sorted(vlan_vni_dict.keys()):
            vni = vlan_vni_dict[vlan]

            if not current_vlan_range:
                current_vlan_range.append(vlan)
                current_vni_range.append(vni)

            else:
                if vlan - 1 == current_vlan_range[-1] and vni - 1 == current_vni_range[-1]:
                    current_vlan_range.append(vlan)
                    current_vni_range.append(vni)
                else:
                    list_to_range(current_vlan_range, current_vni_range, vlan_vni_ranges)
                    current_vlan_range = [vlan]
                    current_vni_range = [vni]

        list_to_range(current_vlan_range, current_vni_range, vlan_vni_ranges)
        return vlan_vni_ranges

    def check_bridge_vlan_vni_map_reserved(self, bridge_ifaceobj, ifaceobj, vlan_to_add):
        if bridge_ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_l3VNI or ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_l3VNI:
            # No need to check for vlan in the reserved range for l3vni bridge
            return
        for vlan in sorted(vlan_to_add):
            self._handle_reserved_vlan(vlan, ifaceobj.name)

    def apply_bridge_port_vlan_vni_map(self, bridge_ifaceobj, ifaceobj):
        """
        bridge vlan add vid <vlan-id> dev vxlan0
        bridge vlan add dev vxlan0 vid <vlan-id> tunnel_info id <vni>
        """
        vxlan_name = ifaceobj.name
        try:
            self.iproute2.batch_start()

            bridge_vlan_tunnel_info_running_config = self.iproute2.bridge_vlan_tunnel_show(vxlan_name)
            all_user_config = {}

            for bridge_vlan_vni_map_entry in ifaceobj.get_attr_value("bridge-vlan-vni-map"):
                if not bridge_vlan_vni_map_entry:
                    continue

                for vlan_vni_map_entry in bridge_vlan_vni_map_entry.split():
                    try:
                        vlans_str, vni_str = utils.get_vlan_vni_in_map_entry(vlan_vni_map_entry)
                    except Exception:
                        return self.__warn_bridge_vlan_vni_map_syntax_error(vxlan_name, vlan_vni_map_entry)

                    # we need to convert vlan_str and vni_str back to a map {vlan: vni}
                    for vlan, vni in zip(utils.ranges_to_ints([vlans_str]), utils.ranges_to_ints([vni_str])):

                        if vlan in all_user_config:
                            self.log_error("duplicate vlan found: %s" % vlan, ifaceobj)

                        all_user_config[vlan] = vni

            vlan_vni_to_remove = {}
            for k, v in set(bridge_vlan_tunnel_info_running_config.items()) - set(all_user_config.items()):
                vlan_vni_to_remove[k] = v

            vlan_vni_to_add = {}
            for k, v in set(all_user_config.items()) - set(bridge_vlan_tunnel_info_running_config.items()):
                vlan_vni_to_add[k] = v

            vlan_vni_ranges_to_remove = self.get_vlan_vni_ranges_from_dict(ifaceobj.name, vlan_vni_to_remove)

            # check if we have duplicated vnis in the user configuration
            self.check_duplicate_vnis(ifaceobj, vlan_vni_to_add)

            # check reserved vlans
            self.check_bridge_vlan_vni_map_reserved(bridge_ifaceobj, ifaceobj, vlan_vni_to_add.keys())

            vlan_vni_ranges_to_add = self.get_vlan_vni_ranges_from_dict(ifaceobj.name, vlan_vni_to_add)

            for vlan_range, vni_range in vlan_vni_ranges_to_remove.items():
                self.iproute2.bridge_vlan_del_vid_list_self(vxlan_name, [vlan_range], False)
                self.iproute2.bridge_vlan_del_vlan_tunnel_info(vxlan_name, vlan_range, vni_range)

            for vlan_range, vni_range in vlan_vni_ranges_to_add.items():
                self.iproute2.bridge_vlan_add_vid_list_self(vxlan_name, [vlan_range], False)
                self.iproute2.bridge_vlan_add_vlan_tunnel_info(vxlan_name, vlan_range, vni_range)

            self.iproute2.batch_commit()
        except Exception as e:
            ifaceobj.set_status(ifaceStatus.ERROR)
            raise BridgeVlanVniMapError("%s: error while processing bridge-vlan-vni-map: %s" % (vxlan_name, str(e)))

    def __warn_bridge_vlan_vni_map_syntax_error(self, ifname, user_config_vlan_vni_map):
        self.logger.warning("%s: syntax error: bridge-vlan-vni-map %s" % (ifname, user_config_vlan_vni_map))

    def is_qinq_bridge(self, ifaceobj, brport_name, running_brports, brport_ifaceobj_dict, ifaceobj_getfunc):
        """ Detect QinQ bridge
        Potential improvement: We could add a ifaceobj.link_privflags called
        BRIDGE_QINQ but for now it is not necessary.
        """

        # bridge-vlan-aware case
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE:
            return (ifaceobj.get_attr_value_first("bridge-vlan-protocol") or "").lower() == "802.1ad"

        # old-bridge
        else:
            for qinq_running_brport in running_brports:
                if qinq_running_brport == brport_name:
                    continue

                qinq_running_brport_ifaceobj = brport_ifaceobj_dict.get(qinq_running_brport)

                if not qinq_running_brport_ifaceobj:
                    continue

                if qinq_running_brport_ifaceobj.link_kind & ifaceLinkKind.VLAN:
                    for lower_iface in qinq_running_brport_ifaceobj.lowerifaces or []:
                        for lower_ifaceobj in ifaceobj_getfunc(lower_iface) or []:
                            if (lower_ifaceobj.get_attr_value_first("vlan-protocol") or "").lower() == "802.1ad":
                                return True
        return False

    def bridge_process_vidinfo_mcqv4src_maxwait(self, ifaceobj):
        self._set_bridge_vidinfo_compat(ifaceobj)
        self._set_bridge_mcqv4src_compat(ifaceobj)
        self._process_bridge_maxwait(ifaceobj, self._get_bridge_port_list(ifaceobj))

    def ifla_brport_group_fwd_mask(self, ifname, brport_name, brports_ifla_info_slave_data, user_config, cached_ifla_brport_group_fwd_mask):
        """
            Support for IFLA_BRPORT_GROUP_FWD_MASK and IFLA_BRPORT_GROUP_FWD_MASKHI
            Since this is the only ifupdown2 attribute dealing with more than 1 netlink
            field we need to have special handling for that.
        """
        ifla_brport_group_fwd_mask = 0
        ifla_brport_group_fwd_maskhi = 0

        if user_config:
            for group in user_config.replace(",", " ").split():
                if not group:
                    continue

                callback = self.l2protocol_tunnel_callback.get(group)

                if not callable(callback):
                    self.logger.warning('%s: %s: bridge-l2protocol-tunnel ignoring invalid parameter \'%s\'' % (ifname, brport_name, group))
                else:
                    ifla_brport_group_fwd_mask, ifla_brport_group_fwd_maskhi = callback(ifla_brport_group_fwd_mask, ifla_brport_group_fwd_maskhi)

        # cached_ifla_brport_group_fwd_mask is given as parameter because it was already pulled out from the cache in the functio above
        cached_ifla_brport_group_fwd_maskhi = self.cache.get_link_info_slave_data_attribute(brport_name, Link.IFLA_BRPORT_GROUP_FWD_MASKHI)

        log_mask_change = True
        # if user specify bridge-l2protocol-tunnel stp cdp
        # we need to set both MASK and MASKHI but we only want to log once

        if cached_ifla_brport_group_fwd_mask is None:
            cached_ifla_brport_group_fwd_mask = 0
        if cached_ifla_brport_group_fwd_maskhi is None:
            cached_ifla_brport_group_fwd_maskhi = 0

        # if the cache value is None it means that the kernel doesn't support this attribute
        # or that the cache is stale, we dumped this intf before it was enslaved in the bridge

        if ifla_brport_group_fwd_mask != cached_ifla_brport_group_fwd_mask:
            if log_mask_change:
                self.logger.info('%s: %s: set bridge-l2protocol-tunnel %s' % (ifname, brport_name, user_config))
                self.logger.debug('(cache %s)' % cached_ifla_brport_group_fwd_mask)
                log_mask_change = False
            brports_ifla_info_slave_data[brport_name][Link.IFLA_BRPORT_GROUP_FWD_MASK] = ifla_brport_group_fwd_mask

        if ifla_brport_group_fwd_maskhi != cached_ifla_brport_group_fwd_maskhi:
            if log_mask_change:
                self.logger.info('%s: %s: set bridge-l2protocol-tunnel %s' % (ifname, brport_name, user_config))
                self.logger.debug('(cache %s)' % cached_ifla_brport_group_fwd_maskhi)
            brports_ifla_info_slave_data[brport_name][Link.IFLA_BRPORT_GROUP_FWD_MASKHI] = ifla_brport_group_fwd_maskhi

    def get_bridge_mtu(self, ifaceobj):
        user_config_mtu = ifaceobj.get_attr_value_first("mtu")

        if not user_config_mtu:
            user_config_mtu = policymanager.policymanager_api.get_attr_default(
                module_name="address",
                attr="mtu"
            )

        try:
            if user_config_mtu:
                int(user_config_mtu)
                self.logger.info("%s: set bridge mtu %s" % (ifaceobj.name, user_config_mtu))
                return str(user_config_mtu)
        except Exception as e:
            self.logger.warning("%s: invalid bridge mtu %s: %s" % (ifaceobj.name, user_config_mtu, str(e)))
        return None

    def vxlan_hopping_filter(self, ifaceobj , ifaceobj_getfunc):
        bridge_ports = [
            port
            for ports in self._get_bridge_port_list(ifaceobj) for port in (ifaceobj_getfunc(ports) or [])
        ]

        vxlan_devs = list(filter(lambda p: p.link_kind == ifaceLinkKind.VXLAN, bridge_ports))
        bridge_is_vxlan = len(vxlan_devs) > 0

        vxlan_ports = set()
        if bridge_is_vxlan:
            vxlan_ports = set([self.netlink.VXLAN_UDP_PORT])
            vxlan_ports = vxlan_ports.union(map(lambda vx: vx.get_attr_value_first("vxlan-port"), vxlan_devs))
            vxlan_ports = set([p for p in vxlan_ports if p is not None ])

            desired_filters = [ (vxlan_port, None, 'drop') for vxlan_port in vxlan_ports ]
        else:
            desired_filters = []

        filters_to_add, filters_to_delete = self.iproute2.check_tc_filters(ifaceobj.name, desired_filters)

        try:
            self.iproute2.batch_start()

            for (vxlan_port, vid, _) in filters_to_delete:
                if vid == None:
                    self.iproute2.del_vxlan_hopping_tc_filter(ifaceobj.name, vxlan_port)

            for (vxlan_port, _, _) in filters_to_add:
                self.iproute2.add_vxlan_hopping_tc_filter(ifaceobj.name, vxlan_port)

            self.iproute2.batch_commit()
        except Exception as e:
            if "Unterminated quoted string" not in str(e):
                raise
            self.logger.debug(f"tc quote failure: {str(e)}")

    def cycle_vxlan_brport_on_vni_change(self, bridge_name: str, ifaceobj: iface):
        """
        Cycle VXLAN bridge port if VNI-to-VLAN mapping has changed.

        This function checks if any VNIs are reused with different VLANs in the new configuration.
        If so, it cycles the VXLAN port (removes it from the bridge and re-adds it) to ensure
        proper updating of the VNI-VLAN mappings.

        Args:
            bridge_name (str): Name of the bridge
            ifaceobj (object): Interface object containing new configuration
        Returns:
            None
        """
        if not ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN:
            return

        ifname: str = ifaceobj.name
        old_vlan_vni_map: dict = {}
        new_vlan_vni_map: dict = {}

        # Get old vlan-vni map from statemanager
        for old_obj in statemanager.get_ifaceobjs(ifname) or []:
            for mapping in old_obj.get_attr_value("bridge-vlan-vni-map") or []:
                for entry in mapping.split():
                    vlan, vni = entry.split("=")
                    old_vlan_vni_map[vni.strip()] = vlan.strip()

        # Get new vlan-vni map from current ifaceobj
        for mapping in ifaceobj.get_attr_value("bridge-vlan-vni-map") or []:
            for entry in mapping.split():
                vlan, vni = entry.split("=")
                new_vlan_vni_map[vni.strip()] = vlan.strip()

        # Find VNIs that are reused with different VLANs
        reused_vnis: list = []
        for vni, new_vlan in new_vlan_vni_map.items():
            if vni in old_vlan_vni_map and old_vlan_vni_map[vni] != new_vlan:
                reused_vnis.append(vni)

        if reused_vnis:
            self.logger.info(f"{ifname}: cycling VXLAN port from bridge '{bridge_name}' due to VNI reuse ({', '.join(reused_vnis)})")
            self.netlink.link_set_nomaster(ifname)
            self.netlink.link_set_master(ifname, bridge_name)

    def up_bridge(self, ifaceobj, ifaceobj_getfunc):
        ifname = ifaceobj.name

        if ifupdownflags.flags.PERFMODE:
            link_exists = False
        else:
            link_exists = self.cache.link_exists(ifaceobj.name)

        if not link_exists:
            self.netlink.link_add_bridge(ifname)
            link_just_created = True

            bridge_mtu = self.get_bridge_mtu(ifaceobj)
            if bridge_mtu:
                self.sysfs.link_set_mtu(ifname, bridge_mtu, int(bridge_mtu))
        else:
            link_just_created = False
            self.logger.info('%s: bridge already exists' % ifname)

        bridge_vlan_aware = self.up_check_bridge_vlan_aware(ifaceobj, ifaceobj_getfunc, link_just_created)

        if utils.is_pvrst_enabled() and bridge_vlan_aware and self.pvrst_vlan_aware_bridge:

            if not (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_l3VNI):
                self.log_error(f"{ifname}: when PVRST is enabled there can only be one vlan-aware "
                               f"bridge on the system ({self.pvrst_vlan_aware_bridge})", ifaceobj)

        elif bridge_vlan_aware:
            self.pvrst_vlan_aware_bridge = ifname

        self.up_apply_bridge_settings(ifaceobj, link_just_created, bridge_vlan_aware)

        try:
            newly_enslaved_ports = self._add_ports(ifaceobj, ifaceobj_getfunc)
            self.up_apply_brports_attributes(ifaceobj, ifaceobj_getfunc, bridge_vlan_aware,
                                             newly_enslaved_ports=newly_enslaved_ports)
        except BridgeVlanVniMapError:
            raise
        except Exception as e:
            self.logger.warning('%s: apply bridge ports settings: %s' % (ifname, str(e)))

        running_ports = ''
        try:
            running_ports = self.cache.get_slaves(ifaceobj.name)
            if not running_ports:
                return
            self._apply_bridge_port_settings_all(ifaceobj,
                                                 ifaceobj_getfunc=ifaceobj_getfunc,
                                                 bridge_vlan_aware=bridge_vlan_aware)
            self.vxlan_hopping_filter(ifaceobj, ifaceobj_getfunc)
        except exceptions.ReservedVlanException as e:
            raise e
        except Exception as e:
            self.logger.warning('%s: apply bridge settings: %s' % (ifname, str(e)))
        finally:
            if ifaceobj.link_type != ifaceLinkType.LINK_NA:
                self.iproute2.batch_start()
                for p in running_ports:
                    ifaceobj_list = ifaceobj_getfunc(p)
                    if (ifaceobj_list and ifaceobj_list[0].link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN):
                        self.iproute2.link_down(p)
                        continue
                    self.iproute2.link_up(p)
                try:
                    self.iproute2.batch_commit()
                except Exception as e:
                    # link set up on bridge ports failed - ignore and log debug
                    self.logger.debug("%s: %s" % (ifname, str(e)))

        try:
            self._up_bridge_mac(ifaceobj, link_just_created, ifaceobj_getfunc)
        except Exception as e:
            self.logger.warning('%s: setting bridge mac address: %s' % (ifaceobj.name, str(e)))

    def _get_bridge_mac(self, ifaceobj, ifname, link_just_created, ifaceobj_getfunc):
        bridge_mac_iface = self.bridge_mac_iface.get(ifname)

        if bridge_mac_iface and bridge_mac_iface[0] and bridge_mac_iface[1]:
            return bridge_mac_iface

        if self.bridge_mac_iface_list:
            self.logger.debug('bridge mac iface list: %s' % self.bridge_mac_iface_list)

            for bridge_mac_intf in self.bridge_mac_iface_list:
                ifaceobj_list = ifaceobj_getfunc(bridge_mac_intf)
                iface_mac = None

                if ifaceobj_list:
                    for obj in ifaceobj_list:
                        iface_user_configured_hwaddress = utils.strip_hwaddress(obj.get_attr_value_first('hwaddress'))
                        # if user did configured 'hwaddress' we need to use this value instead of the cached value.
                        if iface_user_configured_hwaddress:
                            iface_mac = iface_user_configured_hwaddress

                if not iface_mac and not self.cache.link_exists(bridge_mac_intf):
                    continue

                if not iface_mac:
                    iface_mac = self.cache.get_link_address(bridge_mac_intf)
                    # if hwaddress attribute is not configured we use the running mac addr

                self.bridge_mac_iface[ifname] = (bridge_mac_intf, iface_mac)
                return self.bridge_mac_iface[ifname]
        elif self.bridge_set_static_mac_from_port:
            # no policy was provided, we need to get the first physdev or bond ports
            # and use its hwaddress to set the bridge mac

            # first we need to make sure that the bridge mac is not already inherited from one of it's port
            bridge_ports = self._get_bridge_port_list_user_ordered(ifaceobj)

            # if the bridge was just created we need to set it's mac address to the first port and not look at the
            # current bridge mac (the bridge driver probably chose the lowest mac of it's port)
            if not link_just_created:
                current_mac = self.cache.get_link_address(ifname)

                for port in bridge_ports or []:
                    if not self.is_vxlan(ifaceobj_getfunc(port)):
                        port_mac = self.cache.get_link_address(port)

                        if current_mac == port_mac:
                            self.logger.info("bridge mac is already inherited from %s" % port)
                            self.bridge_mac_iface[ifname] = (port, port_mac)
                            return self.bridge_mac_iface[ifname]

            for port in bridge_ports or []:
                # iterate through the bridge-port list
                for port_obj in ifaceobj_getfunc(port) or []:
                    # check if the port is a physdev (link_kind is null) or a bon
                    if port_obj.link_kind != ifaceLinkKind.VXLAN:
                        iface_user_configured_hwaddress = utils.strip_hwaddress(port_obj.get_attr_value_first('hwaddress'))
                        # if user did configured 'hwaddress' we need to use this value instead of the cached value.
                        if iface_user_configured_hwaddress:
                            iface_mac = iface_user_configured_hwaddress.lower()
                            # we need to "normalize" the user provided MAC so it can match with
                            # what we have in the cache (data retrieved via a netlink dump by
                            # nlmanager). nlmanager return all macs in lower-case
                        else:
                            iface_mac = self.cache.get_link_address(port)

                        if iface_mac:
                            self.bridge_mac_iface[ifname] = (port, iface_mac)
                            return self.bridge_mac_iface[ifname]

        return None, None

    @staticmethod
    def is_vxlan(port_obj_list):
        # checking if the port is a vxlan by checking the ifaceobjs
        # instead of checking to cache (saving on locking time)
        for _port_obj in port_obj_list or []:
            if _port_obj.link_kind == ifaceLinkKind.VXLAN:
                return True
        return False

    def _add_bridge_mac_to_fdb(self, ifaceobj, bridge_mac):
        if not ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE and bridge_mac and ifaceobj.get_attr_value('address'):
            self.iproute2.bridge_fdb_add(ifaceobj.name, bridge_mac, vlan=None, bridge=True, remote=None)

    def _up_bridge_mac(self, ifaceobj, link_just_created, ifaceobj_getfunc):
        """
        We have a day one bridge mac changing problem with changing ports
        (basically bridge mac changes when the port it inherited the mac from
        gets de-enslaved).

        We have discussed this problem many times before and tabled it.
        The issue has aggravated with vxlan bridge ports having auto-generated
        random macs...which change on every reboot.

        ifupdown2 extract from policy files an iface to select a mac from and
        configure it automatically.
        """
        if ifaceobj.get_attr_value('hwaddress'):
            # if the user configured a static hwaddress
            # there is no need to assign one
            return

        ifname = ifaceobj.name
        mac_intf, bridge_mac = self._get_bridge_mac(ifaceobj, ifname, link_just_created, ifaceobj_getfunc)
        self.logger.debug("%s: _get_bridge_mac returned (%s, %s)"
                          %(ifname, mac_intf, bridge_mac))

        if bridge_mac:
            # if an interface is configured with the following attribute:
            # hwaddress 08:00:27:42:42:4
            # the cache_check won't match because nlmanager return "08:00:27:42:42:04"
            # from the kernel. The only way to counter that is to convert all mac to int
            # and compare the ints, it will increase perfs and be safer.
            cached_value = self.cache.get_link_address(ifname)
            self.logger.debug('%s: cached hwaddress value: %s' % (ifname, cached_value))
            bridge_mac_int = utils.mac_str_to_int(bridge_mac)

            # if the bridge was just created (link_just_created) we should force-set the mac address
            if not link_just_created and cached_value and utils.mac_str_to_int(cached_value) == bridge_mac_int:
                # the bridge mac is already set to the bridge_mac_intf's mac
                return

            self.logger.info('%s: setting bridge mac to port %s mac' % (ifname, mac_intf))
            try:
                self.netlink.link_set_address(ifname, bridge_mac, bridge_mac_int)  # force=True
            except Exception as e:
                self.logger.info('%s: %s' % (ifname, str(e)))
                # log info this error because the user didn't explicitly configured this
        else:
            self._add_bridge_mac_to_fdb(ifaceobj, self.cache.get_link_address(ifname))

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT:
            self.up_bridge_port(ifaceobj, ifaceobj_getfunc)

        elif ifaceobj.link_kind & ifaceLinkKind.BRIDGE:
            self.up_bridge(ifaceobj, ifaceobj_getfunc)

        else:
            bridge_attributes = list(self._modinfo.get('attrs', {}).keys())

            for ifaceobj_config_attr in list(ifaceobj.config.keys()):
                if ifaceobj_config_attr in bridge_attributes:
                    self.logger.warning('%s: invalid use of bridge attribute (%s) on non-bridge stanza'
                                        % (ifaceobj.name, ifaceobj_config_attr))

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        if not self._is_bridge(ifaceobj):
            return
        ifname = ifaceobj.name
        if not self.cache.link_exists(ifname):
            return

        try:
            self.netlink.link_del(self.get_dummy_brport_name_for_bridge(ifname))
        except Exception:
            pass

        try:
            running_ports = self.cache.get_slaves(ifname)
            if running_ports:
                self.handle_ipv6(running_ports, '0')
                if ifaceobj.link_type != ifaceLinkType.LINK_NA:
                    for p in running_ports:
                        self.netlink.link_down(p)
        except Exception as e:
            self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj)
        try:
            self.netlink.link_del(ifname)
        except Exception as e:
            ifaceobj.set_status(ifaceStatus.ERROR)
            self.logger.error(str(e))
            # netlink exception already contains the ifname

    def _query_running_vidinfo_compat(self, ifaceobjrunning, ports):
        running_attrs = {}
        if ports:
            running_bridge_port_vids = ''
            for p in ports:
                try:
                    _, running_vids = self.cache.get_pvid_and_vids(p)
                    if running_vids:
                        running_bridge_port_vids += ' %s=%s' %(p,
                                                      ','.join(running_vids))
                except Exception:
                    pass
            running_attrs['bridge-port-vids'] = running_bridge_port_vids

            running_bridge_port_pvid = ''
            for p in ports:
                try:
                    running_pvid = self.cache.get_pvid(p)
                    if running_pvid:
                        running_bridge_port_pvid += ' %s=%s' %(p,
                                                        running_pvid)
                except Exception:
                    pass
            running_attrs['bridge-port-pvids'] = running_bridge_port_pvid

        _, running_bridge_vids = self.cache.get_pvid_and_vids(ifaceobjrunning.name)
        if running_bridge_vids:
            running_attrs['bridge-vids'] = ','.join(utils.compress_into_ranges(running_bridge_vids))
        return running_attrs

    def _query_running_vidinfo(self, ifaceobjrunning, ifaceobj_getfunc,
                               bridgeports=None):
        running_attrs = {}

        # 'bridge-vids' under the bridge is all about 'vids' on the port.
        # so query the ports
        running_bridgeport_vids = []
        running_bridgeport_pvids = []
        for bport in bridgeports:
            (vids, pvid) = self._get_running_vids_n_pvid_str(bport)
            if vids:
                running_bridgeport_vids.append(' '.join(vids))
            if pvid:
                running_bridgeport_pvids.append(pvid)

        bridge_vids = None
        if running_bridgeport_vids:
           (vidval, freq) = Counter(running_bridgeport_vids).most_common()[0]
           if freq == len(bridgeports):
              running_attrs['bridge-vids'] = vidval
              bridge_vids = vidval.split()

        bridge_pvid = None
        if running_bridgeport_pvids:
           (vidval, freq) = Counter(running_bridgeport_pvids).most_common()[0]
           if freq == len(bridgeports) and vidval != '1':
              running_attrs['bridge-pvid'] = vidval
              bridge_pvid = vidval.split()[0]

        # Go through all bridge ports and find their vids
        for bport in bridgeports:
            bportifaceobj = ifaceobj_getfunc(bport)
            if not bportifaceobj:
               continue
            bport_vids = []
            bport_pvid = None
            (vids, pvid) = self._get_running_vids_n_pvid_str(bport)
            if vids and vids != bridge_vids:
               bport_vids = vids
            if pvid and pvid != bridge_pvid:
               bport_pvid = pvid
            if bport_vids and bport_pvid in bport_vids:
                bport_vids.remove(bport_pvid)
            if (not bport_vids and bport_pvid and bport_pvid != '1'):
               bportifaceobj[0].replace_config('bridge-access', bport_pvid)
               bportifaceobj[0].delete_config('bridge-pvid')
               bportifaceobj[0].delete_config('bridge-vids')
            else:
               if bport_pvid and bport_pvid != '1':
                  bportifaceobj[0].replace_config('bridge-pvid', bport_pvid)
               else:
                  # delete any stale bridge-vids under ports
                  bportifaceobj[0].delete_config('bridge-pvid')
               if bport_vids:
                  bportifaceobj[0].replace_config('bridge-vids',
                                                  ' '.join(bport_vids))
               else:
                  # delete any stale bridge-vids under ports
                  bportifaceobj[0].delete_config('bridge-vids')
        return running_attrs

    def _query_running_mcqv4src(self, ifaceobjrunning):
        running_mcqv4src = self.sysfs.bridge_get_mcqv4src(ifaceobjrunning.name)
        mcqs = ['%s=%s' %(v, i) for v, i in list(running_mcqv4src.items())]
        mcqs.sort()
        mcq = ' '.join(mcqs)
        return mcq

    def _query_running_attrs(self, ifaceobjrunning, ifaceobj_getfunc,
                             bridge_vlan_aware=False):

        ifname = ifaceobjrunning.name
        bridgeattrdict = {}
        userspace_stp = 0
        ports = None
        try:
            if self.systcl_get_net_bridge_stp_user_space() == '1':
                userspace_stp = 1
        except Exception as e:
            self.logger.info('%s: %s' % (ifaceobjrunning.name, str(e)))

        bridge_ifla_info_data = self.cache.get_link_info_data(ifname)


        # Fill bridge_ports and bridge stp attributes first
        #
        # bridge-ports
        #
        bridgeattrdict["bridge-ports"] = [" ".join(self.cache.get_slaves(ifname))]

        #
        # bridge-stp
        #
        cached_stp = bool(bridge_ifla_info_data.get(Link.IFLA_BR_STP_STATE))

        if cached_stp != utils.get_boolean_from_string(
                self.get_mod_subattr("bridge-stp", "default")
        ):
            bridgeattrdict['bridge-stp'] = ["yes" if cached_stp else "no"]

        skip_kernel_stp_attrs = cached_stp and userspace_stp

        if skip_kernel_stp_attrs:
            bridge_attributes_map = {
                "bridge-mcqifaddr": Link.IFLA_BR_MCAST_QUERY_USE_IFADDR,
                "bridge-mcquerier": Link.IFLA_BR_MCAST_QUERIER,
                "bridge-mcrouter": Link.IFLA_BR_MCAST_ROUTER,
                "bridge-mcstats": Link.IFLA_BR_MCAST_STATS_ENABLED,
                "bridge-mcsnoop": Link.IFLA_BR_MCAST_SNOOPING,
                "bridge-mclmc": Link.IFLA_BR_MCAST_LAST_MEMBER_CNT,
                "bridge-mclmi": Link.IFLA_BR_MCAST_LAST_MEMBER_INTVL,
                "bridge-mcqri": Link.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL,
                "bridge-mcqpi": Link.IFLA_BR_MCAST_QUERIER_INTVL,
                "bridge-mcsqc": Link.IFLA_BR_MCAST_STARTUP_QUERY_CNT,
                "bridge-mcsqi": Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL,
                "bridge-mcmi": Link.IFLA_BR_MCAST_MEMBERSHIP_INTVL,
                "bridge-mcqi": Link.IFLA_BR_MCAST_QUERY_INTVL,
            }
        else:
            bridge_attributes_map = dict(self._ifla_br_attributes_map)
            try:
                del bridge_attributes_map[Link.IFLA_BR_STP_STATE]
            except Exception:
                pass

        #
        # bridge-vlan-stats
        #
        cached_vlan_stats = bridge_ifla_info_data.get(Link.IFLA_BR_VLAN_STATS_ENABLED)

        if cached_vlan_stats != utils.get_boolean_from_string(
                self.get_mod_subattr("bridge-vlan-stats", "default")
        ):
            bridgeattrdict['bridge-vlan-stats'] = ["on" if cached_vlan_stats else "off"]

        try:
            del bridge_attributes_map[Link.IFLA_BR_VLAN_STATS_ENABLED]
        except Exception:
            pass

        lambda_nl_value_int_divide100 = lambda x: str(x // 100)
        lambda_nl_value_to_yes_no_boolean = lambda x: "yes" if x else "no"

        bridge_attr_value_netlink_to_string_dict = {
            Link.IFLA_BR_VLAN_PROTOCOL: lambda x: x.lower(),  # return lower case vlan protocol
            Link.IFLA_BR_AGEING_TIME: lambda_nl_value_int_divide100,
            Link.IFLA_BR_MAX_AGE: lambda_nl_value_int_divide100,
            Link.IFLA_BR_FORWARD_DELAY: lambda_nl_value_int_divide100,
            Link.IFLA_BR_HELLO_TIME: lambda_nl_value_int_divide100,
            Link.IFLA_BR_MCAST_MEMBERSHIP_INTVL: lambda_nl_value_int_divide100,
            Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL: lambda_nl_value_int_divide100,
            Link.IFLA_BR_MCAST_LAST_MEMBER_INTVL: lambda_nl_value_int_divide100,
            Link.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL: lambda_nl_value_int_divide100,
            Link.IFLA_BR_MCAST_QUERIER_INTVL: lambda_nl_value_int_divide100,
            Link.IFLA_BR_MCAST_QUERY_INTVL: lambda_nl_value_int_divide100,
            Link.IFLA_BR_VLAN_FILTERING: lambda_nl_value_to_yes_no_boolean,
            Link.IFLA_BR_MCAST_QUERY_USE_IFADDR: lambda_nl_value_to_yes_no_boolean,
            Link.IFLA_BR_MCAST_SNOOPING: lambda_nl_value_to_yes_no_boolean,
            Link.IFLA_BR_MCAST_QUERIER: lambda_nl_value_to_yes_no_boolean,
            Link.IFLA_BR_MCAST_ROUTER: lambda_nl_value_to_yes_no_boolean,
        }

        for attr_name, attr_nl in bridge_attributes_map.items():
            default_value = self.get_mod_subattr(attr_name, "default")
            cached_value = bridge_ifla_info_data.get(attr_nl)

            if cached_value is None:
                continue

            cached_value_string = bridge_attr_value_netlink_to_string_dict.get(attr_nl, str)(cached_value)

            if default_value != cached_value_string:
                bridgeattrdict[attr_name] = [cached_value_string]

        if bridge_vlan_aware:
            if not ports:
                ports = {}
            bridgevidinfo = self._query_running_vidinfo(ifaceobjrunning,
                                                        ifaceobj_getfunc,
                                                        list(ports.keys()))
        else:
            bridgevidinfo = self._query_running_vidinfo_compat(ifaceobjrunning,
                                                               ports)
        if bridgevidinfo:
           bridgeattrdict.update({k : [v] for k, v in list(bridgevidinfo.items())
                                  if v})

        mcq = self._query_running_mcqv4src(ifaceobjrunning)
        if mcq:
            bridgeattrdict['bridge-mcqv4src'] = [mcq]

        if skip_kernel_stp_attrs:
            return bridgeattrdict

        # Do this only for vlan-UNAWARE-bridge
        if ports and not bridge_vlan_aware:
            portconfig = {'bridge-pathcosts' : '',
                          'bridge-portprios' : '',
                          'bridge-learning' : '',
                          'bridge-unicast-flood' : '',
                          'bridge-multicast-flood' : '',
                          'bridge-broadcast-flood' : '',
                          'bridge-arp-nd-suppress' : '',
                         }
            for p, v in list(ports.items()):
                v = str(self.cache.get_brport_cost(p))
                if v and v != self.get_mod_subattr('bridge-pathcosts',
                                                   'default'):
                    portconfig['bridge-pathcosts'] += ' %s=%s' %(p, v)

                v = str(self.cache.get_brport_priority(p))
                if v and v != self.get_mod_subattr('bridge-portprios',
                                                   'default'):
                    portconfig['bridge-portprios'] += ' %s=%s' %(p, v)

                v = utils.get_onff_from_onezero(self.cache.get_brport_learning(p))
                if (v and
                    v != self.get_mod_subattr('bridge-learning', 'default')):
                    portconfig['bridge-learning'] += ' %s=%s' %(p, v)

                v = utils.get_onff_from_onezero(self.cache.get_brport_unicast_flood(p))
                if (v and
                    v != self.get_mod_subattr('bridge-unicast-flood',
                                              'default')):
                    portconfig['bridge-unicast-flood'] += ' %s=%s' %(p, v)

                v = utils.get_onff_from_onezero(self.cache.get_brport_multicast_flood(p))
                if (v and
                    v != self.get_mod_subattr('bridge-multicast-flood',
                                              'default')):
                    portconfig['bridge-multicast-flood'] += ' %s=%s' %(p, v)

                v = utils.get_onff_from_onezero(self.cache.get_brport_broadcast_flood(p))
                if (v and
                    v != self.get_mod_subattr('bridge-broadcast-flood',
                                              'default')):
                    portconfig['bridge-broadcast-flood'] += ' %s=%s' %(p, v)

                v = utils.get_onff_from_onezero(self.cache.get_brport_neigh_suppress(p))
                if (v and
                    v != self.get_mod_subattr('bridge-arp-nd-suppress',
                                              'default')):
                    portconfig['bridge-arp-nd-suppress'] += ' %s=%s' %(p, v)

            bridgeattrdict.update({k : [v] for k, v in list(portconfig.items())
                                    if v})

        return bridgeattrdict

    def _query_check_mcqv4src(self, ifaceobj, ifaceobjcurr):
        running_mcqs = self._query_running_mcqv4src(ifaceobj)
        attrval = ifaceobj.get_attr_value_first('bridge-mcqv4src')
        if attrval:
            mcqs = attrval.split()
            mcqs.sort()
            mcqsout = ' '.join(mcqs)
            ifaceobjcurr.update_config_with_status('bridge-mcqv4src',
                         running_mcqs, 1 if running_mcqs != mcqsout else 0)

    def _query_check_bridge_vidinfo(self, ifname, ifaceobj, ifaceobjcurr):
        #
        # bridge-port-vids
        #
        bridge_port_vids_user_config = ifaceobj.get_attr_value_first("bridge-port-vids")
        if bridge_port_vids_user_config:

            port_list = self.parse_port_list(ifname, bridge_port_vids_user_config)

            if not port_list:
                self.log_warn("%s: could not parse 'bridge-port-vids %s'"
                              % (ifname, bridge_port_vids_user_config))
                ifaceobjcurr.update_config_with_status("bridge-port-vids", "ERROR", 1)
                return

            error = False
            for port_config in port_list:
                try:
                    port, vids_raw = port_config.split("=")
                    packed_vids = vids_raw.split(",")

                    running_pvid, running_vids = self.cache.get_pvid_and_vids(port)

                    if not utils.compare_ids(packed_vids, running_vids, pvid=running_pvid, expand_range=False):
                        error = True

                except Exception as e:
                    self.log_warn("%s: failure checking vid %s (%s)" % (ifname, port_config, str(e)))

            ifaceobjcurr.update_config_with_status("bridge-port-vids", bridge_port_vids_user_config, error)

        #
        # bridge-port-pvids
        #
        attrval = ifaceobj.get_attr_value_first('bridge-port-pvids')
        if attrval:
            portlist = self.parse_port_list(ifaceobj.name, attrval)
            if not portlist:
                self.log_warn('%s: could not parse \'bridge-port-pvids %s\''
                              % (ifname, attrval))
                return

            error = False
            running_pvid_config = []
            for p in portlist:
                (port, pvid) = p.split('=')
                running_pvid, _ = self.cache.get_pvid_and_vids(port)

                running_pvid_config.append("%s=%s" % (port, running_pvid))

                if running_pvid != int(pvid):
                    error = True

            ifaceobjcurr.update_config_with_status(
                "bridge-port-pvids",
                " ".join(running_pvid_config),
                int(error)
            )

        vids = self.get_ifaceobj_bridge_vids(ifaceobj)
        if vids[1]:
            ifaceobjcurr.update_config_with_status(vids[0], vids[1], -1)

    def _query_check_snooping_wdefault(self, ifaceobj):
        if (ifupdownflags.flags.WITHDEFAULTS
            and not self._vxlan_bridge_default_igmp_snooping
                and ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VXLAN):
            ifaceobj.replace_config('bridge-mcsnoop', 'no')

    def _query_check_bridge(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        if not self._is_bridge(ifaceobj):
            return

        ifname = ifaceobj.name

        if not self.cache.bridge_exists(ifname):
            self.logger.info("%s: bridge: does not exist" % (ifname))
            return

        self._query_check_snooping_wdefault(ifaceobj)

        user_config_attributes = self.dict_key_subset(ifaceobj.config, self.get_mod_attrs())

        # add default attributes if --with-defaults is set
        if ifupdownflags.flags.WITHDEFAULTS and 'bridge-stp' not in user_config_attributes:
            user_config_attributes.append('bridge-stp')

        if not user_config_attributes:
            return

        if "bridge-ports" in user_config_attributes:
            self.query_check_bridge_ports(ifaceobj, ifaceobjcurr, self.cache.get_slaves(ifname), ifaceobj_getfunc)

        if "bridge-ports-condone-regex" in user_config_attributes:
            ifaceobjcurr.update_config_with_status(
                "bridge-ports-condone-regex",
                self._get_bridge_port_condone_regex(ifaceobj, True),
                0
            )

        # Those attributes require separate handling
        filter_attributes = [
            "bridge-trunk",
            "bridge-ports",
            "bridge-vids",
            "bridge-trunk",
            "bridge-mcqv4src",
            "bridge-port-vids",
            "bridge-port-pvids",
            "bridge-l2protocol-tunnel",
            "bridge-ports-condone-regex"
        ]

        ignore_attributes = (
            # bridge-pvid and bridge-vids on a bridge does not correspond
            # directly to a running config on the bridge. They correspond to
            # default values for the bridge ports. And they are already checked
            # against running config of the bridge port and reported against a
            # bridge port. So, ignore these attributes under the bridge. Use '2'
            # for ignore today. XXX: '2' will be mapped to a defined value in
            # subsequent patches.
            "bridge-pvid",
            "bridge-allow-untagged",
        )
        for attr in ignore_attributes:
            if attr in user_config_attributes:
                ifaceobjcurr.update_config_with_status(attr, ifaceobj.get_attr_value_first(attr), 2)
                filter_attributes.append(attr)

        bridge_config = set(user_config_attributes).difference(filter_attributes)
        cached_ifla_info_data = self.cache.get_link_info_data(ifname)

        self._query_check_bridge_attributes(ifaceobj, ifaceobjcurr, bridge_config, cached_ifla_info_data)
        self._query_check_brport_attributes_on_bridge(ifname, ifaceobj, ifaceobjcurr, bridge_config)
        self._query_check_bridge_vidinfo(ifname, ifaceobj, ifaceobjcurr)
        self._query_check_mcqv4src(ifaceobj, ifaceobjcurr)
        self._query_check_l2protocol_tunnel_on_bridge(ifname, ifaceobj, ifaceobjcurr)

    def _query_check_bridge_always_up(self, ifname, ifaceobj, ifaceobjcurr, bridge_config):
        bridge_always_up = ifaceobj.get_attr_value_first("bridge-always-up")

        if bridge_always_up:
            bridge_config.remove("bridge-always-up")

        if utils.get_boolean_from_string(bridge_always_up):
            try:
                link_exists = self.cache.link_exists(self.get_dummy_brport_name_for_bridge(ifname))
            except Exception:
                link_exists = False

            ifaceobjcurr.update_config_with_status(
                "bridge-always-up",
                "yes" if link_exists else "no",
                not link_exists
            )

    def _query_check_bridge_attributes(self, ifaceobj, ifaceobjcurr, bridge_config, cached_ifla_info_data):
        for attr in list(bridge_config):
            query_check_handler, netlink_attr = self._bridge_attribute_query_check_handler.get(attr, (None, None))

            if callable(query_check_handler):
                query_check_handler(attr, ifaceobj.get_attr_value_first(attr), ifaceobjcurr, cached_ifla_info_data.get(netlink_attr))
                bridge_config.remove(attr)

        self._query_check_bridge_always_up(ifaceobj.name, ifaceobj, ifaceobjcurr, bridge_config)

    def _query_check_brport_attributes_on_bridge(self, ifname, ifaceobj, ifaceobjcurr, bridge_config):
        brports_info_slave_data = {}
        # bridge_config should only have bridge-port-list attributes
        for attr in bridge_config:
            attr_nl = self._ifla_brport_attributes_map.get(attr)
            brport_query_check_handler = self._brport_attribute_query_check_handler.get(attr)

            if not attr_nl or not brport_query_check_handler:
                self.logger.warning("%s: query-check: missing handler for attribute: %s (%s)" % (ifname, attr, attr_nl))
                continue

            running_config = []
            status = 0

            for port_config in self.parse_port_list(ifname, ifaceobj.get_attr_value_first(attr)) or []:
                port, config = port_config.split("=")

                if port not in brports_info_slave_data:
                    info_slave_data = brports_info_slave_data[port] = self.cache.get_link_info_slave_data(port)
                else:
                    info_slave_data = brports_info_slave_data[port]

                port_config, port_status = brport_query_check_handler(port, config, info_slave_data.get(attr_nl))

                running_config.append(port_config)

                if port_status:
                    status = 1

            ifaceobjcurr.update_config_with_status(
                attr,
                " ".join(running_config),
                status
            )

    @staticmethod
    def _query_check_br_attr_wait(attr, wait_value, ifaceobjcurr, __):
        ifaceobjcurr.update_config_with_status(attr, wait_value, 0)

    def _query_check_br_attr_stp(self, attr, stp_value, ifaceobjcurr, cached_value):
        if not stp_value:
            if ifupdownflags.flags.WITHDEFAULTS:
                stp_value = "on" if self.default_stp_on else "off"
            else:
                return

        user_config_to_nl = utils.get_boolean_from_string(stp_value)

        ifaceobjcurr.update_config_with_status(
            attr,
            "yes" if cached_value else "no",
            user_config_to_nl != bool(cached_value)
        )

    @staticmethod
    def _query_check_br_attr_int(attr, user_config, ifaceobjcurr, cached_value):
        ifaceobjcurr.update_config_with_status(
            attr,
            str(cached_value),
            int(user_config) != cached_value
        )

    @staticmethod
    def _query_check_br_attr_int_divided100(attr, user_config, ifaceobjcurr, cached_value):
        value = cached_value // 100
        ifaceobjcurr.update_config_with_status(
            attr,
            str(value),
            int(user_config) != value
        )

    @staticmethod
    def _query_check_br_attr_boolean(attr, user_config, ifaceobjcurr, cached_value):
        ifaceobjcurr.update_config_with_status(
            attr,
            "yes" if cached_value else "no",
            utils.get_boolean_from_string(user_config) != cached_value
        )

    @staticmethod
    def _query_check_br_attr_boolean_on_off(attr, user_config, ifaceobjcurr, cached_value):
        ifaceobjcurr.update_config_with_status(
            attr,
            "on" if cached_value else "off",
            utils.get_boolean_from_string(user_config) != cached_value
        )

    @staticmethod
    def _query_check_br_attr_string(attr, user_config, ifaceobjcurr, cached_value):
        ifaceobjcurr.update_config_with_status(
            attr,
            cached_value,
            user_config.lower() != cached_value
        )

    @staticmethod
    def _query_check_brport_attr_boolean_on_off(port, user_config, cached_value):
        return "%s=%s" % (port, "on" if cached_value else "off"), utils.get_boolean_from_string(user_config) != cached_value

    @staticmethod
    def _query_check_brport_attr_boolean_yes_no(port, user_config, cached_value):
        return "%s=%s" % (port, "yes" if cached_value else "no"), utils.get_boolean_from_string(user_config) != cached_value

    @staticmethod
    def _query_check_brport_attr_int(port, user_config, cached_value):
        return "%s=%s" % (port, cached_value), int(user_config) != cached_value

    @classmethod
    def _query_check_brport_attr_portmcrouter(cls, port, user_config, cached_value):
        return (
            "%s=%s" % (port, cls._ifla_brport_multicast_router_dict_int_to_str.get(cached_value)),
            cls._ifla_brport_multicast_router_dict_to_int.get(user_config) != cached_value
        )

    ####################################################################################################################

    def query_check_bridge_ports(self, ifaceobj, ifaceobjcurr, running_port_list, ifaceobj_getfunc):

        # if bridge-always-up is set we need to remove the dummy brport from the running_port_list
        if utils.get_boolean_from_string(ifaceobj.get_attr_value_first("bridge-always-up")):
            try:
                running_port_list.remove(self.get_dummy_brport_name_for_bridge(ifaceobj.name))
            except Exception:
                pass

        bridge_all_ports = []
        for obj in ifaceobj_getfunc(ifaceobj.name) or []:
            bridge_all_ports.extend(self._get_bridge_port_list(obj))

        if not running_port_list and not bridge_all_ports:
            return

        try:
            port_list = self._get_ifaceobj_bridge_ports(ifaceobj).split()
            # we want to display the same bridge-ports list as provided
            # in the interfaces file but if this list contains regexes or
            # globs, for now, we won't try to change it.
            if 'regex' in port_list or 'glob' in port_list:
                port_list = running_port_list
            else:
                ordered = []
                for i in range(0, len(port_list)):
                    if port_list[i] in running_port_list:
                        ordered.append(port_list[i])
                port_list = ordered
        except Exception:
            port_list = running_port_list

        difference = set(running_port_list).symmetric_difference(bridge_all_ports)
        bridge_port_condone_regex = self._get_bridge_port_condone_regex(ifaceobj)

        if bridge_port_condone_regex:
            # Drop any condoned port from the difference set
            condone_ports = [port for port in difference if bridge_port_condone_regex.match(port)]

            for port in condone_ports:
                try:
                    difference.remove(port)
                except ValueError:
                    pass

                # Tag all condoned ports in brackets in output
                if port not in bridge_all_ports:
                    port_list.append("(%s)" % port)

        ifaceobjcurr.update_config_with_status(
            "bridge-ports",
            " ".join(port_list) if port_list else "",
            0 if not difference else 1
        )

    def get_ifaceobj_bridge_vids(self, ifaceobj):
        vids = ('bridge-vids', ifaceobj.get_attr_value_first('bridge-vids'))
        if not vids[1]:
            vids = ('bridge-trunk', ifaceobj.get_attr_value_first('bridge-trunk'))
        return vids

    def get_ifaceobj_bridge_vids_value(self, ifaceobj):
        return self.get_ifaceobj_bridge_vids(ifaceobj)[1]

    def _get_bridge_vids(self, bridgename, ifaceobj_getfunc):
        ifaceobjs = ifaceobj_getfunc(bridgename) or []
        for ifaceobj in ifaceobjs:
            vids = self.get_ifaceobj_bridge_vids_value(ifaceobj)
            if vids: return re.split(r'[\s\t,]\s*', vids)
        return None

    def _get_bridge_pvid(self, bridgename, ifaceobj_getfunc):
        ifaceobjs = ifaceobj_getfunc(bridgename) or []
        pvid = None
        for ifaceobj in ifaceobjs:
            pvid = ifaceobj.get_attr_value_first('bridge-pvid')
            if pvid:
                break
        return pvid

    def _query_check_bridge_port_vidinfo(self, ifname, bridge_name, ifaceobj, ifaceobjcurr, ifaceobj_getfunc):
        running_pvid, running_vids = self.cache.get_pvid_and_vids(ifname)

        if (ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN):
            return

        #
        # bridge-access
        #
        brport_vid_access_user_config = ifaceobj.get_attr_value_first("bridge-access")

        if brport_vid_access_user_config:
            try:
                vid_int = int(brport_vid_access_user_config)
            except ValueError as e:
                ifaceobjcurr.update_config_with_status("bridge-access", brport_vid_access_user_config, 1)
                raise AddonException("%s: bridge-access invalid value: %s" % (ifname, str(e)))

            ifaceobjcurr.update_config_with_status(
                "bridge-access",
                str(running_pvid),
                running_pvid != vid_int or running_vids[0] != vid_int
            )
            return

        #
        # bridge-pvid
        #
        brport_pvid_user_config = ifaceobj.get_attr_value_first("bridge-pvid")

        if brport_pvid_user_config:
            try:
                pvid = int(brport_pvid_user_config)
            except ValueError as e:
                ifaceobjcurr.update_config_with_status("bridge-pvid", brport_pvid_user_config, 1)
                raise AddonException("%s: bridge-pvid invalid value: %s" % (ifname, str(e)))

            ifaceobjcurr.update_config_with_status(
                "bridge-pvid",
                str(running_pvid),
                running_pvid != pvid
            )
        elif (not (ifaceobj.flags & iface.HAS_SIBLINGS) or
              ((ifaceobj.flags & iface.HAS_SIBLINGS) and
               (ifaceobj.flags & iface.OLDEST_SIBLING))):
            # if the interface has multiple iface sections,
            # we check the below only for the oldest sibling
            # or the last iface section
            try:
                pvid = int(self._get_bridge_pvid(bridge_name, ifaceobj_getfunc))
            except (TypeError, ValueError):
                pvid = 0
            if pvid:
                if not running_pvid or running_pvid != pvid:
                    ifaceobjcurr.status = ifaceStatus.ERROR
                    ifaceobjcurr.status_str = 'bridge pvid error'
            elif not running_pvid or running_pvid != 1:
                ifaceobjcurr.status = ifaceStatus.ERROR
                ifaceobjcurr.status_str = 'bridge pvid error'

        attr_name, vids = self.get_ifaceobj_bridge_vids(ifaceobj)
        if vids:
           vids = re.split(r'[\s\t]\s*', vids)

           # Special treatment to make sure that the vlans mapped with vnis
           # (in single-vxlan context) are not mistaken for regular vlans.
           # We need to proactively remove them from the "running_vids"
           vlans_mapped_with_vnis = self.get_bridge_vlans_mapped_to_vnis_as_integer_list(ifaceobj)
           new_running_vids = []
           user_config_vids = utils.ranges_to_ints(vids)
           for v in running_vids:
               if v in user_config_vids:
                   new_running_vids.append(v)
               elif v not in vlans_mapped_with_vnis:
                   new_running_vids.append(v)
           running_vids = new_running_vids
           #####################################################################

           if not running_vids or not utils.compare_ids(vids, running_vids, running_pvid, expand_range=False):
               running_vids = [str(o) for o in running_vids]
               ifaceobjcurr.update_config_with_status(attr_name,
                                            ' '.join(running_vids), 1)
           else:
               ifaceobjcurr.update_config_with_status(attr_name,
                                            ' '.join(vids), 0)
        elif (not (ifaceobj.flags & iface.HAS_SIBLINGS) or
              ((ifaceobj.flags & iface.HAS_SIBLINGS) and
               (ifaceobj.flags & iface.OLDEST_SIBLING))):
           # if the interface has multiple iface sections,
           # we check the below only for the oldest sibling
           # or the last iface section

           # check if it matches the bridge vids
           bridge_vids = self._get_bridge_vids(bridge_name, ifaceobj_getfunc)
           if (bridge_vids and (not running_vids  or
                   not utils.compare_ids(bridge_vids, running_vids, running_pvid, expand_range=False))):
              ifaceobjcurr.status = ifaceStatus.ERROR
              ifaceobjcurr.status_str = 'bridge vid error'

    _query_check_brport_attributes = (
        "bridge-pvid",
        "bridge-vids",
        "bridge-trunk",
        "bridge-access",
        "bridge-pathcosts",
        "bridge-portprios",
        "bridge-portmcrouter",
        "bridge-learning",
        "bridge-portmcfl",
        "bridge-unicast-flood",
        "bridge-multicast-flood",
        "bridge-broadcast-flood",
        "bridge-arp-nd-suppress",
        "bridge-l2protocol-tunnel"
    )

    def _query_check_bridge_port(self, ifaceobj, ifaceobjcurr,
                                 ifaceobj_getfunc):

        ifname = ifaceobj.name

        if not self.cache.link_is_bridge_port(ifname):
            # Mark all bridge brport attributes as failed
            ifaceobjcurr.check_n_update_config_with_status_many(
                ifaceobj, self._query_check_brport_attributes, 1
            )
            return

        bridge_name = self.cache.get_bridge_name_from_port(ifname)
        if not bridge_name:
            self.logger.warning("%s: unable to determine bridge name" % ifname)
            return

        if self.cache.bridge_is_vlan_aware(bridge_name):
            self._query_check_bridge_port_vidinfo(ifname, bridge_name, ifaceobj, ifaceobjcurr, ifaceobj_getfunc)

        brport_info_slave_data = self.cache.get_link_info_slave_data(ifname)

        #
        # bridge-portmcfl
        #
        portmcfl = ifaceobj.get_attr_value_first("bridge-portmcfl")

        if portmcfl:
            cached_value = brport_info_slave_data.get(Link.IFLA_BRPORT_FAST_LEAVE)

            ifaceobjcurr.update_config_with_status(
                "bridge-portmcfl",
                "yes" if cached_value else "no",
                utils.get_boolean_from_string(portmcfl) != cached_value
            )

        #
        # bridge-portmcrouter
        #
        portmcrouter = ifaceobj.get_attr_value_first("bridge-portmcrouter")

        if portmcrouter:
            cached_value = brport_info_slave_data.get(Link.IFLA_BRPORT_MULTICAST_ROUTER)

            ifaceobjcurr.update_config_with_status(
                "bridge-portmcrouter",
                self._ifla_brport_multicast_router_dict_int_to_str.get(cached_value),
                self._ifla_brport_multicast_router_dict_to_int.get(portmcrouter) != cached_value
            )

        #
        # bridge-learning
        # bridge-unicast-flood
        # bridge-multicast-flood
        # bridge-broadcast-flood
        # bridge-arp-nd-suppress
        #
        for attr_name, attr_nl in (
                ("bridge-learning", Link.IFLA_BRPORT_LEARNING),
                ("bridge-unicast-flood", Link.IFLA_BRPORT_UNICAST_FLOOD),
                ("bridge-multicast-flood", Link.IFLA_BRPORT_MCAST_FLOOD),
                ("bridge-broadcast-flood", Link.IFLA_BRPORT_BCAST_FLOOD),
                ("bridge-arp-nd-suppress", Link.IFLA_BRPORT_NEIGH_SUPPRESS),
        ):
            attribute_value = ifaceobj.get_attr_value_first(attr_name)

            if not attribute_value:
                continue

            cached_value = brport_info_slave_data.get(attr_nl)

            ifaceobjcurr.update_config_with_status(
                attr_name,
                "on" if cached_value else "off",
                utils.get_boolean_from_string(attribute_value) != cached_value
                )

        #
        # bridge-pathcosts
        # bridge-portprios
        #
        for attr_name, attr_nl in (
                ("bridge-pathcosts", Link.IFLA_BRPORT_COST),
                ("bridge-portprios", Link.IFLA_BRPORT_PRIORITY),
        ):
            attribute_value = ifaceobj.get_attr_value_first(attr_name)

            if not attribute_value:
                continue

            cached_value = brport_info_slave_data.get(attr_nl)

            try:
                ifaceobjcurr.update_config_with_status(
                    attr_name,
                    str(cached_value),
                    int(attribute_value) != cached_value
                )
            except ValueError as e:
                ifaceobjcurr.update_config_with_status(attr_name, str(cached_value), 1)
                raise AddonException("%s: %s invalid value: %s" % (ifname, attr_name, str(e)))

        self._query_check_l2protocol_tunnel_on_port(ifaceobj, ifaceobjcurr)

        #
        # bridge-vlan-vni-map
        #
        cached_vlans, cached_vnis = self.get_vlan_vni_ranges(self.cache.get_vlan_vni(ifaceobj.name))

        for bridge_vlan_vni_map_entry in ifaceobj.get_attr_value("bridge-vlan-vni-map") or []:
            fail = False

            for vlan_vni in bridge_vlan_vni_map_entry.split():
                try:
                    vlans_str, vni_str = utils.get_vlan_vni_in_map_entry(vlan_vni)
                except Exception:
                    fail = True
                    self.__warn_bridge_vlan_vni_map_syntax_error(ifname, vlan_vni)
                    continue

                if fail:
                    # if we already have detected an error on this entry there's
                    # no point doing anything else than syntax check on the rest
                    continue

                vlans_list = utils.ranges_to_ints([vlans_str])
                vnis_list = utils.ranges_to_ints([vni_str])

                try:
                    for i, vlan in enumerate(vlans_list):
                        index = cached_vnis.index(vlan)

                        if vlan != cached_vnis[index] or vnis_list[i] != cached_vlans[index]:
                            fail = True
                except Exception:
                    fail = True

            ifaceobjcurr.update_config_with_status("bridge-vlan-vni-map", bridge_vlan_vni_map_entry, fail)

    @staticmethod
    def get_vlan_vni_ranges(bridge_vlan_tunnel, compress=False):
        vlans = []
        vnis = []

        if not bridge_vlan_tunnel:
            return vlans, vnis

        tunnel_vlan_range = None
        tunnel_vni_range = None

        for tunnel_vlan, tunnel_vni, tunnel_flags in bridge_vlan_tunnel:

            if tunnel_flags & Link.BRIDGE_VLAN_INFO_RANGE_BEGIN:
                tunnel_vlan_range = tunnel_vlan
                tunnel_vni_range = tunnel_vni

            elif tunnel_flags & Link.BRIDGE_VLAN_INFO_RANGE_END:

                if compress:
                    vlans.append("%s-%s" % (tunnel_vlan_range, tunnel_vlan))
                    vnis.append("%s-%s" % (tunnel_vni_range, tunnel_vni))
                else:
                    vlans.extend(range(tunnel_vlan_range, tunnel_vlan + 1))
                    vnis.extend(range(tunnel_vni_range, tunnel_vni + 1))

            else:
                vlans.append(tunnel_vlan)
                vnis.append(tunnel_vni)

        return vlans, vnis

    def _query_check_l2protocol_tunnel_on_port(self, ifaceobj, ifaceobjcurr):
        user_config_l2protocol_tunnel = ifaceobj.get_attr_value_first('bridge-l2protocol-tunnel')

        if user_config_l2protocol_tunnel:
            result = 0
            try:
                self._query_check_l2protocol_tunnel(ifaceobj.name, user_config_l2protocol_tunnel)
            except Exception as e:
                self.logger.debug('query: %s: %s' % (ifaceobj.name, str(e)))
                result = 1
            ifaceobjcurr.update_config_with_status('bridge-l2protocol-tunnel', user_config_l2protocol_tunnel, result)

    def _query_check_l2protocol_tunnel_on_bridge(self, ifname, ifaceobj, ifaceobjcurr):
        """
            In case the bridge-l2protocol-tunnel is specified under the bridge and not the brport
            We need to make sure that all ports comply with the mask given under the bridge
        """
        user_config_l2protocol_tunnel = ifaceobj.get_attr_value_first('bridge-l2protocol-tunnel')

        if user_config_l2protocol_tunnel:
            if '=' in user_config_l2protocol_tunnel:
                try:
                    config_per_port_dict = self.parse_interface_list_value(user_config_l2protocol_tunnel)
                    brport_list = list(config_per_port_dict.keys())
                except Exception:
                    ifaceobjcurr.update_config_with_status('bridge-l2protocol-tunnel', user_config_l2protocol_tunnel, 1)
                    return
            else:
                config_per_port_dict = {}
                brport_list = self.cache.get_slaves(ifname)

            try:
                for brport_name in brport_list:
                    self._query_check_l2protocol_tunnel(
                        brport_name,
                        config_per_port_dict.get(brport_name) if config_per_port_dict else user_config_l2protocol_tunnel
                    )
                result = 0
            except Exception as e:
                self.logger.debug('query: %s: %s' % (ifaceobj.name, str(e)))
                result = 1
            ifaceobjcurr.update_config_with_status('bridge-l2protocol-tunnel', user_config_l2protocol_tunnel, result)

    def _query_check_l2protocol_tunnel(self, brport_name, user_config_l2protocol_tunnel):
        cached_ifla_brport_group_maskhi = self.cache.get_link_info_slave_data_attribute(brport_name, Link.IFLA_BRPORT_GROUP_FWD_MASKHI)
        cached_ifla_brport_group_mask = self.cache.get_link_info_slave_data_attribute(brport_name, Link.IFLA_BRPORT_GROUP_FWD_MASK)

        for protocol in re.split(',|\s*', user_config_l2protocol_tunnel):
            callback = self.query_check_l2protocol_tunnel_callback.get(protocol)

            if callable(callback) and not callback(cached_ifla_brport_group_mask, cached_ifla_brport_group_maskhi):
                raise AddonException(
                    "%s: bridge-l2protocol-tunnel: protocol '%s' not present (cached value: %d | %d)"
                    % (brport_name, protocol, cached_ifla_brport_group_mask, cached_ifla_brport_group_maskhi)
                )

    def _query_running_bridge_l2protocol_tunnel(self, brport_name, brport_ifaceobj=None, bridge_ifaceobj=None):
        cached_ifla_brport_group_maskhi = self.cache.get_link_info_slave_data_attribute(brport_name, Link.IFLA_BRPORT_GROUP_FWD_MASKHI)
        cached_ifla_brport_group_mask = self.cache.get_link_info_slave_data_attribute(brport_name, Link.IFLA_BRPORT_GROUP_FWD_MASK)
        running_protocols = []
        for protocol_name, callback in list(self.query_check_l2protocol_tunnel_callback.items()):
            if protocol_name == 'all' and callback(cached_ifla_brport_group_mask, cached_ifla_brport_group_maskhi):
                running_protocols = list(self.query_check_l2protocol_tunnel_callback.keys())
                running_protocols.remove('all')
                break
            elif callback(cached_ifla_brport_group_mask, cached_ifla_brport_group_maskhi):
                running_protocols.append(protocol_name)
        if running_protocols:
            if brport_ifaceobj:
                brport_ifaceobj.update_config('bridge-l2protocol-tunnel', ' '.join(running_protocols))
            elif bridge_ifaceobj:
                current_config = bridge_ifaceobj.get_attr_value_first('bridge-l2protocol-tunnel')

                if current_config:
                    bridge_ifaceobj.replace_config('bridge-l2protocol-tunnel', '%s %s=%s' % (current_config, brport_name, ','.join(running_protocols)))
                else:
                    bridge_ifaceobj.replace_config('bridge-l2protocol-tunnel', '%s=%s' % (brport_name, ','.join(running_protocols)))

    def _query_check(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        if self._is_bridge(ifaceobj):
            self._query_check_bridge(ifaceobj, ifaceobjcurr, ifaceobj_getfunc)
        else:
            self._query_check_bridge_port(ifaceobj, ifaceobjcurr,
                                          ifaceobj_getfunc)

    def _query_running_bridge(self, ifaceobjrunning, ifaceobj_getfunc):
        if self.cache.bridge_is_vlan_aware(ifaceobjrunning.name):
            ifaceobjrunning.update_config('bridge-vlan-aware', 'yes')
            ifaceobjrunning.update_config_dict(self._query_running_attrs(
                                               ifaceobjrunning,
                                               ifaceobj_getfunc,
                                               bridge_vlan_aware=True))
        else:
            ifaceobjrunning.update_config_dict(self._query_running_attrs(
                                               ifaceobjrunning, None))

    def _query_running_bridge_port_attrs(self, ifaceobjrunning, bridgename):
        if self.systcl_get_net_bridge_stp_user_space() == '1':
            return

        v = str(self.cache.get_brport_cost(ifaceobjrunning.name))
        if v and v != self.get_mod_subattr('bridge-pathcosts', 'default'):
            ifaceobjrunning.update_config('bridge-pathcosts', v)

        v = str(self.cache.get_brport_priority(ifaceobjrunning.name))
        if v and v != self.get_mod_subattr('bridge-portprios', 'default'):
            ifaceobjrunning.update_config('bridge-portprios', v)

    def _query_running_bridge_port(self, ifaceobjrunning,
                                   ifaceobj_getfunc=None):

        bridgename = self.cache.get_bridge_name_from_port(
                                                ifaceobjrunning.name)
        bridge_vids = None
        bridge_pvid = None
        if not bridgename:
            self.logger.warning('%s: unable to find bridgename'
                             %ifaceobjrunning.name)
            return

        if not self.cache.bridge_is_vlan_aware(bridgename):
            try:
                self._query_running_bridge_l2protocol_tunnel(ifaceobjrunning.name, bridge_ifaceobj=ifaceobj_getfunc(bridgename)[0])
            except Exception as e:
                self.logger.debug('%s: q_query_running_bridge_l2protocol_tunnel: %s' % (ifaceobjrunning.name, str(e)))
            return

        self._query_running_bridge_l2protocol_tunnel(ifaceobjrunning.name, brport_ifaceobj=ifaceobjrunning)

        (bridge_port_vids, bridge_port_pvid) = self._get_running_vids_n_pvid_str(
                                                           ifaceobjrunning.name)
        if bridge_port_vids and bridge_port_pvid in bridge_port_vids:
                bridge_port_vids.remove(bridge_port_pvid)

        bridgeifaceobjlist = ifaceobj_getfunc(bridgename)
        if bridgeifaceobjlist:
           bridge_vids = bridgeifaceobjlist[0].get_attr_value('bridge-vids')
           bridge_pvid = bridgeifaceobjlist[0].get_attr_value_first('bridge-pvid')

        if not bridge_port_vids and bridge_port_pvid:
            # must be an access port
            if bridge_port_pvid != '1':
               ifaceobjrunning.update_config('bridge-access',
                                          bridge_port_pvid)
        else:
            if bridge_port_vids and (not bridge_vids or bridge_port_vids != bridge_vids):
                ifaceobjrunning.update_config("bridge-vids", " ".join(bridge_port_vids))
            if bridge_port_pvid and bridge_port_pvid != "1" and (not bridge_pvid or (bridge_port_pvid != bridge_pvid)):
                    ifaceobjrunning.update_config("bridge-pvid", bridge_port_pvid)

        v = utils.get_onff_from_onezero(self.cache.get_brport_learning(ifaceobjrunning.name))
        if v and v != self.get_mod_subattr('bridge-learning', 'default'):
            ifaceobjrunning.update_config('bridge-learning', v)

        v = utils.get_onff_from_onezero(self.cache.get_brport_unicast_flood(ifaceobjrunning.name))
        if v and v != self.get_mod_subattr('bridge-unicast-flood', 'default'):
            ifaceobjrunning.update_config('bridge-unicast-flood', v)

        v = utils.get_onff_from_onezero(self.cache.get_brport_multicast_flood(ifaceobjrunning.name))
        if v and v != self.get_mod_subattr('bridge-multicast-flood', 'default'):
            ifaceobjrunning.update_config('bridge-multicast-flood', v)

        v = utils.get_onff_from_onezero(self.cache.get_brport_broadcast_flood(ifaceobjrunning.name))
        if v and v != self.get_mod_subattr('bridge-broadcast-flood', 'default'):
            ifaceobjrunning.update_config('bridge-broadcast-flood', v)

        v = utils.get_onff_from_onezero(self.cache.get_brport_neigh_suppress(ifaceobjrunning.name))
        # Display running 'arp-nd-suppress' only on vxlan ports
        # if 'allow_arp_nd_suppress_only_on_vxlan' is set to 'yes'
        # otherwise, display on all bridge-ports

        bportifaceobj = ifaceobj_getfunc(ifaceobjrunning.name)[0]
        if (v and
            v != self.get_mod_subattr('bridge-arp-nd-suppress', 'default') and
            (not self.arp_nd_suppress_only_on_vxlan or
             (self.arp_nd_suppress_only_on_vxlan and
              bportifaceobj.link_kind & ifaceLinkKind.VXLAN))):
            ifaceobjrunning.update_config('bridge-arp-nd-suppress', v)

        self._query_running_bridge_port_attrs(ifaceobjrunning, bridgename)

        #
        # bridge-vlan-vni-map
        #
        try:
            # there's a mix-up vlan_vni should return vlans/vnis and not vnis/vlans
            # ifquery-check is also using this function and has already code to work
            # around the issue, so to fix our ordering problem we will simply and
            # temporarily, swap the two return values
            cached_vnis, cached_vlans = self.get_vlan_vni_ranges(
                self.cache.get_vlan_vni(ifaceobjrunning.name), compress=True
            )

            if cached_vlans and cached_vnis:
                ifaceobjrunning.update_config(
                    "bridge-vlan-vni-map",
                    " ".join(["%s=%s" % (vlan, vni) for vlan, vni in zip(cached_vlans, cached_vnis)])
                )
        except Exception as e:
            self.logger.debug("bridge-vlan-vni-map: exception: %s" % str(e))

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        try:
            if self.cache.bridge_exists(ifaceobjrunning.name):
                self._query_running_bridge(ifaceobjrunning, ifaceobj_getfunc)
            elif self.cache.link_is_bridge_port(ifaceobjrunning.name):
                self._query_running_bridge_port(ifaceobjrunning, ifaceobj_getfunc)
        except Exception as e:
            raise AddonException('%s: %s' % (ifaceobjrunning.name, str(e)))

    def _query(self, ifaceobj, **kwargs):
        """ add default policy attributes supported by the module """

        if self.bridge_vxlan_arp_nd_suppress \
                and ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT \
                and ifaceobj.link_kind & ifaceLinkKind.VXLAN:
            ifaceobj.update_config("bridge-arp-nd-suppress", "on")

        if (not (ifaceobj.link_kind & ifaceLinkKind.BRIDGE) or
            ifaceobj.get_attr_value_first('bridge-stp')):
            return
        if self.default_stp_on:
            ifaceobj.update_config('bridge-stp', 'yes')


    _run_ops = {
        'pre-up': _up,
        'post-down': _down,
        'query-checkcurr': _query_check,
        'query-running': _query_running,
        'query': _query
    }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return list(self._run_ops.keys())

    def run(self, ifaceobj, operation, query_ifaceobj=None, ifaceobj_getfunc=None):
        """ run bridge configuration on the interface object passed as
            argument. Can create bridge interfaces if they dont exist already

        Args:
            **ifaceobj** (object): iface object

            **operation** (str): any of 'pre-up', 'post-down', 'query-checkcurr',
                                 'query-running'

        Kwargs:
            **query_ifaceobj** (object): query check ifaceobject. This is only
                valid when op is 'query-checkcurr'. It is an object same as
                ifaceobj, but contains running attribute values and its config
                status. The modules can use it to return queried running state
                of interfaces. status is success if the running state is same
                as user required state in ifaceobj. error otherwise.
        """
        op_handler = self._run_ops.get(operation)
        if not op_handler:
           return

        if (not self.requirements.bridge_utils_is_installed
                and (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT or ifaceobj.link_kind & ifaceLinkKind.BRIDGE)
                    and self.bridge_utils_missing_warning):
            self.logger.warning('%s: missing - bridge operation may not work as expected. '
                                'Please check if \'bridge-utils\' package is installed' % utils.brctl_cmd)
            self.bridge_utils_missing_warning = False

        # make sure BRIDGE_VXLAN is set if we have a vxlan port
        self._re_evaluate_bridge_vxlan(ifaceobj, ifaceobj_getfunc)
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
        else:
            op_handler(self, ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
