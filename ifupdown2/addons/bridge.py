#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import re
import time
import itertools

from sets import Set
from collections import Counter

try:
    import ifupdown2.ifupdown.exceptions as exceptions
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.netlink import netlink

    from ifupdown2.ifupdownaddons.cache import *
    from ifupdown2.ifupdownaddons.LinkUtils import LinkUtils
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    import ifupdown.exceptions as exceptions
    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags

    from nlmanager.nlmanager import Link

    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdown.netlink import netlink

    from ifupdownaddons.cache import *
    from ifupdownaddons.LinkUtils import LinkUtils
    from ifupdownaddons.modulebase import moduleBase


class bridgeFlags:
    PORT_PROCESSED = 0x1
    PORT_PROCESSED_OVERRIDE = 0x2


class bridge(moduleBase):
    """  ifupdown2 addon module to configure linux bridges """

    _modinfo = { 'mhelp' : 'Bridge configuration module. Supports both ' +
                    'vlan aware and non vlan aware bridges. For the vlan ' +
                    'aware bridge, the port specific attributes must be ' +
                    'specified under the port. And for vlan unaware bridge ' +
                    'port specific attributes must be specified under the ' +
                    'bridge.',
                 'attrs' : {
                   'bridge-vlan-aware' :
                        {'help' : 'vlan aware bridge. Setting this ' +
                                  'attribute to yes enables vlan filtering' +
                                  ' on the bridge',
                         'validvals' : ['yes', 'no'],
                         'example' : ['bridge-vlan-aware yes/no'],
                         'default': 'no'
                         },
                   'bridge-ports' :
                        {'help' : 'bridge ports',
                         'multivalue' : True,
                         'required' : True,
                         'validvals': ['<interface-list>'],
                         'example' : ['bridge-ports swp1.100 swp2.100 swp3.100',
                                      'bridge-ports glob swp1-3.100',
                                      'bridge-ports regex (swp[1|2|3].100)']},
                   'bridge-stp' :
                        {'help': 'bridge-stp yes/no',
                         'example' : ['bridge-stp no'],
                         'validvals' : ['yes', 'on', 'off', 'no'],
                         'default' : 'no'},
                   'bridge-bridgeprio' :
                        {'help': 'bridge priority',
                         'validrange' : ['0', '65535'],
                         'example' : ['bridge-bridgeprio 32768'],
                         'default' : '32768'},
                   'bridge-ageing' :
                       {'help': 'bridge ageing',
                         'validrange' : ['0', '65535'],
                         'example' : ['bridge-ageing 300'],
                         'default' : '300'},
                   'bridge-fd' :
                        { 'help' : 'bridge forward delay',
                          'validrange' : ['0', '255'],
                          'example' : ['bridge-fd 15'],
                          'default' : '15'},
                   'bridge-gcint' :
                        # XXX: recheck values
                        { 'help' : 'bridge garbage collection interval in secs',
                          'validrange' : ['0', '255'],
                          'example' : ['bridge-gcint 4'],
                          'default' : '4',
                          'compat' : True,
                          'deprecated': True},
                   'bridge-hello' :
                        { 'help' : 'bridge set hello time',
                          'validrange' : ['0', '255'],
                          'example' : ['bridge-hello 2'],
                          'default' : '2'},
                   'bridge-maxage' :
                        { 'help' : 'bridge set maxage',
                          'validrange' : ['0', '255'],
                          'example' : ['bridge-maxage 20'],
                          'default' : '20'},
                   'bridge-pathcosts' :
                        { 'help' : 'bridge set port path costs',
                          'validvals': ['<interface-range-list>'],
                          'validrange' : ['0', '65535'],
                          'example' : ['under the port (for vlan aware bridge): bridge-pathcosts 100',
                                       'under the bridge (for vlan unaware bridge): bridge-pathcosts swp1=100 swp2=100'],
                          'default' : '100'},
                   'bridge-portprios' :
                        { 'help' : 'bridge port prios',
                          'validvals': ['<interface-range-list>'],
                          'validrange' : ['0', '65535'],
                          'example' : ['under the port (for vlan aware bridge): bridge-portprios 32',
                                       'under the bridge (for vlan unaware bridge): bridge-portprios swp1=32 swp2=32'],
                          'default' : '32'},
                   'bridge-mclmc' :
                        { 'help' : 'set multicast last member count',
                          'validrange' : ['0', '255'],
                          'example' : ['bridge-mclmc 2'],
                          'default' : '2'},
                    'bridge-mcrouter' :
                        { 'help' : 'set multicast router',
                          'validvals' : ['yes', 'no', '0', '1', '2'],
                          'example' : ['bridge-mcrouter 1'],
                          'default': 'yes'
                          },
                    'bridge-mcsnoop' :
                        { 'help' : 'set multicast snooping',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'yes',
                          'example' : ['bridge-mcsnoop yes']},
                    'bridge-mcsqc' :
                        { 'help' : 'set multicast startup query count',
                          'validrange' : ['0', '255'],
                          'default' : '2',
                          'example' : ['bridge-mcsqc 2']},
                    'bridge-mcqifaddr' :
                        { 'help' : 'set multicast query to use ifaddr',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'no',
                          'example' : ['bridge-mcqifaddr no']},
                    'bridge-mcquerier' :
                        { 'help' : 'set multicast querier',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'no',
                          'example' : ['bridge-mcquerier no']},
                    'bridge-hashel' :
                        { 'help' : 'set hash elasticity',
                          'validrange' : ['0', '4096'],
                          'default' : '4',
                          'example' : ['bridge-hashel 4096']},
                    'bridge-hashmax' :
                        { 'help' : 'set hash max',
                          'validrange' : ['0', '4096'],
                          'default' : '512',
                          'example' : ['bridge-hashmax 4096']},
                    'bridge-mclmi' :
                        { 'help' : 'set multicast last member interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '1',
                          'example' : ['bridge-mclmi 1']},
                    'bridge-mcmi' :
                        { 'help' : 'set multicast membership interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '260',
                          'example' : ['bridge-mcmi 260']},
                    'bridge-mcqpi' :
                        { 'help' : 'set multicast querier interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '255',
                          'example' : ['bridge-mcqpi 255']},
                    'bridge-mcqi' :
                        { 'help' : 'set multicast query interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '125',
                          'example' : ['bridge-mcqi 125']},
                    'bridge-mcqri' :
                        { 'help' : 'set multicast query response interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '10',
                          'example' : ['bridge-mcqri 10']},
                    'bridge-mcsqi' :
                        { 'help' : 'set multicast startup query interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '31',
                          'example' : ['bridge-mcsqi 31']},
                    'bridge-mcqv4src' :
                        { 'help' : 'set per VLAN v4 multicast querier source address',
                          'validvals' : ['<number-ipv4-list>', ],
                          'multivalue' : True,
                          'compat' : True,
                          'example' : ['bridge-mcqv4src 100=172.16.100.1 101=172.16.101.1']},
                     'bridge-portmcrouter':
                         {
                             'help': 'set port multicast routers',
                             'validvals': ['<interface-disabled-automatic-enabled>'],
                             'example': [
                                 'under the port (for vlan aware bridge): bridge-portmcrouter 0',
                                 'under the port (for vlan aware bridge): bridge-portmcrouter 1',
                                 'under the port (for vlan aware bridge): bridge-portmcrouter 2',
                                 'under the port (for vlan aware bridge): bridge-portmcrouter disabled',
                                 'under the port (for vlan aware bridge): bridge-portmcrouter automatic',
                                 'under the port (for vlan aware bridge): bridge-portmcrouter enabled',
                                 'under the bridge (for vlan unaware bridge): bridge-portmcrouter swp1=0 swp2=1 swp2=2',
                                 'under the bridge (for vlan unaware bridge): bridge-portmcrouter swp1=disabled swp2=automatic swp3=enabled',
                                 'under the bridge (for vlan unaware bridge): bridge-portmcrouter swp1=2 swp2=disabled swp3=1',
                             ]
                         },
                    'bridge-portmcfl' :
                        { 'help' : 'port multicast fast leave.',
                          'validvals': ['<interface-yes-no-0-1-list>'],
                          'validrange' : ['yes', 'no', '0', '1'],
                          'default' : 'no',
                          'example' : ['under the port (for vlan aware bridge): bridge-portmcfl no',
                                       'under the bridge (for vlan unaware bridge): bridge-portmcfl swp1=no swp2=no']},
                    'bridge-waitport' :
                        { 'help' : 'wait for a max of time secs for the' +
                                ' specified ports to become available,' +
                                'if no ports are specified then those' +
                                ' specified on bridge-ports will be' +
                                ' used here. Specifying no ports here ' +
                                'should not be used if we are using ' +
                                'regex or \"all\" on bridge_ports,' +
                                'as it wouldnt work.',
                          'default' : '0',
                          'validvals': ['<number-interface-list>'],
                          'example' : ['bridge-waitport 4 swp1 swp2']},
                    'bridge-maxwait' :
                        { 'help' : 'forces to time seconds the maximum time ' +
                                'that the Debian bridge setup scripts will ' +
                                'wait for the bridge ports to get to the ' +
                                'forwarding status, doesn\'t allow factional ' +
                                'part. If it is equal to 0 then no waiting' +
                                ' is done',
                          'validrange' : ['0', '255'],
                          'default' : '0',
                          'example' : ['bridge-maxwait 3']},
                    'bridge-vids' :
                        { 'help' : 'bridge port vids. Can be specified ' +
                                   'under the bridge or under the port. ' +
                                   'If specified under the bridge the ports ' +
                                   'inherit it unless overridden by a ' +
                                   'bridge-vids attribute under the port',
                          'multivalue' : True,
                          'validvals': ['<number-comma-range-list>'],
                          'example' : ['bridge-vids 4000',
                                       'bridge-vids 2000 2200-3000'],
                          'aliases': ['bridge-trunk']},
                    'bridge-pvid' :
                        { 'help' : 'bridge port pvid. Must be specified under' +
                                   ' the bridge port',
                          'validrange' : ['0', '4096'],
                          'example' : ['bridge-pvid 1']},
                    'bridge-access' :
                        { 'help' : 'bridge port access vlan. Must be ' +
                                   'specified under the bridge port',
                          'validrange' : ['1', '4094'],
                          'example' : ['bridge-access 300']},
                    'bridge-allow-untagged' :
                        { 'help' : 'indicate if the bridge port accepts ' +
                                   'untagged packets or not.  Must be ' +
                                   'specified under the bridge port. ' +
                                   'Default is \'yes\'',
                          'validvals' : ['yes', 'no'],
                          'example' : ['bridge-allow-untagged yes'],
                          'default' : 'yes'},
                    'bridge-port-vids' :
                        { 'help' : 'bridge vlans',
                          'compat': True,
                          'example' : ['bridge-port-vids bond0=1-1000,1010-1020']},
                    'bridge-port-pvids' :
                        { 'help' : 'bridge port vlans',
                          'compat': True,
                          'example' : ['bridge-port-pvids bond0=100 bond1=200']},
                    'bridge-learning' :
                        { 'help' : 'bridge port learning flag',
                          'validvals': ['on', 'off', '<interface-on-off-list>'],
                          'default': 'on',
                          'example' : ['bridge-learning off']},
                    'bridge-igmp-version' :
                        { 'help' : 'mcast igmp version',
                          'validvals': ['2', '3'],
                          'default' : '2',
                          'example' : ['bridge-igmp-version 2']},
                    'bridge-mld-version':
                        { 'help' : 'mcast mld version',
                          'validvals': ['1', '2'],
                          'default' : '1',
                          'example' : ['bridge-mld-version 1']},
                    'bridge-unicast-flood' :
                        { 'help' : 'bridge port unicast flood flag',
                          'validvals': ['on', 'off', '<interface-on-off-list>'],
                          'default': 'on',
                          'example' : ['under the port (for vlan aware bridge): bridge-unicast-flood on',
                                       'under the bridge (for vlan unaware bridge): bridge-unicast-flood swp1=on swp2=on']},
                    'bridge-multicast-flood' :
                        { 'help' : 'bridge port multicast flood flag',
                          'validvals': ['on', 'off', '<interface-on-off-list>'],
                          'default': 'on',
                          'example' : ['under the port (for vlan aware bridge): bridge-multicast-flood on',
                                       'under the bridge (for vlan unaware bridge): bridge-multicast-flood swp1=on swp2=on']},
                    'bridge-vlan-protocol' :
                        { 'help' : 'bridge vlan protocol',
                          'default' : '802.1q',
                          'validvals': ['802.1q', '802.1ad'],
                          'example' : ['bridge-vlan-protocol 802.1q']},
                    'bridge-vlan-stats' :
                        { 'help' : 'bridge vlan stats',
                          'default' : 'off',
                          'validvals': ['on', 'off'],
                          'example' : ['bridge-vlan-stats off']},
                    'bridge-arp-nd-suppress' :
                        { 'help' : 'bridge port arp nd suppress flag',
                          'validvals': ['on', 'off', '<interface-on-off-list>'],
                          'default': 'off',
                          'example' : ['under the port (for vlan aware bridge): bridge-arp-nd-suppress on',
                                       'under the bridge (for vlan unaware bridge): bridge-arp-nd-suppress swp1=on swp2=on']},
                    'bridge-mcstats' :
                        { 'help' : 'bridge multicast stats',
                          'default' : 'off',
                          'validvals': ['on', 'off'],
                          'example' : ['bridge-mcstats off']},
                     'bridge-l2protocol-tunnel': {
                         'help': 'layer 2 protocol tunneling',
                         'validvals': [ # XXX: lists all combinations, should move to
                                        # a better representation
                                        'all',
                                        'cdp',
                                        'cdp lacp',
                                        'cdp lacp lldp',
                                        'cdp lacp lldp pvst',
                                        'cdp lacp lldp stp',
                                        'cdp lacp pvst',
                                        'cdp lacp pvst stp',
                                        'cdp lacp stp',
                                        'cdp lldp',
                                        'cdp lldp pvst',
                                        'cdp lldp pvst stp',
                                        'cdp lldp stp',
                                        'cdp pvst',
                                        'cdp pvst stp',
                                        'cdp stp',
                                        'lacp',
                                        'lacp lldp',
                                        'lacp lldp pvst',
                                        'lacp lldp pvst stp',
                                        'lacp lldp stp',
                                        'lacp pvst',
                                        'lacp pvst stp',
                                        'lacp stp',
                                        'lldp',
                                        'lldp pvst',
                                        'lldp pvst stp',
                                        'lldp stp',
                                        'pvst',
                                        'pvst stp',
                                        'stp',
                                        '<interface-l2protocol-tunnel-list>'],
                         'example': [
                             'under the bridge (for vlan unaware bridge): bridge-l2protocol-tunnel swpX=lacp,stp swpY=cdp swpZ=all',
                             'under the port (for vlan aware bridge): bridge-l2protocol-tunnel lacp stp lldp cdp pvst',
                             'under the port (for vlan aware bridge): bridge-l2protocol-tunnel lldp pvst',
                             'under the port (for vlan aware bridge): bridge-l2protocol-tunnel stp',
                             'under the port (for vlan aware bridge): bridge-l2protocol-tunnel all'
                         ]
                     }
                     }}

    # Netlink attributes not associated with ifupdown2
    # attributes are left commented-out for a future use
    # and kept in order :)
    _ifla_br_attributes_map = (
        # Link.IFLA_BR_UNSPEC,
        ('bridge-fd', Link.IFLA_BR_FORWARD_DELAY),
        ('bridge-hello', Link.IFLA_BR_HELLO_TIME),
        ('bridge-maxage', Link.IFLA_BR_MAX_AGE),
        ('bridge-ageing', Link.IFLA_BR_AGEING_TIME),
        ('bridge-stp', Link.IFLA_BR_STP_STATE),
        ('bridge-bridgeprio', Link.IFLA_BR_PRIORITY),
        ('bridge-vlan-aware', Link.IFLA_BR_VLAN_FILTERING),
        ('bridge-vlan-protocol', Link.IFLA_BR_VLAN_PROTOCOL),
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
        ('bridge-mcrouter', Link.IFLA_BR_MCAST_ROUTER),
        #('bridge-mcsnoop', Link.IFLA_BR_MCAST_SNOOPING), # requires special handling so we won't loop on this attr
        ('bridge-mcqifaddr', Link.IFLA_BR_MCAST_QUERY_USE_IFADDR),
        ('bridge-mcquerier', Link.IFLA_BR_MCAST_QUERIER),
        ('bridge-hashel', Link.IFLA_BR_MCAST_HASH_ELASTICITY),
        ('bridge-hashmax', Link.IFLA_BR_MCAST_HASH_MAX),
        ('bridge-mclmc', Link.IFLA_BR_MCAST_LAST_MEMBER_CNT),
        ('bridge-mcsqc', Link.IFLA_BR_MCAST_STARTUP_QUERY_CNT),
        ('bridge-mclmi', Link.IFLA_BR_MCAST_LAST_MEMBER_INTVL),
        ('bridge-mcmi', Link.IFLA_BR_MCAST_MEMBERSHIP_INTVL),
        ('bridge-mcqpi', Link.IFLA_BR_MCAST_QUERIER_INTVL),
        ('bridge-mcqi', Link.IFLA_BR_MCAST_QUERY_INTVL),
        ('bridge-mcqri', Link.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL),
        ('bridge-mcsqi', Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL),
        # Link.IFLA_BR_NF_CALL_IPTABLES,
        # Link.IFLA_BR_NF_CALL_IP6TABLES,
        # Link.IFLA_BR_NF_CALL_ARPTABLES,
        # Link.IFLA_BR_VLAN_DEFAULT_PVID,
        # Link.IFLA_BR_PAD,
        # (Link.IFLA_BR_VLAN_STATS_ENABLED, 'bridge-vlan-stats'), #  already dealt with, in a separate loop
        ('bridge-igmp-version', Link.IFLA_BR_MCAST_IGMP_VERSION, ),
        ('bridge-mcstats', Link.IFLA_BR_MCAST_STATS_ENABLED),
        ('bridge-mld-version', Link.IFLA_BR_MCAST_MLD_VERSION)
    )
    # 'bridge-vlan-stats & bridge-mcstat are commented out even though, today
    # they are supported. It is done this way because this dictionary is used
    # in a loop, but these attributes require additional work. Thus they are
    # excluded from this loop without overhead.

    # we are still using the old linkCache we need an easy way
    # to use this cache with the new full-netlink approach
    _ifla_br_attributes_old_cache_key_map = dict(
        (
            (Link.IFLA_BR_FORWARD_DELAY, 'fd'),
            (Link.IFLA_BR_HELLO_TIME, 'hello'),
            (Link.IFLA_BR_MAX_AGE, 'maxage'),
            (Link.IFLA_BR_AGEING_TIME, 'ageing'),
            (Link.IFLA_BR_STP_STATE, 'stp'),
            (Link.IFLA_BR_PRIORITY, 'bridgeprio'),
            (Link.IFLA_BR_VLAN_FILTERING, 'vlan_filtering'),
            (Link.IFLA_BR_VLAN_PROTOCOL, 'vlan-protocol'),
            (Link.IFLA_BR_MCAST_ROUTER, 'mcrouter'),
            (Link.IFLA_BR_MCAST_SNOOPING, 'mcsnoop'),
            (Link.IFLA_BR_MCAST_QUERY_USE_IFADDR, 'mcqifaddr'),
            (Link.IFLA_BR_MCAST_QUERIER, 'mcquerier'),
            (Link.IFLA_BR_MCAST_HASH_ELASTICITY, 'hashel'),
            (Link.IFLA_BR_MCAST_HASH_MAX, 'hashmax'),
            (Link.IFLA_BR_MCAST_LAST_MEMBER_CNT, 'mclmc'),
            (Link.IFLA_BR_MCAST_STARTUP_QUERY_CNT, 'mcsqc'),
            (Link.IFLA_BR_MCAST_LAST_MEMBER_INTVL, 'mclmi'),
            (Link.IFLA_BR_MCAST_MEMBERSHIP_INTVL, 'mcmi'),
            (Link.IFLA_BR_MCAST_QUERIER_INTVL, 'mcqpi'),
            (Link.IFLA_BR_MCAST_QUERY_INTVL, 'mcqi'),
            (Link.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL, 'mcqri'),
            (Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL, 'mcsqi'),
            (Link.IFLA_BR_VLAN_STATS_ENABLED, 'vlan-stats'),
            (Link.IFLA_BR_MCAST_STATS_ENABLED, 'mcstats'),
            (Link.IFLA_BR_MCAST_IGMP_VERSION, 'igmp-version'),
            (Link.IFLA_BR_MCAST_MLD_VERSION, 'mld-version')
        )
    )

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
            (Link.IFLA_BR_VLAN_PROTOCOL, str),
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

    _ifla_brport_attributes_map = (
        # Link.IFLA_BRPORT_UNSPEC,
        # Link.IFLA_BRPORT_STATE,
        ('bridge-portprios', Link.IFLA_BRPORT_PRIORITY),
        ('bridge-pathcosts', Link.IFLA_BRPORT_COST),
        # Link.IFLA_BRPORT_MODE,
        # Link.IFLA_BRPORT_GUARD,
        # Link.IFLA_BRPORT_PROTECT,
        ('bridge-portmcfl', Link.IFLA_BRPORT_FAST_LEAVE),
        ('bridge-learning', Link.IFLA_BRPORT_LEARNING),
        ('bridge-unicast-flood', Link.IFLA_BRPORT_UNICAST_FLOOD),
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
        ('bridge-portmcrouter', Link.IFLA_BRPORT_MULTICAST_ROUTER),
        # Link.IFLA_BRPORT_PAD,
        ('bridge-multicast-flood', Link.IFLA_BRPORT_MCAST_FLOOD),
        # Link.IFLA_BRPORT_MCAST_TO_UCAST,
        # Link.IFLA_BRPORT_VLAN_TUNNEL,
        # Link.IFLA_BRPORT_BCAST_FLOOD
        ('bridge-l2protocol-tunnel', Link.IFLA_BRPORT_GROUP_FWD_MASK),
        # Link.IFLA_BRPORT_PEER_LINK,
        # Link.IFLA_BRPORT_DUAL_LINK,
        ('bridge-arp-nd-suppress', Link.IFLA_BRPORT_ARP_SUPPRESS),
    )

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
            (Link.IFLA_BRPORT_GROUP_FWD_MASK, lambda x: x),
            (Link.IFLA_BRPORT_ARP_SUPPRESS, utils.get_boolean_from_string)
        )
    )

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self.name = self.__class__.__name__
        self.brctlcmd = None
        self._running_vidinfo = {}
        self._running_vidinfo_valid = False
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

        try:
            self.bridge_allow_multiple_vlans = utils.get_boolean_from_string(
                self.sysctl_get('net.bridge.bridge-allow-multiple-vlans')
            )
        except:
            # Cumulus Linux specific variable. Failure probably means that
            # ifupdown2 is running a a different system.
            self.bridge_allow_multiple_vlans = True
        self.logger.debug('bridge: init: multiple vlans allowed %s' % self.bridge_allow_multiple_vlans)

        self.bridge_mac_iface_list = policymanager.policymanager_api.get_module_globals(self.__class__.__name__, 'bridge_mac_iface') or []
        self.bridge_mac_iface = None, None  # ifname, mac

        self.bridge_set_static_mac_from_port = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                self.__class__.__name__, 'bridge_set_static_mac_from_port'
            )
        )

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
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT:
            if not self.check_bridge_port_vid_attrs(ifaceobj):
                retval = False
        c1 = self.syntax_check_vxlan_in_vlan_aware_br(ifaceobj, ifaceobj_getfunc)
        c2 = self.syntax_check_bridge_allow_multiple_vlans(ifaceobj, ifaceobj_getfunc)
        return retval and c1 #and c2

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
            self.logger.warn('%s: bridge-access given, bridge-vids and bridge-pvid '
                             'will be ignored' % ifaceobj.name)
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
        self.log_error('`bridge-access` attribute is mandatory when vxlan '
                       'device (%s) is part of vlan aware bridge (%s)'
                       % (ifaceobj.name, bridgename), ifaceobj)

    def syntax_check_vxlan_in_vlan_aware_br(self, ifaceobj, ifaceobj_getfunc):
        if not ifaceobj_getfunc:
            return True
        if (ifaceobj.link_kind & ifaceLinkKind.VXLAN
                and ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT):
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
                        or not self._compare_vids(bridge_vids,
                                                  vids,
                                                  pvid=pvid)):
                        self._error_vxlan_in_vlan_aware_br(ifaceobj,
                                                           ifaceobj_upper.name)
                        return False
        return True

    @staticmethod
    def _is_bridge(ifaceobj):
        return (ifaceobj.link_kind & ifaceLinkKind.BRIDGE or
                ifaceobj.get_attr_value_first('bridge-ports') or
                ifaceobj.get_attr_value_first('bridge-vlan-aware'))

    def _get_ifaceobj_bridge_ports(self, ifaceobj):
        bridge_ports = []

        for brport in ifaceobj.get_attr_value('bridge-ports') or []:
            if brport != 'none':
                bridge_ports.extend(brport.split())

        return ' '.join(bridge_ports)

    def _is_bridge_port(self, ifaceobj):
        if self.brctlcmd.is_bridge_port(ifaceobj.name):
            return True
        return False

    def check_valid_bridge(self, ifaceobj, ifname):
        if LinkUtils.link_exists_nodryrun(ifname) and not LinkUtils.is_bridge(ifname):
            self.log_error('misconfiguration of bridge attribute(s) on existing non-bridge interface (%s)' % ifname, ifaceobj=ifaceobj)
            return False
        return True

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        if not self._is_bridge(ifaceobj) or not self.check_valid_bridge(ifaceobj, ifaceobj.name):
            return None
        if ifaceobj.link_type != ifaceLinkType.LINK_NA:
           ifaceobj.link_type = ifaceLinkType.LINK_MASTER
        ifaceobj.link_kind |= ifaceLinkKind.BRIDGE
        # for special vlan aware bridges, we need to add another bit
        if utils.get_boolean_from_string(ifaceobj.get_attr_value_first('bridge-vlan-aware')):
            ifaceobj.link_kind |= ifaceLinkKind.BRIDGE
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE
        ifaceobj.role |= ifaceRole.MASTER
        ifaceobj.dependency_type = ifaceDependencyType.MASTER_SLAVE
        return self.parse_port_list(ifaceobj.name,
                                    self._get_ifaceobj_bridge_ports(ifaceobj),
                                    ifacenames_all)

    def get_dependent_ifacenames_running(self, ifaceobj):
        self._init_command_handlers()
        if not self.brctlcmd.bridge_exists(ifaceobj.name):
            return None
        return self.brctlcmd.get_bridge_ports(ifaceobj.name)

    def _get_bridge_port_list(self, ifaceobj):

        # port list is also available in the previously
        # parsed dependent list. Use that if available, instead
        # of parsing port expr again
        port_list = ifaceobj.lowerifaces
        if port_list:
            return port_list
        ports = self._get_ifaceobj_bridge_ports(ifaceobj)
        if ports:
            return self.parse_port_list(ifaceobj.name, ports)
        else:
            return None

    def _get_bridge_port_list_user_ordered(self, ifaceobj):
        # When enslaving bridge-ports we need to return the exact user
        # configured bridge ports list (bridge will inherit the mac of the
        # first device.
        ports = self._get_ifaceobj_bridge_ports(ifaceobj)
        return self.parse_port_list(ifaceobj.name, ports) if ports else None

    def _process_bridge_waitport(self, ifaceobj, portlist):
        waitport_value = ifaceobj.get_attr_value_first('bridge-waitport')
        if not waitport_value: return
        try:
            waitportvals = re.split(r'[\s\t]\s*', waitport_value, 1)
            if not waitportvals: return
            try:
                waitporttime = int(waitportvals[0])
            except:
                self.log_warn('%s: invalid waitport value \'%s\''
                        %(ifaceobj.name, waitportvals[0]))
                return
            if waitporttime <= 0: return
            try:
                waitportlist = self.parse_port_list(ifaceobj.name,
                                                    waitportvals[1])
            except IndexError, e:
                # ignore error and use all bridge ports
                waitportlist = portlist
                pass
            if not waitportlist: return
            self.logger.info('%s: waiting for ports %s to exist ...'
                    %(ifaceobj.name, str(waitportlist)))
            starttime = time.time()
            while ((time.time() - starttime) < waitporttime):
                if all([False for p in waitportlist
                        if not self.ipcmd.link_exists(p)]):
                    break;
                time.sleep(1)
        except Exception, e:
            self.log_warn('%s: unable to process waitport: %s'
                    %(ifaceobj.name, str(e)))

    def _enable_disable_ipv6(self, port, enable='1'):
        try:
            self.write_file('/proc/sys/net/ipv6/conf/%s/disable_ipv6' % port, enable)
        except Exception, e:
            self.logger.info(str(e))

    def handle_ipv6(self, ports, state, ifaceobj=None):
        if (ifaceobj and
                (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VXLAN) and
                not ifaceobj.get_attr_value('address')):
            self._enable_disable_ipv6(ifaceobj.name, state)
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
                        if vlanid:
                            if currvlanid != vlanid:
                                self.log_error('%s: ' %bridgeifaceobj.name +
                                               'net.bridge.bridge-allow-multiple-vlans not set, multiple vlans not allowed', bridgeifaceobj)
                                break
                        if currvlanid:
                            vlanid = currvlanid
            except Exception as e:
                errstr += '\n%s' % str(e)
        self.log_error(bridgeifaceobj.name + ': ' + errstr, bridgeifaceobj)

    def _add_ports(self, ifaceobj, ifaceobj_getfunc):
        bridgeports = self._get_bridge_port_list(ifaceobj)
        runningbridgeports = []

        self.ipcmd.batch_start()
        self._process_bridge_waitport(ifaceobj, bridgeports)
        self.ipcmd.batch_start()
        # Delete active ports not in the new port list
        if not ifupdownflags.flags.PERFMODE:
            runningbridgeports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
            if runningbridgeports:
                for bport in runningbridgeports:
                    if not bridgeports or bport not in bridgeports:
                        self.ipcmd.link_set(bport, 'nomaster')
                        # set admin DOWN on all removed ports
                        # that don't have config outside bridge
                        if not ifaceobj_getfunc(bport):
                            netlink.link_set_updown(bport, "down")
                        # enable ipv6 for ports that were removed
                        self.handle_ipv6([bport], '0')
            else:
                runningbridgeports = []
        if not bridgeports:
            self.ipcmd.batch_commit()
            return []
        err = 0
        ports = 0
        newbridgeports = Set(bridgeports).difference(Set(runningbridgeports))
        newly_enslaved_ports = []

        newbridgeports_ordered = []
        for br_port in self._get_bridge_port_list_user_ordered(ifaceobj):
            if br_port in newbridgeports:
                newbridgeports_ordered.append(br_port)

        for bridgeport in newbridgeports_ordered:
            try:
                if (not ifupdownflags.flags.DRYRUN and
                    not self.ipcmd.link_exists(bridgeport)):
                    self.log_error('%s: bridge port %s does not exist'
                                   %(ifaceobj.name, bridgeport), ifaceobj)
                    err += 1
                    continue
                hwaddress = self.ipcmd.link_get_hwaddress(bridgeport)
                if not self._valid_ethaddr(hwaddress):
                    self.log_warn('%s: skipping port %s, ' %(ifaceobj.name,
                                  bridgeport) + 'invalid ether addr %s'
                                  %hwaddress)
                    continue
                self.ipcmd.link_set(bridgeport, 'master', ifaceobj.name)
                newly_enslaved_ports.append(bridgeport)
                self.handle_ipv6([bridgeport], '1')
                self.ipcmd.addr_flush(bridgeport)
                ports += 1
                if ports == 250:
                    ports = 0
                    self.ipcmd.batch_commit()
                    self.ipcmd.batch_start()
            except Exception, e:
                self.logger.error(str(e))
                pass
        try:
            self.ipcmd.batch_commit()
        except Exception, e:
            self._pretty_print_add_ports_error(str(e), ifaceobj,
                                               bridgeports)
            pass

        if err:
            self.log_error('bridge configuration failed (missing ports)')

        return newly_enslaved_ports

    def _process_bridge_maxwait(self, ifaceobj, portlist):
        maxwait = ifaceobj.get_attr_value_first('bridge-maxwait')
        if not maxwait: return
        try:
            maxwait = int(maxwait)
        except:
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
        except Exception, e:
            self.log_warn('%s: unable to process maxwait: %s'
                    %(ifaceobj.name, str(e)))

    def _ints_to_ranges(self, ints):
        for a, b in itertools.groupby(enumerate(ints), lambda (x, y): y - x):
            b = list(b)
            yield b[0][1], b[-1][1]

    def _ranges_to_ints(self, rangelist):
        """ returns expanded list of integers given set of string ranges
        example: ['1', '2-4', '6'] returns [1, 2, 3, 4, 6]
        """
        result = []
        try:
            for part in rangelist:
                if '-' in part:
                    a, b = part.split('-')
                    a, b = int(a), int(b)
                    result.extend(range(a, b + 1))
                else:
                    a = int(part)
                    result.append(a)
        except:
            self.logger.warn('unable to parse vids \'%s\''
                             %''.join(rangelist))
            pass
        return result

    def _compress_into_ranges(self, vids_ints):
        return ['%d' %start if start == end else '%d-%d' %(start, end)
                       for start, end in self._ints_to_ranges(vids_ints)]

    def _diff_vids(self, vids1_ints, vids2_ints):
        return Set(vids2_ints).difference(vids1_ints), Set(vids1_ints).difference(vids2_ints)

    def _compare_vids(self, vids1, vids2, pvid=None):
        """ Returns true if the vids are same else return false """

        vids1_ints = self._ranges_to_ints(vids1)
        vids2_ints = self._ranges_to_ints(vids2)
        set_diff = Set(vids1_ints).symmetric_difference(vids2_ints)
        if pvid and int(pvid) in set_diff:
            set_diff.remove(int(pvid))
        if set_diff:
            return False
        else:
            return True

    def _set_bridge_mcqv4src_compat(self, ifaceobj):
        #
        # Sets old style igmp querier
        #
        attrval = ifaceobj.get_attr_value_first('bridge-mcqv4src')
        if attrval:
            running_mcqv4src = {}
            if not ifupdownflags.flags.PERFMODE:
                running_mcqv4src = self.brctlcmd.bridge_get_mcqv4src(ifaceobj.name)
            mcqs = {}
            srclist = attrval.split()
            for s in srclist:
                k, v = s.split('=')
                mcqs[k] = v

            k_to_del = Set(running_mcqv4src.keys()).difference(mcqs.keys())
            for v in k_to_del:
                self.brctlcmd.bridge_del_mcqv4src(ifaceobj.name, v)
            for v in mcqs.keys():
                self.brctlcmd.bridge_set_mcqv4src(ifaceobj.name, v, mcqs[v])
        elif not ifupdownflags.flags.PERFMODE:
            running_mcqv4src = self.brctlcmd.bridge_get_mcqv4src(ifaceobj.name)
            if running_mcqv4src:
                for v in running_mcqv4src.keys():
                    self.brctlcmd.bridge_del_mcqv4src(ifaceobj.name, v)

    def _get_running_vidinfo(self):
        if self._running_vidinfo_valid:
            return self._running_vidinfo
        self._running_vidinfo = {}

        # Removed check for PERFMODE.  Need the get in all cases
        # including reboot, so that we can configure the pvid correctly.
        self._running_vidinfo = self.ipcmd.bridge_port_vids_get_all_json()
        self._running_vidinfo_valid = True
        return self._running_vidinfo

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
                    running_pvid = self._get_running_pvid(port)
                    if running_pvid:
                        if running_pvid == pvid:
                            continue
                        else:
                            self.ipcmd.bridge_port_pvid_del(port, running_pvid)
                    self.ipcmd.bridge_port_pvid_add(port, pvid)
                except Exception, e:
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
                    vids_int =  self._ranges_to_ints(vids)
                    running_vids = self.ipcmd.bridge_vlan_get_vids(port)
                    if running_vids:
                        (vids_to_del, vids_to_add) = \
                                self._diff_vids(vids_int, running_vids)
                        if vids_to_del:
                            self.ipcmd.bridge_port_vids_del(port,
                                    self._compress_into_ranges(vids_to_del))
                        if vids_to_add:
                            self.ipcmd.bridge_port_vids_add(port,
                                    self._compress_into_ranges(vids_to_add))
                    else:
                        self.ipcmd.bridge_port_vids_add(port, vids_int)
                except Exception, e:
                    self.log_warn('%s: failed to set vid `%s` (%s)'
                        %(ifaceobj.name, p, str(e)))

    def _is_running_stp_state_on(self, bridgename):
        """ Returns True if running stp state is on, else False """

        stp_state_file = '/sys/class/net/%s/bridge/stp_state' %bridgename
        try:
            running_stp_state = self.read_file_oneline(stp_state_file)
            return running_stp_state and running_stp_state != '0'
        except:
            return False

    def _is_config_stp_state_on(self, ifaceobj):
        """ Returns true if user specified stp state is on, else False """

        stp_attr = ifaceobj.get_attr_value_first('bridge-stp')
        if not stp_attr:
            return self.default_stp_on
        return utils.get_boolean_from_string(stp_attr)

    def get_bridge_mcsnoop_value(self, ifaceobj):
        mcsnoop = ifaceobj.get_attr_value_first('bridge-mcsnoop')
        if not mcsnoop and ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VXLAN:
            return self._vxlan_bridge_default_igmp_snooping
        return mcsnoop

    def fill_ifla_info_data_with_ifla_br_attribute(self,
                                                   ifla_info_data,
                                                   link_just_created,
                                                   ifname,
                                                   nl_attr,
                                                   attr_name,
                                                   user_config):
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

            old_cache_key = self._ifla_br_attributes_old_cache_key_map.get(nl_attr)
            if old_cache_key and not link_just_created:
                cached_value = self.brctlcmd.link_cache_get([ifname, 'linkinfo', old_cache_key])
                if not cached_value:
                    # the link already exists but we don't have any value
                    # cached for this attr, it probably means that the
                    # capability is not available on this system (i.e old kernel)
                    self.logger.debug('%s: ignoring %s %s: capability '
                                      'probably not supported on this system'
                                      % (ifname, attr_name, user_config))
                    return
                # we need to convert the cache value to "netlink" format
                cached_value = translate_func(cached_value.lower())
            else:
                cached_value = None

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

        self.logger.info('%s: apply bridge settings' % ifname)

        for attr_name, nl_attr in self._ifla_br_attributes_map:
            self.fill_ifla_info_data_with_ifla_br_attribute(
                ifla_info_data=ifla_info_data,
                link_just_created=link_just_created,
                ifname=ifname,
                nl_attr=nl_attr,
                attr_name=attr_name,
                user_config=ifaceobj.get_attr_value_first(attr_name)
            )

        # bridge-mcsnoop
        self.fill_ifla_info_data_with_ifla_br_attribute(
            ifla_info_data=ifla_info_data,
            link_just_created=link_just_created,
            ifname=ifname,
            nl_attr=Link.IFLA_BR_MCAST_SNOOPING,
            attr_name='bridge-mcsnoop',
            user_config=self.get_bridge_mcsnoop_value(ifaceobj)
        )

        # bridge-vlan-stats
        if bridge_vlan_aware:
            self.fill_ifla_info_data_with_ifla_br_attribute(
                ifla_info_data=ifla_info_data,
                link_just_created=link_just_created,
                ifname=ifname,
                nl_attr=Link.IFLA_BR_VLAN_STATS_ENABLED,
                attr_name='bridge-vlan-stats',
                user_config=ifaceobj.get_attr_value_first('bridge-vlan-stats') or self.default_vlan_stats
            )

        try:
            if self._is_config_stp_state_on(ifaceobj):
                if not self._is_running_stp_state_on(ifname):
                    ifla_info_data[Link.IFLA_BR_STP_STATE] = 1
                    self.logger.info('%s: stp state reset, reapplying port settings' % ifname)
                    ifaceobj.module_flags[ifaceobj.name] = \
                        ifaceobj.module_flags.setdefault(self.name, 0) | \
                        bridgeFlags.PORT_PROCESSED_OVERRIDE
            else:
                # If stp not specified and running stp state on, set it to off
                if self._is_running_stp_state_on(ifname):
                    self.logger.info('%s: bridge-stp not specified but running: turning stp off')
                    ifla_info_data[Link.IFLA_BR_STP_STATE] = 0
        except Exception as e:
            self.logger.warning('%s: bridge stp: %s' % (ifname, str(e)))

        if ifla_info_data:
            netlink.link_add_set(ifname=ifname, kind='bridge', ifla_info_data=ifla_info_data, link_exists=True)

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
                self.logger.warn('%s: unable to parse vid \'%s\''
                                 %(ifaceobj.name, v))
        return ret

    def _get_running_pvid(self, ifacename):
        pvid = 0

        running_vidinfo = self._get_running_vidinfo()
        for vinfo in running_vidinfo.get(ifacename, {}):
            v = vinfo.get('vlan')
            pvid = v if 'PVID' in vinfo.get('flags', []) else 0
            if pvid:
                return pvid
        return pvid

    def _get_running_vids_n_pvid_str(self, ifacename):
        vids = []
        pvid = None

        (vids, pvid) = self.ipcmd.bridge_vlan_get_vids_n_pvid(ifacename)

        if vids:
            ret_vids = self._compress_into_ranges(vids)
        else:
            ret_vids = None

        if pvid:
            ret_pvid = '%s' %pvid
        else:
            ret_pvid = None
        return (ret_vids, ret_pvid)

    def _apply_bridge_vids_and_pvid(self, bportifaceobj, vids, pvid,
                                    isbridge):
        """ This method is a combination of methods _apply_bridge_vids and
            _apply_bridge_port_pvids above. A combined function is
            found necessary to do the deletes first and the adds later
            because kernel does honor vid info flags during deletes.

        """
        if not isbridge and bportifaceobj.link_kind & ifaceLinkKind.VXLAN:
            if not vids or not pvid or len(vids) > 1 or vids[0] != pvid:
                self._error_vxlan_in_vlan_aware_br(bportifaceobj,
                                                   bportifaceobj.upperifaces[0])
                return

        vids_int =  self._ranges_to_ints(vids)
        try:
            pvid_int = int(pvid) if pvid else 0
        except Exception:
            self.logger.warn('%s: unable to parse pvid \'%s\''
                             %(bportifaceobj.name, pvid))
            pvid_int = 0
            pass

        vids_to_del = []
        vids_to_add = vids_int
        pvid_to_del = None
        pvid_to_add = pvid_int

        try:
            if not self._check_vids(bportifaceobj, vids):
               return

            (running_vids, running_pvid) = self.ipcmd.bridge_vlan_get_vids_n_pvid(
                                                        bportifaceobj.name)

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
                    self._diff_vids(vids_to_add, running_vids)

            if running_pvid:
                if running_pvid != pvid_int and running_pvid != 0:
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
        except Exception, e:
            self.log_error('%s: failed to process vids/pvids'
                           %bportifaceobj.name + ' vids = %s' %str(vids) +
                           'pvid = %s ' %pvid + '(%s)' %str(e),
                           bportifaceobj, raise_error=False)
        try:
            if vids_to_del:
               if pvid_to_add in vids_to_del:
                   vids_to_del.remove(pvid_to_add)
               self.ipcmd.bridge_vids_del(bportifaceobj.name,
                                          self._compress_into_ranges(
                                          vids_to_del), isbridge)
        except Exception, e:
                self.log_warn('%s: failed to del vid `%s` (%s)'
                        %(bportifaceobj.name, str(vids_to_del), str(e)))

        try:
            if pvid_to_del:
               self.ipcmd.bridge_port_pvid_del(bportifaceobj.name,
                                               pvid_to_del)
        except Exception, e:
                self.log_warn('%s: failed to del pvid `%s` (%s)'
                        %(bportifaceobj.name, pvid_to_del, str(e)))

        try:
            if vids_to_add:
               self.ipcmd.bridge_vids_add(bportifaceobj.name,
                                          self._compress_into_ranges(
                                          vids_to_add), isbridge)
        except Exception, e:
                self.log_error('%s: failed to set vid `%s` (%s)'
                               %(bportifaceobj.name, str(vids_to_add),
                                 str(e)), bportifaceobj, raise_error=False)

        try:
            if pvid_to_add and pvid_to_add != running_pvid:
                self.ipcmd.bridge_port_pvid_add(bportifaceobj.name,
                                                pvid_to_add)
        except Exception, e:
                self.log_error('%s: failed to set pvid `%s` (%s)'
                               %(bportifaceobj.name, pvid_to_add, str(e)),
                               bportifaceobj)

    def _apply_bridge_vlan_aware_port_settings_all(self, bportifaceobj,
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

        if allow_untagged == 'yes':
            if pvids:
                pvid_final = pvids[0]
            elif bridge_pvid:
                pvid_final = bridge_pvid
            else:
                pvid_final = '1'
        else:
            pvid_final = None

        self._apply_bridge_vids_and_pvid(bportifaceobj, vids_final,
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
                bridgeFlags.PORT_PROCESSED_OVERRIDE):
            port_processed_override = True
        else:
            port_processed_override = False

        bridgeports = self._get_bridge_port_list(ifaceobj)
        if not bridgeports:
           self.logger.debug('%s: cannot find bridgeports' %ifaceobj.name)
           return
        self.ipcmd.batch_start()
        for bport in bridgeports:
            # Use the brctlcmd bulk set method: first build a dictionary
            # and then call set
            if not self.ipcmd.bridge_port_exists(ifaceobj.name, bport):
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
                     bridgeFlags.PORT_PROCESSED)):
                    continue
                try:
                    # Add attributes specific to the vlan aware bridge
                    if bridge_vlan_aware:
                        self._apply_bridge_vlan_aware_port_settings_all(
                                bportifaceobj, bridge_vids, bridge_pvid)
                    elif self.warn_on_untagged_bridge_absence:
                        self._check_untagged_bridge(ifaceobj.name, bportifaceobj, ifaceobj_getfunc)
                except exceptions.ReservedVlanException as e:
                    raise e
                except Exception, e:
                    err = True
                    self.logger.warn('%s: %s' %(ifaceobj.name, str(e)))
                    pass
        self.ipcmd.bridge_batch_commit()
        if err:
           raise Exception('%s: errors applying port settings' %ifaceobj.name)

    def _check_untagged_bridge(self, bridgename, bridgeportifaceobj, ifaceobj_getfunc):
        if bridgeportifaceobj.link_kind & ifaceLinkKind.VLAN:
            lower_ifaceobj_list = ifaceobj_getfunc(bridgeportifaceobj.lowerifaces[0])
            if lower_ifaceobj_list and lower_ifaceobj_list[0] and \
                    not lower_ifaceobj_list[0].link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT:
                self.logger.warn('%s: untagged bridge not found. Please configure a bridge with untagged bridge ports to avoid Spanning Tree Interoperability issue.' % bridgename)
                self.warn_on_untagged_bridge_absence = False

    def bridge_port_get_bridge_name(self, ifaceobj):
        bridgename = self.ipcmd.bridge_port_get_bridge_name(ifaceobj.name)
        if not bridgename:
            # bridge port is not enslaved to a bridge we need to find
            # the bridge in it's upper ifaces then enslave it
            for u in ifaceobj.upperifaces:
                if self.ipcmd.is_bridge(u):
                    return True, u
            return False, None
        # return should_enslave port, bridgename
        return False, bridgename

    def up_bridge_port_vlan_aware_bridge(self, ifaceobj, ifaceobj_getfunc, bridge_name, should_enslave_port):
        if should_enslave_port:
            netlink.link_set_master(ifaceobj.name, bridge_name)
            self.handle_ipv6([ifaceobj.name], '1')

        bridge_vids = self._get_bridge_vids(bridge_name, ifaceobj_getfunc)
        bridge_pvid = self._get_bridge_pvid(bridge_name, ifaceobj_getfunc)
        try:
            self._apply_bridge_vlan_aware_port_settings_all(ifaceobj, bridge_vids, bridge_pvid)
        except Exception as e:
            self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj)
            return

    def up_bridge_port(self, ifaceobj, ifaceobj_getfunc):
        should_enslave_port, bridge_name = self.bridge_port_get_bridge_name(ifaceobj)

        if not bridge_name:
            # bridge doesn't exist
            return

        vlan_aware_bridge = self.ipcmd.bridge_is_vlan_aware(bridge_name)
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

        ifaceobj.module_flags[self.name] = ifaceobj.module_flags.setdefault(self.name, 0) | bridgeFlags.PORT_PROCESSED

    def up_check_bridge_vlan_aware(self, ifaceobj, ifaceobj_getfunc, link_exists):
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE:
            if not self.check_bridge_vlan_aware_port(ifaceobj, ifaceobj_getfunc):
                return False
            if link_exists:
                ifaceobj.module_flags[self.name] = ifaceobj.module_flags.setdefault(self.name, 0) | bridgeFlags.PORT_PROCESSED_OVERRIDE
            return True
        return False

    @staticmethod
    def parse_interface_list_value(user_config):
        config = dict()
        for entry in user_config.split():
            ifname, value = entry.split('=')
            config[ifname] = value
        return config

    def sync_bridge_learning_to_vxlan_brport(self, bridge_name, bridge_vlan_aware, brport_ifaceobj,
                                             brport_name, brport_ifla_info_slave_data, brport_learning):
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

        brport_vxlan_learning_config = brport_ifaceobj.get_attr_value_first('vxlan-learning')
        # if the user explicitly defined vxlan-learning we need to honor his config
        # and not sync vxlan-learning with bridge-learning

        brport_vxlan_learning = self.ipcmd.get_vxlandev_learning(brport_name)

        # if BRIDGE_LEARNING is in the desired configuration
        # and differs from the running vxlan configuration
        if brport_learning is not None and brport_learning != brport_vxlan_learning and not brport_vxlan_learning_config:
            kind = 'vxlan'
            ifla_info_data = {Link.IFLA_VXLAN_LEARNING: brport_learning}
            self.logger.info('%s: %s: vxlan learning and bridge learning out of sync: set %s'
                             % (bridge_name, brport_name, brport_learning))

        elif brport_learning is None and bridge_vlan_aware:
            # is bridge-learning is not configured but the bridge is vlan-aware

            running_value = self.ipcmd.get_brport_learning_bool(brport_name)
            default_value = utils.get_boolean_from_string(self.get_mod_subattr('bridge-learning', 'default'))

            if default_value != running_value:
                brport_ifla_info_slave_data[Link.IFLA_BRPORT_LEARNING] = default_value

                if not brport_vxlan_learning_config:
                    kind = 'vxlan'
                    ifla_info_data = {Link.IFLA_VXLAN_LEARNING: default_value}
                    self.logger.info('%s: %s: reset brport learning to %s and sync vxlan learning'
                                     % (bridge_name, brport_name, default_value))

        # if kind and ifla_info_data are set they will be added to the
        # netlink request on the VXLAN brport, to sync IFLA_VXLAN_LEARNING
        return kind, ifla_info_data

    def check_vxlan_brport_arp_suppress(self, ifaceobj, bridge_vlan_aware, brport_ifaceobj, brport_name, user_config):
        if user_config:
            if self.arp_nd_suppress_only_on_vxlan and not brport_ifaceobj.link_kind & ifaceLinkKind.VXLAN:
                self.logger.warning('%s: %s: \'bridge-arp-nd-suppress\' '
                                    'is not supported on a non-vxlan port'
                                    % (ifaceobj.name, brport_name))
                raise Exception()
        elif (bridge_vlan_aware and
                  (not self.arp_nd_suppress_only_on_vxlan or
                       (self.arp_nd_suppress_only_on_vxlan and
                                brport_ifaceobj.link_kind & ifaceLinkKind.VXLAN))):
            return self.get_mod_subattr('bridge-arp-nd-suppress', 'default')
        return None

    def up_apply_brports_attributes(self, ifaceobj, ifaceobj_getfunc, bridge_vlan_aware, target_ports=[], newly_enslaved_ports=[]):
        ifname = ifaceobj.name

        try:
            brports_ifla_info_slave_data    = dict()
            brport_ifaceobj_dict            = dict()

            running_brports = self.brctlcmd.get_bridge_ports(ifname)

            if target_ports:
                new_targets = []
                for brport_name in target_ports:
                    if brport_name not in running_brports:
                        self.logger.info('%s: not enslaved to bridge %s: ignored for now' % (brport_name, ifname))
                    else:
                        new_targets.append(brport_name)
                running_brports = new_targets

            self.logger.info('%s: applying bridge port configuration: %s' % (ifname, running_brports))

            # If target_ports is specified we want to configure only this
            # sub-list of port we need to check if these ports are already
            # enslaved, if not they will be ignored.
            # If target_ports is not populated we will apply the brport
            # attributes on all running brport.

            for port in running_brports:
                brport_list = ifaceobj_getfunc(port)
                if brport_list:
                    brport_ifaceobj_dict[port] = brport_list[0]
                    brports_ifla_info_slave_data[port] = dict()

            bridge_ports_learning = {}

            # we iterate through all IFLA_BRPORT supported attributes
            for attr_name, nl_attr in self._ifla_brport_attributes_map:
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

                if br_config:
                    #if bridge_vlan_aware:
                    #    self.logger.info('%s: is a vlan-aware bridge, "%s %s" '
                    #                     'should be configured under the ports'
                    #                     % (ifname, attr_name, br_config))

                    # convert the <interface-yes-no-0-1-list> and <interface-range-list> value to subdict
                    # brport_name: { attr: value }
                    # example:
                    #   bridge-portprios swp1=5 swp2=32
                    # swp1: { bridge-portprios: 5 } swp2: { bridge-portprios: 32}
                    if '=' in br_config:
                        try:
                            br_config = self.parse_interface_list_value(br_config)
                        except:
                            self.log_error('error while parsing \'%s %s\'' % (attr_name, br_config))
                            continue

                for brport_ifaceobj in brport_ifaceobj_dict.values():
                    brport_config = brport_ifaceobj.get_attr_value_first(attr_name)
                    brport_name = brport_ifaceobj.name

                    if not ifupdownflags.flags.PERFMODE and brport_name not in newly_enslaved_ports:
                        # if the port has just been enslaved, info_slave_data is not cached yet
                        cached_value = self.ipcmd.cache_get_info_slave([brport_name, 'info_slave_data', nl_attr])
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
                    if nl_attr == Link.IFLA_BRPORT_ARP_SUPPRESS:
                        try:
                            arp_suppress = self.check_vxlan_brport_arp_suppress(ifaceobj,
                                                                                bridge_vlan_aware,
                                                                                brport_ifaceobj,
                                                                                brport_name,
                                                                                user_config)
                            if arp_suppress:
                                user_config = arp_suppress
                        except:
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
                            bridge_ports_learning[brport_name] = user_config_nl

                    elif cached_value is not None:
                        # no config found, do we need to reset to default?
                        default = self.get_attr_default_value(attr_name)
                        if default:
                            default_netlink = translate_func(default)

                            if (nl_attr == Link.IFLA_BRPORT_LEARNING
                                and not ifupdownflags.flags.PERFMODE
                                    and brport_name not in newly_enslaved_ports):
                                try:
                                    if self.ipcmd.get_brport_peer_link(brport_name):
                                        if default_netlink != cached_value:
                                            self.logger.debug('%s: %s: bridge port peerlink: ignoring bridge-learning'
                                                              % (ifname, brport_name))
                                        continue
                                    bridge_ports_learning[brport_name] = default_netlink
                                except Exception as e:
                                    self.logger.debug('%s: %s: peerlink check: %s' % (ifname, brport_name, str(e)))

                            if default_netlink != cached_value:
                                self.logger.info('%s: %s: %s: no configuration detected, resetting to default %s'
                                                 % (ifname, brport_name, attr_name, default))
                                self.logger.debug('(cache %s)' % cached_value)
                                brports_ifla_info_slave_data[brport_name][nl_attr] = default_netlink

            # applying bridge port configuration via netlink
            for brport_name, brport_ifla_info_slave_data in brports_ifla_info_slave_data.items():

                brport_ifaceobj = brport_ifaceobj_dict.get(brport_name)
                if (brport_ifaceobj
                    and brport_ifaceobj.link_kind & ifaceLinkKind.VXLAN
                    and brport_ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT):
                    # if the brport is a VXLAN, we might need to sync the VXLAN learning with the brport_learning val
                    # we use the same netlink request, by specfying kind=vxlan and ifla_info_data={vxlan_learning=0/1}
                    kind, ifla_info_data = self.sync_bridge_learning_to_vxlan_brport(ifaceobj.name,
                                                                                     bridge_vlan_aware,
                                                                                     brport_ifaceobj,
                                                                                     brport_name,
                                                                                     brport_ifla_info_slave_data,
                                                                                     bridge_ports_learning.get(brport_name))
                else:
                    kind = None
                    ifla_info_data = {}

                if brport_ifla_info_slave_data or ifla_info_data:
                    try:
                        netlink.link_add_set(ifname=brport_name,
                                             kind=kind,
                                             ifla_info_data=ifla_info_data,
                                             slave_kind='bridge',
                                             ifla_info_slave_data=brport_ifla_info_slave_data)
                    except Exception as e:
                        self.logger.warning('%s: %s: %s' % (ifname, brport_name, str(e)))

            self._set_bridge_vidinfo_compat(ifaceobj)
            self._set_bridge_mcqv4src_compat(ifaceobj)
            self._process_bridge_maxwait(ifaceobj, self._get_bridge_port_list(ifaceobj))

        except Exception as e:
            self.log_error(str(e), ifaceobj)

    def ifla_brport_group_fwd_mask(self, ifname, brport_name, brports_ifla_info_slave_data, user_config, cached_ifla_brport_group_fwd_mask):
        """
            Support for IFLA_BRPORT_GROUP_FWD_MASK and IFLA_BRPORT_GROUP_FWD_MASKHI
            Since this is the only ifupdown2 attribute dealing with more than 1 netlink
            field we need to have special handling for that.
        """
        ifla_brport_group_fwd_mask = 0
        ifla_brport_group_fwd_maskhi = 0
        if user_config:
            for group in re.split(',|\s*', user_config):
                if not group:
                    continue

                callback = self.l2protocol_tunnel_callback.get(group)

                if not callable(callback):
                    self.logger.warning('%s: %s: bridge-l2protocol-tunnel ignoring invalid parameter \'%s\'' % (ifname, brport_name, group))
                else:
                    ifla_brport_group_fwd_mask, ifla_brport_group_fwd_maskhi = callback(ifla_brport_group_fwd_mask, ifla_brport_group_fwd_maskhi)

        # cached_ifla_brport_group_fwd_mask is given as parameter because it was already pulled out from the cache in the functio above
        cached_ifla_brport_group_fwd_maskhi = self.ipcmd.cache_get_info_slave([brport_name, 'info_slave_data', Link.IFLA_BRPORT_GROUP_FWD_MASKHI])

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

    def up_bridge(self, ifaceobj, ifaceobj_getfunc):
        ifname = ifaceobj.name

        if ifupdownflags.flags.PERFMODE:
            link_just_created = True
            link_exists = False
        else:
            link_exists = self.ipcmd.link_exists(ifaceobj.name)
            link_just_created = not link_exists

        if not link_exists:
            netlink.link_add_bridge(ifname)
        else:
            self.logger.info('%s: bridge already exists' % ifname)

        bridge_vlan_aware = self.up_check_bridge_vlan_aware(ifaceobj, ifaceobj_getfunc, not link_just_created)

        self.up_apply_bridge_settings(ifaceobj, link_just_created, bridge_vlan_aware)

        try:
            newly_enslaved_ports = self._add_ports(ifaceobj, ifaceobj_getfunc)
            self.up_apply_brports_attributes(ifaceobj, ifaceobj_getfunc, bridge_vlan_aware,
                                             newly_enslaved_ports=newly_enslaved_ports)
        except Exception as e:
            self.logger.warning('%s: apply bridge ports settings: %s' % (ifname, str(e)))

        running_ports = ''
        try:
            running_ports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
            if not running_ports:
                return
            self.handle_ipv6([], '1', ifaceobj=ifaceobj)
            self._apply_bridge_port_settings_all(ifaceobj,
                                                 ifaceobj_getfunc=ifaceobj_getfunc,
                                                 bridge_vlan_aware=bridge_vlan_aware)
        except exceptions.ReservedVlanException as e:
            raise e
        except Exception as e:
            self.logger.warning('%s: apply bridge settings: %s' % (ifname, str(e)))
        finally:
            if ifaceobj.link_type != ifaceLinkType.LINK_NA:
                for p in running_ports:
                    if (ifaceobj_getfunc(p)[0].link_privflags &
                            ifaceLinkPrivFlags.KEEP_LINK_DOWN):
                        netlink.link_set_updown(p, "down")
                        continue
                    try:
                        netlink.link_set_updown(p, "up")
                    except Exception, e:
                        self.logger.debug('%s: %s: link set up (%s)'
                                          % (ifaceobj.name, p, str(e)))
                        pass

        try:
            self._up_bridge_mac(ifaceobj, ifaceobj_getfunc)
        except Exception as e:
            self.logger.warning('%s: setting bridge mac address: %s' % (ifaceobj.name, str(e)))

    def _get_bridge_mac(self, ifaceobj, ifname, ifaceobj_getfunc):
        if self.bridge_mac_iface and self.bridge_mac_iface[0] and self.bridge_mac_iface[1]:
            return self.bridge_mac_iface

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

                if not iface_mac and not self.ipcmd.link_exists(bridge_mac_intf):
                    continue

                if not iface_mac:
                    iface_mac = self.ipcmd.cache_get('link', [bridge_mac_intf, 'hwaddress'])
                    # if hwaddress attribute is not configured we use the running mac addr

                self.bridge_mac_iface = (bridge_mac_intf, iface_mac)
                return self.bridge_mac_iface
        elif self.bridge_set_static_mac_from_port:
            # no policy was provided, we need to get the first physdev or bond ports
            # and use its hwaddress to set the bridge mac
            for port in self._get_bridge_port_list_user_ordered(ifaceobj) or []:
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
                            iface_mac = self.ipcmd.link_get_hwaddress(port)

                        if iface_mac:
                            self.bridge_mac_iface = (port, iface_mac)
                            return self.bridge_mac_iface

        return None, None

    def _add_bridge_mac_to_fdb(self, ifaceobj, bridge_mac):
        if not ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE and bridge_mac and ifaceobj.get_attr_value('address'):
            self.ipcmd.bridge_fdb_add(ifaceobj.name, bridge_mac, vlan=None, bridge=True, remote=None)

    def _up_bridge_mac(self, ifaceobj, ifaceobj_getfunc):
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
        mac_intf, bridge_mac = self._get_bridge_mac(ifaceobj, ifname, ifaceobj_getfunc)
        self.logger.debug("%s: _get_bridge_mac returned (%s, %s)"
                          %(ifname, mac_intf, bridge_mac))

        if bridge_mac:
            # if an interface is configured with the following attribute:
            # hwaddress 08:00:27:42:42:4
            # the cache_check won't match because nlmanager return "08:00:27:42:42:04"
            # from the kernel. The only way to counter that is to convert all mac to int
            # and compare the ints, it will increase perfs and be safer.
            cached_value = self.ipcmd.cache_get('link', [ifname, 'hwaddress'])
            self.logger.debug('%s: cached hwaddress value: %s' % (ifname, cached_value))
            if cached_value and cached_value == bridge_mac:
                # the bridge mac is already set to the bridge_mac_intf's mac
                return

            self.logger.info('%s: setting bridge mac to port %s mac' % (ifname, mac_intf))
            try:
                self.ipcmd.link_set(ifname, 'address', value=bridge_mac, force=True)
            except Exception as e:
                self.logger.info('%s: %s' % (ifname, str(e)))
                # log info this error because the user didn't explicitly configured this
        else:
            self._add_bridge_mac_to_fdb(ifaceobj, self.ipcmd.link_get_hwaddress(ifname))

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT:
            self.up_bridge_port(ifaceobj, ifaceobj_getfunc)

        elif ifaceobj.link_kind & ifaceLinkKind.BRIDGE:
            self.up_bridge(ifaceobj, ifaceobj_getfunc)

        else:
            bridge_attributes = self._modinfo.get('attrs', {}).keys()

            for ifaceobj_config_attr in ifaceobj.config.keys():
                if ifaceobj_config_attr in bridge_attributes:
                    self.logger.warning('%s: invalid use of bridge attribute (%s) on non-bridge stanza'
                                        % (ifaceobj.name, ifaceobj_config_attr))

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        if not self._is_bridge(ifaceobj):
            return
        ifname = ifaceobj.name
        if not self.ipcmd.link_exists(ifname):
            return
        try:
            running_ports = self.brctlcmd.get_bridge_ports(ifname)
            if running_ports:
                self.handle_ipv6(running_ports, '0')
                if ifaceobj.link_type != ifaceLinkType.LINK_NA:
                    map(lambda p: netlink.link_set_updown(p, 'down'), running_ports)
        except Exception as e:
            self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj)
        try:
            netlink.link_del(ifname)
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
                    running_vids = self._get_runing_vids(p)
                    if running_vids:
                        running_bridge_port_vids += ' %s=%s' %(p,
                                                      ','.join(running_vids))
                except Exception:
                    pass
            running_attrs['bridge-port-vids'] = running_bridge_port_vids

            running_bridge_port_pvid = ''
            for p in ports:
                try:
                    running_pvid = self._get_runing_pvid(p)
                    if running_pvid:
                        running_bridge_port_pvid += ' %s=%s' %(p,
                                                        running_pvid)
                except Exception:
                    pass
            running_attrs['bridge-port-pvids'] = running_bridge_port_pvid

        running_bridge_vids = self.ipcmd.bridge_vlan_get_vids(ifaceobjrunning.name)
        if running_bridge_vids:
            running_attrs['bridge-vids'] = ','.join(self._compress_into_ranges(running_bridge_vids))
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
        running_mcqv4src = self.brctlcmd.bridge_get_mcqv4src(ifaceobjrunning.name)
        mcqs = ['%s=%s' %(v, i) for v, i in running_mcqv4src.items()]
        mcqs.sort()
        mcq = ' '.join(mcqs)
        return mcq

    def _query_running_attrs(self, ifaceobjrunning, ifaceobj_getfunc,
                             bridge_vlan_aware=False):
        bridgeattrdict = {}
        userspace_stp = 0
        ports = None
        skip_kernel_stp_attrs = 0

        try:
            if self.systcl_get_net_bridge_stp_user_space() == '1':
                userspace_stp = 1
        except Exception as e:
            self.logger.info('%s: %s' % (ifaceobjrunning.name, str(e)))

        tmpbridgeattrdict = self.brctlcmd.get_bridge_attrs(ifaceobjrunning.name)
        if not tmpbridgeattrdict:
            self.logger.warn('%s: unable to get bridge attrs'
                    %ifaceobjrunning.name)
            return bridgeattrdict

        # Fill bridge_ports and bridge stp attributes first
        ports = tmpbridgeattrdict.get('ports')
        if ports:
            bridgeattrdict['bridge-ports'] = [' '.join(ports.keys())]
        stp = tmpbridgeattrdict.get('stp', 'no')
        if stp != self.get_mod_subattr('bridge-stp', 'default'):
            bridgeattrdict['bridge-stp'] = [stp]

        if  stp == 'yes' and userspace_stp:
            skip_kernel_stp_attrs = 1

        vlan_stats = utils.get_onff_from_onezero(
                            tmpbridgeattrdict.get('vlan-stats', None))
        if (vlan_stats and
            vlan_stats != self.get_mod_subattr('bridge-vlan-stats', 'default')):
            bridgeattrdict['bridge-vlan-stats'] = [vlan_stats]

        bool2str = {'0': 'no', '1': 'yes'}
        # pick all other attributes
        for k,v in tmpbridgeattrdict.items():
            if not v:
                continue
            if k == 'ports' or k == 'stp':
                continue

            if skip_kernel_stp_attrs and k[:2] != 'mc':
                # only include igmp attributes if kernel stp is off
                continue
            attrname = 'bridge-' + k
            mod_default = self.get_mod_subattr(attrname, 'default')
            if v != mod_default:
                # convert '0|1' running values to 'no|yes'
                if v in bool2str.keys() and bool2str[v] == mod_default:
                    continue
                bridgeattrdict[attrname] = [v]

        if bridge_vlan_aware:
            if not ports:
                ports = {}
            bridgevidinfo = self._query_running_vidinfo(ifaceobjrunning,
                                                        ifaceobj_getfunc,
                                                        ports.keys())
        else:
            bridgevidinfo = self._query_running_vidinfo_compat(ifaceobjrunning,
                                                               ports)
        if bridgevidinfo:
           bridgeattrdict.update({k : [v] for k, v in bridgevidinfo.items()
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
                          'bridge-arp-nd-suppress' : '',
                         }
            for p, v in ports.items():
                v = self.brctlcmd.bridge_get_pathcost(ifaceobjrunning.name, p)
                if v and v != self.get_mod_subattr('bridge-pathcosts',
                                                   'default'):
                    portconfig['bridge-pathcosts'] += ' %s=%s' %(p, v)

                v = self.brctlcmd.bridge_get_portprio(ifaceobjrunning.name, p)
                if v and v != self.get_mod_subattr('bridge-portprios',
                                                   'default'):
                    portconfig['bridge-portprios'] += ' %s=%s' %(p, v)

                v = utils.get_onff_from_onezero(
                        self.brctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                                                          p, 'learning'))
                if (v and
                    v != self.get_mod_subattr('bridge-learning', 'default')):
                    portconfig['bridge-learning'] += ' %s=%s' %(p, v)

                v = utils.get_onff_from_onezero(
                        self.brctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                                                          p, 'unicast-flood'))
                if (v and
                    v != self.get_mod_subattr('bridge-unicast-flood',
                                              'default')):
                    portconfig['bridge-unicast-flood'] += ' %s=%s' %(p, v)

                v = utils.get_onff_from_onezero(
                        self.brctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                                                          p, 'multicast-flood'))
                if (v and
                    v != self.get_mod_subattr('bridge-multicast-flood',
                                              'default')):
                    portconfig['bridge-multicast-flood'] += ' %s=%s' %(p, v)

                v = utils.get_onff_from_onezero(
                        self.brctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                                                          p, 'arp-nd-suppress'))
                if (v and
                    v != self.get_mod_subattr('bridge-arp-nd-suppress',
                                              'default')):
                    portconfig['bridge-arp-nd-suppress'] += ' %s=%s' %(p, v)

            bridgeattrdict.update({k : [v] for k, v in portconfig.items()
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

    def _query_check_bridge_vidinfo(self, ifaceobj, ifaceobjcurr):
        err = 0
        attrval = ifaceobj.get_attr_value_first('bridge-port-vids')
        if attrval:
            running_bridge_port_vids = ''
            portlist = self.parse_port_list(ifaceobj.name, attrval)
            if not portlist:
                self.log_warn('%s: could not parse \'bridge-port-vids %s\''
                          %(ifaceobj.name, attrval))
                return
            err = 0
            for p in portlist:
                try:
                    (port, val) = p.split('=')
                    vids = val.split(',')
                    running_vids = self.ipcmd.bridge_vlan_get_vids(port)
                    if running_vids:
                        if not self._compare_vids(vids, running_vids):
                            err += 1
                            running_bridge_port_vids += ' %s=%s' %(port,
                                                      ','.join(running_vids))
                        else:
                            running_bridge_port_vids += ' %s' %p
                    else:
                        err += 1
                except Exception, e:
                    self.log_warn('%s: failure checking vid %s (%s)'
                        %(ifaceobj.name, p, str(e)))
            if err:
                ifaceobjcurr.update_config_with_status('bridge-port-vids',
                                                 running_bridge_port_vids, 1)
            else:
                ifaceobjcurr.update_config_with_status('bridge-port-vids',
                                                 attrval, 0)

        attrval = ifaceobj.get_attr_value_first('bridge-port-pvids')
        if attrval:
            portlist = self.parse_port_list(ifaceobj.name, attrval)
            if not portlist:
                self.log_warn('%s: could not parse \'bridge-port-pvids %s\''
                              %(ifaceobj.name, attrval))
                return
            running_bridge_port_pvids = ''
            err = 0
            for p in portlist:
                try:
                    (port, pvid) = p.split('=')
                    running_pvid = self.ipcmd.bridge_vlan_get_vids(port)
                    if running_pvid and running_pvid == pvid:
                        running_bridge_port_pvids += ' %s' %p
                    else:
                        err += 1
                        running_bridge_port_pvids += ' %s=%s' %(port,
                                                            running_pvid)
                except Exception, e:
                    self.log_warn('%s: failure checking pvid %s (%s)'
                            %(ifaceobj.name, pvid, str(e)))
            if err:
                ifaceobjcurr.update_config_with_status('bridge-port-pvids',
                                                 running_bridge_port_pvids, 1)
            else:
                ifaceobjcurr.update_config_with_status('bridge-port-pvids',
                                                 running_bridge_port_pvids, 0)

        vids = self.get_ifaceobj_bridge_vids(ifaceobj)
        if vids[1]:
            ifaceobjcurr.update_config_with_status(vids[0], vids[1], -1)

    def _query_check_snooping_wdefault(self, ifaceobj):
        if (ifupdownflags.flags.WITHDEFAULTS
            and not self._vxlan_bridge_default_igmp_snooping
                and ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VXLAN):
            ifaceobj.replace_config('bridge-mcsnoop', 'no')

    def _query_check_bridge(self, ifaceobj, ifaceobjcurr,
                            ifaceobj_getfunc=None):
        if not self._is_bridge(ifaceobj):
            return
        if not self.brctlcmd.bridge_exists(ifaceobj.name):
            self.logger.info('%s: bridge: does not exist' %(ifaceobj.name))
            return

        self._query_check_snooping_wdefault(ifaceobj)

        ifaceattrs = self.dict_key_subset(ifaceobj.config,
                                          self.get_mod_attrs())
        #Add default attributes if --with-defaults is set
        if ifupdownflags.flags.WITHDEFAULTS and 'bridge-stp' not in ifaceattrs:
            ifaceattrs.append('bridge-stp')
        if not ifaceattrs:
            return
        try:
            runningattrs = self.brctlcmd.get_bridge_attrs(ifaceobj.name)
            if not runningattrs:
               self.logger.debug('%s: bridge: unable to get bridge attrs'
                                 %ifaceobj.name)
               runningattrs = {}
        except Exception, e:
            self.logger.warn(str(e))
            runningattrs = {}

        self._query_check_support_yesno_attrs(runningattrs, ifaceobj)

        filterattrs = ['bridge-vids', 'bridge-trunk', 'bridge-port-vids',
                       'bridge-port-pvids']

        diff = Set(ifaceattrs).difference(filterattrs)

        if 'bridge-l2protocol-tunnel' in diff:
            diff.remove('bridge-l2protocol-tunnel')
            # bridge-l2protocol-tunnel requires separate handling

        if 'bridge-ports' in diff:
            self.query_check_bridge_ports(ifaceobj, ifaceobjcurr, runningattrs.get('ports', {}).keys(), ifaceobj_getfunc)
            diff.remove('bridge-ports')

        for k in diff:
            # get the corresponding ifaceobj attr
            v = ifaceobj.get_attr_value_first(k)
            if not v:
                if ifupdownflags.flags.WITHDEFAULTS and k == 'bridge-stp':
                    v = 'on' if self.default_stp_on else 'off'
                else:
                    continue
            rv = runningattrs.get(k[7:])
            if k == 'bridge-mcqv4src':
               continue
            if k == 'bridge-maxwait' or k == 'bridge-waitport':
                ifaceobjcurr.update_config_with_status(k, v, 0)
                continue
            if k == 'bridge-vlan-aware':
                rv = self.ipcmd.bridge_is_vlan_aware(ifaceobj.name)
                if (rv and v == 'yes') or (not rv and v == 'no'):
                    ifaceobjcurr.update_config_with_status('bridge-vlan-aware',
                               v, 0)
                else:
                    ifaceobjcurr.update_config_with_status('bridge-vlan-aware',
                               v, 1)
            elif k == 'bridge-stp':
               # special case stp compare because it may
               # contain more than one valid values
               stp_on_vals = ['on', 'yes']
               stp_off_vals = ['off', 'no']
               if ((v in stp_on_vals and rv in stp_on_vals) or
                   (v in stp_off_vals and rv in stp_off_vals)):
                    ifaceobjcurr.update_config_with_status('bridge-stp',
                               rv, 0)
               else:
                    ifaceobjcurr.update_config_with_status('bridge-stp',
                               rv, 1)
            elif k in ['bridge-pathcosts',
                       'bridge-portprios',
                       'bridge-portmcrouter',
                       'bridge-portmcfl',
                       'bridge-learning',
                       'bridge-unicast-flood',
                       'bridge-multicast-flood',
                       'bridge-arp-nd-suppress',
                      ]:
               if k == 'bridge-arp-nd-suppress':
                  brctlcmdattrname = k[7:]
               else:
                  brctlcmdattrname = k[7:].rstrip('s')
               # for port attributes, the attributes are in a list
               # <portname>=<portattrvalue>
               status = 0
               currstr = ''
               vlist = self.parse_port_list(ifaceobj.name, v)
               if not vlist:
                  continue
               for vlistitem in vlist:
                   try:
                      (p, v) = vlistitem.split('=')
                      if k in ['bridge-learning',
                               'bridge-unicast-flood',
                               'bridge-multicast-flood',
                               'bridge-arp-nd-suppress',
                              ]:
                         currv = utils.get_onoff_bool(
                                    self.brctlcmd.get_bridgeport_attr(
                                         ifaceobj.name, p,
                                         brctlcmdattrname))
                      else:
                         currv = self.brctlcmd.get_bridgeport_attr(
                                         ifaceobj.name, p,
                                         brctlcmdattrname)
                      if currv:
                          currstr += ' %s=%s' %(p, currv)
                      else:
                          currstr += ' %s=%s' %(p, 'None')

                      if k == 'bridge-portmcrouter':
                          if self._ifla_brport_multicast_router_dict_to_int.get(v) != int(currv):
                              status = 1
                      elif currv != v:
                          status = 1
                   except Exception, e:
                      self.log_warn(str(e))
                   pass
               ifaceobjcurr.update_config_with_status(k, currstr, status)
            elif k == 'bridge-vlan-stats' or k == 'bridge-mcstats':
                rv = utils.get_onff_from_onezero(rv)
                if v != rv:
                    ifaceobjcurr.update_config_with_status(k, rv, 1)
                else:
                    ifaceobjcurr.update_config_with_status(k, rv, 0)
            elif not rv:
               if k == 'bridge-pvid' or k == 'bridge-vids' or k == 'bridge-trunk' or k == 'bridge-allow-untagged':
                   # bridge-pvid and bridge-vids on a bridge does
                   # not correspond directly to a running config
                   # on the bridge. They correspond to default
                   # values for the bridge ports. And they are
                   # already checked against running config of the
                   # bridge port and reported against a bridge port.
                   # So, ignore these attributes under the bridge.
                   # Use '2' for ignore today. XXX: '2' will be
                   # mapped to a defined value in subsequent patches.
                   ifaceobjcurr.update_config_with_status(k, v, 2)
               else:
                   ifaceobjcurr.update_config_with_status(k, 'notfound', 1)
               continue
            elif v.upper() != rv.upper():
               ifaceobjcurr.update_config_with_status(k, rv, 1)
            else:
               ifaceobjcurr.update_config_with_status(k, rv, 0)

        self._query_check_bridge_vidinfo(ifaceobj, ifaceobjcurr)

        self._query_check_mcqv4src(ifaceobj, ifaceobjcurr)
        self._query_check_l2protocol_tunnel_on_bridge(ifaceobj, ifaceobjcurr, runningattrs)

    def query_check_bridge_ports(self, ifaceobj, ifaceobjcurr, running_port_list, ifaceobj_getfunc):
        bridge_all_ports = []
        for obj in ifaceobj_getfunc(ifaceobj.name) or []:
            bridge_all_ports.extend(self._get_bridge_port_list(obj) or [])

        if not running_port_list and not bridge_all_ports:
            return

        ports_list_status = 0 if not set(running_port_list).symmetric_difference(bridge_all_ports) else 1

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
        except:
            port_list = running_port_list
        ifaceobjcurr.update_config_with_status('bridge-ports', (' '.join(port_list) if port_list else ''), ports_list_status)

    def get_ifaceobj_bridge_vids(self, ifaceobj):
        vids = ('bridge-vids', ifaceobj.get_attr_value_first('bridge-vids'))
        if not vids[1]:
            vids = ('bridge-trunk', ifaceobj.get_attr_value_first('bridge-trunk'))
        return vids

    def get_ifaceobj_bridge_vids_value(self, ifaceobj):
        return self.get_ifaceobj_bridge_vids(ifaceobj)[1]

    def _get_bridge_vids(self, bridgename, ifaceobj_getfunc):
        ifaceobjs = ifaceobj_getfunc(bridgename)
        for ifaceobj in ifaceobjs:
            vids = self.get_ifaceobj_bridge_vids_value(ifaceobj)
            if vids: return re.split(r'[\s\t,]\s*', vids)
        return None

    def _get_bridge_pvid(self, bridgename, ifaceobj_getfunc):
        ifaceobjs = ifaceobj_getfunc(bridgename)
        pvid = None
        for ifaceobj in ifaceobjs:
            pvid = ifaceobj.get_attr_value_first('bridge-pvid')
            if pvid:
                break
        return pvid

    def _get_bridge_name(self, ifaceobj):
        return self.ipcmd.bridge_port_get_bridge_name(ifaceobj.name)

    def _query_check_bridge_port_vidinfo(self, ifaceobj, ifaceobjcurr,
                                         ifaceobj_getfunc, bridgename):
        attr_name = 'bridge-access'
        vid = ifaceobj.get_attr_value_first(attr_name)
        if vid:
            (running_vids, running_pvid) = self._get_running_vids_n_pvid_str(
                                                        ifaceobj.name)
            if (not running_pvid or running_pvid != vid or
                (running_vids and running_vids[0] != vid)):
               ifaceobjcurr.update_config_with_status(attr_name,
                                running_pvid, 1)
            else:
               ifaceobjcurr.update_config_with_status(attr_name, vid, 0)
            return

        (running_vids, running_pvid) = self._get_running_vids_n_pvid_str(
                                                        ifaceobj.name)
        attr_name = 'bridge-pvid'
        pvid = ifaceobj.get_attr_value_first('bridge-pvid')
        if pvid:
            if running_pvid and running_pvid == pvid:
                ifaceobjcurr.update_config_with_status(attr_name,
                                                       running_pvid, 0)
            else:
                ifaceobjcurr.update_config_with_status(attr_name,
                                                       running_pvid, 1)
        elif (not (ifaceobj.flags & iface.HAS_SIBLINGS) or
              ((ifaceobj.flags & iface.HAS_SIBLINGS) and
               (ifaceobj.flags & iface.OLDEST_SIBLING))):
            # if the interface has multiple iface sections,
            # we check the below only for the oldest sibling
            # or the last iface section
            pvid = self._get_bridge_pvid(bridgename, ifaceobj_getfunc)
            if pvid:
                if not running_pvid or running_pvid != pvid:
                    ifaceobjcurr.status = ifaceStatus.ERROR
                    ifaceobjcurr.status_str = 'bridge pvid error'
            elif not running_pvid or running_pvid != '1':
                ifaceobjcurr.status = ifaceStatus.ERROR
                ifaceobjcurr.status_str = 'bridge pvid error'

        attr_name, vids = self.get_ifaceobj_bridge_vids(ifaceobj)
        if vids:
           vids = re.split(r'[\s\t]\s*', vids)
           if not running_vids or not self._compare_vids(vids, running_vids,
                                                         running_pvid):
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
           bridge_vids = self._get_bridge_vids(bridgename, ifaceobj_getfunc)
           if (bridge_vids and (not running_vids  or
                   not self._compare_vids(bridge_vids, running_vids, running_pvid))):
              ifaceobjcurr.status = ifaceStatus.ERROR
              ifaceobjcurr.status_str = 'bridge vid error'

    def _query_check_bridge_port(self, ifaceobj, ifaceobjcurr,
                                 ifaceobj_getfunc):
        if not self._is_bridge_port(ifaceobj):
            # Mark all bridge attributes as failed
            ifaceobjcurr.check_n_update_config_with_status_many(ifaceobj,
                    ['bridge-vids', 'bridge-trunk', 'bridge-pvid', 'bridge-access',
                     'bridge-pathcosts', 'bridge-portprios',
                     'bridge-portmcrouter',
                     'bridge-learning',
                     'bridge-portmcfl', 'bridge-unicast-flood',
                     'bridge-multicast-flood',
                     'bridge-arp-nd-suppress', 'bridge-l2protocol-tunnel'
                    ], 1)
            return
        bridgename = self._get_bridge_name(ifaceobj)
        if not bridgename:
            self.logger.warn('%s: unable to determine bridge name'
                             %ifaceobj.name)
            return

        if self.ipcmd.bridge_is_vlan_aware(bridgename):
            self._query_check_bridge_port_vidinfo(ifaceobj, ifaceobjcurr,
                                                  ifaceobj_getfunc,
                                                  bridgename)
        for attr, dstattr in {'bridge-pathcosts' : 'pathcost',
                              'bridge-portprios' : 'portprio',
                              'bridge-portmcrouter' : 'portmcrouter',
                              'bridge-portmcfl' : 'portmcfl',
                              'bridge-learning' : 'learning',
                              'bridge-unicast-flood' : 'unicast-flood',
                              'bridge-multicast-flood' : 'multicast-flood',
                              'bridge-arp-nd-suppress' : 'arp-nd-suppress',
                             }.items():
            attrval = ifaceobj.get_attr_value_first(attr)
            if not attrval:
                continue

            try:
                running_attrval = self.brctlcmd.get_bridgeport_attr(
                                       bridgename, ifaceobj.name, dstattr)

                if dstattr == 'portmcfl':
                    if not utils.is_binary_bool(attrval) and running_attrval:
                        running_attrval = utils.get_yesno_boolean(
                            utils.get_boolean_from_string(running_attrval))
                elif dstattr == 'portmcrouter':
                    if self._ifla_brport_multicast_router_dict_to_int.get(attrval) == int(running_attrval):
                        ifaceobjcurr.update_config_with_status(attr, attrval, 0)
                    else:
                        ifaceobjcurr.update_config_with_status(attr, attrval, 1)
                    continue
                elif dstattr in ['learning',
                                 'unicast-flood',
                                 'multicast-flood',
                                 'arp-nd-suppress',
                                ]:
                    if not utils.is_binary_bool(attrval) and running_attrval:
                        running_attrval = utils.get_onff_from_onezero(
                                                running_attrval)

                if running_attrval != attrval:
                    ifaceobjcurr.update_config_with_status(attr,
                                            running_attrval, 1)
                else:
                    ifaceobjcurr.update_config_with_status(attr,
                                            running_attrval, 0)
            except Exception, e:
                self.log_warn('%s: %s' %(ifaceobj.name, str(e)))

        self._query_check_l2protocol_tunnel_on_port(ifaceobj, ifaceobjcurr)

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

    def _query_check_l2protocol_tunnel_on_bridge(self, ifaceobj, ifaceobjcurr, bridge_running_attrs):
        """
            In case the bridge-l2protocol-tunnel is specified under the bridge and not the brport
            We need to make sure that all ports comply with the mask given under the bridge
        """
        user_config_l2protocol_tunnel = ifaceobj.get_attr_value_first('bridge-l2protocol-tunnel')

        if user_config_l2protocol_tunnel:
            if '=' in user_config_l2protocol_tunnel:
                try:
                    config_per_port_dict = self.parse_interface_list_value(user_config_l2protocol_tunnel)
                    brport_list = config_per_port_dict.keys()
                except:
                    ifaceobjcurr.update_config_with_status('bridge-l2protocol-tunnel', user_config_l2protocol_tunnel, 1)
                    return
            else:
                config_per_port_dict = {}
                brport_list = bridge_running_attrs.get('ports', {}).keys()
            result = 1
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
        cached_ifla_brport_group_maskhi = self.ipcmd.cache_get_info_slave([brport_name, 'info_slave_data', Link.IFLA_BRPORT_GROUP_FWD_MASKHI])
        cached_ifla_brport_group_mask = self.ipcmd.cache_get_info_slave([brport_name, 'info_slave_data', Link.IFLA_BRPORT_GROUP_FWD_MASK])

        for protocol in re.split(',|\s*', user_config_l2protocol_tunnel):
            callback = self.query_check_l2protocol_tunnel_callback.get(protocol)

            if callable(callback):
                if not callback(cached_ifla_brport_group_mask, cached_ifla_brport_group_maskhi):
                    raise Exception('%s: bridge-l2protocol-tunnel: protocol \'%s\' not present (cached value: %d | %d)'
                                    % (brport_name, protocol, cached_ifla_brport_group_mask, cached_ifla_brport_group_maskhi))

    def _query_running_bridge_l2protocol_tunnel(self, brport_name, brport_ifaceobj=None, bridge_ifaceobj=None):
        cached_ifla_brport_group_maskhi = self.ipcmd.cache_get_info_slave([brport_name, 'info_slave_data', Link.IFLA_BRPORT_GROUP_FWD_MASKHI])
        cached_ifla_brport_group_mask = self.ipcmd.cache_get_info_slave([brport_name, 'info_slave_data', Link.IFLA_BRPORT_GROUP_FWD_MASK])
        running_protocols = []
        for protocol_name, callback in self.query_check_l2protocol_tunnel_callback.items():
            if protocol_name == 'all' and callback(cached_ifla_brport_group_mask, cached_ifla_brport_group_maskhi):
                running_protocols = self.query_check_l2protocol_tunnel_callback.keys()
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
        if self.ipcmd.bridge_is_vlan_aware(ifaceobjrunning.name):
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

        v = self.brctlcmd.bridge_get_pathcost(bridgename, ifaceobjrunning.name)
        if v and v != self.get_mod_subattr('bridge-pathcosts', 'default'):
            ifaceobjrunning.update_config('bridge-pathcosts', v)

        v = self.brctlcmd.bridge_get_pathcost(bridgename, ifaceobjrunning.name)
        if v and v != self.get_mod_subattr('bridge-portprios', 'default'):
            ifaceobjrunning.update_config('bridge-portprios', v)

    def _query_running_bridge_port(self, ifaceobjrunning,
                                   ifaceobj_getfunc=None):

        bridgename = self.ipcmd.bridge_port_get_bridge_name(
                                                ifaceobjrunning.name)
        bridge_vids = None
        bridge_pvid = None
        if not bridgename:
            self.logger.warn('%s: unable to find bridgename'
                             %ifaceobjrunning.name)
            return

        if not self.ipcmd.bridge_is_vlan_aware(bridgename):
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
            if bridge_port_vids:
                if (not bridge_vids or bridge_port_vids != bridge_vids):
                   ifaceobjrunning.update_config('bridge-vids',
                                        ' '.join(bridge_port_vids))
            if bridge_port_pvid and bridge_port_pvid != '1':
                if (not bridge_pvid or (bridge_port_pvid != bridge_pvid)):
                    ifaceobjrunning.update_config('bridge-pvid',
                                        bridge_port_pvid)

        v = utils.get_onff_from_onezero(
                self.brctlcmd.get_bridgeport_attr(bridgename,
                                                  ifaceobjrunning.name,
                                                  'learning'))
        if v and v != self.get_mod_subattr('bridge-learning', 'default'):
            ifaceobjrunning.update_config('bridge-learning', v)

        v = utils.get_onff_from_onezero(
                self.brctlcmd.get_bridgeport_attr(bridgename,
                                                  ifaceobjrunning.name,
                                                  'unicast-flood'))
        if v and v != self.get_mod_subattr('bridge-unicast-flood', 'default'):
            ifaceobjrunning.update_config('bridge-unicast-flood', v)

        v = utils.get_onff_from_onezero(
                self.brctlcmd.get_bridgeport_attr(bridgename,
                                                  ifaceobjrunning.name,
                                                  'multicast-flood'))
        if v and v != self.get_mod_subattr('bridge-multicast-flood', 'default'):
            ifaceobjrunning.update_config('bridge-multicast-flood', v)

        v = utils.get_onff_from_onezero(
                self.brctlcmd.get_bridgeport_attr(bridgename,
                                                  ifaceobjrunning.name,
                                                  'arp-nd-suppress'))
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

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        try:
            if self.brctlcmd.bridge_exists(ifaceobjrunning.name):
                self._query_running_bridge(ifaceobjrunning, ifaceobj_getfunc)
            elif self.brctlcmd.is_bridge_port(ifaceobjrunning.name):
                self._query_running_bridge_port(ifaceobjrunning, ifaceobj_getfunc)
        except Exception as e:
            raise Exception('%s: %s' % (ifaceobjrunning.name, str(e)))

    def _query(self, ifaceobj, **kwargs):
        """ add default policy attributes supported by the module """
        if (not (ifaceobj.link_kind & ifaceLinkKind.BRIDGE) or
            ifaceobj.get_attr_value_first('bridge-stp')):
            return
        if self.default_stp_on:
            ifaceobj.update_config('bridge-stp', 'yes')

    def _query_check_support_yesno_attrs(self, runningattrs, ifaceobj):
        for attrl in [['mcqifaddr', 'bridge-mcqifaddr'],
                     ['mcquerier', 'bridge-mcquerier'],
                     ['mcsnoop', 'bridge-mcsnoop']]:
            value = ifaceobj.get_attr_value_first(attrl[1])
            if value and not utils.is_binary_bool(value):
                if attrl[0] in runningattrs:
                    bool = utils.get_boolean_from_string(runningattrs[attrl[0]])
                    runningattrs[attrl[0]] = utils.get_yesno_boolean(bool)

        self._query_check_mcrouter(ifaceobj, runningattrs)
        self._query_check_support_yesno_attr_port(runningattrs, ifaceobj, 'portmcfl', ifaceobj.get_attr_value_first('bridge-portmcfl'))
        self._query_check_support_yesno_attr_port(runningattrs, ifaceobj, 'learning', ifaceobj.get_attr_value_first('bridge-learning'))
        self._query_check_support_yesno_attr_port(runningattrs, ifaceobj, 'unicast-flood', ifaceobj.get_attr_value_first('bridge-unicast-flood'))
        self._query_check_support_yesno_attr_port(runningattrs, ifaceobj, 'multicast-flood', ifaceobj.get_attr_value_first('bridge-multicast-flood'))
        self._query_check_support_yesno_attr_port(runningattrs, ifaceobj, 'arp-nd-suppress', ifaceobj.get_attr_value_first('bridge-arp-nd-suppress'))

    def _query_check_mcrouter(self, ifaceobj, running_attrs):
        """
        bridge-mcrouter and bridge-portmcrouter supports: yes-no-0-1-2
        """
        if 'mcrouter' in running_attrs:
            value = ifaceobj.get_attr_value_first('bridge-mcrouter')
            if value:
                try:
                    int(value)
                except:
                    running_attrs['mcrouter'] = 'yes' if utils.get_boolean_from_string(running_attrs['mcrouter']) else 'no'

    def _query_check_support_yesno_attr_port(self, runningattrs, ifaceobj, attr, attrval):
        if attrval:
            portlist = self.parse_port_list(ifaceobj.name, attrval)
            if portlist:
                to_convert = []
                for p in portlist:
                    (port, val) = p.split('=')
                    if not utils.is_binary_bool(val):
                        to_convert.append(port)
                for port in to_convert:
                    runningattrs['ports'][port][attr] = utils.get_yesno_boolean(
                        utils.get_boolean_from_string(runningattrs['ports'][port][attr]))

    _run_ops = {
        'pre-up': _up,
        'post-down': _down,
        'query-checkcurr': _query_check,
        'query-running': _query_running,
        'query': _query
    }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = self.brctlcmd = LinkUtils()

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
        self._init_command_handlers()

        if (not LinkUtils.bridge_utils_is_installed
                and (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT or ifaceobj.link_kind & ifaceLinkKind.BRIDGE)
                    and LinkUtils.bridge_utils_missing_warning):
            self.logger.warning('%s: missing - bridge operation may not work as expected. '
                                'Please check if \'bridge-utils\' package is installed' % utils.brctl_cmd)
            LinkUtils.bridge_utils_missing_warning = False

        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
        else:
            op_handler(self, ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
