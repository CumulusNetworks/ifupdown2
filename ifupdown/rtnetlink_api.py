#!/usr/bin/env python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
#
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
#

from os import getpid
from socket import AF_UNSPEC
from socket import AF_BRIDGE
from iff import IFF_UP
from rtnetlink import *
import os
import ifupdownmain

class rtnetlinkApi(RtNetlink):

    bind_done = False

    def __init__(self, pid):
        RtNetlink.__init__(self, pid)
        self.logger = logging.getLogger('ifupdown.' +
                            self.__class__.__name__)
        self.bind(0, None)
        self.bind_done = True
        self.ifindexmap = {}

    def do_bind(self):
        if self.bind_done:
            return True
        self.bind(0, None)
        self.bind_done = True

    def get_ifindex(self, ifname):
        ifindex = self.ifindexmap.get(ifname)
        if not ifindex:
            with open('/sys/class/net/%s/ifindex' %ifname, 'r') as f:
                ifindex = int(f.read())
                self.ifindexmap[ifname] = ifindex
        return ifindex

    def create_vlan(self, link, ifname, vlanid):
        self.logger.info('rtnetlink: ip link add link %s name %s type vlan id %s' %(link, ifname, vlanid))
        if ifupdownmain.ifupdownFlags.DRYRUN:
            return
        try:
            ifindex = self.get_ifindex(link)
        except Exception, e:
            raise Exception('cannot determine ifindex for link %s (%s)'
                            %(link, str(e)))

        ifm = Ifinfomsg(AF_UNSPEC)
        rtas = {IFLA_IFNAME: ifname,
                    IFLA_LINK : ifindex,
		            IFLA_LINKINFO : {
			            IFLA_INFO_KIND : 'vlan',
			            IFLA_INFO_DATA : {
                            IFLA_VLAN_ID : vlanid,
                        }
                    }
               }
        token = self.request(RTM_NEWLINK,
                        NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK, ifm, rtas)
        self.process_wait([token])

    def create_macvlan(self, ifname, link, mode='private'):
        self.logger.info('rtnetlink: ip link add link %s name %s type macvlan mode private' %(link, ifname))
        if ifupdownmain.ifupdownFlags.DRYRUN:
            return
        try:
            ifindex = self.get_ifindex(link)
        except Exception, e:
            raise Exception('cannot determine ifindex for link %s (%s)'
                            %(link, str(e)))

        ifm = Ifinfomsg(AF_UNSPEC)
        rtas = {IFLA_IFNAME: ifname,
                    IFLA_LINK : ifindex,
		            IFLA_LINKINFO : {
			            IFLA_INFO_KIND : 'macvlan',
		            IFLA_INFO_DATA : {
                           IFLA_MACVLAN_MODE : MACVLAN_MODE_PRIVATE,
                        }
                    }
               }
        token = self.request(RTM_NEWLINK, NLM_F_CREATE | NLM_F_REQUEST |
                             NLM_F_ACK, ifm, rtas)
        self.process_wait([token])

    def link_set(self, ifname, state):
        flags = 0
        self.logger.info('rtnetlink: ip link set dev %s %s' %(ifname, state))
        if ifupdownmain.ifupdownFlags.DRYRUN:
            return

        if state == "up":
            flags |= IFF_UP
        else:
            flags &= ~IFF_UP

        ifm = Ifinfomsg(AF_UNSPEC, ifi_change=IFF_UP, ifi_flags=flags)
        rtas = {IFLA_IFNAME: ifname}

        token = self.request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, ifm, rtas)
        self.process_wait([token])

    def link_set_protodown(self, ifname, state):
        flags = 0
        self.logger.info('rtnetlink: setting link %s protodown %s' %(ifname, state))
        if ifupdownmain.ifupdownFlags.DRYRUN:
            return

        protodown = 1 if state == "on" else 0

        ifm = Ifinfomsg(AF_UNSPEC)
        rtas = {IFLA_IFNAME : ifname,
                IFLA_PROTO_DOWN : protodown}

        token = self.request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, ifm, rtas)
        self.process_wait([token])

    def link_set_hwaddress(self, ifname, hwaddress):
        flags = 0
        self.logger.info('rtnetlink: ip link set dev %s address %s' %(ifname, hwaddress))
        if ifupdownmain.ifupdownFlags.DRYRUN:
            return

        flags &= ~IFF_UP
        ifm = Ifinfomsg(AF_UNSPEC, ifi_change=IFF_UP)
        rtas = {IFLA_IFNAME: ifname,
                IFLA_ADDRESS : str(bytearray([int(a,16) for a in hwaddress.split(':')]))}

        self.logger.info(rtas)

        token = self.request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, ifm, rtas)
        self.process_wait([token])

    def addr_add(self, ifname, address, broadcast=None, peer=None, scope=None,
                 preferred_lifetime=None):
        self.logger.info('rtnetlink: setting address')
        if ifupdownmain.ifupdownFlags.DRYRUN:
            return

        try:
            ifindex = self.get_ifindex(link)
        except Exception, e:
            raise Exception('cannot determine ifindex for link %s (%s)'
                            %(link, str(e)))
        ifa_scope = RT_SCOPE_
        if scope:
            if scope == "universe":
                ifa_scope = RT_SCOPE_UNIVERSE
            elif scope == "site":
                ifa_scope = RT_SCOPE_SITE
            elif scope == "link":
                ifa_scope = RT_SCOPE_LINK
            elif scope == "host":
                ifa_scope = RT_SCOPE_HOST
            elif scope == "nowhere":
                ifa_scope = RT_SCOPE_NOWHERE
        rtas = {IFLA_ADDRESS: ifname}

        ifa = Ifaddrmsg(AF_UNSPEC, ifa_scope=ifa_scope, ifa_index=ifindex)

        token = self.request(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK, ifa, rtas)
        self.process_wait([token])

    def link_set_many(self, ifname, ifattrs):
        _ifattr_to_rta_map = {'dev' : IFLA_NAME,
                              'address' : IFLA_ADDRESS,
                              'broadcast' : IFLA_BROADCAST,
                              'mtu' : IFLA_MTU,
                              'master' : IFLA_MASTER}
        flags = 0
        ifi_change = IFF_UP
        rtas = {}
        self.logger.info('rtnetlink: setting link %s %s' %(ifname, state))
        if ifupdownmain.ifupdownFlags.DRYRUN:
            return
        if not ifattrs:
           return
        state = ifattrs.get('state')
        if state == 'up':
            flags |= IFF_UP
        elif state == 'down':
            flags &= ~IFF_UP
        else:
            ifi_change = 0

        if ifi_change:
           ifm = Ifinfomsg(AF_UNSPEC, ifi_change=IFF_UP, ifi_flags=flags)
        else:
           ifm = Ifinfomsg(AF_UNSPEC)

        for attr, attrval in ifattrs.items():
            rta_attr = _ifattr_to_rta_map.get(attr)
            if rta_attr:
               if attr == 'hwaddress':
                  rtas[rta_attr] = str(bytearray([int(a,16) for a in attrval.split(':')]))
               else:
                  rtas[rta_attr] = attrval

        token = self.request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, ifm, rtas)
        self.process_wait([token])

    def bridge_vlan(self, add=True, vid=None, dev=None, pvid=False,
                    untagged=False, master=True):
        flags = 0
        vflags = 0
        if not vid or not dev:
           return
        self.logger.info('rtnetlink: bridge vlan add vid %s %s %s dev %s %s'
                         %(vid, 'untagged' if untagged else '',
                           'pvid' if pvid else '', dev,
                           'self' if not master else ''))
        if ifupdownmain.ifupdownFlags.DRYRUN:
            return
        try:
            ifindex = self.get_ifindex(dev)
        except Exception, e:
            raise Exception('cannot determine ifindex for dev %s (%s)'
                            %(dev, str(e)))
        if not master:
            flags = BRIDGE_FLAGS_SELF

        if pvid:
           vflags = BRIDGE_VLAN_INFO_PVID
           vflags |= BRIDGE_VLAN_INFO_UNTAGGED
        elif untagged:
           vflags |= BRIDGE_VLAN_INFO_UNTAGGED

        ifm = Ifinfomsg(AF_BRIDGE, ifi_index=ifindex)
        rtas = {IFLA_AF_SPEC: {
                    IFLA_BRIDGE_FLAGS: flags,
                    IFLA_BRIDGE_VLAN_INFO : BridgeVlanInfo(vflags, int(vid))
                  }
               }
        if add:
            token = self.request(RTM_SETLINK,
                        NLM_F_REQUEST | NLM_F_ACK, ifm, rtas)
        else:
            token = self.request(RTM_DELLINK,
                        NLM_F_REQUEST | NLM_F_ACK, ifm, rtas)
        self.process_wait([token])

    def bridge_vlan_many(self, add=True, vids=[], dev=None, pvid=False,
                         untagged=False, master=True):
        for v in vids:
            self.bridge_vlan_add(add, v, dev, ispvid, isuntagged, master)

rtnl_api = rtnetlinkApi(os.getpid())
