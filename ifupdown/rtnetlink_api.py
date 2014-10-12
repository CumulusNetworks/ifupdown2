#!/usr/bin/env python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
#
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
#

from os import getpid
from socket import AF_UNSPEC
from iff import IFF_UP
from rtnetlink import *
import os

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

        try:
            ifindex = self.get_ifindex(link)
        except Exception, e:
            raise Exception('cannot determine ifindex for link %s (%s)' %(link, str(e)))

        self.logger.info('rtnetlink: creating vlan %s' %ifname)
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
        token = self.request(RTM_NEWLINK, NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK, ifm, rtas)
        self.process_wait([token])

    def create_macvlan(self, ifname, link, mode='private'):

        try:
            ifindex = self.get_ifindex(link)
        except Exception, e:
            raise Exception('cannot determine ifindex for link %s (%s)' %(link, str(e)))

        self.logger.info('rtnetlink: creating macvlan %s' %ifname)

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
        token = self.request(RTM_NEWLINK, NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK,
                             ifm, rtas)
        self.process_wait([token])

    def link_set(self, ifname, state):
        flags = 0

        self.logger.info('rtnetlink: setting link %s %s' %(ifname, state))

        if state == "up":
            flags |= IFF_UP
        else:
            flags &= ~IFF_UP

        ifm = Ifinfomsg(AF_UNSPEC, ifi_change=IFF_UP, ifi_flags=flags)
        rtas = {IFLA_IFNAME: ifname}

        token = self.request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, ifm, rtas)
        self.process_wait([token])

rtnl_api = rtnetlinkApi(os.getpid())
