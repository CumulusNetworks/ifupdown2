# Copyright (C) 2017, 2018 Cumulus Networks, Inc. all rights reserved
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# https://www.gnu.org/licenses/gpl-2.0-standalone.html
#
# Author:
#       Julien Fortin, julien@cumulusnetworks.com
#
# addon -- Addon base class
#

import logging

from collections import OrderedDict

try:
    from ifupdown2.lib.io import IO
    from ifupdown2.lib.sysfs import Sysfs
    from ifupdown2.lib.iproute2 import IPRoute2
    from ifupdown2.lib.base_objects import Netlink, Cache, Requirements
    from ifupdown2.ifupdown.iface import ifaceLinkPrivFlags, ifaceLinkKind

    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.nlmanager.ipnetwork as ipnetwork
except ImportError:
    from lib.io import IO
    from lib.sysfs import Sysfs
    from lib.iproute2 import IPRoute2
    from lib.base_objects import Netlink, Cache, Requirements
    from ifupdown.iface import ifaceLinkPrivFlags, ifaceLinkKind


    import ifupdown.policymanager as policymanager
    import nlmanager.ipnetwork as ipnetwork


class AddonException(Exception):
    pass


class Addon(Netlink, Cache):
    """
    Base class for ifupdown2 addon modules
    Provides common infrastructure methods for all addon modules
    """

    def __init__(self):
        Netlink.__init__(self)
        Cache.__init__(self)

        self.logger = logging.getLogger("ifupdown2.addons.%s" % self.__class__.__name__)

        self.io = IO()
        self.sysfs = Sysfs
        self.iproute2 = IPRoute2()
        self.requirements = Requirements()

        self.__alias_to_attribute = {}

        for attribute_name, attribute_object in self.__get_modinfo().get("attrs", {}).items():
            for alias in attribute_object.get("aliases", []):
                self.__alias_to_attribute[alias] = attribute_name

        self._runqueue = []
        self._diff_mode = False

    def set_runqueue(self, runqueue):
        self._runqueue = runqueue
        self._diff_mode = True

    def __get_modinfo(self) -> dict:
        try:
            return self._modinfo
        except AttributeError:
            return {}

    def translate(self, ifaceobjs):
        """
        Replace attribute aliases from user configuration with real attribute name
        """
        for ifaceobj in ifaceobjs:
            ifaceobj.config = OrderedDict(
                [
                    (self.__alias_to_attribute[user_attr], user_value)
                    if user_attr in self.__alias_to_attribute
                    else (user_attr, user_value)
                    for user_attr, user_value in ifaceobj.config.items()
                ]
            )


class Vxlan(Addon):
    single_vxlan_configured = set()
    traditional_vxlan_configured = set()

    def __int__(self):
        super(Vxlan, self).__int__()


class Bridge(Addon):

    bridge_vlan_aware_list = set()

    def __init__(self):
        super(Bridge, self).__init__()

    def _re_evaluate_bridge_vxlan(self, ifaceobj, ifaceobj_getfunc=None):
        """
        Quick fix for BRIDGE_VXLAN

        BRIDGE_VXLAN is not set on the bridge because the VXLAN hasn't been processed yet
        (because its defined after the bridge in /e/n/i), here is what happens:

        - ifupdownmain:populate_dependency_info()
        - loops over all the intf from /e/n/i (with the example config:
            ['lo', 'eth0', 'swp1', 'swp2', 'bridge', 'vni-10', 'bridge.100', 'vlan100'])
            ----> bridge is first in the list of interface (that we care about)

        - ifupdownmain:query_lowerifaces()
        - bridge:get_dependent is called (debug: bridge: evaluating port expr '['swp1', 'swp2', 'vni-10']')
        - ifupdownmain:preprocess_dependency_list()
        - calls ifupdownmain:_set_iface_role_n_kind() on all the brports:

        in _set_iface_role_n_kind:
        ifaceobj is the brport
        upperifaceobj is the bridge

        it tries to see if the bridge has a VXLAN:

        if (ifaceobj.link_kind & ifaceLinkKind.VXLAN) \
        and (upperifaceobj.link_kind & ifaceLinkKind.BRIDGE):
        upperifaceobj.link_privflags |= ifaceLinkPrivFlags.BRIDGE_VXLAN

        but because the bridge is first in the /e/n/i ifupdown2 didn't
        call vxlan:get_dependent_ifacenames so VXLAN is not set on ifaceobj

        :return:
        """
        if not ifaceobj_getfunc:
            return

        if ifaceobj.link_kind & ifaceLinkKind.BRIDGE and not ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VXLAN:
            for port in self._get_bridge_port_list(ifaceobj) or []:
                for brport_ifaceobj in ifaceobj_getfunc(port) or []:
                    if brport_ifaceobj.link_kind & ifaceLinkKind.VXLAN:
                        ifaceobj.link_privflags |= ifaceLinkPrivFlags.BRIDGE_VXLAN
                        self.__check_l3vni_bridge(ifaceobj)
                        return

        elif ifaceobj.link_kind & ifaceLinkKind.BRIDGE:
            self.__check_l3vni_bridge(ifaceobj)

        elif ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT and ifaceobj.link_kind & ifaceLinkKind.VXLAN:
            for iface in ifaceobj.upperifaces if ifaceobj.upperifaces else []:
                for bridge_ifaceobj in ifaceobj_getfunc(iface) or []:
                    bridge_ifaceobj.link_privflags |= ifaceLinkPrivFlags.BRIDGE_VXLAN
                    self.__check_l3vni_bridge(bridge_ifaceobj)

    def __check_l3vni_bridge(self, ifaceobj):
        # the calling function needs to make sure that the following checks were performed:
        # ifaceobj.link_kind & ifaceLinkKind.BRIDGE
        # ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VXLAN
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE \
                and len(self._get_ifaceobj_bridge_ports(ifaceobj, as_list=True)) == 1:
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.BRIDGE_l3VNI

    @staticmethod
    def _get_ifaceobj_bridge_ports(ifaceobj, as_list=False):
        bridge_ports = []

        for brport in ifaceobj.get_attr_value('bridge-ports') or []:
            if brport != 'none':
                bridge_ports.extend(brport.split())

        if as_list:
            return bridge_ports

        return ' '.join(bridge_ports)

    def _get_bridge_port_list(self, ifaceobj):
        # port list is also available in the previously
        # parsed dependent list. Use that if available, instead
        # of parsing port expr again
        port_list = ifaceobj.lowerifaces
        if port_list:
            return port_list
        ports = self._get_ifaceobj_bridge_ports(ifaceobj)
        if ports:
            ports = self.parse_port_list(ifaceobj.name, ports)
        return ports or []


class AddonWithIpBlackList(Addon):
    try:
        ip_blacklist = [ipnetwork.IPNetwork(ip).ip for ip in policymanager.policymanager_api.get_module_globals(
            module_name="address",
            attr="ip_blacklist"
        ) or []]
        __ip_blacklist_exception = None
    except Exception as e:
        __ip_blacklist_exception = e
        ip_blacklist = []

    def __init__(self):
        """
        If an exception occurred during the ip blacklist parsing we need to display it (once)
        Also we keep this as a class variable to share it between the address and addressvirtual module
        """
        super(AddonWithIpBlackList, self).__init__()

        if AddonWithIpBlackList.__ip_blacklist_exception:
            self.logger.warning("policy.d: address: 'ip_blacklist': %s" % AddonWithIpBlackList.__ip_blacklist_exception)
            AddonWithIpBlackList.__ip_blacklist_exception = None

    def ip_blacklist_check(self, ifname, ip):
        """
        Check if the ip address is not blacklisted (in ip_blacklist)

        :param ifname:
        :param ip:
        :return:
        """
        if ip.ip in AddonWithIpBlackList.ip_blacklist:
            raise AddonException("%s: blacklisted ip address in use: %s" % (ifname, ip.ip))
