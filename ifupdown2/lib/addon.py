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

    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.nlmanager.ipnetwork as ipnetwork
except (ImportError, ModuleNotFoundError):
    from lib.io import IO
    from lib.sysfs import Sysfs
    from lib.iproute2 import IPRoute2
    from lib.base_objects import Netlink, Cache, Requirements

    import ifupdown.policymanager as policymanager
    import nlmanager.ipnetwork as ipnetwork


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


class Bridge(Addon):

    bridge_vlan_aware_list = []

    def __init__(self):
        super(Bridge, self).__init__()


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
            raise Exception("%s: blacklisted ip address in use: %s" % (ifname, ip.ip))
