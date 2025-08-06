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
# sysfs -- contains all sysfs related operation
#

import os
import glob

try:
    from ifupdown2.lib.io import IO
    from ifupdown2.lib.base_objects import Requirements

    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.nlmanager.nlpacket import Link
except ImportError:
    from lib.io import IO
    from lib.base_objects import Requirements

    from ifupdown.utils import utils

    from nlmanager.nlpacket import Link


class __Sysfs(IO, Requirements):

    __bond_netlink_to_sysfs_attr_map = {
        Link.IFLA_BOND_MODE: "mode",
        Link.IFLA_BOND_MIIMON: "miimon",
        Link.IFLA_BOND_ARP_INTERVAL: 'arp-interval',
        Link.IFLA_BOND_ARP_IP_TARGET: 'arp-ip-target',
        Link.IFLA_BOND_USE_CARRIER: "use_carrier",
        Link.IFLA_BOND_AD_LACP_RATE: "lacp_rate",
        Link.IFLA_BOND_XMIT_HASH_POLICY: "xmit_hash_policy",
        Link.IFLA_BOND_MIN_LINKS: "min_links",
        Link.IFLA_BOND_NUM_PEER_NOTIF: "num_grat_arp",
        Link.IFLA_BOND_AD_ACTOR_SYSTEM: "ad_actor_system",
        Link.IFLA_BOND_AD_ACTOR_SYS_PRIO: "ad_actor_sys_prio",
        Link.IFLA_BOND_AD_LACP_BYPASS: "lacp_bypass",
        Link.IFLA_BOND_UPDELAY: "updelay",
        Link.IFLA_BOND_DOWNDELAY: "downdelay",
        Link.IFLA_BOND_PRIMARY: "primary",
    }

    def __init__(self):
        IO.__init__(self)
        Requirements.__init__(self)

        # Temporary work around to solve the circular dependency with nlcache.
        # Once nlcache is created it will populate sysfs.cache
        self.cache = None

        # if bridge utils is not installed overrrides specific functions to
        # avoid constantly checking bridge_utils_is_installed
        if not Requirements.bridge_utils_is_installed:
            self.bridge_get_mcqv4src = self.bridge_get_mcqv4src_dry_run

    @staticmethod
    def link_get_uppers(ifname):
        try:
            uppers = glob.glob("/sys/class/net/%s/upper_*" % ifname)
            if not uppers:
                return []
            return [os.path.basename(u)[6:] for u in uppers]
        except Exception:
            return []

    @staticmethod
    def link_get_lowers(ifname):
        try:
            lowers = glob.glob("/sys/class/net/%s/lower_*" % ifname)
            if not lowers:
                return []
            return [os.path.basename(l)[6:] for l in lowers]
        except Exception:
            return []

    def link_is_up(self, ifname):
        """
        Read sysfs operstate file
        """
        return "up" == self.read_file_oneline("/sys/class/net/%s/operstate" % ifname)

    def get_link_address(self, ifname):
        """
        Read MAC hardware address from sysfs
        """
        return self.read_file_oneline("/sys/class/net/%s/address" % ifname)

    #
    # MTU
    #

    def link_get_mtu(self, ifname):
        return int(self.read_file_oneline("/sys/class/net/%s/mtu" % ifname) or 0)

    def link_set_mtu(self, ifname, mtu_str, mtu_int):
        if self.cache.get_link_mtu(ifname) != mtu_int:
            if self.write_to_file('/sys/class/net/%s/mtu' % ifname, mtu_str):
                self.cache.override_link_mtu(ifname, mtu_int)

    def link_set_mtu_dry_run(self, ifname, mtu_str, mtu_int):
        # we can remove the cache check in DRYRUN mode
        self.write_to_file('/sys/class/net/%s/mtu' % ifname, mtu_str)

    #
    # ALIAS
    #

    def link_set_alias(self, ifname, alias):
        cached_alias = self.cache.get_link_alias(ifname)

        if cached_alias == alias:
            return

        if not alias:
            alias = "\n"

        if self.write_to_file("/sys/class/net/%s/ifalias" % ifname, alias):
            pass # self.cache.override_link_mtu(ifname, mtu_int)

    def link_set_alias_dry_run(self, ifname, alias):
        # we can remove the cache check in DRYRUN mode
        if not alias:
            alias = ""
        self.write_to_file("/sys/class/net/%s/ifalias" % ifname, alias)

    ############################################################################
    # BRIDGE
    ############################################################################

    def bridge_port_pvids_get(self, bridge_port_name):
        return self.read_file_oneline("/sys/class/net/%s/brport/pvid" % bridge_port_name)

    def bridge_get_stp(self, bridge):
        stp_state_path = "/sys/class/net/%s/bridge/stp_state" % bridge

        if not os.path.exists(stp_state_path):
            return "error"

        stp_state = self.read_file_oneline(stp_state_path)

        if not stp_state:
            return "error"

        try:
            stp_state_int = int(stp_state)
            return "yes" if stp_state_int > 0 else "no"
        except Exception:
            return "unknown"

    def bridge_get_mcqv4src(self, bridge):
        mcqv4src = {}
        try:
            filename = "/sys/class/net/%s/bridge/multicast_v4_queriers" % bridge
            if os.path.exists(filename):
                for line in self.read_file(filename) or []:
                    vlan_id, ip = line.split('=')
                    mcqv4src[vlan_id] = ip.strip()
            return mcqv4src
        except Exception:
            self.logger.info("%s showmcqv4src: skipping unsupported command" % utils.brctl_cmd)
            self.bridge_get_mcqv4src = self.bridge_get_mcqv4src_dry_run
            return {}

    @staticmethod
    def bridge_get_mcqv4src_dry_run(bridge):
        return {}

    ############################################################################
    # BOND
    ############################################################################

    def bond_remove_slave(self, bond_name, slave_name):
        if self.cache.is_link_enslaved_to(slave_name, bond_name):
            if self.write_to_file("/sys/class/net/%s/bonding/slaves" % bond_name, "-%s" % slave_name):
                # success we can manually update our cache to make sure we stay up-to-date
                self.cache.override_cache_unslave_link(slave=slave_name, master=bond_name)

    def bond_remove_slave_dry_run(self, bond_name, slave_name):
        self.write_to_file("/sys/class/net/%s/bonding/slaves" % bond_name, "-%s" % slave_name)

    ###

    def bond_create(self, bond_name):
        if self.cache.bond_exists(bond_name):
            return
        self.write_to_file("/sys/class/net/bonding_masters", "+%s" % bond_name)

    def bond_create_dry_run(self, bond_name):
        self.write_to_file("/sys/class/net/bonding_masters", "+%s" % bond_name)

    ###

    def bond_set_attrs_nl(self, bond_name, ifla_info_data):
        """
        bond_set_attrs_nl doesn't need a _dry_run handler because each
        entry in ifla_info_data was checked against the cache already.
        Here write_to_file already has a dry_run handler.
        :param bond_name:
        :param ifla_info_data:
        :return:
        """
        bond_attr_name = 'None'  # for log purpose (in case an exception raised)

        for nl_attr, value in list(ifla_info_data.items()):
            try:
                bond_attr_name = self.__bond_netlink_to_sysfs_attr_map.get(nl_attr)

                if bond_attr_name is None:
                    self.logger.warning(
                        "%s: sysfs configuration: unknown bond attribute %s (value %s)"
                        % (bond_name, nl_attr, value)
                    )
                    continue

                file_path = "/sys/class/net/%s/bonding/%s" % (bond_name, bond_attr_name)
                if os.path.exists(file_path):
                    self.write_to_file(file_path, str(value))
            except Exception as e:
                self.logger.warning("%s: %s %s: %s" % (bond_name, bond_attr_name, value, str(e)))

    ############################################################################
    # /proc/sys/ipv6/conf
    ############################################################################

    def get_ipv6_conf_disable_ipv6(self, ifname):
        return int(self.read_file_oneline("/proc/sys/net/ipv6/conf/%s/disable_ipv6" % ifname) or 0)


Sysfs = __Sysfs()
