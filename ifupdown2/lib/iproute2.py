# Copyright (C) 2017, 2018, 2019 Cumulus Networks, Inc. all rights reserved
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
# iproute2 -- contains all iproute2 related operation
#

try:
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.lib.base_objects import Cache
except ImportError:
    from ifupdown.utils import utils
    from lib.base_objects import Cache


class IPRoute2(Cache):

    def __init__(self):
        Cache.__init__(self)
        self.__batch = None
        self.__batch_mode = False

    ############################################################################
    # BATCH
    ############################################################################

    def __add_to_batch(self, cmd):
        self.__batch.append(cmd)

    def __execute_or_batch(self, prefix, cmd):
        if self.__batch_mode:
            self.__add_to_batch(cmd)
        else:
            utils.exec_command("%s %s" % (prefix, cmd))

    def __execute_or_batch_dry_run(self, prefix, cmd):
        """
        The batch function has it's own dryrun handler so we only handle
        dryrun for non-batch mode. Which will be removed once the "utils"
        module has it's own dryrun handlers
        """
        if self.__batch_mode:
            self.__add_to_batch(cmd)
        else:
            self.logger.info("dryrun: executing: %s %s" % (prefix, cmd))

    def batch_start(self):
        self.__batch_mode = True
        self.__batch = list()

    def batch_commit(self):
        if not self.__batch_mode or not self.__batch:
            return
        try:
            utils.exec_command(
                "%s -force -batch -" % utils.ip_cmd,
                stdin="\n".join(self.__batch)
            )
        except:
            raise
        finally:
            self.__batch_mode = False
            del self.__batch
            self.__batch = None

    ############################################################################
    # LINK
    ############################################################################

    def link_up(self, ifname):
        if not self.cache.link_is_up(ifname):
            self.link_up_force(ifname)

    def link_down(self, ifname):
        if self.cache.link_is_up(ifname):
            self.link_down_force(ifname)

    def link_up_dry_run(self, ifname):
        self.link_up_force(ifname)

    def link_down_dry_run(self, ifname):
        self.link_down_force(ifname)

    def link_up_force(self, ifname):
        self.__execute_or_batch(utils.ip_cmd, "link set dev %s up" % ifname)

    def link_down_force(self, ifname):
        self.__execute_or_batch(utils.ip_cmd, "link set dev %s down" % ifname)

    ###

    def link_set_master(self, ifname, master):
        if master != self.cache.get_master(ifname):
            self.__execute_or_batch(
                utils.ip_cmd,
                "link set dev %s master %s" % (ifname, master)
            )

    def link_set_master_dry_run(self, ifname, master):
        self.__execute_or_batch(
            utils.ip_cmd,
            "link set dev %s master %s" % (ifname, master)
        )

    ###

    def link_set_address(self, ifname, address):
        if utils.mac_str_to_int(address) != self.cache.get_link_address_raw(ifname):
            self.link_down(ifname)
            self.__execute_or_batch(
                utils.ip_cmd,
                "link set dev %s address %s" % (ifname, address)
            )
            self.link_up(ifname)

    def link_set_address_dry_run(self, ifname, address):
        self.link_down(ifname)
        self.__execute_or_batch(
            utils.ip_cmd,
            "link set dev %s address %s" % (ifname, address)
        )
        self.link_up(ifname)

    ############################################################################
    ### BRIDGE
    ############################################################################

    @staticmethod
    def bridge_fdb_add(dev, address, vlan=None, bridge=True, remote=None):
        target = "self" if bridge else ""
        vlan_str = "vlan %s " % vlan if vlan else ""
        dst_str = "dst %s " % remote if remote else ""

        utils.exec_command(
            "%s fdb replace %s dev %s %s %s %s"
            % (
                utils.bridge_cmd,
                address,
                dev,
                vlan_str,
                target,
                dst_str
            )
        )

    @staticmethod
    def bridge_fdb_append(dev, address, vlan=None, bridge=True, remote=None):
        target = "self" if bridge else ""
        vlan_str = "vlan %s " % vlan if vlan else ""
        dst_str = "dst %s " % remote if remote else ""

        utils.exec_command(
            "%s fdb append %s dev %s %s %s %s"
            % (
                utils.bridge_cmd,
                address,
                dev,
                vlan_str,
                target,
                dst_str
            )
        )

    @staticmethod
    def bridge_fdb_del(dev, address, vlan=None, bridge=True, remote=None):
        target = "self" if bridge else ""
        vlan_str = "vlan %s " % vlan if vlan else ""
        dst_str = "dst %s " % remote if remote else ""

        utils.exec_command(
            "%s fdb del %s dev %s %s %s %s"
            % (
                utils.bridge_cmd,
                address,
                dev,
                vlan_str,
                target,
                dst_str
            )
        )
