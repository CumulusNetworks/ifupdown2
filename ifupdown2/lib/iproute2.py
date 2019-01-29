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
