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

import re
import shlex
import signal
import ipaddress
import subprocess
import json

try:
    from ifupdown2.lib.sysfs import Sysfs
    from ifupdown2.lib.base_objects import Cache, Requirements

    import ifupdown2.nlmanager.ipnetwork as ipnetwork

    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.iface import ifaceLinkPrivFlags
    from ifupdown2.nlmanager.nlpacket import Link
except (ImportError, ModuleNotFoundError):
    from lib.sysfs import Sysfs
    from lib.base_objects import Cache, Requirements

    import nlmanager.ipnetwork as ipnetwork

    from ifupdown.utils import utils
    from ifupdown.iface import ifaceLinkPrivFlags
    from nlmanager.nlpacket import Link

# WORK AROUND - Tunnel creation should be done via netlink and not iproute2 ####
import struct                                                                  #
import socket                                                                  #
                                                                               #
try:                                                                           #
    import ifupdown2.nlmanager.nlpacket as nlpacket                            #
except Exception:                                                                        #
    import nlmanager.nlpacket as nlpacket                                      #
################################################################################


class IPRoute2(Cache, Requirements):

    VXLAN_UDP_PORT = 4789
    VXLAN_PEER_REGEX_PATTERN = re.compile("\s+dst\s+(\d+.\d+.\d+.\d+)\s+")

    def __init__(self):
        Cache.__init__(self)
        Requirements.__init__(self)

        self.sysfs = Sysfs

        self.__batch = {}
        self.__batch_mode = False

        # if bridge utils is not installed overrrides specific functions to
        # avoid constantly checking bridge_utils_is_installed
        if not Requirements.bridge_utils_is_installed:
            self.bridge_set_stp = lambda _, __: None
            self.bridge_del_mcqv4src = lambda _, __: None
            self.bridge_set_mcqv4src = lambda _, __, ___: None

    ############################################################################
    # WORK-AROUND
    ############################################################################

    def __update_cache_after_link_creation(self, ifname, kind):
        """
        WORK AROUND - when creating tunnel via iproute2 we still need to fill
        our internal cache to keep track of this interface until we receive the
        NEWLINK notification. This code is a copy-paste from:
            nlcache.tx_nlpacket_get_response_with_error_and_cache_on_ack

        :param ifname:
        :param kind:
        :return:
        """
        packet = nlpacket.Link(nlpacket.RTM_NEWLINK, False, use_color=False)
        packet.flags = nlpacket.NLM_F_CREATE | nlpacket.NLM_F_REQUEST | nlpacket.NLM_F_ACK
        packet.body = struct.pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
        packet.add_attribute(nlpacket.Link.IFLA_IFNAME, ifname)
        packet.add_attribute(nlpacket.Link.IFLA_LINKINFO, {
            nlpacket.Link.IFLA_INFO_KIND: kind,
            nlpacket.Link.IFLA_INFO_DATA: {}
        })
        packet.build_message(0, 0)
        # When creating a new link via netlink, we don't always wait for the kernel
        # NEWLINK notification to be cached to continue. If our request is ACKed by
        # the OS we assume that the link was successfully created. Since we aren't
        # waiting for the kernel notification to continue we need to manually fill
        # our cache with the packet we just TX'ed. Once the NEWLINK notification
        # is received it will simply override the previous entry.
        # We need to keep track of those manually cached packets. We set a private
        # flag on the objects via the attribute priv_flags
        packet.priv_flags |= nlpacket.NLM_F_REQUEST
        try:
            # we need to decode the service header so all the attribute are properly
            # filled in the packet object that we are about to store in cache.
            # i.e.: packet.flags shouldn't contain NLM_F_* values but IFF_* (in case of Link object)
            # otherwise call to cache.link_is_up() will probably return True
            packet.decode_service_header()
        except Exception:
            # we can ignore all errors
            pass

        # Then we can use our normal "add_link" API call to cache the packet
        # and fill up our additional internal data structures.
        self.cache.add_link(packet)

    ############################################################################
    # BATCH
    ############################################################################

    def __add_to_batch(self, prefix, cmd):
        if prefix in self.__batch:
            self.__batch[prefix].append(cmd)
        else:
            self.__batch[prefix] = [cmd]

    def __execute_or_batch(self, prefix, cmd):
        if self.__batch_mode:
            self.__add_to_batch(prefix, cmd)
        else:
            utils.exec_command("%s %s" % (prefix, cmd))

    def __execute_or_batch_dry_run(self, prefix, cmd):
        """
        The batch function has it's own dryrun handler so we only handle
        dryrun for non-batch mode. Which will be removed once the "utils"
        module has it's own dryrun handlers
        """
        if self.__batch_mode:
            self.__add_to_batch(prefix, cmd)
        else:
            self.log_info_dry_run("executing: %s %s" % (prefix, cmd))

    def batch_start(self):
        if not self.__batch_mode:
            self.__batch_mode = True
            self.__batch = {}

    def batch_commit(self):
        try:
            if not self.__batch_mode or not self.__batch:
                return
            for prefix, commands in self.__batch.items():
                utils.exec_command(
                    "%s -force -batch -" % prefix,
                    stdin="\n".join(commands)
                )
        except Exception:
            raise
        finally:
            self.__batch_mode = False
            del self.__batch
            self.__batch = None

    ############################################################################
    # LINK
    ############################################################################

    def link_up(self, ifname):
        # TODO: if we already in a batch we shouldn't check the cache as the link might be DOWN during the batch
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

    def link_set_address_and_keep_down(self, ifname, address, keep_down=False):
        if utils.mac_str_to_int(address) != self.cache.get_link_address_raw(ifname):

            self.link_down(ifname)
            self.__execute_or_batch(
                utils.ip_cmd,
                "link set dev %s address %s" % (ifname, address)
            )
            if not keep_down:
                self.link_up_force(ifname)

    def link_set_address_and_keep_down_dry_run(self, ifname, address, keep_down=False):
        self.link_down(ifname)
        self.__execute_or_batch(
            utils.ip_cmd,
            "link set dev %s address %s" % (ifname, address)
        )
        if not keep_down:
            self.link_up(ifname)

    ###

    def link_add_macvlan(self, ifname, macvlan_ifname, macvlan_mode):
        utils.exec_command(
            "%s link add link %s name %s type macvlan mode %s"
            % (utils.ip_cmd, ifname, macvlan_ifname, macvlan_mode)
        )

    def link_add_macvlan_dry_run(self, ifname, macvlan_ifname, macvlan_mode):
        # this dryrun method can be removed once dryrun handlers
        # are added to the utils module
        self.log_info_ifname_dry_run(ifname, "executing %s link add link %s name %s type macvlan mode %s"
            % (utils.ip_cmd, ifname, macvlan_ifname, macvlan_mode)
        )

    ###

    def link_add_veth(self, ifname, peer_name):
        utils.exec_command(
            "%s link add %s type veth peer name %s"
            % (utils.ip_cmd, ifname, peer_name)
        )

    ###

    def link_add_single_vxlan(self, link_exists, ifname, ip, group, physdev, port, vnifilter="off", ttl=None):
        self.logger.info("creating single vxlan device: %s" % ifname)

        if link_exists:
            # When updating an SVD we need to use `ip link set` and we have to
            # drop the external keyword:
            # $ ip link set dev vxlan0 type vxlan external local 27.0.0.242 dev ipmr-lo
            # Error: vxlan: cannot change COLLECT_METADATA flag.
            cmd = ["link set dev %s type vxlan" % ifname]
        else:
            cmd = ["link add dev %s type vxlan external" % ifname]

            # when changing local ip, if we specify vnifilter we get:
            # Error: vxlan: cannot change flag.
            # So we are only setting this attribute on vxlan creation
            if vnifilter and utils.get_boolean_from_string(vnifilter):
                cmd.append("vnifilter")

        if ip:
            cmd.append("local %s" % ip)

        if physdev:
            cmd.append("dev %s" % physdev)

        if group:
            cmd.append("group %s" % group)

        if port:
            cmd.append("dstport %s" % port)

        if ttl:
            cmd.append("ttl %s" % ttl)

        self.__execute_or_batch(utils.ip_cmd, " ".join(cmd))
        self.__update_cache_after_link_creation(ifname, "vxlan")

    def link_add_l3vxi(self, link_exists, ifname, ip, group, physdev, port, ttl=None):
        self.logger.info("creating l3vxi device: %s" % ifname)

        if link_exists:
            # When updating an SVD we need to use `ip link set` and we have to
            # drop the external keyword:
            # $ ip link set dev vxlan0 type vxlan external local 27.0.0.242 dev ipmr-lo
            # Error: vxlan: cannot change COLLECT_METADATA flag.
            cmd = ["link set dev %s type vxlan" % ifname]
        else:
            cmd = ["link add dev %s type vxlan external vnifilter" % ifname]
            # when changing local ip, if we specify vnifilter we get:
            # Error: vxlan: cannot change flag.
            # So we are only setting this attribute on vxlan creation

        if ip:
            cmd.append("local %s" % ip)

        if physdev:
            cmd.append("dev %s" % physdev)

        if group:
            cmd.append("group %s" % group)

        if port:
            cmd.append("dstport %s" % port)

        if ttl:
            cmd.append("ttl %s" % ttl)

        self.__execute_or_batch(utils.ip_cmd, " ".join(cmd))
        self.__update_cache_after_link_creation(ifname, "vxlan")

    def link_create_vxlan(self, name, vxlanid, localtunnelip=None, svcnodeip=None,
                          remoteips=None, learning='on', ageing=None, ttl=None, physdev=None, udp_csum='on', tos = None):
        if svcnodeip and remoteips:
            raise Exception("svcnodeip and remoteip are mutually exclusive")

        if self.cache.link_exists(name):
            cmd = [
                "link set dev %s type vxlan dstport %d"
                % (name, self.VXLAN_UDP_PORT)
            ]
        else:
            cmd = [
                "link add dev %s type vxlan id %s dstport %d"
                % (name, vxlanid, self.VXLAN_UDP_PORT)
            ]

        if svcnodeip:
            if svcnodeip.ip.is_multicast:
                cmd.append("group %s" % svcnodeip)
            else:
                cmd.append("remote %s" % svcnodeip)

        if ageing:
            cmd.append("ageing %s" % ageing)

        if learning == 'off':
            cmd.append("nolearning")

        if udp_csum == 'off':
            cmd.append("noudpcsum")

        if ttl is not None:
            cmd.append("ttl %s" % ttl)

        if tos is not None:
            cmd.append("tos %s" % tos)

        if physdev:
            cmd.append("dev %s" % physdev)

        if localtunnelip:
            cmd.append("local %s" % localtunnelip)

        self.__execute_or_batch(utils.ip_cmd, " ".join(cmd))

    def get_vxlan_peers(self, dev, svcnodeip):
        cmd = "%s fdb show brport %s" % (utils.bridge_cmd, dev)
        cur_peers = []
        try:
            ps = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, close_fds=False)
            utils.enable_subprocess_signal_forwarding(ps, signal.SIGINT)
            output = subprocess.check_output(("grep", "00:00:00:00:00:00"), stdin=ps.stdout).decode()
            ps.wait()
            utils.disable_subprocess_signal_forwarding(signal.SIGINT)
            try:
                for l in output.split('\n'):
                    if "src_vni" in l:
                        continue
                    m = self.VXLAN_PEER_REGEX_PATTERN.search(l)
                    if m and m.group(1) != svcnodeip:
                        cur_peers.append(m.group(1))
            except Exception:
                self.logger.warning('error parsing ip link output')
        except subprocess.CalledProcessError as e:
            if e.returncode != 1:
                self.logger.error(str(e))
        finally:
            utils.disable_subprocess_signal_forwarding(signal.SIGINT)
        return cur_peers

    ###

    def link_add_xfrm(self, ifname, xfrm_name, xfrm_id):
        utils.exec_commandl(['ip', 'link', 'add', xfrm_name, 'type', 'xfrm', 'dev', ifname, 'if_id', xfrm_id])
        self.__update_cache_after_link_creation(xfrm_name, "xfrm")

    def link_add_openvswitch(self, ifname, kind):
        self.__update_cache_after_link_creation(ifname, kind)

    def link_set_protodown_reason_clag_on(self, ifname):
        utils.exec_command("%s link set dev %s protodown_reason clag on" % (utils.ip_cmd, ifname))

    def link_set_protodown_reason_clag_off(self, ifname):
        utils.exec_command("%s link set dev %s protodown_reason clag off" % (utils.ip_cmd, ifname))

    def link_set_protodown_reason_frr_on(self, ifname):
        utils.exec_command("%s link set dev %s protodown_reason frr on" % (utils.ip_cmd, ifname))

    def link_set_protodown_reason_frr_off(self, ifname):
        utils.exec_command("%s link set dev %s protodown_reason frr off" % (utils.ip_cmd, ifname))

    ############################################################################
    # TUNNEL
    ############################################################################

    def tunnel_create(self, tunnelname, mode, attrs=None, link_exists=False):
        if link_exists:
            op = "change"
        else:
            op = "add"

        cmd = []
        if "6" in mode:
            cmd.append("-6")

        if mode in ["gretap"]:
            cmd.append("link %s %s type %s" % (op, tunnelname, mode))
        else:
            cmd.append("tunnel %s %s mode %s" % (op, tunnelname, mode))

        if attrs:
            for k, v in attrs.items():
                cmd.append(k)
                if v:
                    cmd.append(v)

        utils.exec_command("%s %s" % (utils.ip_cmd, " ".join(cmd)))
        self.__update_cache_after_link_creation(tunnelname, mode)

    def tunnel_change(self, tunnelname, attrs=None):
        """ tunnel change function """
        if not self.cache.link_exists(tunnelname):
            return
        cmd = ["tunnel change %s" % tunnelname]
        if attrs:
            for k, v in attrs.items():
                cmd.append(k)
                if v:
                    cmd.append(v)
        self.__execute_or_batch(utils.ip_cmd, " ".join(cmd))

    ############################################################################
    # Wireguard
    ############################################################################
    def wireguard_create(self, tunnelname, wireguard_config_file_path):
        # create the kernel interface
        utils.exec_command("%s link add %s type wireguard" % (utils.ip_cmd, tunnelname))

        # configure wireguard
        cmd = "%s setconf %s %s" % (utils.wireguard_cmd, tunnelname, wireguard_config_file_path)
        self.logger.info("Setting up wg: ", cmd)
        utils.exec_command(cmd)

        self.__update_cache_after_link_creation(tunnelname, "wireguard")

    def wireguard_update(self, tunnelname, wireguard_config_file_path):
        cmd = "%s setconf %s %s" % (utils.wireguard_cmd, tunnelname, wireguard_config_file_path)
        self.logger.info("Setting up wg: ", cmd)
        utils.exec_command(cmd)

    ############################################################################
    # ADDRESS
    ############################################################################

    def addr_flush(self, ifname):
        if self.cache.link_has_ip(ifname):
            self.__execute_or_batch(utils.ip_cmd, "addr flush dev %s" % ifname)

    def link_set_ipv6_addrgen_dry_run(self, ifname, addrgen, link_created):
        addrgen_str = "none" if addrgen else "eui64"
        self.link_down(ifname)
        self.__execute_or_batch(utils.ip_cmd, "link set dev %s addrgenmode %s" % (ifname, addrgen_str))
        self.link_up(ifname)

    def link_set_ipv6_addrgen(self, ifname, addrgen, link_created):
        """
        IFLA_INET6_ADDR_GEN_MODE values:
        0 = eui64
        1 = none

        :param ifname:
        :param addrgen:
        :param link_created:
        :return:
        """
        cached_ipv6_addr_gen_mode = self.cache.get_link_ipv6_addrgen_mode(ifname)

        if cached_ipv6_addr_gen_mode == addrgen:
            return True

        disabled_ipv6 = self.sysfs.get_ipv6_conf_disable_ipv6(ifname)

        if disabled_ipv6:
            self.logger.info("%s: cannot set addrgen: ipv6 is disabled on this device" % ifname)
            return False

        if link_created:
            link_mtu = self.sysfs.link_get_mtu(ifname)
        else:
            link_mtu = self.cache.get_link_mtu(ifname)

        if link_mtu < 1280:
            self.logger.info("%s: ipv6 addrgen is disabled on device with MTU "
                             "lower than 1280 (current mtu %s): cannot set addrgen %s"
                             % (ifname, link_mtu, "off" if addrgen else "on"))
            return False

        if not link_created:
            # When setting addrgenmode it is necessary to flap the macvlan
            # device. After flapping the device we also need to re-add all
            # the user configuration. The best way to add the user config
            # is to flush our internal address cache
            self.cache.address_flush_link(ifname)

        is_link_up = self.cache.link_is_up(ifname)

        if is_link_up:
            self.link_down_force(ifname)

        self.__execute_or_batch(
            utils.ip_cmd,
            "link set dev %s addrgenmode %s" % (ifname, Link.ifla_inet6_addr_gen_mode_dict.get(addrgen))
        )

        if is_link_up:
            self.link_up_force(ifname)

        return True

    @staticmethod
    def __compare_user_config_vs_running_state(running_addrs, user_addrs):
        ip4 = []
        ip6 = []

        for ip in user_addrs or []:
            if ip.version == 6:
                ip6.append(ip)
            else:
                ip4.append(ip)

        running_ipobj = []
        for ip in running_addrs or []:
            running_ipobj.append(ip)

        return running_ipobj == (ip4 + ip6)

    def add_addresses(self, ifacobj, ifname, address_list, purge_existing=False, metric=None, with_address_virtual=False):
        if purge_existing:
            running_address_list = self.cache.get_managed_ip_addresses(
                ifname,
                [ifacobj],
                with_address_virtual=with_address_virtual
            )

            if self.__compare_user_config_vs_running_state(running_address_list, address_list):
                return

            # if primary address is not same, there is no need to keep any - reset all addresses
            if running_address_list and address_list and address_list[0] != running_address_list[0]:
                skip = []
            else:
                skip = address_list

            for addr in running_address_list or []:
                try:
                    if addr in skip:
                        continue
                    self.__execute_or_batch(utils.ip_cmd, "addr del %s dev %s" % (addr, ifname))
                except Exception as e:
                    self.logger.warning("%s: removing ip address failed: %s" % (ifname, str(e)))
        for addr in address_list:
            try:
                if metric:
                    self.__execute_or_batch(utils.ip_cmd, "addr add %s dev %s metric %s" % (addr, ifname, metric))
                else:
                    self.__execute_or_batch(utils.ip_cmd, "addr add %s dev %s" % (addr, ifname))
            except Exception as e:
                self.logger.error("%s: add_address: %s" % (ifname, str(e)))

    ############################################################################
    # BRIDGE
    ############################################################################

    @staticmethod
    def bridge_set_stp(bridge, stp_state):
        utils.exec_command("%s stp %s %s" % (utils.brctl_cmd, bridge, stp_state))

    @staticmethod
    def bridge_fdb_show_dev(dev):
        try:
            fdbs = {}
            output = utils.exec_command("%s fdb show dev %s" % (utils.bridge_cmd, dev))
            if output:
                for fdb_entry in output.splitlines():
                    try:
                        entries = fdb_entry.split()
                        fdbs.setdefault(entries[2], []).append(entries[0])
                    except Exception:
                        pass
            return fdbs
        except Exception:
            return None

    @staticmethod
    def bridge_fdb_show_dev_raw_with_filters(dev, filters):
        try:
            output = utils.exec_command("%s fdb show dev %s" % (utils.bridge_cmd, dev)).splitlines()
            filtered_output = []
            for l in output:
                filter_present = True
                for f in filters:
                    if f not in l:
                        filter_present = False
                if filter_present:
                    filtered_output.append(l)
            return filtered_output
        except Exception:
            return None

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
    def bridge_fdb_add_src_vni(dev, src_vni, dst_ip):
        """
            bridge fdb add dev $dev 00:00:00:00:00:00 src_vni $src_vni dst $dst_ip static self
        """
        utils.exec_command(
            "%s fdb add dev %s 00:00:00:00:00:00 src_vni %s dst %s permanent self"
            % (
                utils.bridge_cmd,
                dev,
                src_vni,
                dst_ip
            )
        )

    @staticmethod
    def bridge_fdb_append(dev, address, vlan=None, bridge=True, remote=None, src_vni=None):
        cmd = ["%s fdb append %s dev %s" % (utils.bridge_cmd, address, dev)]

        if bridge:
            cmd.append("self")

        if vlan:
            cmd.append("vlan %s" % vlan)

        if remote:
            cmd.append("dst %s" % remote)

        if src_vni:
            cmd.append("src_vni %s" % src_vni)

        utils.exec_command(" ".join(cmd))

    @staticmethod
    def bridge_fdb_del_src_vni(dev, mac, src_vni):
        utils.exec_command(
            "%s fdb del %s dev %s src_vni %s"
            % (
                utils.bridge_cmd,
                mac,
                dev,
                src_vni
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

    @staticmethod
    def bridge_fdb_del_raw(dev, args):
        utils.exec_command("%s fdb del dev %s %s" % (utils.bridge_cmd, dev, args))

    @staticmethod
    def bridge_vlan_del_vid_list(ifname, vids):
        if not vids:
            return
        for v in vids:
            utils.exec_command(
                "%s vlan del vid %s dev %s" % (utils.bridge_cmd, v, ifname)
            )

    def bridge_vlan_del_vid_list_self(self, ifname, vids, is_bridge=True):
        target = "self" if is_bridge else ""
        for v in vids:
            self.__execute_or_batch(
                utils.bridge_cmd,
                "vlan del vid %s dev %s %s" % (v, ifname, target)
            )

    def bridge_vlan_del_vlan_tunnel_info(self, ifname, vids, vnis):
        self.__execute_or_batch(
            utils.bridge_cmd,
            "vlan del dev %s vid %s tunnel_info id %s" % (
                ifname, vids, vnis
            )
        )

    def bridge_vlan_add_vlan_tunnel_info(self, ifname, vids, vnis):
        try:
            self.__execute_or_batch(
                utils.bridge_cmd,
                "vlan add dev %s vid %s tunnel_info id %s" % (
                    ifname, vids, vnis
                )
            )
        except Exception as e:
            if "exists" not in str(e).lower():
                self.logger.error(e)

    def bridge_vlan_tunnel_show(self, ifname):
        tunnel_info = {}
        try:
            for entry in utils.exec_command("%s vlan tunnel dev %s" % (utils.bridge_cmd, ifname)).splitlines()[1:]:

                if not entry:
                    continue

                entry_list = entry.split()
                length = len(entry_list)

                if length > 2:
                    # if len == 3, we need to remove the ifname from the list
                    # $ bridge vlan tunnel show dev vxlan42
                    # port    vlan ids        tunnel id
                    # vxlan42   1042    1542
                    entry_list = entry_list[1:]

                if length < 2:
                    continue

                vnis = utils.ranges_to_ints([entry_list[0]])
                tunnel_ids = utils.ranges_to_ints([entry_list[1]])

                for vni, tunnel_id in zip(vnis, tunnel_ids):
                    tunnel_info[int(vni)] = int(tunnel_id)

        except Exception as e:
            self.logger.debug("iproute2: bridge vlan tunnel dev %s: %s" % (ifname, str(e)))
        return tunnel_info

    @staticmethod
    def bridge_vlan_add_vid_list(ifname, vids):
        for v in vids:
            utils.exec_command(
                "%s vlan add vid %s dev %s" % (utils.bridge_cmd, v, ifname)
            )

    def bridge_vlan_add_vid_list_self(self, ifname, vids, is_bridge=True):
        target = "self" if is_bridge else ""
        for v in vids:
            self.__execute_or_batch(
                utils.bridge_cmd,
                "vlan add vid %s dev %s %s" % (v, ifname, target)
            )

    def bridge_vlan_del_vid_list_self(self, ifname, vids, is_bridge=True):
        target = "self" if is_bridge else ""
        for v in vids:
            self.__execute_or_batch(
                utils.bridge_cmd,
                "vlan del vid %s dev %s %s" % (v, ifname, target)
            )

    def bridge_vlan_del_pvid(self, ifname, pvid):
        self.__execute_or_batch(
            utils.bridge_cmd,
            "vlan del vid %s untagged pvid dev %s" % (pvid, ifname)
        )

    def bridge_vlan_add_pvid(self, ifname, pvid):
        self.__execute_or_batch(
            utils.bridge_cmd,
            "vlan add vid %s untagged pvid dev %s" % (pvid, ifname)
        )

    def bridge_del_mcqv4src(self, bridge, vlan):
        try:
            vlan = int(vlan)
        except Exception as e:
            self.logger.info("%s: del mcqv4src vlan: invalid parameter %s: %s"
                             % (bridge, vlan, str(e)))
            return
        utils.exec_command("%s delmcqv4src %s %d" % (utils.brctl_cmd, bridge, vlan))

    def bridge_set_mcqv4src(self, bridge, vlan, mcquerier):
        try:
            vlan = int(vlan)
        except Exception as e:
            self.logger.info("%s: set mcqv4src vlan: invalid parameter %s: %s" % (bridge, vlan, str(e)))
            return
        if vlan == 0 or vlan > 4095:
            self.logger.warning("mcqv4src vlan '%d' invalid range" % vlan)
            return

        ip = mcquerier.split(".")
        if len(ip) != 4:
            self.logger.warning("mcqv4src '%s' invalid IPv4 address" % mcquerier)
            return
        for k in ip:
            if not k.isdigit() or int(k, 10) < 0 or int(k, 10) > 255:
                self.logger.warning("mcqv4src '%s' invalid IPv4 address" % mcquerier)
                return

        utils.exec_command("%s setmcqv4src %s %d %s" % (utils.brctl_cmd, bridge, vlan, mcquerier))

    ############################################################################
    # ROUTE
    ############################################################################

    @staticmethod
    def route_add_gateway(ifname, gateway, vrf=None, metric=None, onlink=True):
        if not gateway:
            return

        if not vrf:
            cmd = "%s route replace default via %s proto kernel" % (utils.ip_cmd, gateway)
        else:
            cmd = "%s route replace table %s default via %s proto kernel" % (utils.ip_cmd, vrf, gateway)

        if metric:
            cmd += " metric %s" % metric

        cmd += " dev %s" % ifname

        if onlink:
            cmd += " onlink"

        utils.exec_command(cmd)

    @staticmethod
    def route_del_gateway(ifname, gateway, vrf=None, metric=None):
        """
        delete default gw
        we don't need a DRYRUN handler here as utils.exec_command should have one
        """
        if not gateway:
            return

        if not vrf:
            cmd = "%s route del default via %s proto kernel" % (utils.ip_cmd, gateway)
        else:
            cmd = "%s route del table %s default via %s proto kernel" % (utils.ip_cmd, vrf, gateway)

        if metric:
            cmd += " metric %s" % metric

        cmd += " dev %s" % ifname
        utils.exec_command(cmd)

    def fix_ipv6_route_metric(self, ifaceobj, macvlan_ifacename, ips):
        vrf_table = None

        if ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE:
            try:
                for upper_iface in ifaceobj.upperifaces:
                    vrf_table = self.cache.get_vrf_table(upper_iface)
                    if vrf_table:
                        break
            except Exception:
                pass

        ip_route_del = []
        for ip in ips:
            ip_network_obj = ipaddress.ip_network(ip)

            if ip_network_obj.version == 6:
                route_prefix = '%s/%d' % (ip_network_obj.network, ip_network_obj.prefixlen)

                if vrf_table:
                    self.__execute_or_batch(
                        utils.ip_cmd,
                        "route del %s table %s dev %s" % (route_prefix, vrf_table, macvlan_ifacename)
                    )
                else:
                    self.__execute_or_batch(
                        utils.ip_cmd,
                        "route del %s dev %s" % (route_prefix, macvlan_ifacename)
                    )

                ip_route_del.append((route_prefix, vrf_table))

        for ip, vrf_table in ip_route_del:
            if vrf_table:
                self.__execute_or_batch(
                    utils.ip_cmd,
                    "route add %s table %s dev %s proto kernel metric 9999" % (ip, vrf_table, macvlan_ifacename)
                )
            else:
                self.__execute_or_batch(
                    utils.ip_cmd,
                    "route add %s dev %s proto kernel metric 9999" % (ip, macvlan_ifacename)
                )

    def ip_route_get_dev(self, prefix, vrf_master=None):
        try:
            if vrf_master:
                cmd = "%s route get %s vrf %s" % (utils.ip_cmd, prefix, vrf_master)
            else:
                cmd = "%s route get %s" % (utils.ip_cmd, prefix)

            output = utils.exec_command(cmd)
            if output:
                rline = output.splitlines()[0]
                if rline:
                    rattrs = rline.split()
                    return rattrs[rattrs.index("dev") + 1]
        except Exception as e:
            self.logger.debug("ip_route_get_dev: failed .. %s" % str(e))
        return None

    def bridge_vni_update(self, vxlandev, vnisd):
        for vr, g in vnisd.items():
            cmd_args = "vni add dev %s vni %s" % (vxlandev, vr)
            if g:
                cmd_args += ' group %s' %(g)
            self.__execute_or_batch(utils.bridge_cmd, cmd_args)

    def bridge_vni_add(self, vxlan_device, vni):
        # bridge vni add understands ranges:
        # bridge vni add dev vx0 vni 10,11,20-30
        self.__execute_or_batch(
            utils.bridge_cmd,
            "vni add dev %s vni %s" % (vxlan_device, ','.join(vni.split()))
        )

    def bridge_vni_int_set_del(self, vxlan_device, vni):
        # bridge vni del understands ranges:
        # bridge vni del dev vx0 vni 10,11,20-30
        self.__execute_or_batch(
            utils.bridge_cmd,
            "vni del dev %s vni %s" % (vxlan_device, ','.join([str(x) for x in vni]))
        )

    def bridge_vni_del_list(self, vxlandev, vnis):
        cmd_args = "vni del dev %s vni %s" % (vxlandev, ','.join(vnis))
        self.__execute_or_batch(utils.bridge_cmd, cmd_args)

    def compress_vnifilter_into_ranges(self, vnis_ints, vnisd):
        vbegin = 0
        vend = 0
        vnisd_ranges = {}
        for v, g in vnisd.items():
            if v not in vnis_ints:
                continue
            if vbegin == 0:
                vbegin = v
                vend = v
                lastg = g
                continue
            elif ((v - vend) == 1 and g == lastg):
                vend = v
                continue
            else:
                if vend > vbegin:
                    range = '%d-%d' %(vbegin, vend)
                    vnisd_ranges[range] = lastg
                else:
                    vnisd_ranges['%s' %vbegin] = lastg
            vbegin = v
            vend = v
            lastg = g

        if vbegin:
                if vend > vbegin:
                    range = '%d-%d' %(vbegin, vend)
                    vnisd_ranges[range] = lastg
                else:
                    vnisd_ranges['%s' %vbegin] = lastg
        return vnisd_ranges

    def print_data(self, lprefix, data):
        self.logger.info(lprefix)
        self.logger.info(data)

    def bridge_link_update_vni_filter(self, vxlandev, vnisd):
        try:
            rvnisd = {}
            cmd = 'bridge -j -p vni show dev %s' %( vxlandev )
            output = utils.exec_command(cmd)
            if output:
                vnishow = json.loads(output.strip("\n"))
            self.logger.debug(vnishow)
            for s in vnishow:
                vlist = s.get('vnis')
                for v in vlist:
                    vstart = v.get('vni')
                    vend = v.get('vniEnd')
                    group = v.get('group')
                    if vend:
                        for tv in range(int(vstart), int(vend)+1):
                            if group:
                                rvnisd[tv] = group
                            else:
                                rvnisd[tv] = None
                    else:
                        if group:
                            rvnisd[int(vstart)] = group
                        else:
                            rvnisd[int(vstart)] = None
            vnis_int = vnisd.keys()
            rvnis_int = rvnisd.keys()

            (vnis_to_del, vnis_to_add) = utils.diff_ids(vnis_int,
                                                        rvnis_int)
            self.batch_start()
            if vnis_to_del:
                self.bridge_vni_del_list(vxlandev,
                        utils.compress_into_ranges(vnis_to_del))
            if vnis_to_add:
                self.bridge_vni_update(vxlandev,
                        self.compress_vnifilter_into_ranges(vnis_to_add, vnisd))

            # Do any vnis need group update ?
            # check remaining vnis
            vnis_rem = set(vnis_int)
            if vnis_to_add:
                vnis_rem = vnis_rem.difference(set(vnis_to_add))
            if vnis_to_del:
                vnis_rem = vnis_rem.difference(set(vnis_to_del))
            vnis_rem = list(vnis_rem)
            vnis_to_update = []
            if vnis_rem:
                for v in vnis_rem:
                    # check if group is not same
                    if vnisd.get(v) != rvnisd.get(v):
                        vnis_to_update.append(v)
            if vnis_to_update:
                self.bridge_vni_update(vxlandev,
                       self.compress_vnifilter_into_ranges(vnis_to_update, vnisd))
            self.batch_commit()
        except Exception as e:
            self.logger.error("bridge vni show failed .. %s" % str(e))
        return None
