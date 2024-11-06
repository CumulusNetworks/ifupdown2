#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
import glob
import ipaddress
import subprocess
import re

from collections import deque

try:
    from ifupdown2.lib.addon import AddonWithIpBlackList
    from ifupdown2.lib.iproute2 import IPRoute2
    from ifupdown2.ifupdown.iface import ifaceType, ifaceLinkKind, ifaceLinkPrivFlags, ifaceStatus
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.nlmanager.nlpacket import Link

    from ifupdown2.ifupdownaddons.modulebase import moduleBase

    import ifupdown2.nlmanager.ipnetwork as ipnetwork

    import ifupdown2.ifupdown.statemanager as statemanager
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.ifupdownconfig as ifupdownconfig
except ImportError:
    from lib.addon import AddonWithIpBlackList
    from lib.iproute2 import IPRoute2
    from ifupdown.iface import ifaceType, ifaceLinkKind, ifaceLinkPrivFlags, ifaceStatus
    from ifupdown.utils import utils

    from nlmanager.nlpacket import Link

    from ifupdownaddons.modulebase import moduleBase

    import nlmanager.ipnetwork as ipnetwork

    import ifupdown.statemanager as statemanager
    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.ifupdownconfig as ifupdownconfig


class addressvirtual(AddonWithIpBlackList, moduleBase):
    """  ifupdown2 addon module to configure virtual addresses """

    _modinfo = {
        "mhelp": "address module configures virtual addresses for interfaces. "
                 "It creates a macvlan interface for every mac ip address-virtual line",
        "attrs": {
            "address-virtual": {
                "help": "bridge router virtual mac and ips",
                "multivalue": True,
                "validvals": ["<mac-ip/prefixlen-list>", ],
                "example": ["address-virtual 00:11:22:33:44:01 11.0.1.1/24 11.0.1.2/24"]
            },
            "address-virtual-ipv6-addrgen": {
                "help": "enable disable ipv6 link addrgenmode",
                "validvals": ["on", "off"],
                "default": "on",
                "example": [
                    "address-virtual-ipv6-addrgen on",
                    "address-virtual-ipv6-addrgen off"
                ]
            },
            "vrrp": {
                "help": "VRRP support",
                "multivalue": True,
                "example": [
                    "vrrp 1 10.0.0.15/24 2001:0db8::0370:7334/64",
                    "vrrp 42 10.0.0.42/24"
                ]
            }
        }
    }

    DEFAULT_IP_METRIC = 1024
    ADDR_METRIC_SUPPORT = None

    def __init__(self, *args, **kargs):
        AddonWithIpBlackList.__init__(self)
        moduleBase.__init__(self, *args, **kargs)
        self.iproute2 = IPRoute2()
        self._bridge_fdb_query_cache = {}
        self.addressvirtual_with_route_metric = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr='addressvirtual_with_route_metric'
            ),
            default=True
        )
        self.mac_regex = re.compile(r"^([0-9A-Fa-f]{1,2}[:-]){5}([0-9A-Fa-f]{1,2})$")
        self.address_virtual_ipv6_addrgen_value_dict = {'on': 0, 'yes': 0, '0': 0, 'off': 1, 'no': 1, '1': 1}

        if addressvirtual.ADDR_METRIC_SUPPORT is None:
            try:
                cmd = [utils.ip_cmd, 'addr', 'help']
                self.logger.info('executing %s addr help' % utils.ip_cmd)

                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                addressvirtual.ADDR_METRIC_SUPPORT = '[ metric METRIC ]' in stderr.decode() or ''
                self.logger.info('address metric support: %s' % ('OK' if addressvirtual.ADDR_METRIC_SUPPORT else 'KO'))
            except Exception:
                addressvirtual.ADDR_METRIC_SUPPORT = False
                self.logger.info('address metric support: KO')

    @classmethod
    def get_addr_metric_support(cls):
        return cls.ADDR_METRIC_SUPPORT

    @classmethod
    def get_default_ip_metric(cls):
        return cls.DEFAULT_IP_METRIC

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None, old_ifaceobjs=False):
        if ifaceobj.get_attr_value('address-virtual') or ifaceobj.get_attr_value("vrrp"):
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.ADDRESS_VIRTUAL_SLAVE

    def _get_macvlan_prefix(self, ifaceobj):
        return '%s-v' %ifaceobj.name[0:13].replace('.', '-')

    def get_vrrp_prefix(self, ifname, family):
        return "vrrp%s-%s-" % (family, self.cache.get_ifindex(ifname))

    def _add_addresses_to_bridge(self, ifaceobj, hwaddress):
        # XXX: batch the addresses
        if ifaceobj.link_kind & ifaceLinkKind.VLAN:
            bridgename = ifaceobj.lowerifaces[0]
            vlan = self._get_vlan_id(ifaceobj)
            if self.cache.bridge_is_vlan_aware(bridgename):
                [self.iproute2.bridge_fdb_add(bridgename, addr,
                    vlan) for addr in hwaddress]
        elif self.cache.link_is_bridge(ifaceobj.name):
            [self.iproute2.bridge_fdb_add(ifaceobj.name, addr)
                    for addr in hwaddress]

    def _remove_addresses_from_bridge(self, ifaceobj, hwaddress):
        # XXX: batch the addresses
        if ifaceobj.link_kind & ifaceLinkKind.VLAN:
            bridgename = ifaceobj.lowerifaces[0]
            vlan = self._get_vlan_id(ifaceobj)
            if self.cache.bridge_is_vlan_aware(bridgename):
                for addr in hwaddress:
                    try:
                        self.iproute2.bridge_fdb_del(bridgename, addr, vlan)
                    except Exception as e:
                        self.logger.debug("%s: %s" %(ifaceobj.name, str(e)))
        elif self.cache.link_is_bridge(ifaceobj.name):
            for addr in hwaddress:
                try:
                    self.iproute2.bridge_fdb_del(ifaceobj.name, addr)
                except Exception as e:
                    self.logger.debug("%s: %s" %(ifaceobj.name, str(e)))

    def _get_bridge_fdbs(self, bridgename, vlan):
        fdbs = self._bridge_fdb_query_cache.get(bridgename)
        if not fdbs:
           fdbs = self.iproute2.bridge_fdb_show_dev(bridgename)
           if not fdbs:
              return
           self._bridge_fdb_query_cache[bridgename] = fdbs
        return fdbs.get(vlan)

    def _check_addresses_in_bridge(self, ifaceobj, hwaddress):
        """ If the device is a bridge, make sure the addresses
        are in the bridge """
        if ifaceobj.link_kind & ifaceLinkKind.VLAN:
            bridgename = ifaceobj.lowerifaces[0]
            vlan = self._get_vlan_id(ifaceobj)
            if self.cache.bridge_is_vlan_aware(bridgename):
                fdb_addrs = self._get_bridge_fdbs(bridgename, str(vlan))
                if not fdb_addrs:
                   return False
                hwaddress_int = utils.mac_str_to_int(hwaddress)
                for mac in fdb_addrs:
                    if utils.mac_str_to_int(mac) == hwaddress_int:
                        return True
                return False
        return True

    def _fix_connected_route(self, ifaceobj, vifacename, addr):
        #
        # XXX: Hack to make sure the primary address
        # is the first in the routing table.
        #
        # We use `ip route get` on the vrr network to see which
        # device the kernel returns. if it is the mac vlan device,
        # flap the macvlan device to adjust the routing table entry.
        #
        # flapping the macvlan device makes sure the macvlan
        # connected route goes through delete + add, hence adjusting
        # the order in the routing table.
        #
        try:
            self.logger.info('%s: checking route entry ...' %ifaceobj.name)

            # here we need to convert the ip address using the standard IPNetwork
            # object from the ipaddress not the custom IPNetwork object from
            # python3-nlmanager, because the standard IPNetwork will automatically
            # convert our ip address with prefixlen:
            # >>> ipaddress.ip_network("10.10.10.242/10", False)
            # IPv4Network('10.0.0.0/10')
            ip = ipaddress.ip_network(addr, False)

            # we don't support ip6 route fix yet
            if ip.version == 6:
                return

            if ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE:
                vrf_master = self.cache.get_master(ifaceobj.name)
            else:
                vrf_master = None

            dev = self.iproute2.ip_route_get_dev(ip.with_prefixlen, vrf_master=vrf_master)

            if dev and dev != ifaceobj.name:
                self.logger.info('%s: preferred routing entry ' %ifaceobj.name +
                                 'seems to be of the macvlan dev %s'
                                 %vifacename +
                                 ' .. flapping macvlan dev to fix entry.')
                self.iproute2.link_down(vifacename)
                self.iproute2.link_up(vifacename)
        except Exception as e:
            self.logger.debug('%s: fixing route entry failed (%s)'
                              % (ifaceobj.name, str(e)))

    def _get_macs_from_old_config(self, ifaceobj=None):
        """ This method returns a list of the mac addresses
        in the address-virtual attribute for the bridge. """
        maclist = []
        saved_ifaceobjs = statemanager.statemanager_api.get_ifaceobjs(ifaceobj.name)
        if not saved_ifaceobjs:
            return maclist
        # we need the old saved configs from the statemanager
        for oldifaceobj in saved_ifaceobjs:
            if not oldifaceobj.get_attr_value('address-virtual'):
                continue
            for av in oldifaceobj.get_attr_value('address-virtual'):
                macip = av.split()
                if len(macip) < 1:
                    self.logger.debug("%s: incorrect old address-virtual attrs '%s'"
                                      %(oldifaceobj.name,  av))
                    continue
                maclist.append(macip[0])
        return maclist

    def get_addressvirtual_ipv6_addrgen_user_conf(self, ifaceobj):
        ipv6_addrgen = ifaceobj.get_attr_value_first('address-virtual-ipv6-addrgen')

        if ipv6_addrgen:
            # IFLA_INET6_ADDR_GEN_MODE values:
            # 0 = eui64
            # 1 = none
            ipv6_addrgen_nl = self.address_virtual_ipv6_addrgen_value_dict.get(ipv6_addrgen.lower(), None)

            if ipv6_addrgen_nl is None:
                self.logger.warning('%s: invalid value "%s" for attribute address-virtual-ipv6-addrgen' % (ifaceobj.name, ipv6_addrgen))
            else:
                return True, ipv6_addrgen_nl

        else:
            # if user didn't configure ipv6-addrgen, should we reset to default?
            ipv6_addrgen_nl = self.address_virtual_ipv6_addrgen_value_dict.get(
                self.get_attr_default_value('address-virtual-ipv6-addrgen'),
                None
            )
            if ipv6_addrgen_nl is not None:
                return True, ipv6_addrgen_nl

        return False, None

    def _get_macvlan_ifnames(self, ifaceobj):
        macvlan_prefixes = (
            self._get_macvlan_prefix(ifaceobj),
            self.get_vrrp_prefix(ifaceobj.name, "4"),
            self.get_vrrp_prefix(ifaceobj.name, "6")
        )

        ifnames = set()

        for f in os.listdir("/sys/class/net/"):
            if f.startswith(macvlan_prefixes):
                ifnames.add(f)

        return ifnames

    def _remove_running_address_config(self, ifaceobj):
        if not self.cache.link_exists(ifaceobj.name):
            return
        hwaddress = []

        for macvlan_ifacename in self._get_macvlan_ifnames(ifaceobj):
            if not self.cache.link_exists(macvlan_ifacename) or self.cache.get_link_kind(macvlan_ifacename) != "macvlan":
                continue
            hwaddress.append(self.cache.get_link_address(macvlan_ifacename))
            self.netlink.link_del(macvlan_ifacename)
            # XXX: Also delete any fdb addresses. This requires, checking mac address
            # on individual macvlan interfaces and deleting the vlan from that.

        if any(hwaddress):
            self._remove_addresses_from_bridge(ifaceobj, hwaddress)

    def _remove_address_config(self, ifaceobj, address_virtual_list=None):
        if not address_virtual_list:
            self._remove_running_address_config(ifaceobj)
            return

        if not self.cache.link_exists(ifaceobj.name):
            return
        hwaddress = []
        av_idx = 0
        macvlan_prefix = self._get_macvlan_prefix(ifaceobj)
        for av in address_virtual_list:
            av_attrs = av.split()

            # Delete the macvlan device on this device
            macvlan_ifacename = '%s%d' %(macvlan_prefix, av_idx)
            self.netlink.link_del(os.path.basename(macvlan_ifacename))
            if av_attrs[0] != 'None':
                hwaddress.append(av_attrs[0])
            av_idx += 1
        self._remove_addresses_from_bridge(ifaceobj, hwaddress)

    def check_mac_address(self, ifaceobj, mac):
        if mac == 'none':
            self.logger.info("%s: The virtual mac address is set as none" %ifaceobj.name)
            return True
        try:
            if int(mac.split(":")[0], 16) & 1 :
                raise Exception("Multicast bit is set in the virtual mac address '%s'"
                               % mac)
            if not self.mac_regex.match(mac):
               raise Exception("'%s'" % mac)
            return True

        except Exception as e:
            self.logger.error("%s: Invalid virtual mac address: %s" % (ifaceobj.name, str(e)))
            return False

    def _fixup_vrf_enslavements(self, ifaceobj, ifaceobj_getfunc=None):
        """ This function fixes up address virtual interfaces
        (macvlans) on vrf slaves. Since this fixup is an overhead,
        this must be called only in cases when ifupdown2 is
        called on the vrf device or its slave and not when
        ifupdown2 is called for all devices. When all
        interfaces are brought up, the expectation is that
        the normal path will fix up a vrf device or its slaves"""

        if not ifaceobj_getfunc:
            return
        if ((ifaceobj.link_kind & ifaceLinkKind.VRF) and
            self.cache.link_exists(ifaceobj.name)):
            # if I am a vrf device and I have slaves
            # that have address virtual config,
            # enslave the slaves 'address virtual
            # interfaces (macvlans)' to myself:
            running_slaves = self.sysfs.link_get_lowers(ifaceobj.name)
            if running_slaves:
                # pick up any existing slaves of a vrf device and
                # look for their upperdevices and enslave them to the
                # vrf device:
                for s in running_slaves:
                    sobjs = ifaceobj_getfunc(s)
                    if (sobjs and
                        (sobjs[0].link_privflags & ifaceLinkPrivFlags.ADDRESS_VIRTUAL_SLAVE)):
                        # enslave all its upper devices to
                        # the vrf device
                        upperdevs = self.sysfs.link_get_uppers(sobjs[0].name)
                        if not upperdevs:
                            continue
                        for u in upperdevs:
                            # skip vrf device which
                            # will also show up in the
                            # upper device list
                            if u == ifaceobj.name:
                                continue
                            self.netlink.link_set_master(u, ifaceobj.name)
                            self.netlink.link_up(u)
        elif ((ifaceobj.link_privflags & ifaceLinkPrivFlags.ADDRESS_VIRTUAL_SLAVE) and
              (ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE) and
              self.cache.link_exists(ifaceobj.name)):
            # If I am a vrf slave and I have 'address virtual'
            # config, make sure my addrress virtual interfaces
            # (macvlans) are also enslaved to the vrf device
            vrfname = ifaceobj.get_attr_value_first('vrf')
            if not vrfname or not self.cache.link_exists(vrfname):
                return
            running_uppers = self.sysfs.link_get_uppers(ifaceobj.name)
            if not running_uppers:
                return
            macvlan_prefix = self._get_macvlan_prefix(ifaceobj)
            if not macvlan_prefix:
                return
            for u in running_uppers:
                if u == vrfname:
                    continue
                if u.startswith(macvlan_prefix):
                    self.netlink.link_set_master(u, vrfname)
                    self.netlink.link_up(u)

    def sync_macvlan_forwarding_state(self, ifname, macvlan_ifname):
        try:
            self.write_file(
                "/proc/sys/net/ipv4/conf/%s/forwarding" % macvlan_ifname,
                self.read_file_oneline("/proc/sys/net/ipv4/conf/%s/forwarding" % ifname)
            )
        except Exception as e:
            self.logger.info("%s: syncing macvlan forwarding with lower device forwarding state failed: %s" % (ifname, str(e)))

    def create_macvlan_and_apply_config(self, ifaceobj, intf_config_list, vrrp=False, ifaceobj_getfunc=None):
        """
        intf_config_list = [
            {
                "ifname": "macvlan_ifname",
                "hwaddress": "macvlan_hwaddress",
                "ips": [str(IPNetwork), ]
            },
        ]
        """
        hw_address_list = []

        if not intf_config_list:
            return hw_address_list

        user_configured_ipv6_addrgenmode, ipv6_addrgen_user_value = self.get_addressvirtual_ipv6_addrgen_user_conf(ifaceobj)
        purge_existing = False if ifupdownflags.flags.PERFMODE else True
        ifname = ifaceobj.name

        update_mtu = lower_iface_mtu = lower_iface_mtu_str = None
        if ifupdownconfig.config.get("adjust_logical_dev_mtu", "1") != "0" and ifaceobj.lowerifaces and intf_config_list:
            update_mtu = True

        if update_mtu:
            lower_iface_mtu = self.cache.get_link_mtu(ifaceobj.name)
            lower_iface_mtu_str = str(lower_iface_mtu)

        self.iproute2.batch_start()  # TODO: make sure we only do 1 ip link set down and set up (only one flap in the batch)

        for intf_config_dict in intf_config_list:
            link_created = False
            macvlan_ifname = intf_config_dict.get("ifname")
            macvlan_hwaddr = intf_config_dict.get("hwaddress")
            macvlan_mode = intf_config_dict.get("mode")
            ips = intf_config_dict.get("ips")

            if len(macvlan_ifname) > 15:
                self.logger.error("%s: macvlan name will exceed the 15 chars limitation - please rename the underlying interface (%s)" % (macvlan_ifname, ifname))
                ifaceobj.set_status(ifaceStatus.ERROR)
                continue

            is_ip6 = False
            for ip in ips:
                self.ip_blacklist_check(ifname, ip)
                ip_network_obj = ipnetwork.IPNetwork(ip)
                is_ip6 |= ip_network_obj.version == 6

            if not self.cache.link_exists(macvlan_ifname):
                # When creating VRRP macvlan with bridge mode, the kernel
                # return an error: 'Invalid argument' (22)
                # so for now we should only use the iproute2 API.
                # try:
                #    self.netlink.link_add_macvlan(ifname, macvlan_ifname)
                # except Exception:
                self.iproute2.link_add_macvlan(ifname, macvlan_ifname, macvlan_mode)
                self.sync_macvlan_forwarding_state(ifname, macvlan_ifname)
                link_created = True

            # Disable IPv6 duplicate address detection on VRR interfaces
            sysctl_prefix = "net.ipv6.conf.%s" % macvlan_ifname

            try:
                syskey = "%s.%s" % (sysctl_prefix, "enhanced_dad")
                if self.sysctl_get(syskey) != "0":
                    self.sysctl_set(syskey, "0")
            except Exception as e:
                self.logger.info("sysctl failure: operation not supported: %s" % str(e))

            for key, sysval in {
                "accept_dad": "0",
                "dad_transmits": "0"
            }.items():
                syskey = "%s.%s" % (sysctl_prefix, key)
                if self.sysctl_get(syskey) != sysval:
                    self.sysctl_set(syskey, sysval)

            # first thing we need to handle vrf enslavement
            if ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE:
                vrf_ifname = self.cache.get_master(ifaceobj.name)
                if vrf_ifname:
                    self.iproute2.link_set_master(macvlan_ifname, vrf_ifname)

            # If we are dealing with a VRRP macvlan we need to set protodown on
            # and set addrgenmode appropriately. For IPv4, a VRRP user only
            # needs the VIP (which is explicitly configured) so addrgenmode
            # should be NONE. For IPv6, a unique link-local address is needed
            # as the SIP for vrrp6 hellos, so addrgenmode should be RANDOM.
            if vrrp:
                try:
                    v6_ag_mode = Link.IN6_ADDR_GEN_MODE_RANDOM if is_ip6 else Link.IN6_ADDR_GEN_MODE_NONE
                    self.iproute2.link_set_ipv6_addrgen(
                        macvlan_ifname,
                        v6_ag_mode,
                        link_created
                    )
                except Exception as e:
                    self.logger.warning("%s: %s: ip link set dev %s addrgenmode none: "
                                     "operation not supported: %s" % (ifname, macvlan_ifname, macvlan_ifname, str(e)))
                try:
                    if link_created:
                        self.netlink.link_set_protodown_on(macvlan_ifname)
                except Exception as e:
                    self.logger.warning("%s: %s: ip link set dev %s protodown on: operation not supported: %s" % (ifname, macvlan_ifname, macvlan_ifname, str(e)))
            elif user_configured_ipv6_addrgenmode:
                self.iproute2.link_set_ipv6_addrgen(macvlan_ifname, ipv6_addrgen_user_value, link_created)

            if macvlan_hwaddr:
                self.iproute2.link_set_address_and_keep_down(
                    macvlan_ifname,
                    macvlan_hwaddr,
                    keep_down=ifaceobj.link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN
                )
                hw_address_list.append(macvlan_hwaddr)

            if self.addressvirtual_with_route_metric and self.get_addr_metric_support():
                metric = self.get_default_ip_metric()
            else:
                metric = None

            self.iproute2.add_addresses(
                ifaceobj,
                macvlan_ifname,
                ips,
                purge_existing,
                metric=metric
            )

            if ifaceobj.link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN:
                self.logger.info("%s: keeping macvlan down - link-down yes on lower device %s" % (macvlan_ifname, ifname))
                self.netlink.link_down(macvlan_ifname)

            # If link existed before, flap the link
            if not link_created:

                if not self.addressvirtual_with_route_metric or not self.get_addr_metric_support():
                    # if the system doesn't support ip addr set METRIC
                    # we need to do manually check the ordering of the ip4 routes
                    self._fix_connected_route(ifaceobj, macvlan_ifname, ips[0])

                if update_mtu:
                    update_mtu = False

                    try:
                        self.sysfs.link_set_mtu(macvlan_ifname, mtu_str=lower_iface_mtu_str, mtu_int=lower_iface_mtu)
                    except Exception as e:
                        self.logger.info('%s: failed to set mtu %s: %s' % (macvlan_ifname, lower_iface_mtu, e))

                # set macvlan device to up in anycase.
                # since we auto create them here..we are responsible
                # to bring them up here in the case they were brought down
                # by some other entity in the system.
                if not ifaceobj.link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN:
                    self.netlink.link_up(macvlan_ifname)
            else:
                try:
                    if not self.addressvirtual_with_route_metric or not self.get_addr_metric_support():
                        # if the system doesn't support ip addr set METRIC
                        # we need to do manually check the ordering of the ip6 routes
                        self.iproute2.fix_ipv6_route_metric(ifaceobj, macvlan_ifname, ips)
                except Exception as e:
                    self.logger.debug('fix_vrf_slave_ipv6_route_metric: failed: %s' % e)

        self.iproute2.batch_commit()
        return hw_address_list

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        if not ifupdownflags.flags.ALL:
            self._fixup_vrf_enslavements(ifaceobj, ifaceobj_getfunc)

        address_virtual_list = ifaceobj.get_attr_value('address-virtual')
        vrr_config_list = ifaceobj.get_attr_value("vrrp")

        if not address_virtual_list and not vrr_config_list:
            # XXX: address virtual is not present. In which case,
            # delete stale macvlan devices.
            self._remove_running_address_config(ifaceobj)
            return

        if ifaceobj.upperifaces and not ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE:
            self.log_error("%s: invalid placement of address-virtual/vrrp lines "
                           "(must be configured under an interface "
                           "with no upper interfaces or parent interfaces)"
                           % ifaceobj.name, ifaceobj)

        if not self.cache.link_exists(ifaceobj.name):
            return

        addr_virtual_macs = self.create_macvlan_and_apply_config(
            ifaceobj,
            self.translate_addrvirtual_user_config_to_list(
                ifaceobj,
                address_virtual_list
            ),
            ifaceobj_getfunc=ifaceobj_getfunc
        )

        vrr_macs = self.create_macvlan_and_apply_config(
            ifaceobj,
            self.translate_vrr_user_config_to_list(
                ifaceobj,
                vrr_config_list
            ),
            vrrp=True,
            ifaceobj_getfunc=ifaceobj_getfunc
        )

        hw_address_list = addr_virtual_macs + vrr_macs

        # check the statemanager for old configs.
        # We need to remove only the previously configured FDB entries
        oldmacs = self._get_macs_from_old_config(ifaceobj)
        # get a list of fdbs in old that are not in new config meaning they should
        # be removed since they are gone from the config
        removed_macs = [mac for mac in oldmacs if mac.lower() not in hw_address_list]
        self._remove_addresses_from_bridge(ifaceobj, removed_macs)
        # if ifaceobj is a bridge and bridge is a vlan aware bridge
        # add the vid to the bridge
        self._add_addresses_to_bridge(ifaceobj, hw_address_list)

    def translate_vrr_user_config_to_list(self, ifaceobj, vrr_config_list, ifquery=False):
        """
        If (IPv4 addresses provided):
            00:00:5e:00:01:<V>
        else if (IPv6 addresses provided):
            00:00:5e:00:02:<V>

        vrrp 1 10.0.0.15/24
        vrrp 1 2001:0db8::0370:7334/64

        # Translate:
        #       vrrp 255 10.0.0.15/24 10.0.0.2/1
        # To:
        # [
        #   {
        #        "ifname": "macvlan_ifname",
        #        "hwaddress": "macvlan_hwaddress",
        #        "mode": "macvlan_mode",
        #        "ips": [str(IPNetwork), ]
        #    },
        # ]
        """
        ifname = ifaceobj.name
        user_config_list = []

        for index, config in enumerate(vrr_config_list or []):
            vrrp_id, ip_addrs = config.split(" ", 1)
            hex_id = '%02x' % int(vrrp_id)
            ip4 = []
            ip6 = []

            for ip_addr in ip_addrs.split():
                ip_network_obj = ipnetwork.IPNetwork(ip_addr)
                is_ip6 = ip_network_obj.version == 6

                if is_ip6:
                    ip6.append(ip_network_obj)
                else:
                    ip4.append(ip_network_obj)

            macvlan_ip4_ifname = "%s%s" % (self.get_vrrp_prefix(ifname, "4"), vrrp_id)
            macvlan_ip6_ifname = "%s%s" % (self.get_vrrp_prefix(ifname, "6"), vrrp_id)

            if ip4 or ifquery:
                merged_with_existing_obj = False
                macvlan_ip4_mac = "00:00:5e:00:01:%s" % hex_id
                macvlan_ip4_mac_int = utils.mac_str_to_int(macvlan_ip4_mac)
                # if the vrr config is defined in different lines for the same ID
                # we need to save the ip4 and ip6 in the objects we previously
                # created, example:
                # vrrp 255 10.0.0.15/24 10.0.0.2/15
                # vrrp 255 fe80::a00:27ff:fe04:42/64
                for obj in user_config_list:
                    if obj.get("hwaddress_int") == macvlan_ip4_mac_int:
                        obj["ips"] += ip4
                        merged_with_existing_obj = True

                if not merged_with_existing_obj:
                    # if ip4 config wasn't merge with an existing object
                    # we need to insert it in our list
                    user_config_list.append({
                        "ifname": macvlan_ip4_ifname,
                        "hwaddress": macvlan_ip4_mac,
                        "hwaddress_int": macvlan_ip4_mac_int,
                        "mode": "bridge",
                        "ips": ip4,
                        "id": vrrp_id
                    })
            elif not ip4 and not ifquery and self.cache.link_exists(macvlan_ip4_ifname):
                # special check to see if all ipv4 were removed from the vrrp
                # configuration, if so we need to remove the associated macvlan
                self.netlink.link_del(macvlan_ip4_ifname)

            if ip6 or ifquery:
                merged_with_existing_obj = False
                macvlan_ip6_mac = "00:00:5e:00:02:%s" % hex_id
                macvlan_ip6_mac_int = utils.mac_str_to_int(macvlan_ip6_mac)
                # if the vrr config is defined in different lines for the same ID
                # we need to save the ip4 and ip6 in the objects we previously
                # created, example:
                # vrrp 255 10.0.0.15/24 10.0.0.2/15
                # vrrp 255 fe80::a00:27ff:fe04:42/64

                for obj in user_config_list:
                    if obj.get("hwaddress_int") == macvlan_ip6_mac_int:
                        obj["ips"] += ip6
                        merged_with_existing_obj = True

                if not merged_with_existing_obj:
                    # if ip6 config wasn't merge with an existing object
                    # we need to insert it in our list
                    user_config_list.append({
                        "ifname": macvlan_ip6_ifname,
                        "hwaddress": macvlan_ip6_mac,
                        "hwaddress_int": macvlan_ip6_mac_int,
                        "mode": "bridge",
                        "ips": ip6,
                        "id": vrrp_id
                    })
            elif not ip6 and not ifquery and self.cache.link_exists(macvlan_ip6_ifname):
                # special check to see if all ipv6 were removed from the vrrp
                # configuration, if so we need to remove the associated macvlan
                self.netlink.link_del(macvlan_ip6_ifname)

        if not ifquery:
            # check if vrrp attribute was removed/re-assigned
            old_vrr_ids = set()

            try:
                for old_ifaceobj in statemanager.statemanager_api.get_ifaceobjs(ifname) or []:
                    for vrr_config in old_ifaceobj.get_attr_value("vrrp") or []:
                        try:
                            old_vrr_ids.add(vrr_config.split()[0])
                        except Exception:
                            continue

                if old_vrr_ids:

                    for config in user_config_list:
                        try:
                            old_vrr_ids.remove(config["id"])
                        except KeyError:
                            pass

                    for id_to_remove in old_vrr_ids:
                        macvlan_ip4_ifname = "%s%s" % (self.get_vrrp_prefix(ifname, "4"), id_to_remove)
                        macvlan_ip6_ifname = "%s%s" % (self.get_vrrp_prefix(ifname, "6"), id_to_remove)

                        if self.cache.link_exists(macvlan_ip4_ifname):
                            self.netlink.link_del(macvlan_ip4_ifname)

                        if self.cache.link_exists(macvlan_ip6_ifname):
                            self.netlink.link_del(macvlan_ip6_ifname)

            except Exception as e:
                self.logger.debug("%s: vrrp: failure while removing unused macvlan(s): %s" % (ifname, e))

        return user_config_list

    def translate_addrvirtual_user_config_to_list(self, ifaceobj, address_virtual_list):
        """
        # Translate:
        #       address-virtual 00:11:22:33:44:01 2001:0db8::0370:7334/64 11.0.1.1/24 11.0.1.2/24
        # To:
        # [
        #   {
        #        "ifname": "macvlan_ifname",
        #        "hwaddress": "macvlan_hwaddress",
        #        "ips": [str(IPNetwork), ]
        #    },
        # ]
        """
        user_config_list = []

        if not address_virtual_list:
            return user_config_list

        macvlan_prefix = self._get_macvlan_prefix(ifaceobj)

        for index, addr_virtual in enumerate(address_virtual_list):
            av_attrs = addr_virtual.split()
            mac = av_attrs[0]
            if mac:
                mac = mac.lower()

            if not self.check_mac_address(ifaceobj, mac):
                continue

            config = {
                "ifname": "%s%d" % (macvlan_prefix, index),
                "mode": "private"
            }

            if mac != "none":
                config["hwaddress"] = mac
                config["hwaddress_int"] = utils.mac_str_to_int(mac)

            ip_network_obj_list = []
            for ip in av_attrs[1:]:
                ip_network_obj_list.append(ipnetwork.IPNetwork(ip))

            config["ips"] = ip_network_obj_list
            user_config_list.append(config)

        return user_config_list

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        try:
            self._remove_address_config(ifaceobj,
                         ifaceobj.get_attr_value('address-virtual'))

            #### VRR
            hwaddress = []
            for vrr_prefix in [self.get_vrrp_prefix(ifaceobj.name, "4"), self.get_vrrp_prefix(ifaceobj.name, "6")]:
                for macvlan_ifacename in glob.glob("/sys/class/net/%s*" % vrr_prefix):
                    macvlan_ifacename = os.path.basename(macvlan_ifacename)
                    if not self.cache.link_exists(macvlan_ifacename):
                        continue
                    hwaddress.append(self.cache.get_link_address(macvlan_ifacename))
                    self.netlink.link_del(macvlan_ifacename)
                    # XXX: Also delete any fdb addresses. This requires, checking mac address
                    # on individual macvlan interfaces and deleting the vlan from that.
            if any(hwaddress):
                self._remove_addresses_from_bridge(ifaceobj, hwaddress)
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):

        if not self.cache.link_exists(ifaceobj.name):
            return

        user_config_address_virtual_ipv6_addr = ifaceobj.get_attr_value_first('address-virtual-ipv6-addrgen')
        if user_config_address_virtual_ipv6_addr and user_config_address_virtual_ipv6_addr not in utils._string_values:
            ifaceobjcurr.update_config_with_status('address-virtual-ipv6-addrgen', user_config_address_virtual_ipv6_addr, 1)
            user_config_address_virtual_ipv6_addr = None

        address_virtual_list = ifaceobj.get_attr_value('address-virtual')

        macvlans_running_ipv6_addr_virtual = self.query_check_macvlan_config(
            ifaceobj,
            ifaceobjcurr,
            "address-virtual",
            user_config_address_virtual_ipv6_addr,
            virtual_addr_list_raw=address_virtual_list,
            macvlan_config_list=self.translate_addrvirtual_user_config_to_list(
                ifaceobj,
                address_virtual_list
            )
        )

        vrr_config_list = ifaceobj.get_attr_value("vrrp")

        macvlans_running_ipv6_addr_vrr = self.query_check_macvlan_config(
            ifaceobj,
            ifaceobjcurr,
            "vrrp",
            user_config_address_virtual_ipv6_addr,
            virtual_addr_list_raw=vrr_config_list,
            macvlan_config_list=self.translate_vrr_user_config_to_list(
                ifaceobj,
                vrr_config_list,
                ifquery=True
            )
        )

        macvlans_running_ipv6_addr = macvlans_running_ipv6_addr_virtual + macvlans_running_ipv6_addr_vrr
        if user_config_address_virtual_ipv6_addr:
            bool_user_ipv6_addrgen = utils.get_boolean_from_string(user_config_address_virtual_ipv6_addr)
            for running_ipv6_addrgen in macvlans_running_ipv6_addr:
                if (not bool_user_ipv6_addrgen) != running_ipv6_addrgen:
                    ifaceobjcurr.update_config_with_status('address-virtual-ipv6-addrgen', user_config_address_virtual_ipv6_addr, 1)
                    return
            ifaceobjcurr.update_config_with_status('address-virtual-ipv6-addrgen', user_config_address_virtual_ipv6_addr, 0)

    @staticmethod
    def compare_user_config_vs_running_state(running_addrs, user_addrs):
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

    def query_check_macvlan_config(self, ifaceobj, ifaceobjcurr, attr_name, user_config_address_virtual_ipv6_addr, virtual_addr_list_raw, macvlan_config_list):
        """
        macvlan_config_list = [
            {
                "ifname": "macvlan_ifname",
                "hwaddress": "macvlan_hwaddress",
                "ips": [str(IPNetwork), ]
            },
        ]
        """
        is_vrr = attr_name == "vrrp"
        macvlans_running_ipv6_addr = []

        if not virtual_addr_list_raw:
            return macvlans_running_ipv6_addr

        macvlan_config_queue = deque(macvlan_config_list)

        while macvlan_config_queue:

            ip4_config = None
            ip6_config = None

            config = macvlan_config_queue.popleft()

            if is_vrr:
                ip4_config = config
                ip6_config = macvlan_config_queue.popleft()

            macvlan_ifacename = config.get("ifname")

            if not self.cache.link_exists(macvlan_ifacename):
                ifaceobjcurr.update_config_with_status(attr_name, "", 1)
                continue

            macvlan_hwaddress = config.get("hwaddress")
            macvlan_hwaddress_int = config.get("hwaddress_int")

            if user_config_address_virtual_ipv6_addr:
                macvlans_running_ipv6_addr.append(self.cache.get_link_ipv6_addrgen_mode(macvlan_ifacename))

            # Check mac and ip address
            rhwaddress = ip4_macvlan_hwaddress = self.cache.get_link_address(macvlan_ifacename)
            raddrs = ip4_running_addrs = self.cache.get_managed_ip_addresses(
                ifname=macvlan_ifacename,
                ifaceobj_list=[ifaceobj],
                with_address_virtual=True
            )

            if not is_vrr:
                ips = config.get("ips")

                if not rhwaddress:
                    ifaceobjcurr.update_config_with_status(attr_name, "", 1)
                    continue

                try:
                    if utils.mac_str_to_int(rhwaddress) == macvlan_hwaddress_int \
                            and self.compare_user_config_vs_running_state(raddrs, ips) \
                            and self._check_addresses_in_bridge(ifaceobj, macvlan_hwaddress):
                        ifaceobjcurr.update_config_with_status(
                            attr_name,
                            " ".join(virtual_addr_list_raw),
                            0
                        )
                    else:
                        if raddrs:
                            address_virtual_value = "%s %s" % (rhwaddress, " ".join(raddrs))
                        else:
                            address_virtual_value = rhwaddress
                        ifaceobjcurr.update_config_with_status(attr_name, address_virtual_value, 1)
                except Exception as e:
                    self.logger.debug("addressvirtual: %s" % str(e))
                    if raddrs:
                        address_virtual_value = "%s %s" % (rhwaddress, " ".join(raddrs))
                    else:
                        address_virtual_value = rhwaddress

                    ifaceobjcurr.update_config_with_status(attr_name, address_virtual_value, 1)
            else:
                # VRRP

                ok = False
                # check macvlan ip4 hwaddress (only if ip4 were provided by the user)
                if not ip4_config.get("ips") or ip4_macvlan_hwaddress == ip4_config.get("hwaddress"):
                    ip6_macvlan_ifname = ip6_config.get("ifname")
                    ip6_macvlan_hwaddress = ip6_config.get("hwaddress")

                    # check macvlan ip6 hwaddress (only if ip6 were provided by the user)
                    if not ip6_config.get("ips") or self.cache.get_link_address_raw(ip6_macvlan_ifname) == ip6_config.get("hwaddress_int"):

                        # check all ip4
                        if self.compare_user_config_vs_running_state(
                                ip4_running_addrs,
                                ip4_config.get("ips")
                        ) and self._check_addresses_in_bridge(ifaceobj, ip4_macvlan_hwaddress):
                            ip6_running_addrs = self.cache.get_managed_ip_addresses(
                                ifname=ip6_macvlan_ifname,
                                ifaceobj_list=[ifaceobj],
                                with_address_virtual=True
                            )

                            # check all ip6
                            if self.compare_user_config_vs_running_state(
                                    ip6_running_addrs,
                                    ip6_config.get("ips")
                            ) and self._check_addresses_in_bridge(ifaceobj, ip6_macvlan_hwaddress):
                                ifaceobjcurr.update_config_with_status(
                                    attr_name,
                                    "%s %s" % (ip4_config.get("id"), " ".join(ip4_config.get("ips") + ip6_config.get("ips"))),
                                    0
                                )
                                ok = True

                if not ok:
                    ifaceobjcurr.update_config_with_status(
                        attr_name,
                        "%s %s" % (ip4_config.get("id"), " ".join(ip4_config.get("ips") + ip6_config.get("ips"))),
                        1
                    )

        return macvlans_running_ipv6_addr

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        macvlan_prefix = self._get_macvlan_prefix(ifaceobjrunning)
        address_virtuals = glob.glob("/sys/class/net/%s*" %macvlan_prefix)
        macvlans_ipv6_addrgen_list = []
        for av in address_virtuals:
            macvlan_ifacename = os.path.basename(av)
            rhwaddress = self.cache.get_link_address(macvlan_ifacename)
            raddress = self.cache.get_managed_ip_addresses(
                ifname=ifaceobjrunning.name,
                ifaceobj_list=ifaceobj_getfunc(ifaceobjrunning.name) or [],
                with_address_virtual=True
            )

            raddress = list(set(raddress))

            if not raddress:
                self.logger.warning('%s: no running addresses'
                                 %ifaceobjrunning.name)
                raddress = []

            ifaceobjrunning.update_config('address-virtual', '%s %s' %(rhwaddress, ' '.join([str(a) for a in raddress])))

            macvlans_ipv6_addrgen_list.append((macvlan_ifacename, self.cache.get_link_ipv6_addrgen_mode(macvlan_ifacename)))

        macvlan_count = len(address_virtuals)
        if not macvlan_count:
            return
        ipv6_addrgen = macvlans_ipv6_addrgen_list[0][1]

        for macvlan_ifname, macvlan_ipv6_addrgen in macvlans_ipv6_addrgen_list:
            if macvlan_ipv6_addrgen != ipv6_addrgen:
                # one macvlan has a different ipv6-addrgen configuration
                # we simply return, ifquery-running will print the macvlan
                # stanzas with the ipv6-addrgen on/off attribute
                return
        ifaceobjrunning.update_config('address-virtual-ipv6-addrgen', 'off' if ipv6_addrgen else 'on')

    _run_ops = {
        'up': _up,
        'down': _down,
        'query-checkcurr': _query_check,
        'query-running': _query_running
    }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return list(self._run_ops.keys())


    def run(self, ifaceobj, operation, query_ifaceobj=None,
            ifaceobj_getfunc=None, **extra_args):
        """ run vlan configuration on the interface object passed as argument

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
        if ifaceobj.type == ifaceType.BRIDGE_VLAN:
            return
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return

        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
