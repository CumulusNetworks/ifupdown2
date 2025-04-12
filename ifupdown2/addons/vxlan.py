#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import json

from ipaddress import IPv4Network, IPv4Address, AddressValueError, ip_address
try:
    import ifupdown2.nlmanager.ipnetwork as ipnetwork
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

    from ifupdown2.lib.addon import Vxlan, AddonException
    from ifupdown2.lib.nlcache import NetlinkCacheIfnameNotFoundError

    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdown.iface import ifaceLinkKind, ifaceLinkPrivFlags, ifaceStatus, iface
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.statemanager import statemanager_api as statemanager
    from ifupdown2.ifupdownaddons.modulebase import moduleBase

except ImportError:
    import nlmanager.ipnetwork as ipnetwork
    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags

    from lib.addon import Vxlan, AddonException
    from lib.nlcache import NetlinkCacheIfnameNotFoundError

    from nlmanager.nlmanager import Link

    from ifupdown.iface import ifaceLinkKind, ifaceLinkPrivFlags, ifaceStatus, iface
    from ifupdown.utils import utils
    from ifupdown.statemanager import statemanager_api as statemanager

    from ifupdownaddons.modulebase import moduleBase


class vxlan(Vxlan, moduleBase):
    _modinfo = {
        "mhelp": "vxlan module configures vxlan interfaces.",
        "attrs": {
            "vxlan-id": {
                "help": "vxlan id",
                "validrange": ["1", "16777214"],
                "required": True,
                "example": ["vxlan-id 100"]
            },
            "vxlan-local-tunnelip": {
                "help": "vxlan local tunnel ip",
                "validvals": ["<ipv4>"],
                "example": ["vxlan-local-tunnelip 172.16.20.103"]
            },
            "vxlan-svcnodeip": {
                "help": "vxlan svc node id",
                "validvals": ["<ipv4>"],
                "example": ["vxlan-svcnodeip 172.16.22.125"]
            },
            "vxlan-svcnodeip6": {
                "help": "vxlan svc node ip",
                "validvals": ["<ipv6>"],
                "example": ["vxlan-svcnodeip6 2001:DB8:8086:6502::"]
            },
            "vxlan-remoteip": {
                "help": "vxlan remote ip",
                "validvals": ["<ipv4>"],
                "example": ["vxlan-remoteip 172.16.22.127"],
                "multiline": True
            },
            "vxlan-learning": {
                "help": "vxlan learning yes/no",
                "validvals": ["yes", "no", "on", "off"],
                "example": ["vxlan-learning no"],
                "default": "yes"
            },
            "vxlan-ageing": {
                "help": "vxlan aging timer",
                "validrange": ["0", "4096"],
                "example": ["vxlan-ageing 300"],
                "default": "300"
            },
            "vxlan-purge-remotes": {
                "help": "vxlan purge existing remote entries",
                "validvals": ["yes", "no"],
                "example": ["vxlan-purge-remotes yes"],
            },
            "vxlan-port": {
                "help": "vxlan UDP port (transmitted to vxlan driver)",
                "example": ["vxlan-port 4789"],
                "validrange": ["1", "65536"],
                "default": "4789",
            },
            "vxlan-physdev": {
                "help": "vxlan physical device",
                "example": ["vxlan-physdev eth1"]
            },
            "vxlan-ttl": {
                "help": "specifies the TTL value to use in outgoing packets "
                        "(range 0..255), 0=auto",
                "default": "0",
                "validrange": ["0", "255"],
                "validvals": ["<number>", "auto"],
                "example": ['vxlan-ttl 42'],
            },
            "vxlan-tos": {
                "help": "specifies the ToS value (range 0..255), 1=inherit",
                "validrange": ["0", "255"],
                "validvals": ["<number>", "inherit"],
                "example": ['vxlan-tos 42'],
            },
            "vxlan-mcastgrp": {
                "help": "vxlan multicast group",
                "validvals": ["<ip>"],
                "example": ["vxlan-mcastgrp 172.16.22.127"],
            },
            "vxlan-mcastgrp6": {
                "help": "vxlan multicast group",
                "validvals": ["<ip6>"],
                "example": ["vxlan-mcastgrp ff02::15c"],
            },
            "vxlan-mcastgrp-map": {
                "help": "vxlan multicast group for single-vxlan device -"
                        "doesn't support multiline attribute",
                "example": ["vxlan-mcastgrp-map 1000=239.1.1.100 1001=239.1.1.200"],
            },
            "vxlan-vnifilter": {
                "help": "vxlan vni filter for single-vxlan device",
                "validvals": ["on", "off"],
                "default": "off",
                "example": ["vxlan-vnifilter yes"],
            },
            "vxlan-remoteip-map": {
                "help": "static HREP entries for static single vxlan device",
                "example": ["vxlan-remoteip-map 1000-1002=27.0.0.10-27.0.0.12"],
            },
            "vxlan-udp-csum": {
                "help": "whether to perform checksumming or not",
                "validvals": ["yes", "no"],
                "example": ["vxlan-udp-csum no"]
            },
            "vxlan-vni": {
                "help": "L3 VxLAN interface (vni list and range are supported)",
                "validvals": ["<number>"],
                "example": ["vxlan-vni 42"]
            }
        }
    }

    VXLAN_PHYSDEV_MCASTGRP_DEFAULT = "ipmr-lo"

    def __init__(self, *args, **kargs):
        Vxlan.__init__(self)
        moduleBase.__init__(self, *args, **kargs)

        self._vxlan_purge_remotes = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr="vxlan-purge-remotes"
            )
        )
        self._vxlan_local_tunnelip = None
        self._clagd_vxlan_anycast_ip = ""

        # If mcastgrp is specified we need to rely on a user-configred device (via physdev)
        # or via a policy variable "vxlan-physdev_mcastgrp". If the device doesn't exist we
        # create it as a dummy device. We need to keep track of the user configuration to
        # know when to delete this dummy device (when user remove mcastgrp from it's config)
        self.vxlan_mcastgrp_ref = False
        self.vxlan_physdev_mcast = policymanager.policymanager_api.get_module_globals(
            module_name=self.__class__.__name__,
            attr="vxlan-physdev-mcastgrp"
        ) or self.VXLAN_PHYSDEV_MCASTGRP_DEFAULT

        self.tvd_svd_mix_support = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr="vxlan-support-mix-dev-types"
            ),
            default=True
        )

        self.svd_tvd_errors = {}

    def reset(self):
        # in daemon mode we need to reset mcastgrp_ref for every new command
        # this variable has to be set in get_dependent_ifacenames
        self.vxlan_mcastgrp_ref = False

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        if self._is_vxlan_device(ifaceobj):
            if not ifaceobj.get_attr_value_first('vxlan-local-tunnelip') and not self._vxlan_local_tunnelip:
                self.logger.warning('%s: missing vxlan-local-tunnelip' % ifaceobj.name)
                return False

            self.check_and_raise_svd_tvd_errors(ifaceobj)

            return self.syntax_check_localip_anycastip_equal(
                ifaceobj.name,
                ifaceobj.get_attr_value_first('vxlan-local-tunnelip') or self._vxlan_local_tunnelip,
                self._clagd_vxlan_anycast_ip
            )
        return True

    def syntax_check_localip_anycastip_equal(self, ifname, local_ip, anycast_ip):
        try:
            if local_ip and anycast_ip and ipnetwork.IPNetwork(local_ip) == ipnetwork.IPNetwork(anycast_ip):
                self.logger.warning('%s: vxlan-local-tunnelip and clagd-vxlan-anycast-ip are identical (%s)'
                                    % (ifname, local_ip))
                return False
        except Exception:
            pass
        return True

    def get_dependent_ifacenames(self, ifaceobj, ifaceobjs_all=None, old_ifaceobjs=False):
        if ifaceobj.get_attr_value_first("bridge-vlan-vni-map"):
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.SINGLE_VXLAN

        if self._is_vxlan_device(ifaceobj):
            ifaceobj.link_kind |= ifaceLinkKind.VXLAN
            self._set_global_local_ip(ifaceobj)

            self.__check_and_tag_l3vxi(ifaceobj)

            if not old_ifaceobjs and not self.tvd_svd_mix_support:
                # mixing TVD and SVD is not supported - we need to warn the user
                # we use a dictionary to make sure to only warn once and prevent each
                # vxlan from being configured on the system

                if ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN:
                    self.single_vxlan_configured.add(ifaceobj.name)

                    if self.traditional_vxlan_configured:
                        self.svd_tvd_errors[ifaceobj.name] = (
                            "%s: mixing single-vxlan-device with tradional %s is not supported (TVD: %s)"
                            % (ifaceobj.name, "vxlans" if len(self.traditional_vxlan_configured) > 1 else "vxlan", ", ".join(self.traditional_vxlan_configured))
                        )
                elif ifaceobj.link_privflags & ifaceLinkPrivFlags.L3VXI:
                    pass
                else:
                    self.traditional_vxlan_configured.add(ifaceobj.name)

                    if self.single_vxlan_configured:
                        self.svd_tvd_errors[ifaceobj.name] = (
                            "%s: mixing traditional vxlan with single vxlan %s is not supported (SVD: %s)"
                            % (ifaceobj.name, "devices" if len(self.single_vxlan_configured) > 1 else "device", ", ".join(self.single_vxlan_configured))
                        )


            # if we detect a vxlan we check if mcastgrp is set (if so we set vxlan_mcastgrp_ref)
            # to know when to delete this device.
            if not self.vxlan_mcastgrp_ref and (ifaceobj.get_attr_value("vxlan-mcastgrp") or ifaceobj.get_attr_value("vxlan-mcastgrp-map")):
                self.vxlan_mcastgrp_ref = True

        elif ifaceobj.name == 'lo' and not old_ifaceobjs:
            clagd_vxlan_list = ifaceobj.get_attr_value('clagd-vxlan-anycast-ip')
            if clagd_vxlan_list:
                if len(clagd_vxlan_list) != 1:
                    self.log_warn('%s: multiple clagd-vxlan-anycast-ip lines, using first one'
                                  % (ifaceobj.name,))
                self._clagd_vxlan_anycast_ip = clagd_vxlan_list[0]

            self._set_global_local_ip(ifaceobj)

        # If we should use a specific underlay device for the VXLAN
        # tunnel make sure this device is set up before the VXLAN iface.
        physdev = ifaceobj.get_attr_value_first('vxlan-physdev')

        if physdev:
            return [physdev]

        return None

    def __check_and_tag_l3vxi(self, ifaceobj):
        if ifaceobj.get_attr_value_first("vxlan-vni"):
            # to validate the l3vxi interface we need to see the vrf attribute
            if ifaceobj.get_attr_value_first("vrf"):
                ifaceobj.link_privflags |= ifaceLinkPrivFlags.L3VXI
            else:
                self.logger.warning("%s: l3vxi misconfiguration? missing `vrf` attribute" % ifaceobj.name)

    def _set_global_local_ip(self, ifaceobj):
        vxlan_local_tunnel_ip = ifaceobj.get_attr_value_first('vxlan-local-tunnelip')
        if vxlan_local_tunnel_ip and not self._vxlan_local_tunnelip:
            self._vxlan_local_tunnelip = vxlan_local_tunnel_ip

    @staticmethod
    def _is_vxlan_device(ifaceobj):
        return ifaceobj.link_kind & ifaceLinkKind.VXLAN \
               or ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN \
               or ifaceobj.link_privflags & ifaceLinkPrivFlags.L3VXI \
               or ifaceobj.get_attr_value_first("vxlan-id") \
               or ifaceobj.get_attr_value_first("vxlan-vni") \
               or ifaceobj.get_attr_value_first("bridge-vlan-vni-map")

    def __get_vlxan_purge_remotes(self, ifaceobj):
        if not ifaceobj:
            return self._vxlan_purge_remotes
        purge_remotes = ifaceobj.get_attr_value_first('vxlan-purge-remotes')
        if purge_remotes:
            purge_remotes = utils.get_boolean_from_string(purge_remotes)
        else:
            purge_remotes = self._vxlan_purge_remotes
        return purge_remotes

    def get_vxlan_ttl_from_string(self, ttl_config):
        ttl = 0
        if ttl_config:
            if ttl_config.lower() == "auto":
                ttl = 0
            else:
                ttl = int(ttl_config)
        return ttl

    def get_vxlan_tos_from_string(self, tos_config):
        if tos_config:
            if tos_config.lower() == "inherit":
                return 1
            else:
                return int(tos_config)
        return None

    def __config_vxlan_id(self, ifname, ifaceobj, vxlan_id_str, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        """
        Get vxlan-id user config and check it's value before inserting it in our netlink dictionary
        :param ifname:
        :param ifaceobj:
        :param vxlan_id_str:
        :param user_request_vxlan_info_data:
        :param cached_vxlan_ifla_info_data:
        :return:
        """
        try:
            vxlan_id = int(vxlan_id_str)
            cached_vxlan_id = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_ID)

            if cached_vxlan_id and cached_vxlan_id != vxlan_id:
                self.log_error(
                    "%s: Cannot change running vxlan id (%s): Operation not supported"
                    % (ifname, cached_vxlan_id),
                    ifaceobj
                )
            user_request_vxlan_info_data[Link.IFLA_VXLAN_ID] = vxlan_id
        except ValueError:
            self.log_error("%s: invalid vxlan-id '%s'" % (ifname, vxlan_id_str), ifaceobj)

    def __get_vxlan_ageing_int(self, ifname, ifaceobj, link_exists):
        """
        Get vxlan-ageing user config or via policy, return integer value, None or raise on error
        :param ifname:
        :param ifaceobj:
        :param link_exists:
        :return:
        """
        vxlan_ageing_str = ifaceobj.get_attr_value_first("vxlan-ageing")
        try:
            if vxlan_ageing_str:
                return int(vxlan_ageing_str)

            vxlan_ageing_str = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__,
                attr="vxlan-ageing"
            )

            if not vxlan_ageing_str and link_exists:
                # if link doesn't exist we let the kernel define ageing
                vxlan_ageing_str = self.get_attr_default_value("vxlan-ageing")

                if vxlan_ageing_str:
                    return int(vxlan_ageing_str)
        except Exception:
            self.log_error("%s: invalid vxlan-ageing '%s'" % (ifname, vxlan_ageing_str), ifaceobj)

    def __config_vxlan_ageing(self, ifname, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        """
        Check user config vxlan-ageing and insert it in our netlink dictionary if needed
        """
        vxlan_ageing = self.__get_vxlan_ageing_int(ifname, ifaceobj, link_exists)

        if not vxlan_ageing or (link_exists and vxlan_ageing == cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_AGEING)):
            return

        self.logger.info("%s: set vxlan-ageing %s" % (ifname, vxlan_ageing))
        user_request_vxlan_info_data[Link.IFLA_VXLAN_AGEING] = vxlan_ageing

    def __config_vxlan_port(self, ifname, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        """
        Check vxlan-port user config, validate the integer value and insert it in the netlink dictionary if needed
        :param ifname:
        :param ifaceobj:
        :param link_exists:
        :param user_request_vxlan_info_data:
        :param cached_vxlan_ifla_info_data:
        :return:
        """
        vxlan_port_str = ifaceobj.get_attr_value_first("vxlan-port")
        try:
            if not vxlan_port_str:
                vxlan_port_str = policymanager.policymanager_api.get_attr_default(
                    module_name=self.__class__.__name__,
                    attr="vxlan-port"
                )

            try:
                vxlan_port = int(vxlan_port_str)
            except TypeError:
                # TypeError means vxlan_port was None
                # ie: not provided by the user or the policy
                vxlan_port = self.netlink.VXLAN_UDP_PORT
            except ValueError as e:
                self.logger.warning(
                    "%s: vxlan-port: using default %s: invalid configured value %s"
                    % (ifname, self.netlink.VXLAN_UDP_PORT, str(e))
                )
                vxlan_port = self.netlink.VXLAN_UDP_PORT

            cached_vxlan_port = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_PORT)

            if link_exists:
                if vxlan_port != cached_vxlan_port:
                    self.logger.warning(
                        "%s: vxlan-port (%s) cannot be changed - to apply the desired change please run: ifdown %s && ifup %s"
                        % (ifname, cached_vxlan_port, ifname, ifname)
                    )
                return

            self.logger.info("%s: set vxlan-port %s" % (ifname, vxlan_port))
            user_request_vxlan_info_data[Link.IFLA_VXLAN_PORT] = vxlan_port
        except Exception:
            self.log_error("%s: invalid vxlan-port '%s'" % (ifname, vxlan_port_str), ifaceobj)

    def __config_vxlan_tos(self, ifname, ifaceobj, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        """
        Get vxlan-tos from user config or policy, validate integer value and insert in netlink dict
        :param ifname:
        :param ifaceobj:
        :param user_request_vxlan_info_data:
        :param cached_vxlan_ifla_info_data:
        :return:
        """
        vxlan_tos_str = ifaceobj.get_attr_value_first("vxlan-tos")
        try:
            if vxlan_tos_str:
                vxlan_tos = self.get_vxlan_tos_from_string(vxlan_tos_str)
            else:
                vxlan_tos = self.get_vxlan_tos_from_string(
                    policymanager.policymanager_api.get_attr_default(
                        module_name=self.__class__.__name__,
                        attr="vxlan-tos"
                    )
                )

            if not vxlan_tos_str:
                return

            cached_ifla_vxlan_tos = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_TOS)

            if vxlan_tos != cached_ifla_vxlan_tos:

                if cached_ifla_vxlan_tos is not None:
                    self.logger.info("%s: set vxlan-tos %s (cache %s)" % (ifname, vxlan_tos_str, cached_ifla_vxlan_tos))
                else:
                    self.logger.info("%s: set vxlan-tos %s" % (ifname, vxlan_tos_str))

                user_request_vxlan_info_data[Link.IFLA_VXLAN_TOS] = vxlan_tos
        except Exception:
            self.log_error("%s: invalid vxlan-tos '%s'" % (ifname, vxlan_tos_str), ifaceobj)

    def __config_vxlan_ttl(self, ifname, ifaceobj, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        """
        Get vxlan-ttl from user config or policy, validate integer value and insert in netlink dict
        :param ifname:
        :param ifaceobj:
        :param user_request_vxlan_info_data:
        :param cached_vxlan_ifla_info_data:
        :return:
        """
        vxlan_ttl_str = ifaceobj.get_attr_value_first("vxlan-ttl")
        try:
            if vxlan_ttl_str:
                vxlan_ttl = self.get_vxlan_ttl_from_string(vxlan_ttl_str)
            else:
                vxlan_ttl = self.get_vxlan_ttl_from_string(
                    policymanager.policymanager_api.get_attr_default(
                        module_name=self.__class__.__name__,
                        attr="vxlan-ttl"
                    )
                )

            cached_ifla_vxlan_ttl = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_TTL)
            if vxlan_ttl != cached_ifla_vxlan_ttl:

                if cached_ifla_vxlan_ttl is not None:
                    self.logger.info("%s: set vxlan-ttl %s (cache %s)" % (ifname, vxlan_ttl_str if vxlan_ttl_str else vxlan_ttl, cached_ifla_vxlan_ttl))
                else:
                    self.logger.info("%s: set vxlan-ttl %s" % (ifname, vxlan_ttl_str if vxlan_ttl_str else vxlan_ttl))

                user_request_vxlan_info_data[Link.IFLA_VXLAN_TTL] = vxlan_ttl
                return vxlan_ttl
        except Exception:
            self.log_error("%s: invalid vxlan-ttl '%s'" % (ifname, vxlan_ttl_str), ifaceobj)

    def is_vxlan_on_a_clag_bridge(self, ifaceobj) -> bool:
        return bool(ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT and self._clagd_vxlan_anycast_ip and self.is_process_running('clagd'))

    def __config_vxlan_local_tunnelip(self, ifname, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        """
        Get vxlan-local-tunnelip user config or policy, validate ip address format and insert in netlink dict
        :param ifname:
        :param ifaceobj:
        :param link_exists:
        :param user_request_vxlan_info_data:
        :param cached_vxlan_ifla_info_data:
        :return:
        """
        local = ifaceobj.get_attr_value_first("vxlan-local-tunnelip")

        if not local and self._vxlan_local_tunnelip:
            local = self._vxlan_local_tunnelip

        if link_exists:
            cached_ifla_vxlan_local = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LOCAL)

            # on ifreload do not overwrite anycast_ip to individual ip
            # if clagd has modified
            if self._clagd_vxlan_anycast_ip and cached_ifla_vxlan_local:
                anycastip = ipnetwork.IPNetwork(self._clagd_vxlan_anycast_ip)

                if (
                    anycastip == cached_ifla_vxlan_local
                    # there's a change that the cache hasn't been updated in
                    # time to reflect the new anycast ip set by clagd, extra checks:
                    or self.is_vxlan_on_a_clag_bridge(ifaceobj)
                ):
                    local = cached_ifla_vxlan_local = anycastip
                    self.logger.info("%s: clagd-vxlan-anycast-ip (%s) inherited from loopback interface" % (ifname, local))
        else:
            cached_ifla_vxlan_local = None

        if not local:
            local = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__,
                attr="vxlan-local-tunnelip"
            )

        if local:
            try:
                local = ipnetwork.IPv4Address(local)

                if local.initialized_with_prefixlen:
                    self.logger.warning("%s: vxlan-local-tunnelip %s: netmask ignored" % (ifname, local))

            except Exception as e:
                raise AddonException("%s: invalid vxlan-local-tunnelip %s: %s" % (ifname, local, str(e)))


        if local:
            if local != cached_ifla_vxlan_local:
                self.logger.info("%s: set vxlan-local-tunnelip %s" % (ifname, local))
                user_request_vxlan_info_data[Link.IFLA_VXLAN_LOCAL] = local

                # if both local-ip and anycast-ip are identical the function prints a warning
                self.syntax_check_localip_anycastip_equal(ifname, local, self._clagd_vxlan_anycast_ip)
        elif cached_ifla_vxlan_local:
            self.logger.info("%s: removing vxlan-local-tunnelip (cache %s)" % (ifname, cached_ifla_vxlan_local))
            user_request_vxlan_info_data[Link.IFLA_VXLAN_LOCAL] = None

        return local

    def __get_vxlan_attribute(self, ifaceobj, attr_name):
        vxlan_attr_value = ifaceobj.get_attr_value_first(attr_name)

        if not vxlan_attr_value:
            vxlan_attr_value = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__,
                attr=attr_name
            )

        return vxlan_attr_value

    def __syntax_check_vxlan_mcast_vni(self, ifaceobj, m, vni):
        try:
            int(vni)
        except ValueError:
            self.log_error('%s: vxlan-mcastgrp-map "%s" vni format is invalid' % (ifaceobj.name, m))

    def __syntax_check_vxlan_mcast_vni_range(self, ifaceobj, m, vni_range):
        if len(vni_range) != 2:
            self.log_error('%s: vxlan-mcastgrp-map "%s" vni range format is invalid' % (ifaceobj.name, m))
        for vni in vni_range:
            self.__syntax_check_vxlan_mcast_vni(ifaceobj, m, vni)
        if int(vni_range[0]) >= int(vni_range[1]):
            self.log_error('%s: vxlan-mcastgrp-map "%s" vni range is invalid' % (ifaceobj.name, m))

    def __syntax_check_vxlan_mcast_grp(self, ifaceobj, m, grp):
        try:
            ip = IPv4Address(grp)
        except AddressValueError:
            self.log_error('%s: vxlan-mcastgrp-map "%s" group format is invalid' % (ifaceobj.name, m))
        if not ip.is_multicast:
            self.log_error('%s: vxlan-mcastgrp-map "%s" group is not multicast' % (ifaceobj.name, m))

    def __syntax_check_vxlan_mcast_grp_range(self, ifaceobj, m, grp_range):
        if len(grp_range) != 2:
            self.log_error('%s: vxlan-mcastgrp-map "%s" group format is invalid' % (ifaceobj.name, m))
        for grp in grp_range:
            self.__syntax_check_vxlan_mcast_grp(ifaceobj, m, grp)
        if int(IPv4Address(grp_range[0])) >= int(IPv4Address(grp_range[1])):
            self.log_error('%s: vxlan-mcastgrp-map "%s" group range is invalid' % (ifaceobj.name, m))

    def __syntax_check_vxlan_mcast_network(self, ifaceobj, m, network, len_vni):
        try:
            ip = IPv4Network(network)
            ip[0]
            ip[len_vni - 1]
        except IndexError:
            self.log_error('%s: vxlan-mcastgrp-map "%s" network range is insufficient' % (ifaceobj.name, m))
        except AddressValueError:
            self.log_error('%s: vxlan-mcastgrp-map "%s" network format is invalid' % (ifaceobj.name, m))
        if not ip.is_multicast:
            self.log_error('%s: vxlan-mcastgrp-map "%s" network is not multicast' % (ifaceobj.name, m))

    def __get_vxlan_mcastgrp_map(self, ifaceobj):
        maps = ifaceobj.get_attr_value('vxlan-mcastgrp-map')
        if not maps:
            maps = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__,
                attr='vxlan-mcastgrp-map'
            )
            return maps

        parsed_maps = {}
        for m_line in maps:
            # Cover single-line multi-entry case
            for m in m_line.split():
                m_parts = m.split('=')
                if len(m_parts) != 2:
                    self.log_error('%s: vxlan-mcastgrp-map %s format is invalid' % (ifaceobj.name, m))
                vni = m_parts[0]
                grp = m_parts[1]
                _range = "-"
                _network = "/"

                # One to one mapping case
                if _range not in vni and _range not in grp:
                    self.__syntax_check_vxlan_mcast_vni(ifaceobj, m, vni)
                    self.__syntax_check_vxlan_mcast_grp(ifaceobj, m, grp)
                    if int(vni) not in parsed_maps:
                        parsed_maps[int(vni)] = IPv4Address(grp)
                    else:
                        self.log_warn('%s: vxlan-mcastgrp-map %s vni %s duplicate' % (ifaceobj.name, vni, m))

                # Many VNI case
                if _range in vni:
                    v_parts = vni.split(_range)
                    self.__syntax_check_vxlan_mcast_vni_range(ifaceobj, m, v_parts)
                    vnis = list(range(int(v_parts[0]), int(v_parts[1]) + 1))

                    if _range not in grp and _network not in grp:
                        self.__syntax_check_vxlan_mcast_grp(ifaceobj, m, grp)
                        for i in vnis:
                            if i not in parsed_maps:
                                parsed_maps[i] = IPv4Address(grp)
                            else:
                                self.log_warn('%s: vxlan-mcastgrp-map %s vni %s duplicate' % (ifaceobj.name, vni, m))
                    else:
                        if _network in grp:
                            self.__syntax_check_vxlan_mcast_network(ifaceobj, m, grp, len(vnis))
                            network = IPv4Network(grp)
                            g_parts = [network[0], network[len(vnis) - 1]]
                        else:
                            g_parts = grp.split(_range)

                        self.__syntax_check_vxlan_mcast_grp_range(ifaceobj, m, g_parts)
                        grp_range = list(range(int(IPv4Address(g_parts[0])), int(IPv4Address(g_parts[1])) + 1))
                        if len(grp_range) != len(vnis):
                            self.log_error('%s: vxlan-mcastgrp-map "%s" range lengths do not match.'
                                           % (ifaceobj.name, m))

                        for v, g in zip(vnis, grp_range):
                            if v not in parsed_maps:
                                parsed_maps[v] = IPv4Address(g)
                            else:
                                self.log_warn('%s: vxlan-mcastgrp-map %s vni %s duplicate' % (ifaceobj.name, v, m))

        return parsed_maps

    def __config_vxlan_group(self, ifname, ifaceobj, link_exists, mcast_grp, group, physdev, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        """
        vxlan-mcastgrp and vxlan-svcnodeip are mutually exclusive
        this function validates ip format for both attribute and tries to understand
        what the user really want (remote or group option).

        :param ifname:
        :param ifaceobj:
        :param mcast_grp:
        :param group:
        :param physdev:
        :param user_request_vxlan_info_data:
        :param cached_vxlan_ifla_info_data:
        :return:
        """
        if mcast_grp and group:
            self.log_error("%s: both group (vxlan-mcastgrp %s) and "
                           "remote (vxlan-svcnodeip %s) cannot be specified"
                           % (ifname, mcast_grp, group), ifaceobj)

        attribute_name = "vxlan-svcnodeip"
        multicast_group_change = False

        if group:
            try:
                group = ipnetwork.IPv4Address(group)

                if group.initialized_with_prefixlen:
                    self.logger.warning("%s: vxlan-svcnodeip %s: netmask ignored" % (ifname, group))

            except Exception as e:
                raise AddonException("%s: invalid vxlan-svcnodeip %s: %s" % (ifname, group, str(e)))

            if group.ip.is_multicast:
                self.logger.warning("%s: vxlan-svcnodeip %s: invalid group address, "
                                    "for multicast IP please use attribute \"vxlan-mcastgrp\"" % (ifname, group))
                # if svcnodeip is used instead of mcastgrp we warn the user
                # if mcast_grp is not provided by the user we can instead
                # use the svcnodeip value
                if not physdev:
                    self.log_error("%s: vxlan: 'group' (vxlan-mcastgrp) requires 'vxlan-physdev' to be specified" % (ifname))

        elif mcast_grp:
            try:
                mcast_grp = ipnetwork.IPv4Address(mcast_grp)

                if mcast_grp.initialized_with_prefixlen:
                    self.logger.warning("%s: vxlan-mcastgrp %s: netmask ignored" % (ifname, mcast_grp))

            except Exception as e:
                raise AddonException("%s: invalid vxlan-mcastgrp %s: %s" % (ifname, mcast_grp, str(e)))

            if not mcast_grp.ip.is_multicast:
                self.logger.warning("%s: vxlan-mcastgrp %s: invalid group address, "
                                    "for non-multicast IP please use attribute \"vxlan-svcnodeip\""
                                    % (ifname, mcast_grp))
                # if mcastgrp is specified with a non-multicast address
                # we warn the user. If the svcnodeip wasn't specified by
                # the user we can use the mcastgrp value as svcnodeip
                if not group:
                    group = mcast_grp
                    mcast_grp = None
            else:
                attribute_name = "vxlan-mcastgrp"

            if mcast_grp:
                group = mcast_grp

                if not physdev:
                    self.log_error("%s: vxlan: 'group' (vxlan-mcastgrp) requires 'vxlan-physdev' to be specified" % (ifname))

        cached_ifla_vxlan_group = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_GROUP)

        if group != cached_ifla_vxlan_group:

            if not group:
                group = ipnetwork.IPNetwork("0.0.0.0")
                attribute_name = "vxlan-svcnodeip/vxlan-mcastgrp"

            self.logger.info("%s: set %s %s" % (ifname, attribute_name, group))
            user_request_vxlan_info_data[Link.IFLA_VXLAN_GROUP] = group

            # if the mcastgrp address is changed we need to signal this to the upper function
            # in this case vxlan needs to be down before applying changes then up'd
            multicast_group_change = True

            if link_exists:
                if cached_ifla_vxlan_group:
                    self.logger.info(
                        "%s: vxlan-mcastgrp configuration changed (cache %s): flapping vxlan device required"
                        % (ifname, cached_ifla_vxlan_group)
                    )
                else:
                    self.logger.info(
                        "%s: vxlan-mcastgrp configuration changed: flapping vxlan device required" % ifname
                    )

        return group, multicast_group_change

    def __config_vxlan_group6(self, ifname, ifaceobj, link_exists, mcast_grp, group, physdev, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        """
        vxlan-mcastgrp and vxlan-svcnodeip are mutually exclusive
        this function validates ip format for both attribute and tries to understand
        what the user really want (remote or group option).

        :param ifname:
        :param ifaceobj:
        :param mcast_grp:
        :param group:
        :param physdev:
        :param user_request_vxlan_info_data:
        :param cached_vxlan_ifla_info_data:
        :return:
        """
        if mcast_grp and group:
            self.log_error("%s: both group (vxlan-mcastgrp6 %s) and "
                           "remote (vxlan-svcnodeip6 %s) cannot be specified"
                           % (ifname, mcast_grp, group), ifaceobj)

        attribute_name = "vxlan-svcnodeip6"
        multicast_group_change = False

        if group:
            try:
                group = ipnetwork.IPv6Address(group)
            except Exception:
                try:
                    group_ip = ipnetwork.IPv6Network(group).ip
                    self.logger.warning("%s: vxlan-svcnodeip6 %s: netmask ignored" % (ifname, group))
                    group = group_ip
                except Exception:
                    raise AddonException("%s: invalid vxlan-svcnodeip6 %s: must be in ipv4 format" % (ifname, group))

            if group.is_multicast:
                self.logger.warning("%s: vxlan-svcnodeip6 %s: invalid group address, "
                                    "for multicast IP please use attribute \"vxlan-mcastgrp6\"" % (ifname, group))
                # if svcnodeip is used instead of mcastgrp we warn the user
                # if mcast_grp is not provided by the user we can instead
                # use the svcnodeip value
                if not physdev:
                    self.log_error("%s: vxlan: 'group' (vxlan-mcastgrp6) requires 'vxlan-physdev' to be specified" % (ifname))

        elif mcast_grp:
            try:
                mcast_grp = ipnetwork.IPv6Address(mcast_grp)
            except Exception:
                try:
                    group_ip = ipnetwork.IPv6Network(mcast_grp).ip
                    self.logger.warning("%s: vxlan-mcastgrp6 %s: netmask ignored" % (ifname, mcast_grp))
                    mcast_grp = group_ip
                except Exception:
                    raise AddonException("%s: invalid vxlan-mcastgrp6 %s: must be in ipv4 format" % (ifname, mcast_grp))

            if not mcast_grp.is_multicast:
                self.logger.warning("%s: vxlan-mcastgrp6 %s: invalid group address, "
                                    "for non-multicast IP please use attribute \"vxlan-svcnodeip6\""
                                    % (ifname, mcast_grp))
                # if mcastgrp is specified with a non-multicast address
                # we warn the user. If the svcnodeip wasn't specified by
                # the user we can use the mcastgrp value as svcnodeip
                if not group:
                    group = mcast_grp
                    mcast_grp = None
            else:
                attribute_name = "vxlan-mcastgrp6"

            if mcast_grp:
                group = mcast_grp

                if not physdev:
                    self.log_error("%s: vxlan: 'group' (vxlan-mcastgrp6) requires 'vxlan-physdev' to be specified" % (ifname))

        cached_ifla_vxlan_group = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_GROUP6)

        if group != cached_ifla_vxlan_group:

            if not group:
                group = ipnetwork.IPNetwork("::0", family=6)
                attribute_name = "vxlan-svcnodeip6/vxlan-mcastgrp6"

            self.logger.info("%s: set %s %s" % (ifname, attribute_name, group))
            user_request_vxlan_info_data[Link.IFLA_VXLAN_GROUP6] = group

            # if the mcastgrp address is changed we need to signal this to the upper function
            # in this case vxlan needs to be down before applying changes then up'd
            multicast_group_change = True

            if link_exists:
                if cached_ifla_vxlan_group:
                    self.logger.info(
                        "%s: vxlan-mcastgrp6 configuration changed (cache %s): flapping vxlan device required"
                        % (ifname, cached_ifla_vxlan_group)
                    )
                else:
                    self.logger.info(
                        "%s: vxlan-mcastgrp6 configuration changed: flapping vxlan device required" % ifname
                    )

        return group, multicast_group_change

    def __config_vxlan_learning(self, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        if not link_exists or not ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT:
            vxlan_learning = ifaceobj.get_attr_value_first('vxlan-learning')
            if not vxlan_learning:
                vxlan_learning = self.get_attr_default_value('vxlan-learning')
            vxlan_learning = utils.get_boolean_from_string(vxlan_learning)
        else:
            vxlan_learning = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LEARNING)

        if vxlan_learning != cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LEARNING):
            self.logger.info("%s: set vxlan-learning %s" % (ifaceobj.name, "on" if vxlan_learning else "off"))
            user_request_vxlan_info_data[Link.IFLA_VXLAN_LEARNING] = vxlan_learning

    def __config_vxlan_udp_csum(self, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        vxlan_udp_csum = ifaceobj.get_attr_value_first('vxlan-udp-csum')

        if not vxlan_udp_csum:
            vxlan_udp_csum = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__,
                attr="vxlan-udp-csum"
            )

        if not vxlan_udp_csum and not link_exists:
            return

        if not vxlan_udp_csum:
            vxlan_udp_csum = self.get_attr_default_value('vxlan-udp-csum')

        if vxlan_udp_csum:
            vxlan_udp_csum = utils.get_boolean_from_string(vxlan_udp_csum)
        else:
            return

        if vxlan_udp_csum != cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_UDP_CSUM):
            self.logger.info("%s: set vxlan-udp-csum %s" % (ifaceobj.name, "on" if vxlan_udp_csum else "off"))
            user_request_vxlan_info_data[Link.IFLA_VXLAN_UDP_CSUM] = vxlan_udp_csum

    def __get_vxlan_physdev(self, ifaceobj, mcastgrp, mcastgrp_map):
        """
        vxlan-physdev wrapper, special handling is required for mcastgrp is provided
        the vxlan needs to use a dummy or real device for tunnel endpoint communication
        This wrapper will get the physdev from user config or policy. IF the device
        doesnt exists we create a dummy device.

        :param ifaceobj:
        :param mcastgrp:
        :return physdev:
        """
        physdev = ifaceobj.get_attr_value_first("vxlan-physdev")

        # if the user provided a physdev we need to honor his config
        # or if mcastgrp wasn't specified we don't need to go further
        if physdev or (not mcastgrp and not mcastgrp_map):
            return physdev

        physdev = self.vxlan_physdev_mcast

        if not self.cache.link_exists(physdev):
            if mcastgrp_map:
                self.logger.info("%s: needs a dummy device (%s) to use for "
                                 "multicast termination (vxlan-mcastgrp-map %s)"
                                 % (ifaceobj.name, physdev, mcastgrp))
            else:
                self.logger.info("%s: needs a dummy device (%s) to use for "
                                 "multicast termination (vxlan-mcastgrp %s)"
                                 % (ifaceobj.name, physdev, mcastgrp))
            self.netlink.link_add_with_attributes(ifname=physdev, kind="dummy", ifla={Link.IFLA_MTU: 16000, Link.IFLA_LINKMODE: 1})
            self.netlink.link_up(physdev)

        return physdev

    def __config_vxlan_physdev(self, link_exists, ifaceobj, vxlan_physdev, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        if vxlan_physdev:
            try:
                vxlan_physdev_ifindex = self.cache.get_ifindex(vxlan_physdev)
            except NetlinkCacheIfnameNotFoundError:
                try:
                    vxlan_physdev_ifindex = int(self.sysfs.read_file_oneline("/sys/class/net/%s/ifindex" % vxlan_physdev))
                except Exception:
                    self.logger.error("%s: physdev %s doesn't exists" % (ifaceobj.name, vxlan_physdev))
                    return

            if vxlan_physdev_ifindex != cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LINK):
                self.logger.info("%s: set vxlan-physdev %s" % (ifaceobj.name, vxlan_physdev))
                user_request_vxlan_info_data[Link.IFLA_VXLAN_LINK] = vxlan_physdev_ifindex

                # if the vxlan exists we need to return True, meaning that the vxlan
                # needs to be flapped because we detected a vxlan-physdev change
                if link_exists:
                    self.logger.info("%s: vxlan-physdev configuration changed: flapping vxlan device required" % ifaceobj.name)
                    return True

        return False

    def __get_vxlan_remote_ip_map(self, ifaceobj):
        attr_name = "vxlan-remoteip-map"

        maps = ifaceobj.get_attr_value(attr_name)
        if not maps:
            maps = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__,
                attr=attr_name
            )
            if not maps:
                return {}

        parsed_maps = {}
        for m_line in maps:
            # Cover single-line multi-entry case
            for m in m_line.split():
                m_parts = m.split('=')
                if len(m_parts) != 2:
                    self.log_error('%s: %s %s format is invalid' % (ifaceobj.name, attr_name, m))

                vnis = m_parts[0]
                _range = "-"
                remote_ips = []

                for config_remote_ip in m_parts[1].split(","):
                    if _range in config_remote_ip:
                        ip_range = config_remote_ip.split("-")
                        try:
                            start = ip_address(ip_range[0])
                            end = ip_address(ip_range[1])
                        except Exception as e:
                            self.log_error("%s: %s: invalid ip range '%s': %s" % (ifaceobj.name, attr_name, config_remote_ip, e), ifaceobj)
                            return
                        remote_ips.extend([ipnetwork.ip_address(i) for i in range(int(start), int(end) + 1)])
                    else:
                        remote_ips.append(ipnetwork.ip_address(config_remote_ip))

                # vxlan-remoteip-map 42,84,1000-1005=10.0.0.1,10.0.0.42-45,222.0.0.1-5
                # higher priority is the comma
                for vni in utils.ranges_to_ints(vnis.split(",")) or []:
                    parsed_maps.setdefault(vni, []).extend(remote_ips)

        return parsed_maps

    def single_vxlan_device_vni_filter(self, ifaceobj, vxlan_mcast_grp):
        vnisd = {}
        for vlan_vni_map in ifaceobj.get_attr_value("bridge-vlan-vni-map"):
            try:
                (vls, vis) = utils.get_vlan_vnis_in_map(vlan_vni_map)
                for v in utils.ranges_to_ints(vis):
                    vnisd[v] = None
            except Exception as e:
                self.logger.error("%s: %s (%s)" %(ifaceobj.name, vlan_vni_map, str(e)))
                return
        if vxlan_mcast_grp:
            try:
                for v, g in vxlan_mcast_grp.items():
                    if v not in vnisd.keys():
                        self.logger.error("%s: group %s configured for a vni (%s) not specified in vlan vni map"
                                          %(ifaceobj.name, g, v))
                        return
                    vnisd[v] = str(g)
            except Exception as e:
                self.logger.error("%s: %s (%s)" %(ifaceobj.name, vlan_vni_map, str(e)))
                return

        self.iproute2.bridge_link_update_vni_filter(ifaceobj.name, vnisd)

    def check_and_raise_svd_tvd_errors(self, ifaceobj):
        err = self.svd_tvd_errors.get(ifaceobj.name)

        if err:
            self.log_error(err, ifaceobj)

    def __get_vxlan_vni_list(self, ifaceobj, string=True):
        vxlan_vni_str = self.__get_vxlan_attribute(ifaceobj, "vxlan-vni")

        if vxlan_vni_str:
            # validate range but return string to be used in bridge vni add cmd
            vxlan_vni_range = utils.ranges_to_ints(vxlan_vni_str.split())
            return vxlan_vni_str if string else vxlan_vni_range

        return None

    def _up(self, ifaceobj):
        self.check_and_raise_svd_tvd_errors(ifaceobj)

        vxlan_id_str = ifaceobj.get_attr_value_first("vxlan-id")

        if not ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN and not ifaceobj.link_privflags & ifaceLinkPrivFlags.L3VXI and not vxlan_id_str:
            self.logger.warning("%s: missing vxlan-id attribute on vxlan device" % ifaceobj.name)
            return

        ifname = ifaceobj.name
        link_exists = self.cache.link_exists(ifname)

        if link_exists:
            # if link already exists make sure this is a vxlan
            device_link_kind = self.cache.get_link_kind(ifname)

            if device_link_kind != "vxlan":
                self.logger.error(
                    "%s: device already exists and is not a vxlan (type %s)"
                    % (ifname, device_link_kind)
                )
                ifaceobj.set_status(ifaceStatus.ERROR)
                return

            # get vxlan running attributes
            cached_vxlan_ifla_info_data = self.cache.get_link_info_data(ifname)
        else:
            cached_vxlan_ifla_info_data = {}

        user_request_vxlan_info_data = {}

        if vxlan_id_str:
            # for single vxlan device we don't have a vxlan-id
            self.__config_vxlan_id(ifname, ifaceobj, vxlan_id_str, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)

        self.__config_vxlan_learning(ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        self.__config_vxlan_ageing(ifname, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        self.__config_vxlan_port(ifname, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        vxlan_ttl = self.__config_vxlan_ttl(ifname, ifaceobj, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        self.__config_vxlan_tos(ifname, ifaceobj, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        self.__config_vxlan_udp_csum(ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        local = self.__config_vxlan_local_tunnelip(ifname, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)

        vxlan_vni = self.__get_vxlan_vni_list(ifaceobj)

        vxlan_mcast_grp = self.__get_vxlan_attribute(ifaceobj, "vxlan-mcastgrp")
        vxlan_svcnodeip = self.__get_vxlan_attribute(ifaceobj, "vxlan-svcnodeip")

        vxlan_mcast_grp6 = self.__get_vxlan_attribute(ifaceobj, "vxlan-mcastgrp6")
        vxlan_svcnodeip6 = self.__get_vxlan_attribute(ifaceobj, "vxlan-svcnodeip6")

        vxlan_mcast_grp_map = self.__get_vxlan_mcastgrp_map(ifaceobj)

        vxlan_physdev = self.__get_vxlan_physdev(ifaceobj, vxlan_mcast_grp, vxlan_mcast_grp_map)

        vxlan_vnifilter = self.__get_vxlan_attribute(ifaceobj, "vxlan-vnifilter")

        vxlan_physdev_changed = self.__config_vxlan_physdev(
            link_exists,
            ifaceobj,
            vxlan_physdev,
            user_request_vxlan_info_data,
            cached_vxlan_ifla_info_data
        )

        group, multicast_group_changed = self.__config_vxlan_group(
            ifname,
            ifaceobj,
            link_exists,
            vxlan_mcast_grp,
            vxlan_svcnodeip,
            vxlan_physdev,
            user_request_vxlan_info_data,
            cached_vxlan_ifla_info_data
        )

        group6, multicast_group_changed6 = self.__config_vxlan_group6(
            ifname,
            ifaceobj,
            link_exists,
            vxlan_mcast_grp6,
            vxlan_svcnodeip6,
            vxlan_physdev,
            user_request_vxlan_info_data,
            cached_vxlan_ifla_info_data
        )

        flap_vxlan_device = link_exists and (multicast_group_changed or multicast_group_changed6 or vxlan_physdev_changed)

        if user_request_vxlan_info_data:

            if link_exists and len(user_request_vxlan_info_data) == 1 and Link.IFLA_VXLAN_ID in user_request_vxlan_info_data:
                # if the vxlan already exists it's already cached
                # user_request_vxlan_info_data always contains at least one
                # element: vxlan-id
                self.logger.info('%s: vxlan already exists - no change detected' % ifname)
            else:
                if ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN:

                    if Link.IFLA_VXLAN_LOCAL in user_request_vxlan_info_data and not user_request_vxlan_info_data[Link.IFLA_VXLAN_LOCAL]:
                        local_str = "0"
                    else:
                        local_str = local.ip if local else None

                    if Link.IFLA_VXLAN_GROUP in user_request_vxlan_info_data and not user_request_vxlan_info_data[Link.IFLA_VXLAN_GROUP]:
                        group_str = "0"
                    else:
                        group_str = group.ip if group else None

                    self.iproute2.link_add_single_vxlan(
                        link_exists,
                        ifname,
                        local_str,
                        group_str,
                        vxlan_physdev,
                        user_request_vxlan_info_data.get(Link.IFLA_VXLAN_PORT),
                        vxlan_vnifilter,
                        vxlan_ttl
                    )
                elif ifaceobj.link_privflags & ifaceLinkPrivFlags.L3VXI:
                    self.iproute2.link_add_l3vxi(
                        link_exists,
                        ifname,
                        local.ip if local else None,
                        group.ip if group else None,
                        vxlan_physdev,
                        user_request_vxlan_info_data.get(Link.IFLA_VXLAN_PORT),
                        vxlan_ttl
                    )
                else:
                    try:
                        if flap_vxlan_device:
                            self.netlink.link_down_force(ifname)

                        self.netlink.link_add_vxlan_with_info_data(ifname, user_request_vxlan_info_data)

                        if flap_vxlan_device:
                            self.netlink.link_up_force(ifname)
                    except Exception as e:
                        if link_exists:
                            self.log_error("%s: applying vxlan change failed: %s" % (ifname, str(e)), ifaceobj)
                        else:
                            self.log_error("%s: vxlan creation failed: %s" % (ifname, str(e)), ifaceobj)
                        return

        if ifaceobj.link_privflags & ifaceLinkPrivFlags.L3VXI:
            add_vni = True
            if link_exists:
                running_vxlan_vni_set = set()

                for obj in json.loads(utils.exec_command("bridge -j -p vni show dev %s" % ifname) or "[]"):
                    for vni_obj in obj.get("vnis", []):
                        start = vni_obj.get("vni")
                        end = vni_obj.get("vniEnd")

                        for vni in utils.ranges_to_ints(["%s-%s" % (start, end if end else start)]):
                            running_vxlan_vni_set.add(vni)

                if running_vxlan_vni_set != set(utils.ranges_to_ints([vxlan_vni])):
                    self.iproute2.bridge_vni_int_set_del(ifname, running_vxlan_vni_set)
                else:
                    add_vni = False

            if add_vni:
                try:
                    self.iproute2.bridge_vni_add(ifname, vxlan_vni)
                except Exception as e:
                    self.logger.warning("%s: l3 vxlan vni failure: %s" % (ifname, e))

        if ifaceobj.link_privflags & ifaceLinkPrivFlags.SINGLE_VXLAN:
            if vxlan_vnifilter and utils.get_boolean_from_string(vxlan_vnifilter):
                self.single_vxlan_device_vni_filter(ifaceobj, vxlan_mcast_grp_map)
            #self.single_vxlan_device_mcast_grp_map_fdb_vnifilter(ifaceobj, ifname, vxlan_mcast_grp_map)

        vxlan_purge_remotes = self.__get_vlxan_purge_remotes(ifaceobj)

        remoteips = ifaceobj.get_attr_value('vxlan-remoteip')
        if remoteips:
            try:
                for remoteip in remoteips:
                    ipnetwork.IPv4Address(remoteip)
            except Exception as e:
                self.log_error('%s: vxlan-remoteip: %s' % (ifaceobj.name, str(e)))
        else:
            remoteips = []

        # get old remote ips to compare with new user config value and
        # purge any removed remote ip
        old_remoteips = self.get_old_remote_ips(ifaceobj.name)

        if vxlan_purge_remotes or (isinstance(remoteips,list) and remoteips != old_remoteips):
            # figure out the diff for remotes and do the bridge fdb updates
            # only if provisioned by user and not by an vxlan external
            # controller.
            local_str = str(local)

            if local_str and remoteips and local_str in remoteips:
                remoteips.remove(local_str)

            peers = self.iproute2.get_vxlan_peers(ifaceobj.name, str(group.ip) if group else None)

            cur_peers = set(peers)
            if remoteips:
                new_peers = set(remoteips)
                del_list = cur_peers.difference(new_peers)
                add_list = new_peers.difference(cur_peers)
            else:
                del_list = cur_peers
                add_list = []

            for addr in del_list:
                try:
                    self.iproute2.bridge_fdb_del(
                        ifaceobj.name,
                        "00:00:00:00:00:00",
                        None, True, addr
                    )
                except Exception:
                    pass

            for addr in add_list:
                try:
                    self.iproute2.bridge_fdb_append(
                        ifaceobj.name,
                        "00:00:00:00:00:00",
                        None, True, addr
                    )
                except Exception:
                    pass

        self.vxlan_remote_ip_map(ifaceobj, vxlan_mcast_grp_map)

    @staticmethod
    def get_old_remote_ips(ifname):
        old_remoteips = []
        for old_ifaceobj in statemanager.get_ifaceobjs(ifname) or []:
            for remote in old_ifaceobj.get_attr_value("vxlan-remoteip") or []:
                old_remoteips.append(remote)
        return old_remoteips

    def vxlan_remote_ip_map(self, ifaceobj, vxlan_mcast_grp_map):
        # get user configured remote ip map
        vxlan_remote_ip_map = self.__get_vxlan_remote_ip_map(ifaceobj) or {}

        # if we have an older config we need to see what needs to be removed
        # and not check the running state as FRR or other component can add fdb entries
        old_vxlan_remote_ip_map = {}

        for old_ifaceobj in statemanager.get_ifaceobjs(ifaceobj.name) or []:
            old_vxlan_remote_ip_map = {**old_vxlan_remote_ip_map, **self.__get_vxlan_remote_ip_map(old_ifaceobj)}

        # go through the user config and add new entries while removing existing entries from 'old_vxlan_remote_ip_map'
        for vni, ips in vxlan_remote_ip_map.items():
            for ip in ips:
                if ip not in old_vxlan_remote_ip_map.get(vni, []):
                    self.iproute2.bridge_fdb_append(ifaceobj.name, "00:00:00:00:00:00", remote=ip, src_vni=vni)
                else:
                    old_vxlan_remote_ip_map.get(vni, []).remove(ip)

        # in old_vxlan_remote_ip_map we have the delta between user config and running config. We should delete those
        # extra fdb entries. First we need to make sure that those are not added by vxlan-mcastgrp-map
        if old_vxlan_remote_ip_map:
            for vni, ip in (vxlan_mcast_grp_map or {}).items():
                try:
                    old_vxlan_remote_ip_map[vni].remove(ip)
                except Exception:
                    pass

            for vni, ips in old_vxlan_remote_ip_map.items():
                for ip in ips:
                    try:
                        self.iproute2.bridge_fdb_del_raw(ifaceobj.name, "00:00:00:00:00:00 dst %s src_vni %s" % (ip, vni))
                    except Exception:
                        pass

    @staticmethod
    def get_vxlan_fdb_src_vni(vxlan_mcast_grp_map):
        fdbs = []
        if vxlan_mcast_grp_map:
            for src_vni, dst_ip in vxlan_mcast_grp_map.items():
                fdbs.append(("00:00:00:00:00:00", src_vni, dst_ip))
        return fdbs

    @staticmethod
    def get_svd_running_fdb(ifname):
        vxlan_fdb_data = utils.exec_command("bridge fdb show dev %s" % ifname)
        current_fdb = []

        if vxlan_fdb_data:
            # each entry should look like the following:
            # 00:00:00:00:00:00 dst 239.1.1.100 src_vni 1000 self permanent
            for entry in [line for line in vxlan_fdb_data.strip().split("\n") if "src_vni" in line and "00:00:00:00:00:00" in line]:
                mac, _, dst, _, src_vni = entry.split()[0:5]
                current_fdb.append((mac, src_vni, dst))

        return current_fdb

    def single_vxlan_device_mcast_grp_map_fdb_vnifilter(self, ifaceobj, ifname, vxlan_mcast_grp_map):
        # in this piece of code we won't be checking the running state of the fdb table
        # dumping all fdb entries would cause scalability issues in certain cases.

        # pulling old mcastgrp-map configuration
        old_user_config_fdb = []

        for old_ifaceobj in statemanager.get_ifaceobjs(ifname) or []:
            old_user_config_fdb += self.get_vxlan_fdb_src_vni(self.__get_vxlan_mcastgrp_map(old_ifaceobj))

        # new user configuration
        user_config_fdb = self.get_vxlan_fdb_src_vni(vxlan_mcast_grp_map)

        # compare old and new config to know if we should remove any stale fdb entries.
        fdb_entries_to_remove = set(old_user_config_fdb) - set(user_config_fdb)

        if fdb_entries_to_remove:
            for mac, src_vni, dst_ip in fdb_entries_to_remove:
                try:
                    self.iproute2.bridge_fdb_del_src_vni(ifname, mac, src_vni)
                except Exception as e:
                    if "no such file or directory" not in str(e).lower():
                        self.logger.warning("%s: removing stale fdb entries failed: %s" % (ifname, str(e)))

        if not user_config_fdb:
            # if vxlan-mcastgrp-map wasn't configure return
            return

        for mac, src_vni, dst_ip in user_config_fdb:
            try:
                self.iproute2.bridge_fdb_add_src_vni(ifname, src_vni, dst_ip)
            except Exception as e:
                if "file exists" not in str(e).lower():
                    ifaceobj.set_status(ifaceStatus.ERROR)
                    self.log_error(
                        "%s: vxlan-mcastgrp-map: %s=%s: %s"
                        % (ifname, src_vni, dst_ip, str(e)), raise_error=False
                    )

    def _down(self, ifaceobj):
        try:
            self.netlink.link_del(ifaceobj.name)
        except Exception as e:
            self.log_warn(str(e))

    @staticmethod
    def _query_check_n_update(ifaceobj, ifaceobjcurr, attrname, attrval, running_attrval):
        if not ifaceobj.get_attr_value_first(attrname):
            return
        if running_attrval and attrval == running_attrval:
            ifaceobjcurr.update_config_with_status(attrname, attrval, 0)
        else:
            ifaceobjcurr.update_config_with_status(attrname, running_attrval, 1)

    @staticmethod
    def _query_check_n_update_addresses(ifaceobjcurr, attrname, addresses, running_addresses):
        if addresses:
            for a in addresses:
                if a in running_addresses:
                    ifaceobjcurr.update_config_with_status(attrname, a, 0)
                else:
                    ifaceobjcurr.update_config_with_status(attrname, a, 1)
            running_addresses = set(running_addresses).difference(
                                                    set(addresses))
        [ifaceobjcurr.update_config_with_status(attrname, a, 1) for a in running_addresses]

    def _query_check(self, ifaceobj, ifaceobjcurr):
        ifname = ifaceobj.name

        if not self.cache.link_exists(ifname):
            return

        cached_vxlan_ifla_info_data = self.cache.get_link_info_data(ifname)

        if not cached_vxlan_ifla_info_data:
            ifaceobjcurr.check_n_update_config_with_status_many(ifaceobj, self.get_mod_attrs(), -1)
            return

        for vxlan_attr_str, vxlan_attr_nl, callable_type in (
                ('vxlan-id', Link.IFLA_VXLAN_ID, int),
                ('vxlan-ttl', Link.IFLA_VXLAN_TTL, int),
                ('vxlan-tos', Link.IFLA_VXLAN_TOS, int),
                ('vxlan-port', Link.IFLA_VXLAN_PORT, int),
                ('vxlan-ageing', Link.IFLA_VXLAN_AGEING, int),
                ('vxlan-mcastgrp', Link.IFLA_VXLAN_GROUP, ipnetwork.IPv4Address),
                ('vxlan-mcastgrp6', Link.IFLA_VXLAN_GROUP6, ipnetwork.IPv6Address),
                ('vxlan-svcnodeip', Link.IFLA_VXLAN_GROUP, ipnetwork.IPv4Address),
                ('vxlan-svcnodeip6', Link.IFLA_VXLAN_GROUP6, ipnetwork.IPv6Address),
                ('vxlan-physdev', Link.IFLA_VXLAN_LINK, lambda x: self.cache.get_ifindex(x)),
                ('vxlan-learning', Link.IFLA_VXLAN_LEARNING, lambda boolean_str: utils.get_boolean_from_string(boolean_str)),
                ('vxlan-udp-csum', Link.IFLA_VXLAN_UDP_CSUM, lambda boolean_str: utils.get_boolean_from_string(boolean_str)),
        ):
            vxlan_attr_value = ifaceobj.get_attr_value_first(vxlan_attr_str)

            if not vxlan_attr_value:
                continue

            cached_vxlan_attr_value = cached_vxlan_ifla_info_data.get(vxlan_attr_nl)

            try:
                vxlan_attr_value_nl = callable_type(vxlan_attr_value)
            except Exception as e:
                self.logger.warning('%s: %s: %s' % (ifname, vxlan_attr_str, str(e)))
                ifaceobjcurr.update_config_with_status(vxlan_attr_str, cached_vxlan_attr_value or 'None', 1)
                continue

            if vxlan_attr_value_nl == cached_vxlan_attr_value:
                ifaceobjcurr.update_config_with_status(vxlan_attr_str, vxlan_attr_value, 0)
            else:
                ifaceobjcurr.update_config_with_status(vxlan_attr_str, cached_vxlan_attr_value or 'None', 1)

        #
        # vxlan-local-tunnelip
        #
        running_attrval = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LOCAL)
        attrval = ifaceobj.get_attr_value_first('vxlan-local-tunnelip')
        if not attrval:
            attrval = self._vxlan_local_tunnelip
            # TODO: vxlan._vxlan_local_tunnelip should be a ipnetwork.IPNetwork obj
            ifaceobj.update_config('vxlan-local-tunnelip', attrval)

        if str(running_attrval) == self._clagd_vxlan_anycast_ip:
            # if local ip is anycast_ip, then let query_check to go through
            attrval = self._clagd_vxlan_anycast_ip

        self._query_check_n_update(
            ifaceobj,
            ifaceobjcurr,
            'vxlan-local-tunnelip',
            str(attrval),
            str(running_attrval.ip) if running_attrval else None
        )

        #
        # vxlan-remoteip
        #
        purge_remotes = self.__get_vlxan_purge_remotes(ifaceobj)
        if purge_remotes or ifaceobj.get_attr_value('vxlan-remoteip'):
            # If purge remotes or if vxlan-remoteip's are set
            # in the config file, we are owners of the installed
            # remote-ip's, lets check and report any remote ips we don't
            # understand
            cached_svcnode = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_GROUP)

            self._query_check_n_update_addresses(
                ifaceobjcurr,
                'vxlan-remoteip',
                ifaceobj.get_attr_value('vxlan-remoteip'),
                self.iproute2.get_vxlan_peers(ifaceobj.name, str(cached_svcnode.ip) if cached_svcnode else None)
            )

        # not ideal but will work for now, l3vxi dev:
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.L3VXI:
            user_config_vni_list = set(self.__get_vxlan_vni_list(ifaceobj, string=False))
            vxlan_vni_list = set()

            for obj in json.loads(utils.exec_command("bridge -j -p vni show dev %s" % ifname) or "[]"):
                for vni_obj in obj.get("vnis", []):
                    start = vni_obj.get("vni")
                    end = vni_obj.get("vniEnd")

                    for vni in utils.ranges_to_ints(["%s-%s" % (start, end if end else start)]):
                        vxlan_vni_list.add(vni)

            ifaceobjcurr.update_config_with_status(
                "vxlan-vni",
                " ".join(utils.compress_into_ranges(vxlan_vni_list)),
                vxlan_vni_list != user_config_vni_list
            )

        #
        # vxlan-mcastgrp-map & vxlan-remoteip-map
        # fdb entries can be added by FRR, so we won't be checking the running
        # state if there's no record of a user configuration in /e/n/i
        user_mcastgrp_map = self.__get_vxlan_mcastgrp_map(ifaceobj)
        user_remote_ip_map = self.__get_vxlan_remote_ip_map(ifaceobj)

        if not user_mcastgrp_map and not user_remote_ip_map:
            return

        fdb_mcast = {}
        fdb_remote = {}

        if user_remote_ip_map:
            for _, src_vni, dst in self.get_svd_running_fdb(ifname):
                ip = ipnetwork.IPv4Address(dst)

                if not ip.is_multicast:
                    fdb_remote.setdefault(int(src_vni), []).append(ip)

        if user_mcastgrp_map:
            for obj in json.loads(utils.exec_command("bridge -j -p vni show dev %s" % ifname) or "[]"):
                for vni in obj.get("vnis", []):
                    group = vni.get("group")

                    if not group:
                        continue

                    # we need to reconvert back to ipaddress.IPv4Address because
                    # the existing code uses this type of obj (namely: __get_vxlan_mcastgrp_map)
                    fdb_mcast[vni.get("vni")] = IPv4Address(group)

        #
        # vxlan-mcastgrp-map
        #
        if not user_mcastgrp_map and fdb_mcast:
            ifaceobjcurr.update_config_with_status(
                "vxlan-mcastgrp-map",
                " ".join(["%s=%s" % (vni, ip) for vni, ip in fdb_mcast.items()]),
                1
            )
        elif user_mcastgrp_map and not fdb_mcast:
            ifaceobjcurr.update_config_with_status("vxlan-mcastgrp-map", "", 1)
        elif user_mcastgrp_map or fdb_mcast:
            ifaceobjcurr.update_config_with_status(
                "vxlan-mcastgrp-map",
                " ".join(["%s=%s" % (vni, ip) for vni, ip in fdb_mcast.items()]),
                user_mcastgrp_map != fdb_mcast
            )

        #
        # vxlan-remoteip-map
        #
        if not user_remote_ip_map and fdb_remote:
            ifaceobjcurr.update_config_with_status(
                "vxlan-remoteip-map",
                " ".join(["%s=%s" % (vni, ",".join(map(str, ips))) for vni, ips in fdb_remote.items()]),
                1
            )
        elif user_remote_ip_map and not fdb_remote:
            ifaceobjcurr.update_config_with_status("vxlan-remoteip-map", "", 1)
        elif user_remote_ip_map or fdb_remote:

            if user_remote_ip_map == fdb_remote:
                # display the user config with "pass"
                for config in ifaceobj.get_attr_value("vxlan-remoteip-map"):
                    ifaceobjcurr.update_config_with_status(
                        "vxlan-remoteip-map",
                        config,
                        0
                    )
            else:
                # display current running state with ip ranges (but no vni ranges yet)
                ifaceobjcurr.update_config_with_status(
                    "vxlan-remoteip-map",
                    " ".join(["%s=%s" % (vni, ",".join(utils.compress_into_ip_ranges(ips))) for vni, ips in fdb_remote.items()]),
                    1
                )

    def _query_running(self, ifaceobjrunning):
        ifname = ifaceobjrunning.name

        if not self.cache.link_exists(ifname):
            return

        if self.cache.get_link_kind(ifname) != 'vxlan':
            return

        cached_vxlan_ifla_info_data = self.cache.get_link_info_data(ifname)

        if not cached_vxlan_ifla_info_data:
            return

        #
        # vxlan-id
        #
        vxlan_id = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_ID)

        if not vxlan_id:
            # no vxlan id, meaning this not a vxlan
            return

        ifaceobjrunning.update_config('vxlan-id', str(vxlan_id))

        #
        # vxlan-port
        #
        vxlan_port = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_PORT)

        if vxlan_port:
            ifaceobjrunning.update_config('vxlan-port', vxlan_port)

        #
        # vxlan-svcnode
        #
        vxlan_svcnode_value = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_GROUP)

        if vxlan_svcnode_value:
            vxlan_svcnode_value = str(vxlan_svcnode_value)
            ifaceobjrunning.update_config('vxlan-svcnode', vxlan_svcnode_value)

        #
        # vxlan-remoteip
        #
        purge_remotes = self.__get_vlxan_purge_remotes(None)
        if purge_remotes:
            # if purge_remotes is on, it means we own the
            # remote ips. Query them and add it to the running config
            attrval = self.iproute2.get_vxlan_peers(ifname, vxlan_svcnode_value)
            if attrval:
                [ifaceobjrunning.update_config('vxlan-remoteip', a) for a in attrval]

        #
        # vxlan-link
        # vxlan-ageing
        # vxlan-learning
        # vxlan-local-tunnelip
        #
        for vxlan_attr_name, vxlan_attr_nl, callable_netlink_value_to_string in (
                ('vxlan-physdev', Link.IFLA_VXLAN_LINK, self._get_ifname_for_ifindex),
                ('vxlan-ageing', Link.IFLA_VXLAN_AGEING, str),
                ('vxlan-learning', Link.IFLA_VXLAN_LEARNING, lambda value: 'on' if value else 'off'),
                ('vxlan-udp-csum', Link.IFLA_VXLAN_UDP_CSUM, lambda value: 'on' if value else 'off'),
                ('vxlan-local-tunnelip', Link.IFLA_VXLAN_LOCAL, str),
        ):
            vxlan_attr_value = cached_vxlan_ifla_info_data.get(vxlan_attr_nl)

            if vxlan_attr_value is not None:
                vxlan_attr_value_str = callable_netlink_value_to_string(vxlan_attr_value)

                if vxlan_attr_value:
                    ifaceobjrunning.update_config(vxlan_attr_name, vxlan_attr_value_str)

    def _get_ifname_for_ifindex(self, ifindex):
        """
        we need this middle-man function to query the cache
        cache.get_ifname can raise KeyError, we need to catch
        it and return None
        """
        try:
            return self.cache.get_ifname(ifindex)
        except KeyError:
            return None

    _run_ops = {
        "pre-up": _up,
        "post-down": _down,
        "query-running": _query_running,
        "query-checkcurr": _query_check
    }

    def get_ops(self):
        return list(self._run_ops.keys())

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return

        if not self._is_vxlan_device(ifaceobj):
            return

        if "query" not in operation and \
                    not self.vxlan_mcastgrp_ref \
                    and self.vxlan_physdev_mcast \
                    and self.cache.link_exists(self.vxlan_physdev_mcast):
                self.netlink.link_del(self.vxlan_physdev_mcast)
                self.reset()

        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
