#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#


from sets import Set
from ipaddr import IPNetwork, IPAddress, IPv4Address, IPv4Network, AddressValueError

try:
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

    from ifupdown2.lib.addon import Addon
    from ifupdown2.lib.nlcache import NetlinkCacheIfnameNotFoundError

    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdownaddons.cache import *
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags

    from lib.addon import Addon
    from lib.nlcache import NetlinkCacheIfnameNotFoundError

    from nlmanager.nlmanager import Link

    from ifupdown.iface import *
    from ifupdown.utils import utils

    from ifupdownaddons.cache import *
    from ifupdownaddons.modulebase import moduleBase


class vxlan(Addon, moduleBase):
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
                "help": "vxlan id",
                "validvals": ["<ipv4>"],
                "example": ["vxlan-svcnodeip 172.16.22.125"]
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
                "validvals": ["0", "255"],
                "example": ['vxlan-ttl 42'],
            },
            "vxlan-mcastgrp": {
                "help": "vxlan multicast group",
                "validvals": ["<ip>"],
                "example": ["vxlan-mcastgrp 172.16.22.127"],
            }
        }
    }

    VXLAN_PHYSDEV_MCASTGRP_DEFAULT = "ipmr-lo"

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
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

    def reset(self):
        # in daemon mode we need to reset mcastgrp_ref for every new command
        # this variable has to be set in get_dependent_ifacenames
        self.vxlan_mcastgrp_ref = False

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        if self._is_vxlan_device(ifaceobj):
            if not ifaceobj.get_attr_value_first('vxlan-local-tunnelip') and not self._vxlan_local_tunnelip:
                self.logger.warning('%s: missing vxlan-local-tunnelip' % ifaceobj.name)
                return False
            return self.syntax_check_localip_anycastip_equal(
                ifaceobj.name,
                ifaceobj.get_attr_value_first('vxlan-local-tunnelip') or self._vxlan_local_tunnelip,
                self._clagd_vxlan_anycast_ip
            )
        return True

    def syntax_check_localip_anycastip_equal(self, ifname, local_ip, anycast_ip):
        try:
            if local_ip and anycast_ip and IPNetwork(local_ip) == IPNetwork(anycast_ip):
                self.logger.warning('%s: vxlan-local-tunnelip and clagd-vxlan-anycast-ip are identical (%s)'
                                    % (ifname, local_ip))
                return False
        except:
            pass
        return True

    def get_dependent_ifacenames(self, ifaceobj, ifaceobjs_all=None):
        if self._is_vxlan_device(ifaceobj):
            ifaceobj.link_kind |= ifaceLinkKind.VXLAN
            self._set_global_local_ip(ifaceobj)

            # if we detect a vxlan we check if mcastgrp is set (if so we set vxlan_mcastgrp_ref)
            # to know when to delete this device.
            if not self.vxlan_mcastgrp_ref and ifaceobj.get_attr_value("vxlan-mcastgrp"):
                self.vxlan_mcastgrp_ref = True

        elif ifaceobj.name == 'lo':
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

    def _set_global_local_ip(self, ifaceobj):
        vxlan_local_tunnel_ip = ifaceobj.get_attr_value_first('vxlan-local-tunnelip')
        if vxlan_local_tunnel_ip and not self._vxlan_local_tunnelip:
            self._vxlan_local_tunnelip = vxlan_local_tunnel_ip

    @staticmethod
    def _is_vxlan_device(ifaceobj):
        return ifaceobj.link_kind & ifaceLinkKind.VXLAN or ifaceobj.get_attr_value_first('vxlan-id')

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
        except:
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
        except:
            self.log_error("%s: invalid vxlan-port '%s'" % (ifname, vxlan_port_str), ifaceobj)

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

            if vxlan_ttl != cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_TTL):
                self.logger.info("%s: set vxlan-ttl %s" % (ifname, vxlan_ttl_str if vxlan_ttl_str else vxlan_ttl))
                user_request_vxlan_info_data[Link.IFLA_VXLAN_TTL] = vxlan_ttl
        except:
            self.log_error("%s: invalid vxlan-ttl '%s'" % (ifname, vxlan_ttl_str), ifaceobj)

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
            # on ifreload do not overwrite anycast_ip to individual ip
            # if clagd has modified
            running_localtunnelip = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LOCAL)

            if self._clagd_vxlan_anycast_ip and running_localtunnelip:
                anycastip = IPAddress(self._clagd_vxlan_anycast_ip)
                if anycastip == running_localtunnelip:
                    local = running_localtunnelip

        if not local:
            local = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__,
                attr="vxlan-local-tunnelip"
            )

        if local:
            try:
                local = IPv4Address(local)
            except AddressValueError:
                try:
                    local_ip = IPv4Network(local).ip
                    self.logger.warning("%s: vxlan-local-tunnelip %s: netmask ignored" % (ifname, local))
                    local = local_ip
                except:
                    raise Exception("%s: invalid vxlan-local-tunnelip %s: must be in ipv4 format" % (ifname, local))

        if local and local != cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LOCAL):
            self.logger.info("%s: set vxlan-local-tunnelip %s" % (ifname, local))
            user_request_vxlan_info_data[Link.IFLA_VXLAN_LOCAL] = local

            # if both local-ip and anycast-ip are identical the function prints a warning
            self.syntax_check_localip_anycastip_equal(ifname, local, self._clagd_vxlan_anycast_ip)

        return local

    def __get_vxlan_mcast_grp(self, ifaceobj):
        """
        Get vxlan-mcastgrp user config or policy
        :param ifaceobj:
        :return:
        """
        vxlan_mcast_grp = ifaceobj.get_attr_value_first("vxlan-mcastgrp")

        if not vxlan_mcast_grp:
            vxlan_mcast_grp = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__,
                attr="vxlan-mcastgrp"
            )

        return vxlan_mcast_grp

    def __get_vxlan_svcnodeip(self, ifaceobj):
        """
        Get vxlan-svcnodeip user config or policy
        :param ifaceobj:
        :return:
        """
        vxlan_svcnodeip = ifaceobj.get_attr_value_first('vxlan-svcnodeip')

        if not vxlan_svcnodeip:
            vxlan_svcnodeip = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__,
                attr="vxlan-svcnodeip"
            )

        return vxlan_svcnodeip

    def __config_vxlan_group(self, ifname, ifaceobj, mcast_grp, group, physdev, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
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

        if group:
            try:
                group = IPv4Address(group)
            except AddressValueError:
                try:
                    group_ip = IPv4Network(group).ip
                    self.logger.warning("%s: vxlan-svcnodeip %s: netmask ignored" % (ifname, group))
                    group = group_ip
                except:
                    raise Exception("%s: invalid vxlan-svcnodeip %s: must be in ipv4 format" % (ifname, group))

            if group.is_multicast:
                self.logger.warning("%s: vxlan-svcnodeip %s: invalid group address, "
                                    "for multicast IP please use attribute \"vxlan-mcastgrp\"" % (ifname, group))
                # if svcnodeip is used instead of mcastgrp we warn the user
                # if mcast_grp is not provided by the user we can instead
                # use the svcnodeip value
                if not physdev:
                    self.log_error("%s: vxlan: 'group' (vxlan-mcastgrp) requires 'vxlan-physdev' to be specified" % (ifname))

        if mcast_grp:
            try:
                mcast_grp = IPv4Address(mcast_grp)
            except AddressValueError:
                try:
                    group_ip = IPv4Network(mcast_grp).ip
                    self.logger.warning("%s: vxlan-mcastgrp %s: netmask ignored" % (ifname, mcast_grp))
                    mcast_grp = group_ip
                except:
                    raise Exception("%s: invalid vxlan-mcastgrp %s: must be in ipv4 format" % (ifname, mcast_grp))

            if not mcast_grp.is_multicast:
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

        if group != cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_GROUP):
            self.logger.info("%s: set %s %s" % (ifname, attribute_name, group))
            user_request_vxlan_info_data[Link.IFLA_VXLAN_GROUP] = group

        return group

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

    def __get_vxlan_physdev(self, ifaceobj, mcastgrp):
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
        if physdev or not mcastgrp:
            return physdev

        physdev = self.vxlan_physdev_mcast

        if not self.cache.link_exists(physdev):
            self.logger.info("%s: needs a dummy device (%s) to use for "
                             "multicast termination (vxlan-mcastgrp %s)"
                             % (ifaceobj.name, physdev, mcastgrp))
            self.netlink._link_add_set(ifname=physdev, kind="dummy", ifla={Link.IFLA_MTU: 16000})
            self.netlink.link_up(physdev)

        return physdev

    def __config_vxlan_physdev(self, ifaceobj, vxlan_physdev, user_request_vxlan_info_data, cached_vxlan_ifla_info_data):
        if vxlan_physdev:
            try:
                vxlan_physdev_ifindex = self.cache.get_ifindex(vxlan_physdev)
            except NetlinkCacheIfnameNotFoundError:
                try:
                    vxlan_physdev_ifindex = int(self.sysfs.read_file_oneline("/sys/class/net/%s/ifindex" % vxlan_physdev))
                except:
                    self.logger.error("%s: physdev %s doesn't exists" % (ifaceobj.name, vxlan_physdev))
                    return

            if vxlan_physdev_ifindex != cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LINK):
                self.logger.info("%s: set vxlan-physdev %s" % (ifaceobj.name, vxlan_physdev))
                user_request_vxlan_info_data[Link.IFLA_VXLAN_LINK] = vxlan_physdev_ifindex

    def _up(self, ifaceobj):
        vxlan_id_str = ifaceobj.get_attr_value_first("vxlan-id")

        if not vxlan_id_str:
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

        self.__config_vxlan_id(ifname, ifaceobj, vxlan_id_str, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        self.__config_vxlan_learning(ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        self.__config_vxlan_ageing(ifname, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        self.__config_vxlan_port(ifname, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        self.__config_vxlan_ttl(ifname, ifaceobj, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)
        local = self.__config_vxlan_local_tunnelip(ifname, ifaceobj, link_exists, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)

        vxlan_mcast_grp = self.__get_vxlan_mcast_grp(ifaceobj)
        vxlan_svcnodeip = self.__get_vxlan_svcnodeip(ifaceobj)
        vxlan_physdev = self.__get_vxlan_physdev(ifaceobj, vxlan_mcast_grp)

        self.__config_vxlan_physdev(ifaceobj, vxlan_physdev, user_request_vxlan_info_data, cached_vxlan_ifla_info_data)

        group = self.__config_vxlan_group(
            ifname,
            ifaceobj,
            vxlan_mcast_grp,
            vxlan_svcnodeip,
            vxlan_physdev,
            user_request_vxlan_info_data,
            cached_vxlan_ifla_info_data
        )

        if user_request_vxlan_info_data:

            if link_exists and not len(user_request_vxlan_info_data) > 1:
                # if the vxlan already exists it's already cached
                # user_request_vxlan_info_data always contains at least one
                # element: vxlan-id
                self.logger.info('%s: vxlan already exists - no change detected' % ifname)
            else:
                try:
                    self.netlink.link_add_vxlan_with_info_data(ifname, user_request_vxlan_info_data)
                except Exception as e:
                    if link_exists:
                        self.log_error("%s: applying vxlan change failed: %s" % (ifname, str(e)), ifaceobj)
                    else:
                        self.log_error("%s: vxlan creation failed: %s" % (ifname, str(e)), ifaceobj)
                    return

        vxlan_purge_remotes = self.__get_vlxan_purge_remotes(ifaceobj)

        remoteips = ifaceobj.get_attr_value('vxlan-remoteip')
        if remoteips:
            try:
                for remoteip in remoteips:
                    IPv4Address(remoteip)
            except Exception as e:
                self.log_error('%s: vxlan-remoteip: %s' % (ifaceobj.name, str(e)))

        if vxlan_purge_remotes or remoteips:
            # figure out the diff for remotes and do the bridge fdb updates
            # only if provisioned by user and not by an vxlan external
            # controller.
            peers = self.iproute2.get_vxlan_peers(ifaceobj.name, group)
            if local and remoteips and local in remoteips:
                remoteips.remove(local)
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
                except:
                    pass

            for addr in add_list:
                try:
                    self.iproute2.bridge_fdb_append(
                        ifaceobj.name,
                        "00:00:00:00:00:00",
                        None, True, addr
                    )
                except:
                    pass

    def _down(self, ifaceobj):
        try:
            self.netlink.link_del(ifaceobj.name)
        except Exception, e:
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
            running_addresses = Set(running_addresses).difference(
                                                    Set(addresses))
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
                ('vxlan-port', Link.IFLA_VXLAN_PORT, int),
                ('vxlan-ageing', Link.IFLA_VXLAN_AGEING, int),
                ('vxlan-mcastgrp', Link.IFLA_VXLAN_GROUP, IPv4Address),
                ('vxlan-svcnodeip', Link.IFLA_VXLAN_GROUP, IPv4Address),
                ('vxlan-physdev', Link.IFLA_VXLAN_LINK, lambda x: self.cache.get_ifindex(x)),
                ('vxlan-learning', Link.IFLA_VXLAN_LEARNING, lambda boolean_str: utils.get_boolean_from_string(boolean_str)),
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
            # TODO: vxlan._vxlan_local_tunnelip should be a IPNetwork obj
            ifaceobj.update_config('vxlan-local-tunnelip', attrval)

        if str(running_attrval) == self._clagd_vxlan_anycast_ip:
            # if local ip is anycast_ip, then let query_check to go through
            attrval = self._clagd_vxlan_anycast_ip

        self._query_check_n_update(
            ifaceobj,
            ifaceobjcurr,
            'vxlan-local-tunnelip',
            str(attrval),
            str(running_attrval)
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
                self.iproute2.get_vxlan_peers(ifaceobj.name, str(cached_svcnode))
            )

    def _query_running(self, ifaceobjrunning):
        ifname = ifaceobjrunning.name

        if not self.cache.link_exists(ifname):
            return

        if not self.cache.get_link_kind(ifname) == 'vxlan':
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
                ('vxlan-local-tunnelip', Link.IFLA_VXLAN_LOCAL, str),
        ):
            vxlan_attr_value = cached_vxlan_ifla_info_data.get(vxlan_attr_nl)

            if vxlan_attr_value is not None:
                vxlan_attr_value_str = callable_netlink_value_to_string(vxlan_attr_nl)

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
        return self._run_ops.keys()

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return

        if operation != 'query-running':
            if not self._is_vxlan_device(ifaceobj):
                return

            if not self.vxlan_mcastgrp_ref \
                    and self.vxlan_physdev_mcast \
                    and self.cache.link_exists(self.vxlan_physdev_mcast):
                self.netlink.link_del(self.vxlan_physdev_mcast)
                self.reset()

        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
