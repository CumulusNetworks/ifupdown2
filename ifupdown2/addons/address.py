#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import re
import socket
import json
import time
import subprocess

from setuptools.dist import strtobool

try:
    from ifupdown2.lib.addon import AddonWithIpBlackList, AddonException
    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdown.iface import ifaceType, ifaceLinkKind, ifaceLinkPrivFlags, ifaceStatus, iface
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.dhclient import dhclient
    from ifupdown2.ifupdownaddons.modulebase import moduleBase

    import ifupdown2.nlmanager.ipnetwork as ipnetwork

    import ifupdown2.ifupdown.statemanager as statemanager
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.ifupdownconfig as ifupdownconfig
except ImportError:
    from lib.addon import AddonWithIpBlackList, AddonException
    from nlmanager.nlmanager import Link

    from ifupdown.iface import ifaceType, ifaceLinkKind, ifaceLinkPrivFlags, ifaceStatus, iface
    from ifupdown.utils import utils

    from ifupdownaddons.dhclient import dhclient
    from ifupdownaddons.modulebase import moduleBase

    import nlmanager.ipnetwork as ipnetwork

    import ifupdown.statemanager as statemanager
    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.ifupdownconfig as ifupdownconfig


class address(AddonWithIpBlackList, moduleBase):
    """  ifupdown2 addon module to configure address, mtu, hwaddress, alias
    (description) on an interface """

    _modinfo = {
        'mhelp': 'address configuration module for interfaces',
        'attrs': {
            'address': {
                'help': 'The address of the interface. The format of the '
                        'address depends on the protocol. It is a dotted '
                        'quad for IP and a sequence of hexadecimal halfwords '
                        'separated by colons for IPv6. The ADDRESS may be '
                        'followed by a slash and a decimal number which '
                        'encodes the network prefix length.',
                'validvals': ['<ipv4/prefixlen>', '<ipv6/prefixlen>'],
                'multiline': True,
                'example': [
                    'address 10.0.12.3/24',
                    'address 2000:1000:1000:1000:3::5/128'
                ]
            },
            'netmask': {
                'help': 'Address netmask',
                'example': ['netmask 255.255.255.0'],
                'compat': True
            },
            'dad-attempts': {
                'help': 'Number of attempts to settle DAD (0 to disable DAD). '
                        'To use this feature, the ipv6_dad_handling_enabled '
                        'module global must be set to true',
                'example': ['dad-attempts 0'],
                'default': '60',
            },
            'dad-interval': {
                'help': 'DAD state polling interval in seconds. '
                        'To use this feature, the ipv6_dad_handling_enabled '
                        'module global must be set to true',
                'example': ['dad-interval 0.5'],
                'default': '0.1',
            },
            'broadcast': {
                'help': 'The broadcast address on the interface.',
                'validvals': ['<ipv4>'],
                'example': ['broadcast 10.0.1.255']
            },
            'scope': {
                'help': 'The scope of the area where this address is valid. '
                        'The available scopes are listed in file /etc/iproute2/rt_scopes. '
                        'Predefined scope values are: '
                        'global - the address is globally valid. '
                        'site - (IPv6 only, deprecated) the address is site local, i.e. it is valid inside this site. '
                        'link - the address is link local, i.e. it is valid only on this device. '
                        'host - the address is valid only inside this host.',
                'validvals': ['universe', 'site', 'link', 'host', 'nowhere'],
                'example': ['scope host']
            },
            'preferred-lifetime': {
                'help': 'The preferred lifetime of this address; see section '
                        '5.5.4 of RFC 4862. When it expires, the address is '
                        'no longer used for new outgoing connections. '
                        'Defaults to forever.',
                'validrange': ['0', '65535'],
                'example': [
                    'preferred-lifetime forever',
                    'preferred-lifetime 10'
                ]
            },
            'pointopoint': {
                'help': 'Set the remote IP address for a point-to-point link',
                'validvals': ['<ipv4/prefixlen>', '<ipv6/prefixlen>'],
                'example': [
                    'pointopoint 10.10.10.42/32'
                ]
            },
            'gateway': {
                'help': 'Default gateway',
                'validvals': ['<ipv4>', '<ipv6>'],
                'multiline': True,
                'example': ['gateway 255.255.255.0']
            },
            'mtu': {
                'help': 'Interface MTU (maximum transmission unit)',
                'validrange': ['552', '9216'],
                'example': ['mtu 1600'],
                'default': '1500'
            },
            'hwaddress': {
                'help': 'Hardware address (mac)',
                'validvals': ['<mac>'],
                'example': ['hwaddress 44:38:39:00:27:b8']
            },
            'alias': {
                'help': 'description/alias: give the device a symbolic name for easy reference.',
                'example': ['alias testnetwork']
            },
            'address-purge': {
                'help': 'Purge existing addresses. By default any existing '
                        'ip addresses on an interface are purged to match '
                        'persistant addresses in the interfaces file. Set '
                        'this attribute to \'no\' if you want to preserve '
                        'existing addresses',
                'validvals': ['yes', 'no'],
                'default': 'yes',
                'example': ['address-purge yes/no']
            },
            'clagd-vxlan-anycast-ip': {
                'help': 'Anycast local IP address for dual connected VxLANs',
                'validvals': ['<ipv4>'],
                'example': ['clagd-vxlan-anycast-ip 36.0.0.11']
            },
            'ip-forward': {
                'help': 'ip forwarding flag',
                'validvals': ['on', 'off', 'yes', 'no', '0', '1'],
                'default': 'off',
                'example': ['ip-forward off']
            },
            'ip6-forward': {
                'help': 'ipv6 forwarding flag',
                'validvals': ['on', 'off', 'yes', 'no', '0', '1'],
                'default': 'off',
                'example': ['ip6-forward off']
            },
            'mpls-enable': {
                'help': 'mpls enable flag',
                'validvals': ['yes', 'no'],
                'default': 'no',
                'example': ['mpls-enable yes']
            },
            'ipv6-addrgen': {
                'help': 'enable disable ipv6 link addrgenmode',
                'validvals': ['on', 'off'],
                'default': 'on',
                'example': [
                    'ipv6-addrgen on',
                    'ipv6-addrgen off'
                ]
            },
            'arp-accept': {
                'help': 'Allow gratuitous arp to update arp table',
                'validvals': ['on', 'off', 'yes', 'no', '0', '1'],
                'default': 'off',
                'example': ['arp-accept on']
            },
            "disable-ipv6": {
                "help": "disable IPv6",
                "validvals": ['on', 'off', 'yes', 'no', '0', '1'],
                "default": "no",
                "aliases": ["disable-ip6"]
            }
        }
    }

    DEFAULT_MTU_STRING = "1500"

    def __init__(self, *args, **kargs):
        AddonWithIpBlackList.__init__(self)
        moduleBase.__init__(self, *args, **kargs)
        self._bridge_fdb_query_cache = {}
        self.ipforward = policymanager.policymanager_api.get_attr_default(module_name=self.__class__.__name__, attr='ip-forward')
        self.ip6forward = policymanager.policymanager_api.get_attr_default(module_name=self.__class__.__name__, attr='ip6-forward')
        self.ifaces_defaults = policymanager.policymanager_api.get_iface_defaults(module_name=self.__class__.__name__)
        self.enable_l3_iface_forwarding_checks = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                self.__class__.__name__,
                'enable_l3_iface_forwarding_checks'
            )
        )
        self.ipv6_dad_handling_enabled = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                self.__class__.__name__,
                'ipv6_dad_handling_enabled'
            ),
            default=False
        )

        self.default_mtu = str(self.__policy_get_default_mtu())
        self.default_mgmt_intf_mtu = self.__policy_get_mgmt_intf_mtu()
        if not self.default_mgmt_intf_mtu:
            self.default_mgmt_intf_mtu = self.default_mtu
            self.default_mgmt_intf_mtu_int = self.default_mtu_int
        self.max_mtu    = self.__policy_get_max_mtu()

        self.default_loopback_addresses = (ipnetwork.IPNetwork('127.0.0.1/8'), ipnetwork.IPNetwork('::1/128'))

        self.l3_intf_arp_accept = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr='l3_intf_arp_accept'
            ),
            default=0
        )

        try:
            l3_intf_arp_accept_str = policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr="l3_intf_arp_accept"
            )
            try:
                self.l3_intf_arp_accept = int(l3_intf_arp_accept_str)
            except ValueError:
                self.l3_intf_arp_accept = int(strtobool(l3_intf_arp_accept_str))
        except Exception:
            self.l3_intf_arp_accept = 0

        self.l3_intf_default_gateway_set_onlink = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr='l3_intf_default_gateway_set_onlink'
            ),
            default=True
        )

        self.check_l3_svi_ip_forwarding = utils.get_boolean_from_string(policymanager.policymanager_api.get_module_globals(
            module_name=self.__class__.__name__,
            attr="check_l3_svi_ip_forwarding")
        )

        self.default_loopback_scope = policymanager.policymanager_api.get_module_globals(
            module_name=self.__class__.__name__,
            attr="default_loopback_scope"
        )
        self.logger.debug(f"policy: default_loopback_scope set to {self.default_loopback_scope}")
        self.valid_scopes = self.get_mod_subattr("scope", "validvals")

        self.mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


    def __policy_get_default_mtu(self):
        default_mtu = policymanager.policymanager_api.get_attr_default(
            module_name=self.__class__.__name__,
            attr="mtu"
        )

        if not default_mtu:
            default_mtu = self.DEFAULT_MTU_STRING

        try:
            self.default_mtu_int = int(default_mtu)
        except ValueError as e:
            self.logger.error("address: invalid default mtu \"%s\" set via policy: %s" % (default_mtu, str(e)))
            default_mtu = self.DEFAULT_MTU_STRING
            self.default_mtu_int = int(self.DEFAULT_MTU_STRING)

        self.logger.info("address: using default mtu %s" % default_mtu)

        return default_mtu

    def __policy_get_max_mtu(self):
        max_mtu = policymanager.policymanager_api.get_module_globals(module_name=self.__class__.__name__, attr="max_mtu")
        if max_mtu:
            try:
                max_mtu_int = int(max_mtu)
                self.logger.info("address: using max mtu %s" % self.max_mtu)
                return max_mtu_int
            except ValueError as e:
                self.logger.warning("address: policy max_mtu: %s" % str(e))
        else:
            self.logger.info("address: max_mtu undefined")
        return 0

    def __policy_get_mgmt_intf_mtu(self):
        default_mgmt_mtu = policymanager.policymanager_api.get_module_globals(
                                module_name=self.__class__.__name__,
                                attr="mgmt_intf_mtu")
        self.default_mgmt_mtu_int = None

        if not default_mgmt_mtu:
            return None

        try:
            self.default_mgmt_mtu_int = int(default_mgmt_mtu)
        except ValueError as e:
            self.logger.error("address: invalid default mgmt mtu \"%s\" set via policy: %s" % (default_mgmt_mtu, str(e)))
            default_mgmt_mtu = self.DEFAULT_MTU_STRING
            self.default_mgmt_mtu_int = int(self.DEFAULT_MTU_STRING)

        self.logger.info("address: using default mgmt interface mtu %s" % default_mgmt_mtu)

        return default_mgmt_mtu

    def syntax_check(self, ifaceobj, ifaceobj_getfunc=None):
        self.syntax_check_l3_svi_ip_forward(ifaceobj)
        return (self.syntax_check_multiple_gateway(ifaceobj)
                and self.syntax_check_addr_allowed_on(ifaceobj, True)
                and self.syntax_check_mtu(ifaceobj, ifaceobj_getfunc)
                and self.syntax_check_sysctls(ifaceobj)
                and self.syntax_check_enable_l3_iface_forwardings(ifaceobj, ifaceobj_getfunc, syntax_check=True))

    def syntax_check_l3_svi_ip_forward(self, ifaceobj):
        """ enabled via policy: 'check_l3_svi_ip_forwarding' """

        if not self.check_l3_svi_ip_forwarding:
            return True

        if ifaceobj.link_kind & ifaceLinkKind.VLAN and ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE:
            ip_forward = ifaceobj.get_attr_value_first("ip-forward")

            if ip_forward and not utils.get_boolean_from_string(ip_forward):
                self.logger.error("%s: misconfiguration: disabling ip4 forwarding on an l3-svi is not allowed" % ifaceobj.name)
                return False

            ip6_forward = ifaceobj.get_attr_value_first("ip6-forward")

            if ip6_forward and not utils.get_boolean_from_string(ip6_forward):
                self.logger.error("%s: misconfiguration: disabling ip6 forwarding on an l3-svi is not allowed" % ifaceobj.name)
                return False

        return True

    def syntax_check_enable_l3_iface_forwardings(self, ifaceobj, ifaceobj_getfunc, syntax_check=False):
        if (self.enable_l3_iface_forwarding_checks
                and (ifaceobj.link_kind & ifaceLinkKind.VLAN
                     or ifaceobj.link_kind & ifaceLinkKind.BRIDGE)
                and not ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT):

            ifname = ifaceobj.name
            vlan_addr = None
            vlan_ipforward_off = None

            for obj in ifaceobj_getfunc(ifname) or [ifaceobj]:
                if not vlan_addr:
                    vlan_addr = obj.get_attr_value('address')

                if not vlan_ipforward_off:
                    ip_forward_value = obj.get_attr_value_first('ip-forward')

                    if ip_forward_value and not utils.get_boolean_from_string(ip_forward_value):
                        vlan_ipforward_off = True

                if vlan_addr and vlan_ipforward_off:
                    if syntax_check:
                        raise AddonException(
                            'configuring ip-forward off and ip address(es) (%s) is not compatible'
                            % (', '.join(vlan_addr))
                        )
                    else:
                        raise AddonException(
                            '%s: configuring ip-forward off and ip address(es) (%s) is not compatible'
                            % (ifname, ', '.join(vlan_addr))
                        )

        return True

    def syntax_check_sysctls(self, ifaceobj):
        result = True
        bridge_port = (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT)
        ipforward = ifaceobj.get_attr_value_first('ip-forward')
        if bridge_port and ipforward:
            result = False
            self.log_error('%s: \'ip-forward\' is not supported for '
                           'bridge port' %ifaceobj.name)
        ip6forward = ifaceobj.get_attr_value_first('ip6-forward')
        if bridge_port and ip6forward:
            result = False
            self.log_error('%s: \'ip6-forward\' is not supported for '
                           'bridge port' %ifaceobj.name)
        return result

    def syntax_check_mtu(self, ifaceobj, ifaceobj_getfunc):
        mtu_str = ifaceobj.get_attr_value_first('mtu')
        if mtu_str:
            try:
                mtu_int = int(mtu_str)
            except ValueError as e:
                self.logger.warning("%s: invalid mtu %s: %s" % (ifaceobj.name, mtu_str, str(e)))
                return False
            return self._check_mtu_config(ifaceobj, mtu_str, mtu_int, ifaceobj_getfunc, syntaxcheck=True)
        return True

    def syntax_check_addr_allowed_on(self, ifaceobj, syntax_check=False):
        if ifaceobj.get_attr_value('address'):
            return utils.is_addr_ip_allowed_on(ifaceobj, syntax_check=syntax_check)
        return True

    def _syntax_check_multiple_gateway(self, family, found, addr, version):
        if ipnetwork.IPNetwork(addr).version == version:
            if found:
                raise AddonException('%s: multiple gateways for %s family'
                                % (addr, family))
            return True
        return False

    def syntax_check_multiple_gateway(self, ifaceobj):
        result = True
        inet = False
        inet6 = False
        gateways = ifaceobj.get_attr_value('gateway')
        for addr in gateways if gateways else []:
            try:
                if self._syntax_check_multiple_gateway('inet', inet, addr, 4):
                    inet = True
                if self._syntax_check_multiple_gateway('inet6', inet6, addr, 6):
                    inet6 = True
            except Exception as e:
                self.logger.warning('%s: address: %s' % (ifaceobj.name, str(e)))
                result = False
        return result

    def _address_valid(self, addrs):
        if not addrs:
           return False
        if any([True if a[:7] != '0.0.0.0'
                else False for a in addrs]):
           return True
        return False

    def _get_hwaddress(self, ifaceobj):
        return utils.strip_hwaddress(ifaceobj.get_attr_value_first('hwaddress'))

    def _process_bridge(self, ifaceobj, up, hwaddress, old_mac_addr=None):
        addrs = ifaceobj.get_attr_value_first('address')
        arp_accept = ifaceobj.get_attr_value_first('arp-accept')
        arp_accept = utils.boolean_support_binary(arp_accept)
        is_vlan_dev_on_vlan_aware_bridge = False
        is_bridge = self.cache.get_link_kind(ifaceobj.name) == 'bridge'
        if not is_bridge and ifaceobj.link_kind & ifaceLinkKind.VLAN:
            bridgename = ifaceobj.lowerifaces[0]
            vlan = self._get_vlan_id(ifaceobj)
            is_vlan_dev_on_vlan_aware_bridge = self.cache.bridge_is_vlan_aware(bridgename)
        if ((is_bridge and not self.cache.bridge_is_vlan_aware(ifaceobj.name))
                        or is_vlan_dev_on_vlan_aware_bridge):
            if self._address_valid(addrs):
                if self.l3_intf_arp_accept:
                    if up:
                        self.write_file('/proc/sys/net/ipv4/conf/%s' % ifaceobj.name +
                                        '/arp_accept', str(self.l3_intf_arp_accept))
                    else:
                        self.write_file('/proc/sys/net/ipv4/conf/%s' % ifaceobj.name +
                                        '/arp_accept', '0')
                else:
                    self.write_file('/proc/sys/net/ipv4/conf/%s/arp_accept' % ifaceobj.name, arp_accept)
        if hwaddress and is_vlan_dev_on_vlan_aware_bridge:
            if old_mac_addr:
                # corner case, first the user's /e/n/i is configured without 'hwaddress', then it is used to fix the svi
                # mac address. The current code only checks for the statemanager for old 'hwaddress' attribute but
                # couldn't find any. Now we save the mac addr before updating it, so we can later clear it from the fdb.
                try:
                    if utils.mac_str_to_int(old_mac_addr) != utils.mac_str_to_int(hwaddress):
                        self.iproute2.bridge_fdb_del(bridgename, old_mac_addr, vlan)
                except Exception:
                    pass
            if up:
                # check statemanager to delete the old entry if necessary
                try:
                    for old_obj in statemanager.statemanager_api.get_ifaceobjs(ifaceobj.name) or []:
                        old_hwaddress = old_obj.get_attr_value_first("hwaddress")
                        if old_hwaddress and utils.mac_str_to_int(old_hwaddress) != utils.mac_str_to_int(hwaddress):
                            if old_hwaddress != old_mac_addr:
                                self.iproute2.bridge_fdb_del(bridgename, old_hwaddress, vlan)
                            break
                except Exception:
                    pass
                self.iproute2.bridge_fdb_add(bridgename, hwaddress, vlan)
            else:
                self.iproute2.bridge_fdb_del(bridgename, hwaddress, vlan)

        if is_bridge:
            # Get the link hwaddress of bridge if we cannot find it in defaults
            if not hwaddress:
                hwaddress = self.cache.get_link_address(ifaceobj.name)

            # we need to do an fdb check during bridge processing and purge stale macs
            fdbs = self._get_bridge_fdbs(ifaceobj.name)

            # Save the permanent MACs for comparison too, as this can be used to preserve
            # perm entries for VRR interfaces.
            valid_macs = set([utils.mac_str_to_int(i) for i in fdbs.get('permanent', [])])
            # Add the actual bridge MAC to this set too.
            valid_macs.add(utils.mac_str_to_int(hwaddress))

            # Now iterate and purge if it's not a valid mac.
            for vlan, macs in fdbs.items():
                for mac in macs:
                    if utils.mac_str_to_int(mac) not in valid_macs:
                        self.logger.info(f"{ifaceobj.name}: stale fdb entry ({mac}) detected on vlan {vlan}")
                        try:
                            if vlan == 'permanent':
                                self.iproute2.bridge_fdb_del(ifaceobj.name, mac)
                            else:
                                self.iproute2.bridge_fdb_del(ifaceobj.name, mac, vlan)
                        except Exception as e:
                            self.logger.debug(f"{ifaceobj.name}: bridge_fdb_del failed: {str(e)}")

    def __get_ip_addr_with_attributes(self, ifaceobj_list, ifname):
        user_config_ip_addrs_list = []

        try:
            for ifaceobj in ifaceobj_list or []:

                user_addrs = ifaceobj.get_attr_value("address")

                if not user_addrs:
                    continue

                if not self.syntax_check_addr_allowed_on(ifaceobj, syntax_check=False):
                    return False, None

                for index, addr in enumerate(user_addrs):
                    addr_attributes = {}
                    addr_obj = None

                    # convert the ip from string to IPNetwork object
                    if "/" in addr:
                        addr_obj = ipnetwork.IPNetwork(addr)
                    else:
                        netmask = ifaceobj.get_attr_value_n("netmask", index)

                        if netmask:
                            addr_obj = ipnetwork.IPNetwork(addr, netmask)
                        else:
                            addr_obj = ipnetwork.IPNetwork(addr)

                    for attr_name in ("broadcast", "scope", "preferred-lifetime"):
                        attr_value = ifaceobj.get_attr_value_n(attr_name, index)
                        if attr_value:
                            addr_attributes[attr_name] = attr_value

                    scope = None
                    if addr_obj.ip.is_loopback and "scope" not in addr_attributes and self.default_loopback_scope:
                        scope = addr_attributes["scope"] = self.default_loopback_scope

                    if scope and scope not in self.valid_scopes:
                        self.logger.warning(f"{ifname}: invalid scope ({scope}) for {addr}")
                        self.logger.warning(f"valid scopes: {self.valid_scopes}")
                        try:
                            del addr_attributes["scope"]
                        except:
                            pass

                    pointopoint = ifaceobj.get_attr_value_n("pointopoint", index)
                    try:
                        if pointopoint:
                            addr_attributes["pointopoint"] = ipnetwork.IPNetwork(pointopoint)
                    except Exception as e:
                        self.logger.warning("%s: pointopoint %s: %s" % (ifaceobj.name, pointopoint, str(e)))

                    user_config_ip_addrs_list.append((addr_obj, addr_attributes))
        except Exception as e:
            self.log_error("%s: convert string ip address into IPNetwork object: %s" % (ifname, str(e)), ifaceobj)
            return False, None

        return True, user_config_ip_addrs_list

    def __add_ip_addresses_with_attributes(self, ifaceobj, ifname, user_config_ip_addrs):
        ipv6_is_disabled = None
        nodad = False
        if self.ipv6_dad_handling_enabled:
            nodad = ifaceobj.get_attr_value_first('dad-attempts') == '0'

        for ip, attributes in user_config_ip_addrs:
            try:
                if ip.version == 6 and ipv6_is_disabled is None:
                    # check (only once) if ipv6 is disabled on this device
                    proc_path = "/proc/sys/net/ipv6/conf/%s/disable_ipv6" % ifname
                    ipv6_is_disabled = utils.get_boolean_from_string(self.read_file_oneline(proc_path))

                    if ipv6_is_disabled:
                        # enable ipv6
                        self.write_file(proc_path, "0")

                # check if ip is not blacklisted
                self.ip_blacklist_check(ifname, ip)

                if attributes:
                    self.netlink.addr_add(
                        ifname, ip,
                        scope=attributes.get("scope"),
                        peer=attributes.get("pointopoint"),
                        broadcast=attributes.get("broadcast"),
                        preferred_lifetime=attributes.get("preferred-lifetime"),
                        nodad=nodad
                    )
                else:
                    self.netlink.addr_add(ifname, ip, nodad=nodad)
            except Exception as e:
                self.log_error(str(e), ifaceobj, raise_error=False)

    @staticmethod
    def __add_loopback_anycast_ip_to_running_ip_addr_list(ifaceobjlist):
        """
        if anycast address is configured on 'lo' and is in running
        config add it to newaddrs so that ifreload doesn't wipe it out
        :param ifaceobjlist:
        :param running_ip_addrs:
        """
        anycast_ip_addr = None

        for ifaceobj in ifaceobjlist:
            anycast_addr = ifaceobj.get_attr_value_first("clagd-vxlan-anycast-ip")
            if anycast_addr:
                anycast_ip_addr = ipnetwork.IPNetwork(anycast_addr)

        return anycast_ip_addr

    def process_addresses(self, ifaceobj, ifaceobj_getfunc=None, force_reapply=False):
        squash_addr_config = ifupdownconfig.config.get("addr_config_squash", "0") == "1"

        if squash_addr_config and not ifaceobj.flags & ifaceobj.YOUNGEST_SIBLING:
            return

        ifname = ifaceobj.name
        purge_addresses = utils.get_boolean_from_string(ifaceobj.get_attr_value_first("address-purge"), default=True)

        if not squash_addr_config and ifaceobj.flags & iface.HAS_SIBLINGS:
            # if youngest sibling and squash addr is not set
            # print a warning that addresses will not be purged
            if ifaceobj.flags & iface.YOUNGEST_SIBLING:
                self.logger.warning("%s: interface has multiple iface stanzas, skip purging existing addresses" % ifname)
            purge_addresses = False

        if squash_addr_config and ifaceobj.flags & iface.HAS_SIBLINGS:
            ifaceobj_list = ifaceobj_getfunc(ifname)
        else:
            ifaceobj_list = [ifaceobj]

        addr_supported, user_config_ip_addrs_list = self.__get_ip_addr_with_attributes(ifaceobj_list, ifname)

        if not addr_supported:
            return

        if not ifupdownflags.flags.PERFMODE and purge_addresses:
            # if perfmode is not set and purge addresses is set to True
            # lets purge addresses not in the config
            anycast_ip = None

            running_ip_addrs = self.cache.get_managed_ip_addresses(ifname, ifaceobj_list)

            if ifaceobj.link_privflags & ifaceLinkPrivFlags.LOOPBACK:
                anycast_ip = self.__add_loopback_anycast_ip_to_running_ip_addr_list(ifaceobj_list)

            user_ip4, user_ip6, ordered_user_configured_ips = self.order_user_configured_addrs(user_config_ip_addrs_list)

            if ordered_user_configured_ips == running_ip_addrs or self.compare_running_ips_and_user_config(user_ip4, user_ip6, running_ip_addrs):
                if force_reapply:
                    self.__add_ip_addresses_with_attributes(ifaceobj, ifname, user_config_ip_addrs_list)
                return
            try:
                # if primary address is not same, there is no need to keep any, reset all addresses.
                if ordered_user_configured_ips and running_ip_addrs and ordered_user_configured_ips[0] != running_ip_addrs[0]:
                    self.logger.info("%s: primary ip changed (from %s to %s) we need to purge all ip addresses and re-add them"
                                     % (ifname, ordered_user_configured_ips[0], running_ip_addrs[0]))
                    skip_addrs = []
                else:
                    skip_addrs = ordered_user_configured_ips

                if anycast_ip:
                    skip_addrs.append(anycast_ip)

                for addr in running_ip_addrs:
                    if addr in skip_addrs:
                        continue
                    self.netlink.addr_del(ifname, addr)
            except Exception as e:
                self.log_warn(str(e))
        if not user_config_ip_addrs_list:
            return
        self.__add_ip_addresses_with_attributes(ifaceobj, ifname, user_config_ip_addrs_list)

    def compare_running_ips_and_user_config(self, user_ip4, user_ip6, running_addrs):
        """
            We need to compare the user config ips and the running ips.
            ip4 ordering matters (primary etc) but ip6 order doesn't matter

            this function replaces the strict comparison previously in place
                if newaddrs == running_addrs ?

            We will compare if the ip4 ordering is correct, then check if all
            ip6 are present in the list (without checking the ordering)
        """
        if (user_ip4 or user_ip6) and not running_addrs:
            return False
        elif running_addrs and not user_ip4 and not user_ip6:
            return False
        elif not running_addrs and not user_ip4 and not user_ip6:
            return True

        len_ip4 = len(user_ip4)
        len_running_addrs = len(running_addrs)

        if len_ip4 > len_running_addrs:
            return False

        i = 0
        while i < len_ip4:
            if user_ip4[i] != running_addrs[i]:
                return False
            i += 1

        if len_ip4 > 0:
            running_ip6 = running_addrs[len_ip4:]
        else:
            running_ip6 = running_addrs

        i = 0
        len_ip6 = len(user_ip6)

        for ip6 in running_ip6:
            if ip6 not in user_ip6:
                return False
            i += 1

        return i == len_ip6

    @staticmethod
    def order_user_configured_addrs(user_config_addrs):
        ip4 = []
        ip6 = []

        for a, _ in user_config_addrs:
            if a.version == 6:
                ip6.append(a)
            else:
                ip4.append(a)

        return ip4, ip6, ip4 + ip6

    def _delete_gateway(self, ifaceobj, gateways, vrf, metric):
        for del_gw in gateways:
            try:
                self.iproute2.route_del_gateway(ifaceobj.name, del_gw, vrf, metric)
            except Exception as e:
                self.logger.debug('%s: %s' % (ifaceobj.name, str(e)))

    def _add_delete_gateway(self, ifaceobj, gateways=[], prev_gw=[]):
        vrf = ifaceobj.get_attr_value_first('vrf')
        metric = ifaceobj.get_attr_value_first('metric')
        self._delete_gateway(ifaceobj, list(set(prev_gw) - set(gateways)),
                             vrf, metric)
        for add_gw in gateways:
            try:
                self.iproute2.route_add_gateway(ifaceobj.name, add_gw, vrf, metric, onlink=self.l3_intf_default_gateway_set_onlink)
            except Exception as e:
                self.log_error('%s: %s' % (ifaceobj.name, str(e)))

    def _get_prev_gateway(self, ifaceobj, gateways):
        ipv = []
        saved_ifaceobjs = statemanager.statemanager_api.get_ifaceobjs(ifaceobj.name)
        if not saved_ifaceobjs:
            return ipv
        prev_gateways = saved_ifaceobjs[0].get_attr_value('gateway')
        if not prev_gateways:
            return ipv
        return prev_gateways

    def _check_mtu_config(self, ifaceobj, mtu_str, mtu_int, ifaceobj_getfunc, syntaxcheck=False):
        retval = True
        if (ifaceobj.link_kind & ifaceLinkKind.BRIDGE):
            if syntaxcheck:
                self.logger.warning('%s: bridge inherits mtu from its ports. There is no need to assign mtu on a bridge' %ifaceobj.name)
                retval = False
            else:
                self.logger.info('%s: bridge inherits mtu from its ports. There is no need to assign mtu on a bridge' %ifaceobj.name)
        elif ifaceobj_getfunc:
            if ((ifaceobj.link_privflags & ifaceLinkPrivFlags.BOND_SLAVE) and
                ifaceobj.upperifaces):
                masterobj = ifaceobj_getfunc(ifaceobj.upperifaces[0])
                if masterobj:
                    master_mtu = masterobj[0].get_attr_value_first('mtu')
                    if master_mtu and master_mtu != mtu_str:
                        log_msg = ("%s: bond slave mtu %s is different from bond master %s mtu %s. "
                                  "There is no need to configure mtu on a bond slave." %
                                   (ifaceobj.name, mtu_str, masterobj[0].name, master_mtu))
                        if syntaxcheck:
                            self.logger.warning(log_msg)
                            retval = False
                        else:
                            self.logger.info(log_msg)
            elif ((ifaceobj.link_kind & ifaceLinkKind.VLAN) and
                  ifaceobj.lowerifaces):
                lowerobj = ifaceobj_getfunc(ifaceobj.lowerifaces[0])
                if lowerobj:
                    if syntaxcheck:
                        lowerdev_mtu = int(lowerobj[0].get_attr_value_first('mtu') or 0)
                    else:
                        lowerdev_mtu = self.cache.get_link_mtu(lowerobj[0].name)  # return type: int
                    if lowerdev_mtu and mtu_int > lowerdev_mtu:
                        self.logger.warning('%s: vlan dev mtu %s is greater than lower realdev %s mtu %s'
                                         %(ifaceobj.name, mtu_str, lowerobj[0].name, lowerdev_mtu))
                        retval = False
                    elif (not lowerobj[0].link_kind and
                          not (lowerobj[0].link_privflags & ifaceLinkPrivFlags.LOOPBACK) and
                          not lowerdev_mtu and self.default_mtu and (mtu_int > self.default_mtu_int)):
                        # only check default mtu on lower device which is a physical interface
                        self.logger.warning('%s: vlan dev mtu %s is greater than lower realdev %s mtu %s'
                                         %(ifaceobj.name, mtu_str, lowerobj[0].name, self.default_mtu))
                        retval = False
            if self.max_mtu and mtu_int > self.max_mtu:
                self.logger.warning('%s: specified mtu %s is greater than max mtu %s'
                                 %(ifaceobj.name, mtu_str, self.max_mtu))
                retval = False
        return retval

    def _propagate_mtu_to_upper_devs(self, ifaceobj, mtu_str, mtu_int, ifaceobj_getfunc):
        if not (
                (not ifupdownflags.flags.ALL or ifupdownconfig.diff_mode) and
                not ifaceobj.link_kind and
                ifupdownconfig.config.get('adjust_logical_dev_mtu', '1') != '0'
        ):
            # This is additional cost to us, so do it only when
            # ifupdown2 is called on a particular interface and
            # it is a physical interface (or diff mode)
            return

        if (not ifaceobj.upperifaces or
            (ifaceobj.link_privflags & ifaceLinkPrivFlags.BOND_SLAVE) or
            (ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE) or
            (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT)):
            return
        for u in ifaceobj.upperifaces:
            upperobjs = ifaceobj_getfunc(u)
            if (not upperobjs or
                not (upperobjs[0].link_kind & ifaceLinkKind.VLAN)):
                continue
            # only adjust mtu for vlan devices on ifaceobj
            umtu = upperobjs[0].get_attr_value_first('mtu')
            if not umtu:
                running_mtu = self.cache.get_link_mtu(upperobjs[0].name)
                if not running_mtu or running_mtu != mtu_int:
                    self.sysfs.link_set_mtu(u, mtu_str=mtu_str, mtu_int=mtu_int)

    def _process_mtu_config_mtu_valid(self, ifaceobj, ifaceobj_getfunc, mtu_str, mtu_int):
        if not self._check_mtu_config(ifaceobj, mtu_str, mtu_int, ifaceobj_getfunc):
            return

        if mtu_int != self.cache.get_link_mtu(ifaceobj.name):
            self.sysfs.link_set_mtu(ifaceobj.name, mtu_str=mtu_str, mtu_int=mtu_int)
            self._propagate_mtu_to_upper_devs(ifaceobj, mtu_str, mtu_int, ifaceobj_getfunc)

    def _process_mtu_config_mtu_none(self, ifaceobj, ifaceobj_getfunc):
        if (ifaceobj.link_privflags & ifaceLinkPrivFlags.MGMT_INTF):
            return

        cached_link_mtu = self.cache.get_link_mtu(ifaceobj.name)

        if ifaceobj.link_kind:
            # bonds, vxlan and custom devices (like dummy) need an explicit set of mtu.
            # bridges don't need mtu set
            if ifaceobj.link_kind & ifaceLinkKind.BOND \
                    or ifaceobj.link_kind & ifaceLinkKind.VXLAN \
                    or ifaceobj.link_kind & ifaceLinkKind.BRIDGE \
                    or ifaceobj.link_kind & ifaceLinkKind.OTHER:
                if cached_link_mtu != self.default_mtu_int:
                    self.sysfs.link_set_mtu(ifaceobj.name, mtu_str=self.default_mtu, mtu_int=self.default_mtu_int)
                return

            # set vlan interface mtu to lower device mtu
            if (
                ifupdownconfig.config.get('adjust_logical_dev_mtu', '1') != '0'
                and ifaceobj.lowerifaces
                and ifaceobj.link_kind & ifaceLinkKind.VLAN
            ):
                lower_iface = ifaceobj.lowerifaces[0]
                lower_iface_mtu_int = self.cache.get_link_mtu(lower_iface)

                if lower_iface_mtu_int != cached_link_mtu:
                    self.sysfs.link_set_mtu(ifaceobj.name, mtu_str=str(lower_iface_mtu_int), mtu_int=lower_iface_mtu_int)

        elif (
            ifaceobj.name != 'lo'
            and not ifaceobj.link_kind
            and not (ifaceobj.link_privflags & ifaceLinkPrivFlags.BOND_SLAVE)
            and self.default_mtu
            and cached_link_mtu != self.default_mtu_int
        ):
            # logical devices like bridges and vlan devices rely on mtu
            # from their lower devices. ie mtu travels from
            # lower devices to upper devices. For bonds mtu travels from
            # upper to lower devices. running mtu depends on upper and
            # lower device mtu. With all this implicit mtu
            # config by the kernel in play, we try to be cautious here
            # on which devices we want to reset mtu to default.
            # essentially only physical interfaces which are not bond slaves
            self.sysfs.link_set_mtu(ifaceobj.name, mtu_str=self.default_mtu, mtu_int=self.default_mtu_int)
            if ifupdownconfig.diff_mode:
                self._propagate_mtu_to_upper_devs(ifaceobj, self.default_mtu, self.default_mtu_int, ifaceobj_getfunc)

    def _set_bridge_forwarding(self, ifaceobj):
        """ set ip forwarding to 0 if bridge interface does not have a
        ip nor svi """
        ifname = ifaceobj.name

        netconf_ipv4_forwarding = self.cache.get_netconf_forwarding(socket.AF_INET, ifname)
        netconf_ipv6_forwarding = self.cache.get_netconf_forwarding(socket.AF_INET6, ifname)

        if not ifaceobj.upperifaces and not ifaceobj.get_attr_value('address') and (ifaceobj.addr_method and "dhcp" not in ifaceobj.addr_method):
            if netconf_ipv4_forwarding:
                self.sysctl_write_forwarding_value_to_proc(ifname, "ipv4", 0)
            if netconf_ipv6_forwarding:
                self.sysctl_write_forwarding_value_to_proc(ifname, "ipv6", 0)
        else:
            if not netconf_ipv4_forwarding:
                self.sysctl_write_forwarding_value_to_proc(ifname, "ipv4", 1)
            if not netconf_ipv6_forwarding:
                self.sysctl_write_forwarding_value_to_proc(ifname, "ipv6", 1)

    def sysctl_write_forwarding_value_to_proc(self, ifname, family, value):
        self.write_file("/proc/sys/net/%s/conf/%s/forwarding" % (family, ifname), "%s\n" % value)

    def _sysctl_config(self, ifaceobj):
        setting_default_value = False
        mpls_enable = ifaceobj.get_attr_value_first('mpls-enable');
        if not mpls_enable:
            setting_default_value = True
            mpls_enable = self.get_mod_subattr('mpls-enable', 'default')
        mpls_enable = utils.boolean_support_binary(mpls_enable)
        # File read has been used for better performance
        # instead of using sysctl command
        if ifupdownflags.flags.PERFMODE:
            running_mpls_enable = '0'
        else:
            running_mpls_enable = str(self.cache.get_netconf_mpls_input(ifaceobj.name))

        if mpls_enable != running_mpls_enable:
            try:
                self.sysctl_set('net.mpls.conf.%s.input'
                                %('/'.join(ifaceobj.name.split("."))),
                                mpls_enable)
            except Exception as e:
                if not setting_default_value:
                    ifaceobj.status = ifaceStatus.ERROR
                    self.logger.error('%s: %s' %(ifaceobj.name, str(e)))

        if (ifaceobj.link_kind & ifaceLinkKind.BRIDGE):
            self._set_bridge_forwarding(ifaceobj)

        if not self.syntax_check_sysctls(ifaceobj):
            return
        if not self.syntax_check_l3_svi_ip_forward(ifaceobj):
            return

        ipforward = ifaceobj.get_attr_value_first('ip-forward')
        ip6forward = ifaceobj.get_attr_value_first('ip6-forward')
        if ifupdownflags.flags.PERFMODE:
            if ipforward:
                self.sysctl_set('net.ipv4.conf.%s.forwarding'
                                 %('/'.join(ifaceobj.name.split("."))),
                                utils.boolean_support_binary(ipforward))
            if ip6forward:
                self.sysctl_set('net.ipv6.conf.%s.forwarding'
                                %('/'.join(ifaceobj.name.split("."))),
                                utils.boolean_support_binary(ip6forward))
            return
        bridge_port = ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT
        if bridge_port:
            if ipforward:
                self.log_error('%s: \'ip-forward\' is not supported for '
                               'bridge port' %ifaceobj.name)
            if ip6forward:
                self.log_error('%s: \'ip6-forward\' is not supported for '
                               'bridge port' %ifaceobj.name)
            return
        setting_default_value = False
        if not ipforward:
            setting_default_value = True
            ipforward = self.ipforward
        if ipforward:
            ipforward = int(utils.get_boolean_from_string(ipforward))
            running_ipforward = self.cache.get_netconf_forwarding(socket.AF_INET, ifaceobj.name)
            if ipforward != running_ipforward:
                try:
                    self.sysctl_set('net.ipv4.conf.%s.forwarding'
                                    %('/'.join(ifaceobj.name.split("."))),
                                    ipforward)
                except Exception as e:
                    if not setting_default_value:
                        ifaceobj.status = ifaceStatus.ERROR
                        self.logger.error('%s: %s' %(ifaceobj.name, str(e)))

        setting_default_value = False

        if not ip6forward:
            setting_default_value = True
            ip6forward = self.ip6forward

        if ip6forward:
            ip6forward = int(utils.get_boolean_from_string(ip6forward))
            running_ip6forward = self.cache.get_netconf_forwarding(socket.AF_INET6, ifaceobj.name)
            if ip6forward != running_ip6forward:
                try:
                    self.sysctl_set('net.ipv6.conf.%s.forwarding'
                                    %('/'.join(ifaceobj.name.split("."))),
                                    ip6forward)
                except Exception as e:
                    # There is chance of ipv6 being removed because of,
                    # for example, setting mtu < 1280
                    # In such cases, log error only if user has configured
                    # ip6-forward
                    if not setting_default_value:
                       ifaceobj.status = ifaceStatus.ERROR
                       self.logger.error('%s: %s' %(ifaceobj.name, str(e)))

    def process_mtu(self, ifaceobj, ifaceobj_getfunc):

        if ifaceobj.link_privflags & ifaceLinkPrivFlags.OPENVSWITCH:
            return

        mtu_str = ifaceobj.get_attr_value_first('mtu')
        mtu_from_policy = False

        if not mtu_str:
            if (ifaceobj.link_privflags & ifaceLinkPrivFlags.MGMT_INTF):
                mtu_str = self.default_mgmt_intf_mtu
            if not mtu_str:
                mtu_str = self.ifaces_defaults.get(ifaceobj.name, {}).get('mtu')

            mtu_from_policy = True

        if mtu_str:
            try:
                mtu_int = int(mtu_str)
            except Exception as e:
                if mtu_from_policy:
                    self.logger.warning("%s: invalid MTU value from policy file (iface_defaults): %s" % (ifaceobj.name, str(e)))
                else:
                    self.logger.warning("%s: invalid MTU value: %s" % (ifaceobj.name, str(e)))
                return

            self._process_mtu_config_mtu_valid(ifaceobj, ifaceobj_getfunc, mtu_str, mtu_int)
        else:
            self._process_mtu_config_mtu_none(ifaceobj, ifaceobj_getfunc)

    def up_ipv6_addrgen(self, ifaceobj):
        user_configured_ipv6_addrgen = ifaceobj.get_attr_value_first('ipv6-addrgen')

        if not user_configured_ipv6_addrgen and ifupdownflags.flags.PERFMODE:
            # no need to go further during perfmode (boot)
            return

        if not user_configured_ipv6_addrgen and ifaceobj.addr_method in ["dhcp", "ppp"]:
            return

        if not user_configured_ipv6_addrgen:
            # if user didn't configure ipv6-addrgen, should we reset to default?
            user_configured_ipv6_addrgen = self.get_attr_default_value('ipv6-addrgen')

        ipv6_addrgen_nl = {
            'on': 0,
            'yes': 0,
            '0': 0,
            'off': 1,
            'no': 1,
            '1': 1
        }.get(user_configured_ipv6_addrgen.lower(), None)

        if ipv6_addrgen_nl is not None:
            self.iproute2.batch_start()
            self.iproute2.link_set_ipv6_addrgen(ifaceobj.name, ipv6_addrgen_nl, link_created=True)
            self.iproute2.batch_commit()
            # link_create=False will flush the addr cache of that intf
        else:
            self.logger.warning('%s: invalid value "%s" for attribute ipv6-addrgen' % (ifaceobj.name, user_configured_ipv6_addrgen))

    def disable_ipv6(self, ifaceobj):
        user_config = ifaceobj.get_attr_value_first("disable-ipv6")
        sysfs_path = f"/proc/sys/net/ipv6/conf/{ifaceobj.name}/disable_ipv6"

        if not user_config:
            # check if disable-ipv6 was removed from the stanza
            for old_ifaceobj in statemanager.statemanager_api.get_ifaceobjs(ifaceobj.name) or []:
                old_value = old_ifaceobj.get_attr_value_first("disable-ipv6")

                if old_value:
                    default_bool = utils.get_boolean_from_string(
                        self.get_mod_subattr("disable-ipv6", "default")
                    )

                    if default_bool != utils.get_boolean_from_string(old_value):
                        self.sysfs.write_to_file(sysfs_path, "1" if default_bool else "0")
                        return
        else:
            user_config_bool = utils.get_boolean_from_string(user_config)

            if user_config_bool != utils.get_boolean_from_string(self.sysfs.read_file_oneline(sysfs_path)):
                self.sysfs.write_to_file(sysfs_path, "1" if user_config_bool else "0")

    def _pre_up(self, ifaceobj, ifaceobj_getfunc=None):
        if not self.cache.link_exists(ifaceobj.name):
            return

        if not self.syntax_check_enable_l3_iface_forwardings(ifaceobj, ifaceobj_getfunc):
            return

        self.disable_ipv6(ifaceobj)

        #
        # alias
        #
        self.sysfs.link_set_alias(ifaceobj.name, ifaceobj.get_attr_value_first("alias"))

        self._sysctl_config(ifaceobj)

        addr_method = ifaceobj.addr_method
        force_reapply = False
        try:
            # release any stale dhcp addresses if present
            if (addr_method not in ["dhcp", "ppp"]  and not ifupdownflags.flags.PERFMODE and
                    not (ifaceobj.flags & iface.HAS_SIBLINGS)):
                # if not running in perf mode and ifaceobj does not have
                # any sibling iface objects, kill any stale dhclient
                # processes
                dhclientcmd = dhclient()
                if dhclientcmd.is_running(ifaceobj.name):
                    # release any dhcp leases
                    dhclientcmd.release(ifaceobj.name)
                    self.cache.force_address_flush_family(ifaceobj.name, socket.AF_INET)
                    force_reapply = True
                elif dhclientcmd.is_running6(ifaceobj.name):
                    dhclientcmd.release6(ifaceobj.name)
                    self.cache.force_address_flush_family(ifaceobj.name, socket.AF_INET6)
                    force_reapply = True
        except Exception:
            pass

        self.process_mtu(ifaceobj, ifaceobj_getfunc)
        self.up_ipv6_addrgen(ifaceobj)

        try:
            hwaddress, old_mac_addr = self.process_hwaddress(ifaceobj)
        except Exception as e:
            self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj)

        if addr_method not in ["dhcp", "ppp"]:
            self.process_addresses(ifaceobj, ifaceobj_getfunc, force_reapply)
        else:
            # remove old addresses added by ifupdown2
            # (if intf was moved from static config to dhcp)
            for old_ifaceobj in statemanager.statemanager_api.get_ifaceobjs(ifaceobj.name) or []:
                for addr in old_ifaceobj.get_attr_value("address") or []:
                    self.netlink.addr_del(ifaceobj.name, ipnetwork.IPNetwork(addr))


        try:
            # Handle special things on a bridge
            self._process_bridge(ifaceobj, True, hwaddress, old_mac_addr)
        except Exception as e:
            self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj)

    def _settle_dad(self, ifaceobj, ips):
        """ Settle dad for any given ips """
        def ip_addr_list(what):
            raw = json.loads(utils.exec_commandl([
                'ip', '-j', '-o', '-6', 'address', 'list', 'dev',
                ifaceobj.name, what
            ]))
            addr_infos = (x for t in raw for x in t.get('addr_info', []))
            ip_list = [f'{x["local"]}/{x["prefixlen"]}' for x in addr_infos if x]
            return ip_list

        def get_param(key, default=None):
            return (ifaceobj.get_attr_value_first(key)
                    or policymanager.policymanager_api.get_iface_default(
                        self.__class__.__name__, ifaceobj.name, key)
                    or default)

        interval = float(get_param('dad-interval', '0.1'))  # 0.1: ifupdown default value
        attempts = int(get_param('dad-attempts', '60'))     # 60: ifupdown default value
        if not attempts or not ips:
            return
        try:
            for _attempt in range(0, attempts):
                tentative = ip_addr_list('tentative')
                if all(str(ip) not in tentative for ip in ips):
                    break
                self.logger.info("%s: dad-interval: sleeping for %s" % (ifaceobj.name, interval))
                time.sleep(interval)
            else:
                timeout = ','.join(ip for ip in ips if str(ip) not in tentative)
                self.logger.warning('address: %s: dad timeout "%s"', ifaceobj.name, timeout)
                return
            failure = ip_addr_list('dadfailed')
            if failure:
                self.logger.warning('address: %s: dad failure "%s"', ifaceobj.name, ','.join(failure))
        except subprocess.CalledProcessError as exc:
            self.logger.error('address: %s: could not settle dad %s', ifaceobj.name, str(exc))

    def _get_ifaceobjs(self, ifaceobj, ifaceobj_getfunc):
        squash_addr_config = ifupdownconfig.config.get("addr_config_squash", "0") == "1"
        if not squash_addr_config:
            return [ifaceobj]  # no squash, returns current ifaceobj
        if not ifaceobj.flags & ifaceobj.YOUNGEST_SIBLING:
            return []  # when squash is present, work only on the youngest sibling
        if ifaceobj.flags & iface.HAS_SIBLINGS:
            return ifaceobj_getfunc(ifaceobj.name) # get sibling interfaces
        return [ifaceobj]

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        gateways = ifaceobj.get_attr_value('gateway')
        if not gateways:
            gateways = []
        prev_gw = self._get_prev_gateway(ifaceobj, gateways)
        self._add_delete_gateway(ifaceobj, gateways, prev_gw)
        # settle dad
        if not self.ipv6_dad_handling_enabled:
            return
        if not self.cache.link_exists(ifaceobj.name):
            return
        ifname = ifaceobj.name
        ifaceobjs = self._get_ifaceobjs(ifaceobj, ifaceobj_getfunc)
        addr_supported, user_addrs_list = self.__get_ip_addr_with_attributes(ifaceobjs, ifname)
        if not addr_supported:
            return
        self._settle_dad(ifaceobj, [ip for ip, _ in user_addrs_list if ip.version == 6])

    def validate_mac(self, mac):
        if not mac:
            return False
        if not bool(self.mac_regex.match(mac)):
            raise Exception("Invalid MAC address from policy: %s" % mac)
        return True

    def process_hwaddress_reset_to_default(self, ifaceobj):
        if not ifaceobj.link_kind and ifaceobj.link_privflags & ifaceLinkPrivFlags.BOND_SLAVE:
            # if the switch port is part of a bond we shouldn't revert the mac address
            return None

        iface_defaults = policymanager.policymanager_api.get_iface_defaults("address")

        if iface_defaults:
            interface_mac_default = iface_defaults.get(ifaceobj.name, {}).get("hwaddress")

            if self.validate_mac(interface_mac_default):
                return interface_mac_default

        return None

    def process_hwaddress(self, ifaceobj):
        hwaddress = self._get_hwaddress(ifaceobj)

        if not hwaddress:
            if ifaceobj.link_kind & ifaceLinkKind.VLAN:
                # When hwaddress is removed from vlan config
                # we should go back to system or bridge mac
                for lower in ifaceobj.lowerifaces:
                    if self.cache.get_link_kind(lower) == "bridge":
                        hwaddress = self.cache.get_link_address(lower)
                        break
                if not hwaddress:
                    return None, None
            else:
                hwaddress = self.process_hwaddress_reset_to_default(ifaceobj)
                if not hwaddress:
                    return None, None

        if not ifupdownflags.flags.PERFMODE:  # system is clean
            running_hwaddress = self.cache.get_link_address(ifaceobj.name)
        else:
            running_hwaddress = None

        old_mac_addr = None

        hwaddress_int = utils.mac_str_to_int(hwaddress)

        if hwaddress_int != utils.mac_str_to_int(running_hwaddress):
            slave_down = False
            if ifaceobj.link_kind & ifaceLinkKind.BOND and ifaceobj.lowerifaces:
                # if bond, down all the slaves
                for l in ifaceobj.lowerifaces:
                    self.netlink.link_down(l)
                slave_down = True
            try:
                if ifaceobj.link_privflags & ifaceLinkPrivFlags.BOND_SLAVE and ifaceobj.get_attr_value("hwaddress"):
                    master_ifname = self.cache.get_master(ifaceobj.name)
                    if master_ifname:
                        self.log_error("%s: setting hwaddress is not permitted on an existing bond slave" % ifaceobj.name, ifaceobj=ifaceobj)

                self.netlink.link_set_address(
                    ifaceobj.name,
                    hwaddress,
                    hwaddress_int,
                    keep_link_down=ifaceobj.link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN
                )
                old_mac_addr = running_hwaddress
            finally:
                if slave_down:
                    for l in ifaceobj.lowerifaces:
                        self.netlink.link_up(l)

        return hwaddress, old_mac_addr

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        try:
            if not self.cache.link_exists(ifaceobj.name):
                return
            addr_method = ifaceobj.addr_method
            if addr_method not in ["dhcp", "ppp"]:
                if ifaceobj.get_attr_value_first('address-purge')=='no':
                    addrlist = ifaceobj.get_attr_value('address')
                    for addr in addrlist or []:
                        self.netlink.addr_del(ifaceobj.name, addr)
                elif not ifaceobj.link_kind:
                    # for logical interfaces we don't need to remove the ip addresses
                    # kernel will do it for us on 'ip link del'
                    if ifaceobj_getfunc:
                        ifaceobj_list = ifaceobj_getfunc(ifaceobj.name) or [ifaceobj]
                    else:
                        ifaceobj_list = [ifaceobj]

                    for addr in self.cache.get_managed_ip_addresses(ifaceobj.name, ifaceobj_list):
                        self.netlink.addr_del(ifaceobj.name, addr)

            gateways = ifaceobj.get_attr_value('gateway')
            if gateways:
                self._delete_gateway(ifaceobj, gateways,
                                     ifaceobj.get_attr_value_first('vrf'),
                                     ifaceobj.get_attr_value_first('metric'))

            #
            # mtu --
            # If device is not a logical intf and has its MTU configured by
            # ifupdown2. If this MTU is different from our default mtu,
            # if so we need to reset it back to default.
            if not ifaceobj.link_kind and self.default_mtu and ifaceobj.get_attr_value_first('mtu') and self.cache.get_link_mtu(ifaceobj.name) != self.default_mtu_int:
                self.sysfs.link_set_mtu(ifaceobj.name, mtu_str=self.default_mtu, mtu_int=self.default_mtu_int)

            #
            # alias
            # only reset alias on non-logical device
            if not ifaceobj.link_kind:
                alias = ifaceobj.get_attr_value_first("alias")
                if alias:
                    self.sysfs.link_set_alias(ifaceobj.name, None)  # None to reset alias.

            hwaddress = self.process_hwaddress_reset_to_default(ifaceobj)
            if hwaddress != None and not ifaceobj.link_kind:
                hwaddress_int = utils.mac_str_to_int(hwaddress)
                self.netlink.link_set_address(
                    ifaceobj.name,
                    hwaddress,
                    hwaddress_int,
                    keep_link_down=ifaceobj.link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN
                )
            else:
              # Handle special things on a bridge
              hwaddress = self._get_hwaddress(ifaceobj)
              if not hwaddress:
                  hwaddress = self.cache.get_link_address(ifaceobj.name)

            self._process_bridge(ifaceobj, False, hwaddress, None)
        except Exception as e:
            self.logger.debug('%s : %s' %(ifaceobj.name, str(e)))

    def _get_bridge_fdbs(self, bridgename, vlan=None):
        fdbs = self._bridge_fdb_query_cache.get(bridgename)
        if not fdbs:
           fdbs = self.iproute2.bridge_fdb_show_dev(bridgename)
           if not fdbs:
              return {}
           self._bridge_fdb_query_cache[bridgename] = fdbs
        return fdbs.get(vlan) if vlan else fdbs

    def _check_addresses_in_bridge(self, ifaceobj, hwaddress):
        """ If the device is a bridge, make sure the addresses
        are in the bridge """
        if ifaceobj.link_kind & ifaceLinkKind.VLAN:
            bridgename = ifaceobj.lowerifaces[0]
            vlan = self._get_vlan_id(ifaceobj)
            if self.cache.bridge_is_vlan_aware(bridgename):
                fdb_addrs = [utils.mac_str_to_int(fdb_addr) for fdb_addr in self._get_bridge_fdbs(bridgename, str(vlan))]
                if not fdb_addrs:
                   return False
                hwaddress_int = utils.mac_str_to_int(hwaddress)
                if hwaddress_int not in fdb_addrs:
                    return False
        return True

    def _query_sysctl(self, ifaceobj, ifaceobjcurr):
        bridge_port = ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT
        ipforward = ifaceobj.get_attr_value_first('ip-forward')
        if ipforward:
            if bridge_port:
                ifaceobjcurr.status = ifaceStatus.ERROR
                ifaceobjcurr.status_str = ('\'ip-forward\' not supported ' +
                                           'for bridge port')
                ifaceobjcurr.update_config_with_status('ip-forward', 1, None)
            else:
                running_ipforward = self.cache.get_netconf_forwarding(socket.AF_INET, ifaceobj.name)
                config_ipforward = utils.get_boolean_from_string(ipforward)
                ifaceobjcurr.update_config_with_status(
                    'ip-forward',
                    'on' if running_ipforward else 'off',
                    running_ipforward != config_ipforward
                )

        ip6forward = ifaceobj.get_attr_value_first('ip6-forward')
        if ip6forward:
            if bridge_port:
                ifaceobjcurr.status = ifaceStatus.ERROR
                ifaceobjcurr.status_str = ('\'ip6-forward\' not supported ' +
                                           'for bridge port')
                ifaceobjcurr.update_config_with_status('ip6-forward', 1, None)
            else:
                running_ip6forward = self.cache.get_netconf_forwarding(socket.AF_INET6, ifaceobj.name)
                config_ip6forward = utils.get_boolean_from_string(ip6forward)
                ifaceobjcurr.update_config_with_status(
                    'ip6-forward',
                    'on' if running_ip6forward else 'off',
                    running_ip6forward != config_ip6forward
                )
        mpls_enable = ifaceobj.get_attr_value_first('mpls-enable');
        if mpls_enable:
            running_mpls_enable = utils.get_yesno_from_onezero(str(self.cache.get_netconf_mpls_input(ifaceobj.name)))
            ifaceobjcurr.update_config_with_status('mpls-enable',
                                                   running_mpls_enable,
                                            mpls_enable != running_mpls_enable)

    def query_check_ipv6_addrgen(self, ifaceobj, ifaceobjcurr):
        ipv6_addrgen = ifaceobj.get_attr_value_first('ipv6-addrgen')

        if not ipv6_addrgen:
            return

        if ipv6_addrgen in utils._string_values:
            ifaceobjcurr.update_config_with_status(
                'ipv6-addrgen',
                ipv6_addrgen,
                utils.get_boolean_from_string(ipv6_addrgen) == self.cache.get_link_ipv6_addrgen_mode(ifaceobj.name)
            )
        else:
            ifaceobjcurr.update_config_with_status('ipv6-addrgen', ipv6_addrgen, 1)

    def query_check_disable_ipv6(self, ifaceobj, ifaceobjcurr):
        user_config = ifaceobj.get_attr_value_first("disable-ipv6")

        if not user_config:
            return

        user_config_bool = utils.get_boolean_from_string(user_config)
        sysfs_path = f"/proc/sys/net/ipv6/conf/{ifaceobj.name}/disable_ipv6"

        ifaceobjcurr.update_config_with_status(
            "disable-ipv6",
            user_config,
            user_config_bool != utils.get_boolean_from_string(self.sysfs.read_file_oneline(sysfs_path))
        )

    def _query_check(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        """
        TODO: Check broadcast address, scope, etc
        """
        if not self.cache.link_exists(ifaceobj.name):
            self.logger.debug('iface %s not found' %ifaceobj.name)
            return

        self.query_check_disable_ipv6(ifaceobj, ifaceobjcurr)
        self.query_check_ipv6_addrgen(ifaceobj, ifaceobjcurr)

        self.query_n_update_ifaceobjcurr_attr(ifaceobj, ifaceobjcurr,
                'mtu', self.cache.get_link_mtu_str)
        hwaddress = self._get_hwaddress(ifaceobj)
        if hwaddress:
            rhwaddress = self.cache.get_link_address(ifaceobj.name)
            if not rhwaddress or utils.mac_str_to_int(rhwaddress) != utils.mac_str_to_int(hwaddress):
               ifaceobjcurr.update_config_with_status('hwaddress', rhwaddress,
                       1)
            elif not self._check_addresses_in_bridge(ifaceobj, hwaddress):
               # XXX: hw address is not in bridge
               ifaceobjcurr.update_config_with_status('hwaddress', rhwaddress,
                       1)
               ifaceobjcurr.status_str = 'bridge fdb error'
            else:
               ifaceobjcurr.update_config_with_status('hwaddress', rhwaddress,
                       0)
        self.query_n_update_ifaceobjcurr_attr(ifaceobj, ifaceobjcurr,
                    'alias', self.cache.get_link_alias)

        self._query_sysctl(ifaceobj, ifaceobjcurr)

        self._query_check_address(ifaceobj, ifaceobjcurr, ifaceobj_getfunc)

    def _query_check_address(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc):
        """ ifquery-check: attribute: "address" """
        if ifaceobj.addr_method in ["dhcp", "ppp"]:
            return

        if ifaceobj_getfunc:
            ifaceobj_list = ifaceobj_getfunc(ifaceobj.name)
        else:
            ifaceobj_list = [ifaceobj]

        intf_running_addrs = self.cache.get_managed_ip_addresses(ifaceobj.name, ifaceobj_list)
        user_config_addrs = self.cache.get_user_configured_addresses([ifaceobj])

        try:
            clagd_vxlan_anycast_ip = ipnetwork.IPNetwork(ifaceobj.get_attr_value_first("clagd-vxlan-anycast-ip"))

            if clagd_vxlan_anycast_ip in intf_running_addrs:
                user_config_addrs.append(clagd_vxlan_anycast_ip)
        except Exception:
            pass

        # Set ifaceobjcurr method and family
        ifaceobjcurr.addr_method = ifaceobj.addr_method
        ifaceobjcurr.addr_family = ifaceobj.addr_family

        if not intf_running_addrs and not user_config_addrs:
            # The device doesn't have any ips configured and the
            # the user didn't specify any ip in the configuration file
            return

        for address in user_config_addrs:
            ifaceobjcurr.update_config_with_status('address', str(address), address not in intf_running_addrs)
            try:
                intf_running_addrs.remove(address)
            except Exception:
                pass

        # if any ip address is left in 'intf_running_addrs' it means that they
        # used to be configured by ifupdown2 but not anymore. The entry was
        # removed from the configuration file but the IP is still configured on
        # the device, so we need to mark them as FAIL (we will only mark them
        # as failure on the first sibling).
        if ifaceobj.flags & iface.HAS_SIBLINGS and not ifaceobj.flags & iface.YOUNGEST_SIBLING:
                return

        all_stanza_user_config_ip = self.cache.get_user_configured_addresses(ifaceobj_list)

        for address in intf_running_addrs:
            if address not in all_stanza_user_config_ip:
                ifaceobjcurr.update_config_with_status('address', str(address), 1)

    def query_running_ipv6_addrgen(self, ifaceobjrunning):
        ipv6_addrgen = self.cache.get_link_ipv6_addrgen_mode(ifaceobjrunning.name)

        if ipv6_addrgen:
            ifaceobjrunning.update_config('ipv6-addrgen', 'off')

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        if not self.cache.link_exists(ifaceobjrunning.name):
            self.logger.debug('iface %s not found' %ifaceobjrunning.name)
            return

        self.query_running_ipv6_addrgen(ifaceobjrunning)

        dhclientcmd = dhclient()
        if (dhclientcmd.is_running(ifaceobjrunning.name) or
                dhclientcmd.is_running6(ifaceobjrunning.name)):
            # If dhcp is configured on the interface, we skip it
            return

        intf_running_addrs = self.cache.get_ip_addresses(ifaceobjrunning.name) or []

        if self.cache.link_is_loopback(ifaceobjrunning.name):
            for default_addr in self.default_loopback_addresses:
                try:
                    intf_running_addrs.remove(default_addr)
                except Exception:
                    pass
            ifaceobjrunning.addr_family.append('inet')
            ifaceobjrunning.addr_method = 'loopback'

        for addr in intf_running_addrs:
            ifaceobjrunning.update_config('address', str(addr))

        mtu = self.cache.get_link_mtu_str(ifaceobjrunning.name)
        if (mtu and
                (ifaceobjrunning.name == 'lo' and mtu != '16436') or
                (ifaceobjrunning.name != 'lo' and
                    mtu != self.get_mod_subattr('mtu', 'default'))):
                ifaceobjrunning.update_config('mtu', mtu)

        alias = self.cache.get_link_alias(ifaceobjrunning.name)
        if alias:
            ifaceobjrunning.update_config('alias', alias)

        ifaceobjrunning.update_config("hwaddress", self.cache.get_link_address(ifaceobjrunning.name))

    _run_ops = {
        'pre-up': _pre_up,
        'up': _up,
        'down': _down,
        'query-checkcurr': _query_check,
        'query-running': _query_running
    }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return list(self._run_ops.keys())

    def run(self, ifaceobj, operation, query_ifaceobj=None, ifaceobj_getfunc=None):
        """ run address configuration on the interface object passed as argument

        Args:
            **ifaceobj** (object): iface object

            **operation** (str): any of 'up', 'down', 'query-checkcurr',
                                 'query-running'
        Kwargs:
            query_ifaceobj (object): query check ifaceobject. This is only
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
            op_handler(self, ifaceobj, query_ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
        else:
            op_handler(self, ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
