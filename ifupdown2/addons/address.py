#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import socket

from ipaddr import IPNetwork, IPv4Network, IPv6Network, _BaseV6

try:
    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.netlink import netlink

    from ifupdown2.ifupdownaddons.dhclient import dhclient
    from ifupdown2.ifupdownaddons.LinkUtils import LinkUtils
    from ifupdown2.ifupdownaddons.modulebase import moduleBase

    import ifupdown2.ifupdown.statemanager as statemanager
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.ifupdownconfig as ifupdownconfig
except ImportError:
    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdown.netlink import netlink

    from ifupdownaddons.dhclient import dhclient
    from ifupdownaddons.LinkUtils import LinkUtils
    from ifupdownaddons.modulebase import moduleBase

    import ifupdown.statemanager as statemanager
    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.ifupdownconfig as ifupdownconfig


class address(moduleBase):
    """  ifupdown2 addon module to configure address, mtu, hwaddress, alias
    (description) on an interface """

    _modinfo = {'mhelp' : 'address configuration module for interfaces',
                'attrs': {
                      'address' :
                            {'help' : 'ipv4 or ipv6 addresses',
                             'validvals' : ['<ipv4/prefixlen>', '<ipv6/prefixlen>'],
                             'multiline' : True,
                             'example' : ['address 10.0.12.3/24',
                             'address 2000:1000:1000:1000:3::5/128']},
                      'netmask' :
                            {'help': 'netmask',
                             'example' : ['netmask 255.255.255.0'],
                             'compat' : True},
                      'broadcast' :
                            {'help': 'broadcast address',
                             'validvals' : ['<ipv4>', ],
                             'example' : ['broadcast 10.0.1.255']},
                      'scope' :
                            {'help': 'scope',
                             'validvals' : ['universe', 'site', 'link', 'host', 'nowhere'],
                             'example' : ['scope host']},
                      'preferred-lifetime' :
                            {'help': 'preferred lifetime',
                              'validrange' : ['0', '65535'],
                             'example' : ['preferred-lifetime forever',
                                          'preferred-lifetime 10']},
                      'gateway' :
                            {'help': 'default gateway',
                             'validvals' : ['<ipv4>', '<ipv6>'],
                             'multiline' : True,
                             'example' : ['gateway 255.255.255.0']},
                      'mtu' :
                            { 'help': 'interface mtu',
                              'validrange' : ['552', '9216'],
                              'example' : ['mtu 1600'],
                              'default' : '1500'},
                      'hwaddress' :
                            {'help' : 'hw address',
                             'validvals' : ['<mac>',],
                             'example': ['hwaddress 44:38:39:00:27:b8']},
                      'alias' :
                            { 'help': 'description/alias',
                              'example' : ['alias testnetwork']},
                      'address-purge' :
                            { 'help': 'purge existing addresses. By default ' +
                              'any existing ip addresses on an interface are ' +
                              'purged to match persistant addresses in the ' +
                              'interfaces file. Set this attribute to \'no\'' +
                              'if you want to preserve existing addresses',
                              'validvals' : ['yes', 'no'],
                              'default' : 'yes',
                              'example' : ['address-purge yes/no']},
                      'clagd-vxlan-anycast-ip' :
                            { 'help'     : 'Anycast local IP address for ' +
                              'dual connected VxLANs',
                              'validvals' : ['<ipv4>', ],
                              'example'  : ['clagd-vxlan-anycast-ip 36.0.0.11']},
                      'ip-forward' :
                            { 'help': 'ip forwarding flag',
                              'validvals': ['on', 'off', 'yes', 'no', '0', '1'],
                              'default' : 'off',
                              'example' : ['ip-forward off']},
                      'ip6-forward' :
                            { 'help': 'ipv6 forwarding flag',
                              'validvals': ['on', 'off', 'yes', 'no', '0', '1'],
                              'default' : 'off',
                              'example' : ['ip6-forward off']},
                      'mpls-enable' :
                            { 'help': 'mpls enable flag',
                              'validvals': ['yes', 'no'],
                              'default' : 'no',
                              'example' : ['mpls-enable yes']},
                    'ipv6-addrgen': {
                        'help': 'enable disable ipv6 link addrgenmode',
                        'validvals': ['on', 'off'],
                        'default': 'on',
                        'example': [
                            'ipv6-addrgen on',
                            'ipv6-addrgen off'
                        ]
                    }
                }}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self._bridge_fdb_query_cache = {}
        self.default_mtu = policymanager.policymanager_api.get_attr_default(module_name=self.__class__.__name__, attr='mtu')
        self.max_mtu = policymanager.policymanager_api.get_module_globals(module_name=self.__class__.__name__, attr='max_mtu')
        self.ipforward = policymanager.policymanager_api.get_attr_default(module_name=self.__class__.__name__, attr='ip-forward')
        self.ip6forward = policymanager.policymanager_api.get_attr_default(module_name=self.__class__.__name__, attr='ip6-forward')
        self.ifaces_defaults = policymanager.policymanager_api.get_iface_defaults(module_name=self.__class__.__name__)
        self.enable_l3_iface_forwarding_checks = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                self.__class__.__name__,
                'enable_l3_iface_forwarding_checks'
            )
        )

        if not self.default_mtu:
            self.default_mtu = '1500'

        self.logger.info('address: using default mtu %s' %self.default_mtu)

        if self.max_mtu:
            self.logger.info('address: using max mtu %s' %self.max_mtu)

        self.lower_iface_mtu_checked_list = list()

    def syntax_check(self, ifaceobj, ifaceobj_getfunc=None):
        return (self.syntax_check_multiple_gateway(ifaceobj)
                and self.syntax_check_addr_allowed_on(ifaceobj, True)
                and self.syntax_check_mtu(ifaceobj, ifaceobj_getfunc)
                and self.syntax_check_sysctls(ifaceobj)
                and self.syntax_check_enable_l3_iface_forwardings(ifaceobj, ifaceobj_getfunc, syntax_check=True))

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
                        raise Exception(
                            'configuring ip-forward off and ip address(es) (%s) is not compatible'
                            % (', '.join(vlan_addr))
                        )
                    else:
                        raise Exception(
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
        mtu = ifaceobj.get_attr_value_first('mtu')
        if mtu:
            return self._check_mtu_config(ifaceobj, mtu, ifaceobj_getfunc,
                                          syntaxcheck=True)
        return True

    def syntax_check_addr_allowed_on(self, ifaceobj, syntax_check=False):
        if ifaceobj.get_attr_value('address'):
            return utils.is_addr_ip_allowed_on(ifaceobj, syntax_check=syntax_check)
        return True

    def _syntax_check_multiple_gateway(self, family, found, addr, type_obj):
        if type(IPNetwork(addr)) == type_obj:
            if found:
                raise Exception('%s: multiple gateways for %s family'
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
                if self._syntax_check_multiple_gateway('inet', inet, addr,
                                                       IPv4Network):
                    inet = True
                if self._syntax_check_multiple_gateway('inet6', inet6, addr,
                                                       IPv6Network):
                    inet6 = True
            except Exception as e:
                self.logger.warning('%s: address: %s' % (ifaceobj.name, str(e)))
                result = False
        return result

    def _address_valid(self, addrs):
        if not addrs:
           return False
        if any(map(lambda a: True if a[:7] != '0.0.0.0'
                else False, addrs)):
           return True
        return False

    def _get_hwaddress(self, ifaceobj):
        return utils.strip_hwaddress(ifaceobj.get_attr_value_first('hwaddress'))

    def _process_bridge(self, ifaceobj, up):
        hwaddress = self._get_hwaddress(ifaceobj)
        addrs = ifaceobj.get_attr_value_first('address')
        is_vlan_dev_on_vlan_aware_bridge = False
        is_bridge = self.ipcmd.is_bridge(ifaceobj.name)
        if not is_bridge:
            if ifaceobj.link_kind & ifaceLinkKind.VLAN:
                bridgename = ifaceobj.lowerifaces[0]
                vlan = self._get_vlan_id(ifaceobj)
                is_vlan_dev_on_vlan_aware_bridge = self.ipcmd.bridge_is_vlan_aware(bridgename)
        if ((is_bridge and not self.ipcmd.bridge_is_vlan_aware(ifaceobj.name))
                        or is_vlan_dev_on_vlan_aware_bridge):
           if self._address_valid(addrs):
              if up:
                self.write_file('/proc/sys/net/ipv4/conf/%s' %ifaceobj.name +
                                '/arp_accept', '1')
              else:
                self.write_file('/proc/sys/net/ipv4/conf/%s' %ifaceobj.name +
                                '/arp_accept', '0')
        if hwaddress and is_vlan_dev_on_vlan_aware_bridge:
           if up:
              self.ipcmd.bridge_fdb_add(bridgename, hwaddress, vlan)
           else:
              self.ipcmd.bridge_fdb_del(bridgename, hwaddress, vlan)

    def _get_anycast_addr(self, ifaceobjlist):
        for ifaceobj in ifaceobjlist:
            anycast_addr = ifaceobj.get_attr_value_first('clagd-vxlan-anycast-ip')
            if anycast_addr:
                anycast_addr = anycast_addr+'/32'
                return anycast_addr
        return None

    def _inet_address_convert_to_cidr(self, ifaceobjlist):
        newaddrs = []
        newaddr_attrs = {}

        for ifaceobj in ifaceobjlist:
            addrs = ifaceobj.get_attr_value('address')
            if not addrs:
                continue

            if not self.syntax_check_addr_allowed_on(ifaceobj,
                                                     syntax_check=False):
                return (False, newaddrs, newaddr_attrs)
            # If user address is not in CIDR notation, convert them to CIDR
            for addr_index in range(0, len(addrs)):
                addr = addrs[addr_index]
                newaddr = addr
                if '/' in addr:
                    newaddrs.append(addr)
                else:
                    netmask = ifaceobj.get_attr_value_n('netmask', addr_index)
                    if netmask:
                        prefixlen = IPNetwork('%s' %addr +
                                    '/%s' %netmask).prefixlen
                        newaddr = addr + '/%s' %prefixlen
                    else:
                        # we are here because there is no slash (/xx) and no netmask
                        # just let IPNetwork handle the ipv4 or ipv6 address mask
                        prefixlen = IPNetwork(addr).prefixlen
                        newaddr = addr + '/%s' %prefixlen
                    newaddrs.append(newaddr)

                attrs = {}
                for a in ['broadcast', 'pointopoint', 'scope',
                        'preferred-lifetime']:
                    aval = ifaceobj.get_attr_value_n(a, addr_index)
                    if aval:
                        attrs[a] = aval

                if attrs:
                    newaddr_attrs[newaddr]= attrs
        return (True, newaddrs, newaddr_attrs)

    def _inet_address_list_config(self, ifaceobj, newaddrs, newaddr_attrs):
        for addr_index in range(0, len(newaddrs)):
            try:
                if newaddr_attrs:
                    self.ipcmd.addr_add(ifaceobj.name, newaddrs[addr_index],
                        newaddr_attrs.get(newaddrs[addr_index],
                                          {}).get('broadcast'),
                        newaddr_attrs.get(newaddrs[addr_index],
                                          {}).get('pointopoint'),
                        newaddr_attrs.get(newaddrs[addr_index],
                                          {}).get('scope'),
                        newaddr_attrs.get(newaddrs[addr_index],
                                          {}).get('preferred-lifetime'))
                else:
                    self.ipcmd.addr_add(ifaceobj.name, newaddrs[addr_index])
            except Exception, e:
                self.log_error(str(e), ifaceobj)

    def _inet_address_config(self, ifaceobj, ifaceobj_getfunc=None,
                             force_reapply=False):
        squash_addr_config = (True if \
                                  ifupdownconfig.config.get('addr_config_squash', \
                              '0') == '1' else False)

        if (squash_addr_config and
            not (ifaceobj.flags & ifaceobj.YOUNGEST_SIBLING)):
            return

        purge_addresses = ifaceobj.get_attr_value_first('address-purge')
        if not purge_addresses:
           purge_addresses = 'yes'

        if squash_addr_config and ifaceobj.flags & iface.HAS_SIBLINGS:
            ifaceobjlist = ifaceobj_getfunc(ifaceobj.name)
        else:
            ifaceobjlist = [ifaceobj]

        module_name = self.__class__.__name__
        ifname = ifaceobj.name

        (addr_supported, newaddrs, newaddr_attrs) = self._inet_address_convert_to_cidr(ifaceobjlist)
        newaddrs = utils.get_ip_objs(module_name, ifname, newaddrs)

        if not addr_supported:
            return
        if (not squash_addr_config and (ifaceobj.flags & iface.HAS_SIBLINGS)):
            # if youngest sibling and squash addr is not set
            # print a warning that addresses will not be purged
            if (ifaceobj.flags & iface.YOUNGEST_SIBLING):
                self.logger.warn('%s: interface has multiple ' %ifaceobj.name +
                               'iface stanzas, skip purging existing addresses')
            purge_addresses = 'no'

        if not ifupdownflags.flags.PERFMODE and purge_addresses == 'yes':
            # if perfmode is not set and purge addresses is not set to 'no'
            # lets purge addresses not in the config
            runningaddrs = self.ipcmd.get_running_addrs(ifaceobj, details=False)

            # if anycast address is configured on 'lo' and is in running config
            # add it to newaddrs so that ifreload doesn't wipe it out
            anycast_addr = utils.get_normalized_ip_addr(ifaceobj.name, self._get_anycast_addr(ifaceobjlist))

            if runningaddrs and anycast_addr and anycast_addr in runningaddrs:
                newaddrs.append(anycast_addr)

            user_ip4, user_ip6, newaddrs = self.order_user_configured_addrs(newaddrs)

            if newaddrs == runningaddrs or self.compare_running_ips_and_user_config(user_ip4, user_ip6, runningaddrs):
                if force_reapply:
                    self._inet_address_list_config(ifaceobj, newaddrs, newaddr_attrs)
                return
            try:
                # if primary address is not same, there is no need to keep any.
                # reset all addresses
                if newaddrs and runningaddrs and newaddrs[0] != runningaddrs[0]:
                    skip_addrs = []
                else:
                    skip_addrs = newaddrs or []
                for addr in runningaddrs or []:
                    if addr in skip_addrs:
                        continue
                    self.ipcmd.addr_del(ifaceobj.name, addr)
            except Exception, e:
                self.log_warn(str(e))
        if not newaddrs:
            return
        self._inet_address_list_config(ifaceobj, newaddrs, newaddr_attrs)

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

    def order_user_configured_addrs(self, user_config_addrs):
        ip4 = []
        ip6 = []

        for a in user_config_addrs:
            if isinstance(a, _BaseV6):
                ip6.append(str(a))
            else:
                ip4.append(str(a))

        return ip4, ip6, ip4 + ip6

    def _delete_gateway(self, ifaceobj, gateways, vrf, metric):
        for del_gw in gateways:
            try:
                self.ipcmd.route_del_gateway(ifaceobj.name, del_gw, vrf, metric)
            except Exception as e:
                self.logger.debug('%s: %s' % (ifaceobj.name, str(e)))

    def _add_delete_gateway(self, ifaceobj, gateways=[], prev_gw=[]):
        vrf = ifaceobj.get_attr_value_first('vrf')
        metric = ifaceobj.get_attr_value_first('metric')
        self._delete_gateway(ifaceobj, list(set(prev_gw) - set(gateways)),
                             vrf, metric)
        for add_gw in gateways:
            try:
                self.ipcmd.route_add_gateway(ifaceobj.name, add_gw, vrf, metric)
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

    def _check_mtu_config(self, ifaceobj, mtu, ifaceobj_getfunc, syntaxcheck=False):
        retval = True
        if (ifaceobj.link_kind & ifaceLinkKind.BRIDGE):
            if syntaxcheck:
                self.logger.warn('%s: bridge inherits mtu from its ports. There is no need to assign mtu on a bridge' %ifaceobj.name)
                retval = False
            else:
                self.logger.info('%s: bridge inherits mtu from its ports. There is no need to assign mtu on a bridge' %ifaceobj.name)
        elif ifaceobj_getfunc:
            if ((ifaceobj.link_privflags & ifaceLinkPrivFlags.BOND_SLAVE) and
                ifaceobj.upperifaces):
                masterobj = ifaceobj_getfunc(ifaceobj.upperifaces[0])
                if masterobj:
                    master_mtu = masterobj[0].get_attr_value_first('mtu')
                    if master_mtu and master_mtu != mtu:
                        if syntaxcheck:
                            self.logger.warn('%s: bond slave mtu %s is different from bond master %s mtu %s. There is no need to configure mtu on a bond slave.' %(ifaceobj.name, mtu, masterobj[0].name, master_mtu))
                            retval = False
                        else:
                            self.logger.info('%s: bond slave mtu %s is different from bond master %s mtu %s. There is no need to configure mtu on a bond slave.' %(ifaceobj.name, mtu, masterobj[0].name, master_mtu))
            elif ((ifaceobj.link_kind & ifaceLinkKind.VLAN) and
                  ifaceobj.lowerifaces):
                lowerobj = ifaceobj_getfunc(ifaceobj.lowerifaces[0])
                if lowerobj:
                    if syntaxcheck:
                        lowerdev_mtu = lowerobj[0].get_attr_value_first('mtu')
                    else:
                        lowerdev_mtu = self.ipcmd.link_get_mtu_sysfs(lowerobj[0].name)
                    if lowerdev_mtu and int(mtu) > int(lowerdev_mtu):
                        self.logger.warn('%s: vlan dev mtu %s is greater than lower realdev %s mtu %s'
                                         %(ifaceobj.name, mtu, lowerobj[0].name, lowerdev_mtu))
                        retval = False
                    elif (not lowerobj[0].link_kind and
                          not (lowerobj[0].link_privflags & ifaceLinkPrivFlags.LOOPBACK) and
                          not lowerdev_mtu and self.default_mtu and
                          (int(mtu) > int(self.default_mtu))):
                        # only check default mtu on lower device which is a physical interface
                        self.logger.warn('%s: vlan dev mtu %s is greater than lower realdev %s mtu %s'
                                         %(ifaceobj.name, mtu, lowerobj[0].name, self.default_mtu))
                        retval = False
            if self.max_mtu and mtu > self.max_mtu:
                self.logger.warn('%s: specified mtu %s is greater than max mtu %s'
                                 %(ifaceobj.name, mtu, self.max_mtu))
                retval = False
        return retval

    def _propagate_mtu_to_upper_devs(self, ifaceobj, mtu, ifaceobj_getfunc):
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
                running_mtu = self.ipcmd.link_get_mtu(upperobjs[0].name)
                if not running_mtu or (running_mtu != mtu):
                    self.ipcmd.link_set(u, 'mtu', mtu)

    def _process_mtu_config(self, ifaceobj, ifaceobj_getfunc, mtu):
        if mtu:
            if not self._check_mtu_config(ifaceobj, mtu, ifaceobj_getfunc):
                return
            cached_running_mtu = self.ipcmd.link_get_mtu(ifaceobj.name)
            running_mtu = self.ipcmd.link_get_mtu_sysfs(ifaceobj.name)
            if not running_mtu or (running_mtu and running_mtu != mtu):
                force = cached_running_mtu != running_mtu
                self.ipcmd.link_set(ifaceobj.name, 'mtu', mtu, force=force)
                if (not ifupdownflags.flags.ALL and
                    not ifaceobj.link_kind and
                    ifupdownconfig.config.get('adjust_logical_dev_mtu', '1') != '0'):
                    # This is additional cost to us, so do it only when
                    # ifupdown2 is called on a particular interface and
                    # it is a physical interface
                    self._propagate_mtu_to_upper_devs(ifaceobj, mtu, ifaceobj_getfunc)
            return

        if ifaceobj.link_kind:
            # bonds and vxlan devices need an explicit set of mtu.
            # bridges don't need mtu set
            if (ifaceobj.link_kind & ifaceLinkKind.BOND or
                ifaceobj.link_kind & ifaceLinkKind.VXLAN):
                running_mtu = self.ipcmd.link_get_mtu(ifaceobj.name)
                if (self.default_mtu and running_mtu != self.default_mtu):
                    self.ipcmd.link_set(ifaceobj.name, 'mtu', self.default_mtu)
                return
            if (ifupdownconfig.config.get('adjust_logical_dev_mtu', '1') != '0'
                and ifaceobj.lowerifaces):
                # set vlan interface mtu to lower device mtu
                if (ifaceobj.link_kind & ifaceLinkKind.VLAN):
                    lower_iface = ifaceobj.lowerifaces[0]
                    if lower_iface not in self.lower_iface_mtu_checked_list:
                        lower_iface_mtu = self.ipcmd.link_get_mtu_sysfs(lower_iface)
                        self.ipcmd.cache_update([lower_iface, 'mtu'], lower_iface_mtu)
                        self.lower_iface_mtu_checked_list.append(lower_iface)
                    else:
                        lower_iface_mtu = self.ipcmd.link_get_mtu(lower_iface)

                    if lower_iface_mtu != self.ipcmd.link_get_mtu_sysfs(ifaceobj.name):
                        self.ipcmd.link_set_mtu(ifaceobj.name, lower_iface_mtu)

        elif (not (ifaceobj.name == 'lo') and not ifaceobj.link_kind and
              not (ifaceobj.link_privflags & ifaceLinkPrivFlags.BOND_SLAVE) and
              self.default_mtu):
            # logical devices like bridges and vlan devices rely on mtu
            # from their lower devices. ie mtu travels from
            # lower devices to upper devices. For bonds mtu travels from
            # upper to lower devices. running mtu depends on upper and
            # lower device mtu. With all this implicit mtu
            # config by the kernel in play, we try to be cautious here
            # on which devices we want to reset mtu to default.
            # essentially only physical interfaces which are not bond slaves
            running_mtu = self.ipcmd.link_get_mtu(ifaceobj.name)
            if running_mtu != self.default_mtu:
                self.ipcmd.link_set(ifaceobj.name, 'mtu', self.default_mtu)

    def _set_bridge_forwarding(self, ifaceobj):
        """ set ip forwarding to 0 if bridge interface does not have a
        ip nor svi """
        if not ifaceobj.upperifaces and not ifaceobj.get_attr_value('address'):
            # set forwarding = 0
            if self.sysctl_get('net.ipv4.conf.%s.forwarding' %ifaceobj.name) == '1':
                self.sysctl_set('net.ipv4.conf.%s.forwarding' %ifaceobj.name, 0)
            if self.sysctl_get('net.ipv6.conf.%s.forwarding' %ifaceobj.name) == '1':
                self.sysctl_set('net.ipv6.conf.%s.forwarding' %ifaceobj.name, 0)
        else:
            if self.sysctl_get('net.ipv4.conf.%s.forwarding' %ifaceobj.name) == '0':
                self.sysctl_set('net.ipv4.conf.%s.forwarding' %ifaceobj.name, 1)
            if self.sysctl_get('net.ipv6.conf.%s.forwarding' %ifaceobj.name) == '0':
                self.sysctl_set('net.ipv6.conf.%s.forwarding' %ifaceobj.name, 1)

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
            running_mpls_enable = self.read_file_oneline(
                '/proc/sys/net/mpls/conf/%s/input'
                % ifaceobj.name
            )

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
            return
        if not self.syntax_check_sysctls(ifaceobj):
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
            ipforward = (self.ipforward or
                         self.get_mod_subattr('ip-forward', 'default'))
        ipforward = utils.boolean_support_binary(ipforward)
        # File read has been used for better performance
        # instead of using sysctl command
        running_ipforward = self.read_file_oneline(
                                '/proc/sys/net/ipv4/conf/%s/forwarding'
                                %ifaceobj.name)
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
            ip6forward = (self.ip6forward or
                          self.get_mod_subattr('ip6-forward', 'default'))
        ip6forward = utils.boolean_support_binary(ip6forward)
        # File read has been used for better performance
        # instead of using sysctl command
        running_ip6forward = self.read_file_oneline(
                                '/proc/sys/net/ipv6/conf/%s/forwarding'
                                %ifaceobj.name)
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
        mtu = ifaceobj.get_attr_value_first('mtu')

        if not mtu:
            default_iface_mtu = self.ifaces_defaults.get(ifaceobj.name, {}).get('mtu')

            if default_iface_mtu:
                try:
                    mtu = default_iface_mtu
                    int(default_iface_mtu)
                except Exception as e:
                    self.logger.warning('%s: MTU value from policy file: %s' % (ifaceobj.name, str(e)))
                    return

        self._process_mtu_config(ifaceobj, ifaceobj_getfunc, mtu)

    def up_ipv6_addrgen(self, ifaceobj):
        user_configured_ipv6_addrgen = ifaceobj.get_attr_value_first('ipv6-addrgen')

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
            self.ipcmd.ipv6_addrgen(ifaceobj.name, ipv6_addrgen_nl, link_created=True)
            # link_create=False will flush the addr cache of that intf
        else:
            self.logger.warning('%s: invalid value "%s" for attribute ipv6-addrgen' % (ifaceobj.name, user_configured_ipv6_addrgen))

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        if not self.ipcmd.link_exists(ifaceobj.name):
            return

        if not self.syntax_check_enable_l3_iface_forwardings(ifaceobj, ifaceobj_getfunc):
            return

        alias = ifaceobj.get_attr_value_first('alias')
        current_alias = self.ipcmd.link_get_alias(ifaceobj.name)
        if alias and alias != current_alias:
            self.ipcmd.link_set_alias(ifaceobj.name, alias)
        elif not alias and current_alias:
            self.ipcmd.link_set_alias(ifaceobj.name, '')

        self._sysctl_config(ifaceobj)

        addr_method = ifaceobj.addr_method
        force_reapply = False
        try:
            # release any stale dhcp addresses if present
            if (addr_method not in ["dhcp", "ppp"] and not ifupdownflags.flags.PERFMODE and
                    not (ifaceobj.flags & iface.HAS_SIBLINGS)):
                # if not running in perf mode and ifaceobj does not have
                # any sibling iface objects, kill any stale dhclient
                # processes
                dhclientcmd = dhclient()
                if dhclientcmd.is_running(ifaceobj.name):
                    # release any dhcp leases
                    dhclientcmd.release(ifaceobj.name)
                    force_reapply = True
                elif dhclientcmd.is_running6(ifaceobj.name):
                    dhclientcmd.release6(ifaceobj.name)
                    force_reapply = True
        except:
            pass

        self.ipcmd.batch_start()
        self.up_ipv6_addrgen(ifaceobj)

        if addr_method not in ["dhcp", "ppp"]:
            self._inet_address_config(ifaceobj, ifaceobj_getfunc,
                                      force_reapply)

        self.process_mtu(ifaceobj, ifaceobj_getfunc)

        try:
            self.ipcmd.batch_commit()
        except Exception as e:
            self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj, raise_error=False)

        try:
            hwaddress = self._get_hwaddress(ifaceobj)
            if hwaddress:
                running_hwaddress = None
                if not ifupdownflags.flags.PERFMODE: # system is clean
                    running_hwaddress = self.ipcmd.link_get_hwaddress(ifaceobj.name)
                if hwaddress != running_hwaddress:
                    slave_down = False
                    netlink.link_set_updown(ifaceobj.name, "down")
                    if ifaceobj.link_kind & ifaceLinkKind.BOND:
                        # if bond, down all the slaves
                        if ifaceobj.lowerifaces:
                            for l in ifaceobj.lowerifaces:
                                netlink.link_set_updown(l, "down")
                            slave_down = True
                    try:
                        self.ipcmd.link_set(ifaceobj.name, 'address', hwaddress)
                    finally:
                        netlink.link_set_updown(ifaceobj.name, "up")
                        if slave_down:
                            for l in ifaceobj.lowerifaces:
                                netlink.link_set_updown(l, "up")

            # Handle special things on a bridge
            self._process_bridge(ifaceobj, True)
        except Exception, e:
            self.log_error('%s: %s' %(ifaceobj.name, str(e)), ifaceobj)

        gateways = ifaceobj.get_attr_value('gateway')
        if not gateways:
            gateways = []
        prev_gw = self._get_prev_gateway(ifaceobj, gateways)
        self._add_delete_gateway(ifaceobj, gateways, prev_gw)

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        try:
            if not self.ipcmd.link_exists(ifaceobj.name):
                return
            addr_method = ifaceobj.addr_method
            if addr_method not in ["dhcp", "ppp"]:
                if ifaceobj.get_attr_value_first('address-purge')=='no':
                    addrlist = ifaceobj.get_attr_value('address')
                    for addr in addrlist:
                        self.ipcmd.addr_del(ifaceobj.name, addr)
                    #self.ipcmd.addr_del(ifaceobj.name, ifaceobj.get_attr_value('address')[0])
                elif not ifaceobj.link_kind:
                    # for logical interfaces we don't need to remove the ip addresses
                    # kernel will do it for us on 'ip link del'
                    self.ipcmd.del_addr_all(ifaceobj.name)
            gateways = ifaceobj.get_attr_value('gateway')
            if gateways:
                self._delete_gateway(ifaceobj, gateways,
                                     ifaceobj.get_attr_value_first('vrf'),
                                     ifaceobj.get_attr_value_first('metric'))
            mtu = ifaceobj.get_attr_value_first('mtu')
            if (not ifaceobj.link_kind and mtu and
                self.default_mtu and (mtu != self.default_mtu)):
                self.ipcmd.link_set(ifaceobj.name, 'mtu', self.default_mtu)
            alias = ifaceobj.get_attr_value_first('alias')
            if alias:
                self.write_file('/sys/class/net/%s/ifalias' % ifaceobj.name, '\n')
            # XXX hwaddress reset cannot happen because we dont know last
            # address.

            # Handle special things on a bridge
            self._process_bridge(ifaceobj, False)
        except Exception, e:
            self.logger.debug('%s : %s' %(ifaceobj.name, str(e)))
            pass

    def _get_iface_addresses(self, ifaceobj):
        addrlist = ifaceobj.get_attr_value('address')
        outaddrlist = []

        if not addrlist: return None
        for addrindex in range(0, len(addrlist)):
            addr = addrlist[addrindex]
            netmask = ifaceobj.get_attr_value_n('netmask', addrindex)
            if netmask:
                prefixlen = IPNetwork('%s' %addr +
                                '/%s' %netmask).prefixlen
                addr = addr + '/%s' %prefixlen
            outaddrlist.append(addr)
        return outaddrlist

    def _get_bridge_fdbs(self, bridgename, vlan):
        fdbs = self._bridge_fdb_query_cache.get(bridgename)
        if not fdbs:
           fdbs = self.ipcmd.bridge_fdb_show_dev(bridgename)
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
            if self.ipcmd.bridge_is_vlan_aware(bridgename):
                fdb_addrs = self._get_bridge_fdbs(bridgename, str(vlan))
                if not fdb_addrs or hwaddress not in fdb_addrs:
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
                running_ipforward = self.read_file_oneline(
                                        '/proc/sys/net/ipv4/conf/%s/forwarding'
                                        %ifaceobj.name)
                running_ipforward = utils.get_boolean_from_string(running_ipforward)
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
                running_ip6forward = self.read_file_oneline(
                                        '/proc/sys/net/ipv6/conf/%s/forwarding'
                                        %ifaceobj.name)
                running_ip6forward = utils.get_boolean_from_string(running_ip6forward)
                config_ip6forward = utils.get_boolean_from_string(ip6forward)
                ifaceobjcurr.update_config_with_status(
                    'ip6-forward',
                    'on' if running_ip6forward else 'off',
                    running_ip6forward != config_ip6forward
                )
        mpls_enable = ifaceobj.get_attr_value_first('mpls-enable');
        if mpls_enable:
            running_mpls_enable = self.read_file_oneline(
                                    '/proc/sys/net/mpls/conf/%s/input'
                                    %ifaceobj.name)
            running_mpls_enable = utils.get_yesno_from_onezero(
                                            running_mpls_enable)
            ifaceobjcurr.update_config_with_status('mpls-enable',
                                                   running_mpls_enable,
                                            mpls_enable != running_mpls_enable)
        return

    def query_check_ipv6_addrgen(self, ifaceobj, ifaceobjcurr):
        ipv6_addrgen = ifaceobj.get_attr_value_first('ipv6-addrgen')

        if not ipv6_addrgen:
            return

        if ipv6_addrgen in utils._string_values:
            ifaceobjcurr.update_config_with_status(
                'ipv6-addrgen',
                ipv6_addrgen,
                utils.get_boolean_from_string(ipv6_addrgen) == self.ipcmd.get_ipv6_addrgen_mode(ifaceobj.name)
            )
        else:
            ifaceobjcurr.update_config_with_status('ipv6-addrgen', ipv6_addrgen, 1)

    def _query_check(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        runningaddrsdict = None
        if not self.ipcmd.link_exists(ifaceobj.name):
            self.logger.debug('iface %s not found' %ifaceobj.name)
            return

        self.query_check_ipv6_addrgen(ifaceobj, ifaceobjcurr)

        addr_method = ifaceobj.addr_method
        self.query_n_update_ifaceobjcurr_attr(ifaceobj, ifaceobjcurr,
                'mtu', self.ipcmd.link_get_mtu)
        hwaddress = self._get_hwaddress(ifaceobj)
        if hwaddress:
            rhwaddress = self.ipcmd.link_get_hwaddress(ifaceobj.name)
            if not rhwaddress  or rhwaddress != hwaddress:
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
                    'alias', self.ipcmd.link_get_alias)
        self._query_sysctl(ifaceobj, ifaceobjcurr)
        # compare addresses
        if addr_method in ["dhcp", "ppp"]:
           return
        addrs = utils.get_normalized_ip_addr(ifaceobj.name,
                                             self._get_iface_addresses(ifaceobj))
        runningaddrsdict = self.ipcmd.get_running_addrs(ifaceobj)
        # if anycast address is configured on 'lo' and is in running config
        # add it to addrs so that query_check doesn't fail
        anycast_addr = utils.get_normalized_ip_addr(ifaceobj.name, ifaceobj.get_attr_value_first('clagd-vxlan-anycast-ip'))
        if anycast_addr:
            anycast_addr = anycast_addr+'/32'
        if runningaddrsdict and anycast_addr and runningaddrsdict.get(anycast_addr):
            addrs.append(anycast_addr)

        # Set ifaceobjcurr method and family
        ifaceobjcurr.addr_method = ifaceobj.addr_method
        ifaceobjcurr.addr_family = ifaceobj.addr_family
        if not runningaddrsdict and not addrs:
            return
        runningaddrs = runningaddrsdict.keys() if runningaddrsdict else []
        # Add /32 netmask to configured address without netmask.
        # This may happen on interfaces where pointopoint is used.
        runningaddrs = [ addr if '/' in addr else addr + '/32' for addr in runningaddrs]
        if runningaddrs != addrs:
            runningaddrsset = set(runningaddrs) if runningaddrs else set([])
            addrsset = set(addrs) if addrs else set([])
            if (ifaceobj.flags & iface.HAS_SIBLINGS):
                if not addrsset:
                    return
                # only check for addresses present in running config
                addrsdiff = addrsset.difference(runningaddrsset)
                for addr in addrs:
                    if addr in addrsdiff:
                        ifaceobjcurr.update_config_with_status('address',
                                    addr, 1)
                    else:
                        ifaceobjcurr.update_config_with_status('address',
                                    addr, 0)
            else:
                addrsdiff = addrsset.symmetric_difference(runningaddrsset)
                for addr in addrsset.union(runningaddrsset):
                    if addr in addrsdiff:
                        ifaceobjcurr.update_config_with_status('address',
                                                               addr, 1)
                    else:
                        ifaceobjcurr.update_config_with_status('address',
                                                               addr, 0)
        elif addrs:
            [ifaceobjcurr.update_config_with_status('address',
                       addr, 0) for addr in addrs]
        #XXXX Check broadcast address, scope, etc
        return

    def query_running_ipv6_addrgen(self, ifaceobjrunning):
        ipv6_addrgen = self.ipcmd.get_ipv6_addrgen_mode(ifaceobjrunning.name)

        if ipv6_addrgen:
            ifaceobjrunning.update_config('ipv6-addrgen', 'off')

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        if not self.ipcmd.link_exists(ifaceobjrunning.name):
            self.logger.debug('iface %s not found' %ifaceobjrunning.name)
            return

        self.query_running_ipv6_addrgen(ifaceobjrunning)

        dhclientcmd = dhclient()
        if (dhclientcmd.is_running(ifaceobjrunning.name) or
                dhclientcmd.is_running6(ifaceobjrunning.name)):
            # If dhcp is configured on the interface, we skip it
            return
        isloopback = self.ipcmd.link_isloopback(ifaceobjrunning.name)
        if isloopback:
            default_addrs = ['127.0.0.1/8', '::1/128']
            ifaceobjrunning.addr_family.append('inet')
            ifaceobjrunning.addr_method = 'loopback'
        else:
            default_addrs = []
        runningaddrsdict = self.ipcmd.get_running_addrs(ifaceobjrunning)
        if runningaddrsdict:
            [ifaceobjrunning.update_config('address', addr)
                for addr, addrattrs in runningaddrsdict.items()
                if addr not in default_addrs]
        mtu = self.ipcmd.link_get_mtu(ifaceobjrunning.name)
        if (mtu and
                (ifaceobjrunning.name == 'lo' and mtu != '16436') or
                (ifaceobjrunning.name != 'lo' and
                    mtu != self.get_mod_subattr('mtu', 'default'))):
                ifaceobjrunning.update_config('mtu', mtu)
        alias = self.ipcmd.link_get_alias(ifaceobjrunning.name)
        if alias:
            ifaceobjrunning.update_config('alias', alias)

        ipforward = self.read_file_oneline(
                        '/proc/sys/net/ipv4/conf/%s/forwarding'
                        %ifaceobjrunning.name)


    _run_ops = {'up' : _up,
               'down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = LinkUtils()

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
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
        else:
            op_handler(self, ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
