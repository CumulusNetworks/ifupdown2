#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os

try:
    from ipaddr import IPNetwork, IPv4Network, IPv6Network, IPv4Address, IPv6Address
    from sets import Set
    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdownaddons.modulebase import moduleBase
    from ifupdownaddons.iproute2 import iproute2
    from ifupdownaddons.dhclient import dhclient
    import ifupdown.policymanager as policymanager
    from ifupdown.netlink import netlink
    import ifupdown.ifupdownconfig as ifupdownConfig
    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.statemanager as statemanager
except ImportError, e:
    raise ImportError(str(e) + "- required module not found")


class address(moduleBase):
    """  ifupdown2 addon module to configure address, mtu, hwaddress, alias
    (description) on an interface """

    _modinfo = {'mhelp': 'address configuration module for interfaces',
                'attrs': {
                    'address':
                    {'help': 'ipv4 or ipv6 addresses',
                     'validvals': ['<ipv4/prefixlen>', '<ipv6/prefixlen>'],
                             'multiline': True,
                             'example': ['address 10.0.12.3/24',
                                         'address 2000:1000:1000:1000:3::5/128']},
                    'netmask':
                    {'help': 'netmask',
                             'example': ['netmask 255.255.255.0'],
                             'compat': True},
                    'broadcast':
                    {'help': 'broadcast address',
                             'validvals': ['<ipv4>', ],
                             'example': ['broadcast 10.0.1.255']},
                    'scope':
                    {'help': 'scope',
                             'validvals': ['universe', 'site', 'link', 'host', 'nowhere'],
                             'example': ['scope host']},
                    'preferred-lifetime':
                    {'help': 'preferred lifetime',
                             'validrange': ['0', '65535'],
                             'example': ['preferred-lifetime forever',
                                         'preferred-lifetime 10']},
                    'gateway':
                    {'help': 'default gateway',
                             'validvals': ['<ipv4>', '<ipv6>'],
                             'multiline': True,
                             'example': ['gateway 255.255.255.0']},
                    'mtu':
                    {'help': 'interface mtu',
                             'validrange': ['552', '9216'],
                             'example': ['mtu 1600'],
                             'default': '1500'},
                    'hwaddress':
                    {'help': 'hw address',
                             'validvals': ['<mac>', ],
                             'example': ['hwaddress 44:38:39:00:27:b8']},
                    'alias':
                    {'help': 'description/alias',
                             'example': ['alias testnetwork']},
                    'address-purge':
                    {'help': 'purge existing addresses. By default ' +
                             'any existing ip addresses on an interface are ' +
                             'purged to match persistant addresses in the ' +
                             'interfaces file. Set this attribute to \'no\'' +
                             'if you want to preserve existing addresses',
                             'validvals': ['yes', 'no'],
                             'default': 'yes',
                             'example': ['address-purge yes/no']},
                    'clagd-vxlan-anycast-ip':
                    {'help': 'Anycast local IP address for ' +
                             'dual connected VxLANs',
                             'validvals': ['<ipv4>', ],
                             'example': ['clagd-vxlan-anycast-ip 36.0.0.11']}}}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self._bridge_fdb_query_cache = {}
        self.default_mtu = policymanager.policymanager_api.get_attr_default(
            module_name=self.__class__.__name__, attr='mtu')

    def _address_valid(self, addrs):
        if not addrs:
            return False
        if any(map(lambda a: True if a[:7] != '0.0.0.0'
                   else False, addrs)):
            return True
        return False

    def _get_hwaddress(self, ifaceobj):
        hwaddress = ifaceobj.get_attr_value_first('hwaddress')
        if hwaddress and hwaddress.startswith("ether"):
            hwaddress = hwaddress[5:].strip()
        return hwaddress

    def _process_bridge(self, ifaceobj, up):
        hwaddress = self._get_hwaddress(ifaceobj)
        addrs = ifaceobj.get_attr_value_first('address')
        is_vlan_dev_on_vlan_aware_bridge = False
        is_bridge = self.ipcmd.is_bridge(ifaceobj.name)
        if not is_bridge:
            if '.' in ifaceobj.name:
                (bridgename, vlan) = ifaceobj.name.split('.')
                is_vlan_dev_on_vlan_aware_bridge = self.ipcmd.bridge_is_vlan_aware(
                    bridgename)
        if ((is_bridge and not self.ipcmd.bridge_is_vlan_aware(ifaceobj.name))
                or is_vlan_dev_on_vlan_aware_bridge):
            if self._address_valid(addrs):
                if up:
                    self.write_file('/proc/sys/net/ipv4/conf/%s' % ifaceobj.name +
                                    '/arp_accept', '1')
                else:
                    self.write_file('/proc/sys/net/ipv4/conf/%s' % ifaceobj.name +
                                    '/arp_accept', '0')
        if hwaddress and is_vlan_dev_on_vlan_aware_bridge:
            if up:
                self.ipcmd.bridge_fdb_add(bridgename, hwaddress, vlan)
            else:
                self.ipcmd.bridge_fdb_del(bridgename, hwaddress, vlan)

    def _get_anycast_addr(self, ifaceobjlist):
        for ifaceobj in ifaceobjlist:
            anycast_addr = ifaceobj.get_attr_value_first(
                'clagd-vxlan-anycast-ip')
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

            if (((ifaceobj.role & ifaceRole.SLAVE) and
                 not (ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE)) or
                ((ifaceobj.link_kind & ifaceLinkKind.BRIDGE) and
                 (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE))):
                # we must not configure an IP address if the interface is
                # enslaved or is a VLAN AWARE BRIDGE
                self.logger.info('%s: ignoring ip address. Interface is '
                                 'enslaved or a vlan aware bridge and cannot'
                                 ' have an IP Address' % (ifaceobj.name))
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
                        prefixlen = IPNetwork('%s' % addr +
                                              '/%s' % netmask).prefixlen
                        newaddr = addr + '/%s' % prefixlen
                    else:
                        # we are here because there is no slash (/xx) and no netmask
                        # just let IPNetwork handle the ipv4 or ipv6 address mask
                        prefixlen = IPNetwork(addr).prefixlen
                        newaddr = addr + '/%s' % prefixlen
                    newaddrs.append(newaddr)

                attrs = {}
                for a in ['broadcast', 'pointopoint', 'scope',
                          'preferred-lifetime']:
                    aval = ifaceobj.get_attr_value_n(a, addr_index)
                    if aval:
                        attrs[a] = aval

                if attrs:
                    newaddr_attrs[newaddr] = attrs
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
        squash_addr_config = (True if
                              ifupdownConfig.config.get('addr_config_squash',
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

        (addr_supported, newaddrs,
         newaddr_attrs) = self._inet_address_convert_to_cidr(ifaceobjlist)
        newaddrs = utils.get_normalized_ip_addr(ifaceobj.name, newaddrs)
        if not addr_supported:
            return
        if (not squash_addr_config and (ifaceobj.flags & iface.HAS_SIBLINGS)):
            # if youngest sibling and squash addr is not set
            # print a warning that addresses will not be purged
            if (ifaceobj.flags & iface.YOUNGEST_SIBLING):
                self.logger.warn('%s: interface has multiple ' % ifaceobj.name +
                                 'iface stanzas, skip purging existing addresses')
            purge_addresses = 'no'

        if not ifupdownflags.flags.PERFMODE and purge_addresses == 'yes':
            # if perfmode is not set and purge addresses is not set to 'no'
            # lets purge addresses not in the config
            runningaddrs = utils.get_normalized_ip_addr(
                ifaceobj.name, self.ipcmd.addr_get(ifaceobj.name, details=False))

            # if anycast address is configured on 'lo' and is in running config
            # add it to newaddrs so that ifreload doesn't wipe it out
            anycast_addr = utils.get_normalized_ip_addr(
                ifaceobj.name, self._get_anycast_addr(ifaceobjlist))

            if runningaddrs and anycast_addr and anycast_addr in runningaddrs:
                newaddrs.append(anycast_addr)
            if newaddrs == runningaddrs:
                if force_reapply:
                    self._inet_address_list_config(
                        ifaceobj, newaddrs, newaddr_attrs)
                return
            try:
                # if primary address is not same, there is no need to keep any.
                # reset all addresses
                if (newaddrs and runningaddrs and
                        (newaddrs[0] != runningaddrs[0])):
                    self.ipcmd.del_addr_all(ifaceobj.name)
                else:
                    self.ipcmd.del_addr_all(ifaceobj.name, newaddrs)
            except Exception, e:
                self.log_warn(str(e))
        if not newaddrs:
            return
        self._inet_address_list_config(ifaceobj, newaddrs, newaddr_attrs)

    def _add_delete_gateway(self, ifaceobj, gateways=[], prev_gw=[]):
        vrf = ifaceobj.get_attr_value_first('vrf')
        metric = ifaceobj.get_attr_value_first('metric')
        for del_gw in list(set(prev_gw) - set(gateways)):
            try:
                self.ipcmd.route_del_gateway(
                    ifaceobj.name, del_gw, vrf, metric)
            except:
                pass
        for add_gw in list(set(gateways) - set(prev_gw)):
            try:
                self.ipcmd.route_add_gateway(ifaceobj.name, add_gw, vrf)
            except:
                pass

    def _get_prev_gateway(self, ifaceobj, gateways):
        ipv = []
        saved_ifaceobjs = statemanager.statemanager_api.get_ifaceobjs(
            ifaceobj.name)
        if not saved_ifaceobjs:
            return ipv
        prev_gateways = saved_ifaceobjs[0].get_attr_value('gateway')
        if not prev_gateways:
            return ipv
        return prev_gateways

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        if not self.ipcmd.link_exists(ifaceobj.name):
            return
        addr_method = ifaceobj.addr_method
        force_reapply = False
        try:
            # release any stale dhcp addresses if present
            if (addr_method != "dhcp" and not ifupdownflags.flags.PERFMODE and
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
        if addr_method != "dhcp":
            self._inet_address_config(ifaceobj, ifaceobj_getfunc,
                                      force_reapply)
        mtu = ifaceobj.get_attr_value_first('mtu')
        if mtu:
            self.ipcmd.link_set(ifaceobj.name, 'mtu', mtu)
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

        alias = ifaceobj.get_attr_value_first('alias')
        if alias:
            self.ipcmd.link_set_alias(ifaceobj.name, alias)
        try:
            self.ipcmd.batch_commit()
        except Exception as e:
            self.log_error('%s: %s' % (ifaceobj.name, str(e)),
                           ifaceobj, raise_error=False)

        try:
            hwaddress = self._get_hwaddress(ifaceobj)
            if hwaddress:
                running_hwaddress = None
                if not ifupdownflags.flags.PERFMODE:  # system is clean
                    running_hwaddress = self.ipcmd.link_get_hwaddress(
                        ifaceobj.name)
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
                        self.ipcmd.link_set(
                            ifaceobj.name, 'address', hwaddress)
                    finally:
                        netlink.link_set_updown(ifaceobj.name, "up")
                        if slave_down:
                            for l in ifaceobj.lowerifaces:
                                netlink.link_set_updown(l, "up")

            # Handle special things on a bridge
            self._process_bridge(ifaceobj, True)
        except Exception, e:
            self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj)

        if addr_method != "dhcp":
            gateways = ifaceobj.get_attr_value('gateway')
            if not gateways:
                gateways = []
            prev_gw = self._get_prev_gateway(ifaceobj, gateways)
            self._add_delete_gateway(ifaceobj, gateways, prev_gw)
        return

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        try:
            if not self.ipcmd.link_exists(ifaceobj.name):
                return
            addr_method = ifaceobj.addr_method
            if addr_method != "dhcp":
                if ifaceobj.get_attr_value_first('address-purge') == 'no':
                    addrlist = ifaceobj.get_attr_value('address')
                    for addr in addrlist:
                        self.ipcmd.addr_del(ifaceobj.name, addr)
                    #self.ipcmd.addr_del(ifaceobj.name, ifaceobj.get_attr_value('address')[0])
                else:
                    self.ipcmd.del_addr_all(ifaceobj.name)
            mtu = ifaceobj.get_attr_value_first('mtu')
            if (not ifaceobj.link_kind and mtu and
                    self.default_mtu and (mtu != self.default_mtu)):
                self.ipcmd.link_set(ifaceobj.name, 'mtu', self.default_mtu)
            alias = ifaceobj.get_attr_value_first('alias')
            if alias:
                filename = '/sys/class/net/%s/ifalias' % ifaceobj.name
                self.logger.info('executing echo "" > %s' % filename)
                os.system('echo "" > %s' % filename)
            # XXX hwaddress reset cannot happen because we dont know last
            # address.

            # Handle special things on a bridge
            self._process_bridge(ifaceobj, False)
        except Exception, e:
            self.logger.debug('%s : %s' % (ifaceobj.name, str(e)))
            pass

    def _get_iface_addresses(self, ifaceobj):
        addrlist = ifaceobj.get_attr_value('address')
        outaddrlist = []

        if not addrlist:
            return None
        for addrindex in range(0, len(addrlist)):
            addr = addrlist[addrindex]
            netmask = ifaceobj.get_attr_value_n('netmask', addrindex)
            if netmask:
                prefixlen = IPNetwork('%s' % addr +
                                      '/%s' % netmask).prefixlen
                addr = addr + '/%s' % prefixlen
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
        if '.' in ifaceobj.name:
            (bridgename, vlan) = ifaceobj.name.split('.')
            if self.ipcmd.bridge_is_vlan_aware(bridgename):
                fdb_addrs = self._get_bridge_fdbs(bridgename, vlan)
                if not fdb_addrs or hwaddress not in fdb_addrs:
                    return False
        return True

    def _query_check(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        runningaddrsdict = None
        if not self.ipcmd.link_exists(ifaceobj.name):
            self.logger.debug('iface %s not found' % ifaceobj.name)
            return
        addr_method = ifaceobj.addr_method
        self.query_n_update_ifaceobjcurr_attr(ifaceobj, ifaceobjcurr,
                                              'mtu', self.ipcmd.link_get_mtu)
        hwaddress = self._get_hwaddress(ifaceobj)
        if hwaddress:
            rhwaddress = self.ipcmd.link_get_hwaddress(ifaceobj.name)
            if not rhwaddress or rhwaddress != hwaddress:
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
        # compare addresses
        if addr_method == 'dhcp':
            return
        addrs = utils.get_normalized_ip_addr(ifaceobj.name,
                                             self._get_iface_addresses(ifaceobj))
        runningaddrsdict = self.ipcmd.addr_get(ifaceobj.name)
        # if anycast address is configured on 'lo' and is in running config
        # add it to addrs so that query_check doesn't fail
        anycast_addr = utils.get_normalized_ip_addr(
            ifaceobj.name, ifaceobj.get_attr_value_first('clagd-vxlan-anycast-ip'))
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
        runningaddrs = [addr if '/' in addr else addr +
                        '/32' for addr in runningaddrs]
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
        # XXXX Check broadcast address, scope, etc
        return

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        if not self.ipcmd.link_exists(ifaceobjrunning.name):
            self.logger.debug('iface %s not found' % ifaceobjrunning.name)
            return
        dhclientcmd = dhclient()
        if (dhclientcmd.is_running(ifaceobjrunning.name) or
                dhclientcmd.is_running6(ifaceobjrunning.name)):
            # If dhcp is configured on the interface, we skip it
            return
        isloopback = self.ipcmd.link_isloopback(ifaceobjrunning.name)
        if isloopback:
            default_addrs = ['127.0.0.1/8', '::1/128']
            ifaceobjrunning.addr_family = 'inet'
            ifaceobjrunning.addr_method = 'loopback'
        else:
            default_addrs = []
        runningaddrsdict = self.ipcmd.addr_get(ifaceobjrunning.name)
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

    _run_ops = {'up': _up,
                'down': _down,
                'query-checkcurr': _query_check,
                'query-running': _query_running}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = iproute2()

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
