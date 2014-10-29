#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

try:
    from ipaddr import IPNetwork
    from sets import Set
    from ifupdown.iface import *
    from ifupdownaddons.modulebase import moduleBase
    from ifupdownaddons.iproute2 import iproute2
    from ifupdownaddons.dhclient import dhclient
except ImportError, e:
    raise ImportError (str(e) + "- required module not found")

class address(moduleBase):
    """  ifupdown2 addon module to configure address, mtu, hwaddress, alias
    (description) on an interface """

    _modinfo = {'mhelp' : 'address configuration module for interfaces',
                'attrs': {
                      'address' :
                            {'help' : 'ipv4 or ipv6 addresses',
                             'example' : ['address 10.0.12.3/24',
                             'address 2000:1000:1000:1000:3::5/128']},
                      'netmask' :
                            {'help': 'netmask',
                             'example' : ['netmask 255.255.255.0'],
                             'compat' : True},
                      'broadcast' :
                            {'help': 'broadcast address',
                             'example' : ['broadcast 10.0.1.255']},
                      'scope' :
                            {'help': 'scope',
                             'example' : ['scope host']},
                      'preferred-lifetime' :
                            {'help': 'preferred lifetime',
                             'example' : ['preferred-lifetime forever',
                                          'preferred-lifetime 10']},
                      'gateway' :
                            {'help': 'default gateway',
                             'example' : ['gateway 255.255.255.0']},
                      'mtu' :
                            { 'help': 'interface mtu',
                              'example' : ['mtu 1600'],
                              'default' : '1500'},
                      'hwaddress' :
                            {'help' : 'hw address',
                             'example': ['hwaddress 44:38:39:00:27:b8']},
                      'alias' :
                            { 'help': 'description/alias',
                                'example' : ['alias testnetwork']}}}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None

    def _add_address_to_bridge(self, ifaceobj, hwaddress):
        if '.' in ifaceobj.name:
            (bridgename, vlan) = ifaceobj.name.split('.')
            if self.ipcmd.bridge_is_vlan_aware(bridgename):
                self.ipcmd.bridge_fdb_add(bridgename, hwaddress,
                    vlan)

    def _remove_address_from_bridge(self, ifaceobj, hwaddress):
        if '.' in ifaceobj.name:
            (bridgename, vlan) = ifaceobj.name.split('.')
            if self.ipcmd.bridge_is_vlan_aware(bridgename):
                self.ipcmd.bridge_fdb_del(bridgename, hwaddress,
                    vlan)

    def _inet_address_config(self, ifaceobj):
        newaddrs = []
        addrs = ifaceobj.get_attr_value('address')
        if addrs:
            # If user address is not in CIDR notation, convert them to CIDR
            for addr_index in range(0, len(addrs)):
                addr = addrs[addr_index]
                if '/' in addr:
                    newaddrs.append(addr)
                    continue
                netmask = ifaceobj.get_attr_value_n('netmask', addr_index)
                if netmask:
                    prefixlen = IPNetwork('%s' %addr +
                                '/%s' %netmask).prefixlen
                    newaddrs.append(addr + '/%s' %prefixlen)
                else:
                    newaddrs.append(addr)

        if not self.PERFMODE and not (ifaceobj.flags & iface.HAS_SIBLINGS):
            # if perfmode is not set and also if iface has no sibling
            # objects, purge addresses that are not present in the new
            # config
            runningaddrs = self.ipcmd.addr_get(ifaceobj.name, details=False)
            if newaddrs == runningaddrs:
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
        for addr_index in range(0, len(newaddrs)):
            try:
                self.ipcmd.addr_add(ifaceobj.name, newaddrs[addr_index],
                    ifaceobj.get_attr_value_n('broadcast', addr_index),
                    ifaceobj.get_attr_value_n('pointopoint',addr_index),
                    ifaceobj.get_attr_value_n('scope', addr_index),
                    ifaceobj.get_attr_value_n('preferred-lifetime', addr_index))
            except Exception, e:
                self.log_error(str(e))

    def _up(self, ifaceobj):
        if not self.ipcmd.link_exists(ifaceobj.name):
            return
        try:
            # release any stale dhcp addresses if present
            if (not self.PERFMODE and
                    not (ifaceobj.flags & iface.HAS_SIBLINGS)):
                # if not running in perf mode and ifaceobj does not have
                # any sibling iface objects, kill any stale dhclient
                # processes
                dhclientcmd = self.dhclient()
                if dhclient.is_running(ifaceobj.name):
                    # release any dhcp leases
                    dhclientcmd.release(ifaceobj.name)
                elif dhclient.is_running6(ifaceobj.name):
                    dhclientcmd.release6(ifaceobj.name)
        except:
            pass
        self.ipcmd.batch_start()
        self._inet_address_config(ifaceobj)
        mtu = ifaceobj.get_attr_value_first('mtu')
        if mtu:
            self.ipcmd.link_set(ifaceobj.name, 'mtu', mtu)
        alias = ifaceobj.get_attr_value_first('alias')
        if alias:
            self.ipcmd.link_set_alias(ifaceobj.name, alias)
        hwaddress = ifaceobj.get_attr_value_first('hwaddress')
        if hwaddress:
            self.ipcmd.link_set(ifaceobj.name, 'address', hwaddress)
        self.ipcmd.batch_commit()

        # After all adds are successful, also add the hw address
        # to the bridge if required
        if hwaddress:
            self._add_address_to_bridge(ifaceobj, hwaddress)

        self.ipcmd.route_add_gateway(ifaceobj.name,
                ifaceobj.get_attr_value_first('gateway'))

    def _down(self, ifaceobj):
        try:
            if not self.ipcmd.link_exists(ifaceobj.name):
                return
            self.ipcmd.route_del_gateway(ifaceobj.name,
                    ifaceobj.get_attr_value_first('gateway'),
                    ifaceobj.get_attr_value_first('metric'))
            self.ipcmd.del_addr_all(ifaceobj.name)
            mtu = ifaceobj.get_attr_value_first('mtu')
            if mtu:
                self.ipcmd.link_set(ifaceobj.name, 'mtu',
                        self.get_mod_subattr('mtu', 'default'))
            alias = ifaceobj.get_attr_value_first('alias')
            if alias:
                self.ipcmd.link_set(ifaceobj.name, 'alias', "\'\'")
            hwaddress = ifaceobj.get_attr_value_first('hwaddress')
            if hwaddress:
                # XXX Dont know what to reset the address to
                self._remove_address_from_bridge(ifaceobj, hwaddress)
        except Exception, e:
            self.log_warn(str(e))

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

    def _query_check(self, ifaceobj, ifaceobjcurr):
        runningaddrsdict = None
        if not self.ipcmd.link_exists(ifaceobj.name):
            self.logger.debug('iface %s not found' %ifaceobj.name)
            return
        self.query_n_update_ifaceobjcurr_attr(ifaceobj, ifaceobjcurr,
                'mtu', self.ipcmd.link_get_mtu)
        self.query_n_update_ifaceobjcurr_attr(ifaceobj, ifaceobjcurr,
                'hwaddress', self.ipcmd.link_get_hwaddress)
        self.query_n_update_ifaceobjcurr_attr(ifaceobj, ifaceobjcurr,
                    'alias', self.ipcmd.link_get_alias)
        # compare addresses
        addrs = self._get_iface_addresses(ifaceobj)
        runningaddrsdict = self.ipcmd.addr_get(ifaceobj.name)

        # Set ifaceobjcurr method and family
        ifaceobjcurr.addr_method = ifaceobj.addr_method
        ifaceobjcurr.addr_family = ifaceobj.addr_family
        if not runningaddrsdict and not addrs:
            return
        runningaddrs = runningaddrsdict.keys() if runningaddrsdict else []
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

    def _query_running(self, ifaceobjrunning):
        if not self.ipcmd.link_exists(ifaceobjrunning.name):
            self.logger.debug('iface %s not found' %ifaceobjrunning.name)
            ifaceobjrunning.status = ifaceStatus.NOTFOUND
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

    _run_ops = {'up' : _up,
               'down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = iproute2(**self.get_flags())

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
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

        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        if (operation != 'query-running' and ifaceobj.addr_family and
                ifaceobj.addr_family != 'inet' and
                ifaceobj.addr_family != 'inet6'):
            return
        if (operation != 'query-running' and ifaceobj.addr_method and
                ifaceobj.addr_method != 'static' and
            ifaceobj.addr_method != 'loopback'):
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
