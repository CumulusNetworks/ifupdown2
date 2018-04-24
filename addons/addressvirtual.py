#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

try:
    import os
    import glob

    from ipaddr import IPNetwork, IPv6Network

    import ifupdown.statemanager as statemanager
    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.ifupdownconfig as ifupdownConfig

    from ifupdown.iface import *
    from ifupdown.netlink import netlink

    from ifupdownaddons.LinkUtils import LinkUtils
    from ifupdownaddons.modulebase import moduleBase
except ImportError, e:
    raise ImportError('%s - required module not found' % str(e))


class addressvirtual(moduleBase):
    """  ifupdown2 addon module to configure virtual addresses """

    _modinfo = {'mhelp' : 'address module configures virtual addresses for ' +
                          'interfaces. It creates a macvlan interface for ' +
                          'every mac ip address-virtual line',
                'attrs' : {
                    'address-virtual' :
                        { 'help' : 'bridge router virtual mac and ips',
                          'multivalue' : True,
                          'validvals' : ['<mac-ip/prefixlen-list>',],
                          'example' : ['address-virtual 00:11:22:33:44:01 11.0.1.1/24 11.0.1.2/24']}
                 }}


    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self._bridge_fdb_query_cache = {}

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        if ifaceobj.get_attr_value('address-virtual'):
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.ADDRESS_VIRTUAL_SLAVE

    def _get_macvlan_prefix(self, ifaceobj):
        return '%s-v' %ifaceobj.name[0:13].replace('.', '-')

    def _add_addresses_to_bridge(self, ifaceobj, hwaddress):
        # XXX: batch the addresses
        if ifaceobj.link_kind & ifaceLinkKind.VLAN:
            bridgename = ifaceobj.lowerifaces[0]
            vlan = self._get_vlan_id(ifaceobj)
            if self.ipcmd.bridge_is_vlan_aware(bridgename):
                [self.ipcmd.bridge_fdb_add(bridgename, addr,
                    vlan) for addr in hwaddress]
        elif self.ipcmd.is_bridge(ifaceobj.name):
            [self.ipcmd.bridge_fdb_add(ifaceobj.name, addr)
                    for addr in hwaddress]

    def _remove_addresses_from_bridge(self, ifaceobj, hwaddress):
        # XXX: batch the addresses
        if ifaceobj.link_kind & ifaceLinkKind.VLAN:
            bridgename = ifaceobj.lowerifaces[0]
            vlan = self._get_vlan_id(ifaceobj)
            if self.ipcmd.bridge_is_vlan_aware(bridgename):
                for addr in hwaddress:
                    try:
                        self.ipcmd.bridge_fdb_del(bridgename, addr, vlan)
                    except Exception, e:
                        self.logger.debug("%s: %s" %(ifaceobj.name, str(e)))
                        pass
        elif self.ipcmd.is_bridge(ifaceobj.name):
            for addr in hwaddress:
                try:
                    self.ipcmd.bridge_fdb_del(ifaceobj.name, addr)
                except Exception, e:
                    self.logger.debug("%s: %s" %(ifaceobj.name, str(e)))
                    pass

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
            ip = IPNetwork(addr)

            # we don't support ip6 route fix yet
            if type(ip) == IPv6Network:
                return

            route_prefix = '%s/%d' %(ip.network, ip.prefixlen)

            dev = self.ipcmd.ip_route_get_dev(route_prefix)
            if dev and dev != ifaceobj.name:
                self.logger.info('%s: preferred routing entry ' %ifaceobj.name +
                                 'seems to be of the macvlan dev %s'
                                 %vifacename +
                                 ' .. flapping macvlan dev to fix entry.')
                self.ipcmd.link_down(vifacename)
                self.ipcmd.link_up(vifacename)
        except Exception, e:
            self.logger.debug('%s: fixing route entry failed (%s)'
                              % (ifaceobj.name, str(e)))
            pass

    def _handle_vrf_slaves(self, macvlan_ifacename, ifaceobj):
        vrfname = self.ipcmd.link_get_master(ifaceobj.name)
        if vrfname:
            self.ipcmd.link_set(macvlan_ifacename, 'master', vrfname)

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
                if len(macip) < 2:
                    self.logger.debug("%s: incorrect old address-virtual attrs '%s'"
                                      %(oldifaceobj.name,  av))
                    continue
                maclist.append(macip[0])
        return maclist

    def _apply_address_config(self, ifaceobj, address_virtual_list):
        purge_existing = False if ifupdownflags.flags.PERFMODE else True

        lower_iface_mtu = update_mtu = None
        if ifupdownConfig.config.get('adjust_logical_dev_mtu', '1') != '0':
            if ifaceobj.lowerifaces and address_virtual_list:
                update_mtu = True

        hwaddress = []
        self.ipcmd.batch_start()
        av_idx = 0
        macvlan_prefix = self._get_macvlan_prefix(ifaceobj)
        for av in address_virtual_list:
            av_attrs = av.split()
            if len(av_attrs) < 2:
                self.log_error("%s: incorrect address-virtual attrs '%s'"
                               %(ifaceobj.name,  av), ifaceobj,
                               raise_error=False)
                av_idx += 1
                continue

            mac = av_attrs[0]
            if not self.check_mac_address(ifaceobj, mac):
                continue
            # Create a macvlan device on this device and set the virtual
            # router mac and ip on it
            link_created = False
            macvlan_ifacename = '%s%d' %(macvlan_prefix, av_idx)
            if not self.ipcmd.link_exists(macvlan_ifacename):
                try:
                    netlink.link_add_macvlan(ifaceobj.name, macvlan_ifacename)
                except:
                    self.ipcmd.link_add_macvlan(ifaceobj.name, macvlan_ifacename)
                link_created = True

            # first thing we need to handle vrf enslavement
            if (ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE):
                self._handle_vrf_slaves(macvlan_ifacename, ifaceobj)

            ips = av_attrs[1:]
            if mac != 'None':
                mac = mac.lower()
                # customer could have used UPPERCASE for MAC
                self.ipcmd.link_set_hwaddress(macvlan_ifacename, mac)
                hwaddress.append(mac)
            self.ipcmd.addr_add_multiple(ifaceobj, macvlan_ifacename, ips,
                                         purge_existing)

            # If link existed before, flap the link
            if not link_created:
                self._fix_connected_route(ifaceobj, macvlan_ifacename,
                                          ips[0])
                if update_mtu:
                    lower_iface_mtu = self.ipcmd.link_get_mtu(ifaceobj.name, refresh=True)
                    update_mtu = False

                if lower_iface_mtu and lower_iface_mtu != self.ipcmd.link_get_mtu(macvlan_ifacename, refresh=True):
                    try:
                        self.ipcmd.link_set_mtu(macvlan_ifacename,
                                                lower_iface_mtu)
                    except Exception as e:
                        self.logger.info('%s: failed to set mtu %s: %s' %
                                         (macvlan_ifacename, lower_iface_mtu, e))

                # set macvlan device to up in anycase.
                # since we auto create them here..we are responsible
                # to bring them up here in the case they were brought down
                # by some other entity in the system.
                netlink.link_set_updown(macvlan_ifacename, "up")
            else:
                try:
                    self.ipcmd.fix_ipv6_route_metric(ifaceobj, macvlan_ifacename, ips)
                except Exception as e:
                    self.logger.debug('fix_vrf_slave_ipv6_route_metric: failed: %s' % e)

            # Disable IPv6 duplicate address detection on VRR interfaces
            for key, sysval in { 'accept_dad' : '0', 'dad_transmits' : '0' }.iteritems():
                syskey = 'net.ipv6.conf.%s.%s' % (macvlan_ifacename, key)
                if self.sysctl_get(syskey) != sysval:
                    self.sysctl_set(syskey, sysval)

            av_idx += 1
        self.ipcmd.batch_commit()

        # check the statemanager for old configs.
        # We need to remove only the previously configured FDB entries
        oldmacs = self._get_macs_from_old_config(ifaceobj)
        # get a list of fdbs in old that are not in new config meaning they should
        # be removed since they are gone from the config
        removed_macs = [mac for mac in oldmacs if mac.lower() not in hwaddress]
        self._remove_addresses_from_bridge(ifaceobj, removed_macs)
        # if ifaceobj is a bridge and bridge is a vlan aware bridge
        # add the vid to the bridge
        self._add_addresses_to_bridge(ifaceobj, hwaddress)

    def _remove_running_address_config(self, ifaceobj):
        if not self.ipcmd.link_exists(ifaceobj.name):
            return
        hwaddress = []
        self.ipcmd.batch_start()
        macvlan_prefix = self._get_macvlan_prefix(ifaceobj)
        for macvlan_ifacename in glob.glob("/sys/class/net/%s*" %macvlan_prefix):
            macvlan_ifacename = os.path.basename(macvlan_ifacename)
            if not self.ipcmd.link_exists(macvlan_ifacename):
                continue
            hwaddress.append(self.ipcmd.link_get_hwaddress(macvlan_ifacename))
            self.ipcmd.link_delete(os.path.basename(macvlan_ifacename))
            # XXX: Also delete any fdb addresses. This requires, checking mac address
            # on individual macvlan interfaces and deleting the vlan from that.
        self.ipcmd.batch_commit()
        if any(hwaddress):
            self._remove_addresses_from_bridge(ifaceobj, hwaddress)

    def _remove_address_config(self, ifaceobj, address_virtual_list=None):
        if not address_virtual_list:
            self._remove_running_address_config(ifaceobj)
            return

        if not self.ipcmd.link_exists(ifaceobj.name):
            return
        hwaddress = []
        self.ipcmd.batch_start()
        av_idx = 0
        macvlan_prefix = self._get_macvlan_prefix(ifaceobj)
        for av in address_virtual_list:
            av_attrs = av.split()
            if len(av_attrs) < 2:
                self.log_error("%s: incorrect address-virtual attrs '%s'"
                               %(ifaceobj.name,  av), ifaceobj,
                               raise_error=False)
                av_idx += 1
                continue

            # Delete the macvlan device on this device
            macvlan_ifacename = '%s%d' %(macvlan_prefix, av_idx)
            self.ipcmd.link_delete(os.path.basename(macvlan_ifacename))
            if av_attrs[0] != 'None':
                hwaddress.append(av_attrs[0])
            av_idx += 1
        self.ipcmd.batch_commit()
        self._remove_addresses_from_bridge(ifaceobj, hwaddress)

    def check_mac_address(self, ifaceobj, mac):
        if mac == 'None':
            return True 
        mac = mac.lower()
        try:
            if int(mac.split(":")[0], 16) & 1 :
                self.logger.error("%s: Multicast bit is set in the virtual mac address '%s'" %(ifaceobj.name, mac))
                return False
            return True
        except Exception:
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
            self.ipcmd.link_exists(ifaceobj.name)):
            # if I am a vrf device and I have slaves
            # that have address virtual config,
            # enslave the slaves 'address virtual
            # interfaces (macvlans)' to myself:
            running_slaves = self.ipcmd.link_get_lowers(ifaceobj.name)
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
                        upperdevs = self.ipcmd.link_get_uppers(sobjs[0].name)
                        if not upperdevs:
                            continue
                        for u in upperdevs:
                            # skip vrf device which
                            # will also show up in the
                            # upper device list
                            if u == ifaceobj.name:
                                continue
                            self.ipcmd.link_set(u, 'master', ifaceobj.name,
                                                state='up')
        elif ((ifaceobj.link_privflags & ifaceLinkPrivFlags.ADDRESS_VIRTUAL_SLAVE) and
              (ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE) and
              self.ipcmd.link_exists(ifaceobj.name)):
            # If I am a vrf slave and I have 'address virtual'
            # config, make sure my addrress virtual interfaces
            # (macvlans) are also enslaved to the vrf device
            vrfname = ifaceobj.get_attr_value_first('vrf')
            if not vrfname or not self.ipcmd.link_exists(vrfname):
                return
            running_uppers = self.ipcmd.link_get_uppers(ifaceobj.name)
            if not running_uppers:
                return
            macvlan_prefix = self._get_macvlan_prefix(ifaceobj)
            if not macvlan_prefix:
                return
            for u in running_uppers:
                if u == vrfname:
                    continue
                if u.startswith(macvlan_prefix):
                    self.ipcmd.link_set(u, 'master', vrfname,
                                        state='up')

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        if not ifupdownflags.flags.ALL:
            self._fixup_vrf_enslavements(ifaceobj, ifaceobj_getfunc)
        address_virtual_list = ifaceobj.get_attr_value('address-virtual')
        if not address_virtual_list:
            # XXX: address virtual is not present. In which case,
            # delete stale macvlan devices.
            self._remove_address_config(ifaceobj, address_virtual_list)
            return

        if (ifaceobj.upperifaces and
            not ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE):
            self.log_error('%s: invalid placement of address-virtual lines (must be configured under an interface with no upper interfaces or parent interfaces)'
                % (ifaceobj.name), ifaceobj)
            return

        if not self.ipcmd.link_exists(ifaceobj.name):
            return
        self._apply_address_config(ifaceobj, address_virtual_list)

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        try:
            self._remove_address_config(ifaceobj,
                         ifaceobj.get_attr_value('address-virtual'))
        except Exception, e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        address_virtual_list = ifaceobj.get_attr_value('address-virtual')
        if not address_virtual_list:
            return
        if not self.ipcmd.link_exists(ifaceobj.name):
            return
        av_idx = 0
        macvlan_prefix = self._get_macvlan_prefix(ifaceobj)
        for address_virtual in address_virtual_list:
            av_attrs = address_virtual.split()
            if len(av_attrs) < 2:
                self.logger.warn("%s: incorrect address-virtual attrs '%s'"
                             %(ifaceobj.name,  address_virtual))
                av_idx += 1
                continue

            # Check if the macvlan device on this interface
            macvlan_ifacename = '%s%d' %(macvlan_prefix, av_idx)
            if not self.ipcmd.link_exists(macvlan_ifacename):
                ifaceobjcurr.update_config_with_status('address-virtual',
                            '', 1)
                av_idx += 1
                continue
            # Check mac and ip address
            rhwaddress = self.ipcmd.link_get_hwaddress(macvlan_ifacename)
            raddrs = self.ipcmd.get_running_addrs(
                ifname=macvlan_ifacename,
                details=False,
                addr_virtual_ifaceobj=ifaceobj
            )
            if not raddrs or not rhwaddress:
               ifaceobjcurr.update_config_with_status('address-virtual', '', 1)
               av_idx += 1
               continue
            try:
                av_attrs[0] = ':'.join([i if len(i) == 2 else '0%s' % i
                                        for i in av_attrs[0].split(':')])
            except:
                self.logger.info('%s: %s: invalid value for address-virtual (%s)'
                                 % (ifaceobj.name,
                                    macvlan_ifacename,
                                    ' '.join(av_attrs)))
            try:
                if (rhwaddress == av_attrs[0].lower() and
                    self.ipcmd.compare_user_config_vs_running_state(raddrs, av_attrs[1:]) and
                    self._check_addresses_in_bridge(ifaceobj, av_attrs[0].lower())):
                    ifaceobjcurr.update_config_with_status('address-virtual',
                                                           address_virtual, 0)
                else:
                    raddress_virtual = '%s %s' % (rhwaddress, ' '.join(raddrs))
                    ifaceobjcurr.update_config_with_status('address-virtual',
                                                           raddress_virtual, 1)
            except:
                raddress_virtual = '%s %s' % (rhwaddress, ' '.join(raddrs))
                ifaceobjcurr.update_config_with_status('address-virtual',
                                                       raddress_virtual, 1)
            av_idx += 1
        return

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        macvlan_prefix = self._get_macvlan_prefix(ifaceobjrunning)
        address_virtuals = glob.glob("/sys/class/net/%s*" %macvlan_prefix)
        for av in address_virtuals:
            macvlan_ifacename = os.path.basename(av)
            rhwaddress = self.ipcmd.link_get_hwaddress(macvlan_ifacename)
            raddress = self.ipcmd.get_running_addrs(None, macvlan_ifacename)
            if not raddress:
                self.logger.warn('%s: no running addresses'
                                 %ifaceobjrunning.name)
                raddress = []
            ifaceobjrunning.update_config('address-virtual',
                            '%s %s' %(rhwaddress, ''.join(raddress)))
        return

    _run_ops = {'up' : _up,
               'down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = LinkUtils()

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
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
