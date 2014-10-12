#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from ifupdown.iface import *
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.iproute2 import iproute2
import ifupdown.rtnetlink_api as rtnetlink_api
import logging
import os
import glob

class addressvirtual(moduleBase):
    """  ifupdown2 addon module to configure virtual addresses """

    _modinfo = {'mhelp' : 'address module configures virtual addresses for ' +
                          'interfaces. It creates a macvlan interface for ' +
                          'every mac ip address-virtual line',
                'attrs' : {
                    'address-virtual' :
                        { 'help' : 'bridge router virtual mac and ip',
                          'example' : ['address-virtual 00:11:22:33:44:01 11.0.1.254/24 11.0.1.254/24']}
                 }}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None

    def _is_supported(self, ifaceobj):
        if ifaceobj.get_attr_value_first('address-virtual'):
            return True
        return False

    def _apply_address_config(self, ifaceobj, realifacename, address_virtual_list):
        purge_existing = False if self.PERFMODE else True

        self.ipcmd.batch_start()
        av_idx = 0
        macvlan_prefix = '%s-virt' %ifaceobj.name.replace('.', '-')
        for av in address_virtual_list:
            av_attrs = av.split()
            if len(av_attrs) < 2:
                self.logger.warn("%s: incorrect address-virtual attrs '%s'"
                             %(ifaceobj.name,  av))
                av_idx += 1
                continue

            # Create a macvlan device on this device and set the virtual
            # router mac and ip on it
            macvlan_ifacename = '%s-%d' %(macvlan_prefix, av_idx)
            if not self.ipcmd.link_exists(macvlan_ifacename):
                rtnetlink_api.rtnl_api.create_macvlan(macvlan_ifacename,
                                                      realifacename)
            if av_attrs[0] != 'None':
                self.ipcmd.link_set_hwaddress(macvlan_ifacename, av_attrs[0])
            self.ipcmd.addr_add_multiple(macvlan_ifacename, av_attrs[1:],
                                         purge_existing)
            av_idx += 1
        self.ipcmd.batch_commit()

    def _remove_address_config(self, ifaceobj, ifacename):
        if not self.ipcmd.link_exists(ifacename):
            return
        self.ipcmd.batch_start()
        macvlan_prefix = '%s-virt' %ifacename.replace('.', '-')
        for macvlan_ifacename in glob.glob("/sys/class/net/%s-*" %macvlan_prefix):
            self.ipcmd.link_delete(os.path.basename(macvlan_ifacename))
        self.ipcmd.batch_commit()

    def _get_real_ifacename(self, ifaceobj):
        realifacename = ifaceobj.name
        if ifaceobj.type == ifaceType.BRIDGE_VLAN:
            bridgename = ifaceobj.get_attr_value_first('bridge')
            if bridgename:
                realifacename = '%s.%s' %(bridgename, ifaceobj.priv_data)
        return realifacename

    def _up(self, ifaceobj):
        realifacename = self._get_real_ifacename(ifaceobj)
        address_virtual_list = ifaceobj.get_attr_value('address-virtual')
        if not address_virtual_list:
            # XXX: address virtual is not present. In which case,
            # delete stale any macvlan devices.
            self._remove_address_config(ifaceobj, realifacename)
            return

        if not self.ipcmd.link_exists(realifacename):
            self.log_warn('%s: target link %s does not exist'
                          %(ifaceobj.name, realifacename))
            return
        self._apply_address_config(ifaceobj, realifacename, address_virtual_list)

    def _down(self, ifaceobj):
        realifacename = self._get_real_ifacename(ifaceobj)
        try:
            self._remove_address_config(ifaceobj, realifacename)
        except Exception, e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        address_virtual_list = ifaceobj.get_attr_value('address-virtual')
        if not address_virtual_list:
            return
        realifacename = self._get_real_ifacename(ifaceobj)
        av_idx = 0
        macvlan_prefix = '%s-virt' %realifacename.replace('.', '-')
        for address_virtual in address_virtual_list:
            av_attrs = address_virtual.split()
            if len(av_attrs) < 2:
                self.logger.warn("%s: incorrect address-virtual attrs '%s'"
                             %(ifaceobj.name,  address_virtual))
                av_idx += 1
                continue

            # Check if the macvlan device on this interface
            macvlan_ifacename = '%s-%d' %(macvlan_prefix, av_idx)
            if self.ipcmd.link_exists(macvlan_ifacename):
                # XXX Check mac and ip address
                rhwaddress = self.ipcmd.link_get_hwaddress(macvlan_ifacename)
                raddrs = self.ipcmd.addr_get(macvlan_ifacename)
                if rhwaddress == av_attrs[0] and raddrs == av_attrs[1:]:
                    ifaceobjcurr.update_config_with_status('address-virtual',
                            address_virtual, 0)
                else:
                    raddress_virtual = '%s %s' %(rhwaddress, ' '.join(raddrs))
                    ifaceobjcurr.update_config_with_status('address-virtual',
                            raddress_virtual, 1)
            av_idx += 1
        return

    def _query_running(self, ifaceobjrunning):
        # Not implemented
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
            self.ipcmd = iproute2(**self.get_flags())

    def run(self, ifaceobj, operation, query_ifaceobj=None):
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
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
