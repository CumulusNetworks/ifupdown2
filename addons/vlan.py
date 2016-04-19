#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from ifupdown.iface import *
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.iproute2 import iproute2
import ifupdown.rtnetlink_api as rtnetlink_api
import ifupdown.ifupdownflags as ifupdownflags
import logging
import re

class vlan(moduleBase):
    """  ifupdown2 addon module to configure vlans """

    _modinfo = {'mhelp' : 'vlan module configures vlan interfaces.' +
                        'This module understands vlan interfaces with dot ' +
                        'notations. eg swp1.100. Vlan interfaces with any ' +
                        'other names need to have raw device and vlan id ' +
                        'attributes',
                'attrs' : {
                        'vlan-raw-device' :
                            {'help' : 'vlan raw device'},
                        'vlan-id' :
                            {'help' : 'vlan id'}}}


    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self._bridge_vids_query_cache = {}
        self._resv_vlan_range =  self._get_reserved_vlan_range()
        self.logger.debug('%s: using reserved vlan range %s'
                  %(self.__class__.__name__, str(self._resv_vlan_range)))

    def _is_vlan_device(self, ifaceobj):
        vlan_raw_device = ifaceobj.get_attr_value_first('vlan-raw-device')
        if vlan_raw_device:
            return True
        elif '.' in ifaceobj.name:
            return True
        return False

    def _get_vlan_id(self, ifaceobj):
        """ Derives vlanid from iface name
        
        Example:
            Returns 1 for ifname vlan0001 returns 1
            Returns 1 for ifname vlan1
            Returns 1 for ifname eth0.1

            Returns -1 if vlan id cannot be determined
        """
        vid_str = ifaceobj.get_attr_value_first('vlan-id')
        try:
            if vid_str: return int(vid_str)
        except:
            return -1

        if '.' in ifaceobj.name:
            vid_str = ifaceobj.name.split('.', 1)[1]
        elif ifaceobj.name.startswith('vlan'):
            vid_str = ifaceobj.name[4:]
        else:
            return -1
        try:
            vid = int(vid_str)
        except:
            return -1
        return vid

    def _is_vlan_by_name(self, ifacename):
        return '.' in ifacename

    def _get_vlan_raw_device_from_ifacename(self, ifacename):
        """ Returns vlan raw device from ifname
        Example:
            Returns eth0 for ifname eth0.100

            Returns None if vlan raw device name cannot
            be determined
        """
        vlist = ifacename.split('.', 1)
        if len(vlist) == 2:
            return vlist[0]
        return None

    def _get_vlan_raw_device(self, ifaceobj):
        vlan_raw_device = ifaceobj.get_attr_value_first('vlan-raw-device')
        if vlan_raw_device:
            return vlan_raw_device
        return self._get_vlan_raw_device_from_ifacename(ifaceobj.name)
        
    def get_dependent_ifacenames(self, ifaceobj, ifaceobjs_all=None):
        if not self._is_vlan_device(ifaceobj):
            return None
        ifaceobj.link_kind |= ifaceLinkKind.VLAN
        return [self._get_vlan_raw_device(ifaceobj)]

    def _bridge_vid_add_del(self, ifaceobj, bridgename, vlanid,
                            add=True):
        """ If the lower device is a vlan aware bridge, add/del the vlanid
        to the bridge """
        if self.ipcmd.bridge_is_vlan_aware(bridgename):
           if add:
              rtnetlink_api.rtnl_api.bridge_vlan(add=True, dev=bridgename,
                                                 vid=vlanid, master=False)
           else:
              rtnetlink_api.rtnl_api.bridge_vlan(add=False, dev=bridgename,
                                                 vid=vlanid, master=False)

    def _bridge_vid_check(self, ifaceobj, ifaceobjcurr, bridgename, vlanid):
        """ If the lower device is a vlan aware bridge, check if the vlanid
        is configured on the bridge """
        if not self.ipcmd.bridge_is_vlan_aware(bridgename):
            return
        vids = self._bridge_vids_query_cache.get(bridgename)
        if vids == None:
           vids = self.ipcmd.bridge_port_vids_get(bridgename)
           self._bridge_vids_query_cache[bridgename] = vids
        if not vids or vlanid not in vids:
            ifaceobjcurr.status = ifaceStatus.ERROR
            ifaceobjcurr.status_str = 'bridge vid error'

    def _up(self, ifaceobj):
        vlanid = self._get_vlan_id(ifaceobj)
        if vlanid == -1:
            raise Exception('could not determine vlanid')
        if self._handle_reserved_vlan(vlanid, ifaceobj.name):
           return
        vlanrawdevice = self._get_vlan_raw_device(ifaceobj)
        if not vlanrawdevice:
            raise Exception('could not determine vlan raw device')
        if not ifupdownflags.flags.PERFMODE:
            if not self.ipcmd.link_exists(vlanrawdevice):
                raise Exception('rawdevice %s not present' %vlanrawdevice)
            if self.ipcmd.link_exists(ifaceobj.name):
                self._bridge_vid_add_del(ifaceobj, vlanrawdevice, vlanid)
                return
        rtnetlink_api.rtnl_api.create_vlan(vlanrawdevice,
                    ifaceobj.name, vlanid)
        self._bridge_vid_add_del(ifaceobj, vlanrawdevice, vlanid)
        if ifaceobj.addr_method == 'manual':
           rtnetlink_api.rtnl_api.link_set(ifaceobj.name, "up")

    def _down(self, ifaceobj):
        vlanid = self._get_vlan_id(ifaceobj)
        if vlanid == -1:
            raise Exception('could not determine vlanid')
        vlanrawdevice = self._get_vlan_raw_device(ifaceobj)
        if not vlanrawdevice:
            raise Exception('could not determine vlan raw device')
        if (not ifupdownflags.flags.PERFMODE and
            not self.ipcmd.link_exists(ifaceobj.name)):
           return
        try:
            self.ipcmd.link_delete(ifaceobj.name)
            self._bridge_vid_add_del(ifaceobj, vlanrawdevice, vlanid, add=False)
        except Exception, e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if not self.ipcmd.link_exists(ifaceobj.name):
           return
        if not '.' in ifaceobj.name:
            # if vlan name is not in the dot format, check its running state
            (vlanrawdev, vlanid) = self.ipcmd.get_vlandev_attrs(ifaceobj.name)
            if vlanrawdev != ifaceobj.get_attr_value_first('vlan-raw-device'):
                ifaceobjcurr.update_config_with_status('vlan-raw-device',
                        vlanrawdev, 1)
            else:
                ifaceobjcurr.update_config_with_status('vlan-raw-device',
                        vlanrawdev, 0)
            if vlanid != ifaceobj.get_attr_value_first('vlan-id'):
                ifaceobjcurr.update_config_with_status('vlan-id', vlanid, 1)
            else:
                ifaceobjcurr.update_config_with_status('vlan-id',
                        vlanid, 0)
            self._bridge_vid_check(ifaceobj, ifaceobjcurr, vlanrawdev, vlanid)

    def _query_running(self, ifaceobjrunning):
        if not self.ipcmd.link_exists(ifaceobjrunning.name):
            return
        if not self.ipcmd.get_vlandev_attrs(ifaceobjrunning.name):
            return
        # If vlan name is not in the dot format, get the
        # vlan dev and vlan id
        if not '.' in ifaceobjrunning.name:
            (vlanrawdev, vlanid) = self.ipcmd.get_vlandev_attrs(ifaceobjrunning.name)
            ifaceobjrunning.update_config_dict({(k, v) for k, v in
                                                {'vlan-raw-device' : vlanrawdev,
                                                 'vlan-id' : vlanid}.items()
                                                if v})

    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = iproute2()
        
    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
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
        if (operation != 'query-running' and
                not self._is_vlan_device(ifaceobj)):
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
