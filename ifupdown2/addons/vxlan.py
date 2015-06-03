#!/usr/bin/python

from ifupdown.iface import *
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.iproute2 import iproute2
import ifupdown.rtnetlink_api as rtnetlink_api
import logging
from sets import Set

class vxlan(moduleBase):
    _modinfo = {'mhelp' : 'vxlan module configures vxlan interfaces.',
                'attrs' : {
                        'vxlan-id' :
                            {'help' : 'vxlan id',
                             'required' : True,
                             'example': ['vxlan-id 100']},
                        'vxlan-local-tunnelip' :
                            {'help' : 'vxlan local tunnel ip',
                             'example': ['vxlan-local-tunnelip 172.16.20.103']},
                        'vxlan-svcnodeip' :
                            {'help' : 'vxlan id',
                             'example': ['vxlan-svcnodeip 172.16.22.125']},
                        'vxlan-remoteip' :
                            {'help' : 'vxlan remote ip',
                             'example': ['vxlan-remoteip 172.16.22.127']},
                        'vxlan-learning' :
                            {'help' : 'vxlan learning on/off',
                             'example': ['vxlan-learning off'],
                             'default': 'on'},
                }}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None

    def get_dependent_ifacenames(self, ifaceobj, ifaceobjs_all=None):
        if not self._is_vxlan_device(ifaceobj):
            return None
        ifaceobj.link_kind |= ifaceLinkKind.VXLAN
        return None

    def _is_vxlan_device(self, ifaceobj):
        if ifaceobj.get_attr_value_first('vxlan-id'):
            return True
        return False

    def _up(self, ifaceobj):
        vxlanid = ifaceobj.get_attr_value_first('vxlan-id')
        if vxlanid:
            self.ipcmd.link_create_vxlan(ifaceobj.name, vxlanid,
            localtunnelip=ifaceobj.get_attr_value_first('vxlan-local-tunnelip'),
            svcnodeips=ifaceobj.get_attr_value('vxlan-svcnodeip'),
            remoteips=ifaceobj.get_attr_value('vxlan-remoteip'),
            learning=ifaceobj.get_attr_value_first('vxlan-learning'),
            ageing=ifaceobj.get_attr_value_first('vxlan-ageing'))
            if ifaceobj.addr_method == 'manual':
               rtnetlink_api.rtnl_api.link_set(ifaceobj.name, "up")

    def _down(self, ifaceobj):
        try:
            self.ipcmd.link_delete(ifaceobj.name)
        except Exception, e:
            self.log_warn(str(e))

    def _query_check_n_update(self, ifaceobjcurr, attrname, attrval,
                              running_attrval):
        if running_attrval and attrval == running_attrval:
           ifaceobjcurr.update_config_with_status(attrname, attrval, 0)
        else:
           ifaceobjcurr.update_config_with_status(attrname, running_attrval, 1)

    def _query_check_n_update_addresses(self, ifaceobjcurr, attrname,
                                        addresses, running_addresses):
        if addresses:
            for a in addresses: 
                if a in running_addresses:
                    ifaceobjcurr.update_config_with_status(attrname, a, 0)
                else:
                    ifaceobjcurr.update_config_with_status(attrname, a, 1)
            running_addresses = Set(running_addresses).difference(
                                                    Set(addresses))
        [ifaceobjcurr.update_config_with_status(attrname, a, 1)
                    for a in running_addresses]

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if not self.ipcmd.link_exists(ifaceobj.name):
           return
        # Update vxlan object
        vxlanattrs = self.ipcmd.get_vxlandev_attrs(ifaceobj.name)
        if not vxlanattrs:
            ifaceobjcurr.check_n_update_config_with_status_many(ifaceobj,
                    self.get_mod_attrs(), -1)
            return
        self._query_check_n_update(ifaceobjcurr, 'vxlan-id',
                       ifaceobj.get_attr_value_first('vxlan-id'), 
                       vxlanattrs.get('vxlanid'))

        self._query_check_n_update(ifaceobjcurr, 'vxlan-local-tunnelip',
                       ifaceobj.get_attr_value_first('vxlan-local-tunnelip'), 
                       vxlanattrs.get('local'))

        self._query_check_n_update_addresses(ifaceobjcurr, 'vxlan-svcnodeip',
                       ifaceobj.get_attr_value('vxlan-svcnodeip'), 
                       vxlanattrs.get('svcnode', []))

        self._query_check_n_update_addresses(ifaceobjcurr, 'vxlan-remoteip',
                       ifaceobj.get_attr_value('vxlan-remoteip'), 
                       vxlanattrs.get('remote', []))

        learning = ifaceobj.get_attr_value_first('vxlan-learning')
        if not learning:
            learning = 'on'
        running_learning = vxlanattrs.get('learning')
        if learning == running_learning:
           ifaceobjcurr.update_config_with_status('vxlan-learning',
                                                  running_learning, 0)
        else:
           ifaceobjcurr.update_config_with_status('vxlan-learning',
                                                  running_learning, 1)

    def _query_running(self, ifaceobjrunning):
        vxlanattrs = self.ipcmd.get_vxlandev_attrs(ifaceobjrunning.name)
        if not vxlanattrs:
            return
        attrval = vxlanattrs.get('vxlanid')
        if attrval:
            ifaceobjrunning.update_config('vxlan-id', vxlanattrs.get('vxlanid'))
        attrval = vxlanattrs.get('local')
        if attrval:
            ifaceobjrunning.update_config('vxlan-local-tunnelip', attrval)
        attrval = vxlanattrs.get('svcnode')
        if attrval:
            [ifaceobjrunning.update_config('vxlan-svcnode', a)
                        for a in attrval]
        attrval = vxlanattrs.get('remote')
        if attrval:
            [ifaceobjrunning.update_config('vxlan-remoteip', a)
                        for a in attrval]
        attrval = vxlanattrs.get('learning')
        if attrval and attrval == 'on':
            ifaceobjrunning.update_config('vxlan-learning', 'on')


    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running}

    def get_ops(self):
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = iproute2(**self.get_flags())

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        if (operation != 'query-running' and
                not self._is_vxlan_device(ifaceobj)):
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
