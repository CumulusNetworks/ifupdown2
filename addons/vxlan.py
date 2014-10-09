#!/usr/bin/python

from ifupdown.iface import *
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.iproute2 import iproute2
import logging

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
                        'vxlan-peernodeip' :
                            {'help' : 'vxlan peer node ip',
                             'example': ['vxlan-peernodeip 172.16.22.127']},
                        'vxlan-learning' :
                            {'help' : 'vxlan learning on/off',
                             'example': ['vxlan-learning on']},
                }}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None

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
            peernodeips=ifaceobj.get_attr_value('vxlan-peernodeip'),
            learning=ifaceobj.get_attr_value_first('vxlan-learning'))

    def _down(self, ifaceobj):
        try:
            self.ipcmd.link_delete(ifaceobj.name)
        except Exception, e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if not self.ipcmd.link_exists(ifaceobj.name):
           ifaceobjcurr.status = ifaceStatus.NOTFOUND
           return

        # Update vxlan object

    def _query_running(self, ifaceobjrunning):
        # Not implemented
        return

    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running}

    def get_ops(self):
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = iproute2(**self.get_flags())

    def run(self, ifaceobj, operation, query_ifaceobj=None):
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
