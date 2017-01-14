#!/usr/bin/python

# This should be pretty simple and might not really even need to exist.
# The key is that we need to call link_create with a type of "dummy"
# since that will translate to 'ip link add loopbackX type dummy'
# The config file should probably just indicate that the type is
# loopback or dummy.

from ifupdown.iface import *
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.iproute2 import iproute2
import ifupdown.ifupdownflags as ifupdownflags
import logging

class link(moduleBase):
    _modinfo = {'mhelp' : 'create/configure link types. similar to ip-link',
                'attrs' : {
                   'link-type' :
                        {'help' : 'type of link as in \'ip link\' command.',
                         'validvals' : ['dummy', 'veth'],
                         'example' : ['link-type <dummy|veth>']},
                   'veth-peer-name':
                        {'help' : 'Name of the veth peer interface.',
                         'validvals' : '<interface>',
                         'example' : ['veth-peer-name veth_ext2int']}}}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None

    def _is_my_interface(self, ifaceobj):
        if ifaceobj.get_attr_value_first('link-type'):
            return True
        return False

    def get_dependent_ifacenames (self, ifaceobj, ifaceobjs_all=None):
        link_type = ifaceobj.get_attr_value_first('link-type')

        # If this interface is one side of a veth link pair and a name for
        # the peer interface if given, pass it to the link_create call.
        if link_type == 'veth' and ifaceobj.get_attr_value_first('veth-peer-name'):
            return [ ifaceobj.get_attr_value_first('veth-peer-name') ]

        return None

    def _up(self, ifaceobj):
        attrs = {}

        link_type = ifaceobj.get_attr_value_first('link-type')

        # If this interface is one side of a veth link pair and a name for
        # the peer interface if given, pass it to the link_create call.
        if link_type == 'veth' and ifaceobj.get_attr_value_first('veth-peer-name'):
            attrs["peer name"] = ifaceobj.get_attr_value_first('veth-peer-name')

        if not self.ipcmd.link_exists(ifaceobj.name):
            self.ipcmd.link_create(ifaceobj.name, link_type, attrs)

    def _down(self, ifaceobj):
        if (not ifupdownflags.flags.PERFMODE and
            not self.ipcmd.link_exists(ifaceobj.name)):
           return
        try:
            self.ipcmd.link_delete(ifaceobj.name)
        except Exception, e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if not self.ipcmd.link_exists(ifaceobj.name):
            ifaceobjcurr.update_config_with_status('link-type', 'None', 1)
        else:
            link_type = ifaceobj.get_attr_value_first('link-type')
            if self.ipcmd.link_get_kind(ifaceobj.name) == link_type:
                ifaceobjcurr.update_config_with_status('link-type',
                                                        link_type, 0)
            else:
                ifaceobjcurr.update_config_with_status('link-type',
                                                        link_type, 1)

    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check}

    def get_ops(self):
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = iproute2()

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        if (operation != 'query-running' and
                not self._is_my_interface(ifaceobj)):
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
