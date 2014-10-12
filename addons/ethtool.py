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
except ImportError, e:
    raise ImportError (str(e) + "- required module not found")

class ethtool(moduleBase):
    """  ifupdown2 addon module to configure ethtool attributes """

    _modinfo = {'mhelp' : 'ethtool configuration module for interfaces',
                'attrs': {
                      'link-speed' :
                            {'help' : 'set link speed',
                             'example' : ['link-speed 1000']},
                      'link-duplex' :
                            {'help': 'set link duplex',
                             'example' : ['link-duplex full'],
                             'validvals' : ['half', 'full'],
                             'default' : 'half'},
                      'link-autoneg' :
                            {'help': 'set autonegotiation',
                             'example' : ['link-autoneg on'],
                             'validvals' : ['on', 'off'],
                             'default' : 'off'}}}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None

    def _post_up(self, ifaceobj):
        if not self.ipcmd.link_exists(ifaceobj.name):
            return
        cmd = ''
        attrval = ifaceobj.get_attr_value_first('link-speed')
        if attrval:
            cmd += ' speed %s' %attrval
        attrval = ifaceobj.get_attr_value_first('link-duplex')
        if attrval:
            cmd += ' duplex %s' %attrval
        attrval = ifaceobj.get_attr_value_first('link-autoneg')
        if attrval:
            cmd += ' autoneg %s' %attrval
        if cmd:
            try:
                cmd = 'ethtool -s %s %s' %(ifaceobj.name, cmd)
                self.exec_command(cmd)
            except Exception, e:
                ifaceobj.status = ifaceStatus.ERROR
                self.log_warn('%s: %s' %(ifaceobj.name, str(e)))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        """
        Advertised auto-negotiation: No
        Speed: 1000Mb/s
        Duplex: Full"""
        ethtool_attrs = self.dict_key_subset(ifaceobj.config,
                                          self.get_mod_attrs())
        if not ethtool_attrs:
            return
        try:
            speed = ifaceobj.get_attr_value_first('link-speed')
            if speed:
                running_speed = self.read_file_oneline(
                                    '/sys/class/net/%s/speed' %ifaceobj.name)
                if running_speed and running_speed != speed:
                     ifaceobjcurr.update_config_with_status('link-speed',
                             running_speed, 1)
                else:
                     ifaceobjcurr.update_config_with_status('link-speed',
                             running_speed, 0)
            duplex = ifaceobj.get_attr_value_first('link-duplex')
            if duplex:
                running_duplex = self.read_file_oneline(
                                    '/sys/class/net/%s/duplex' %ifaceobj.name)
                if running_duplex and running_duplex != duplex:
                     ifaceobjcurr.update_config_with_status('link-duplex',
                             running_duplex, 1)
                else:
                     ifaceobjcurr.update_config_with_status('link-duplex',
                             running_duplex, 0)
        except Exception, e:
            pass
        return

    def _query_running(self, ifaceobjrunning):
        return

    _run_ops = {'post-up' : _post_up,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = iproute2(**self.get_flags())

    def run(self, ifaceobj, operation, query_ifaceobj=None):
        """ run ethtool configuration on the interface object passed as
            argument

        Args:
            **ifaceobj** (object): iface object

            **operation** (str): any of 'post-up', 'query-checkcurr',
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
