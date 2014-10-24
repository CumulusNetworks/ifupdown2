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
    from ifupdownaddons.dhclient import dhclient
    from ifupdownaddons.iproute2 import iproute2
except ImportError, e:
    raise ImportError (str(e) + "- required module not found")

class dhcp(moduleBase):
    """ ifupdown2 addon module to configure dhcp on interface """

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.dhclientcmd = dhclient(**kargs)
        self.ipcmd = None

    def _up(self, ifaceobj):
        try:
            if ifaceobj.addr_family == 'inet':
                # First release any existing dhclient processes
                try:
                    if not self.PERFMODE:
                        self.dhclientcmd.stop(ifaceobj.name)
                except:
                    pass
                self.dhclientcmd.start(ifaceobj.name)
            elif ifaceobj.addr_family == 'inet6':
                accept_ra = ifaceobj.get_attr_value_first('accept_ra')
                if accept_ra:
                    # XXX: Validate value
                    self.sysctl_set('net.ipv6.conf.%s' %ifaceobj.name +
                            '.accept_ra', accept_ra)
                autoconf = ifaceobj.get_attr_value_first('autoconf')
                if autoconf:
                    # XXX: Validate value
                    self.sysctl_set('net.ipv6.conf.%s' %ifaceobj.name +
                            '.autoconf', autoconf)
                    try:
                        self.dhclientcmd.stop6(ifaceobj.name)
                    except:
                        pass
                self.dhclientcmd.start6(ifaceobj.name)
        except Exception, e:
            self.log_error(str(e))

    def _down(self, ifaceobj):
        self.dhclientcmd.release(ifaceobj.name)
        self.ipcmd.link_down(ifaceobj.name)

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if self.dhclientcmd.is_running(ifaceobjcurr.name):
            ifaceobjcurr.addr_family = 'inet'
            if ifaceobj.addr_family != 'inet':
                ifaceobjcurr.status = ifaceStatus.ERROR
            ifaceobjcurr.addr_method = 'dhcp'
        elif self.dhclientcmd.is_running6(ifaceobjcurr.name):
            ifaceobjcurr.addr_family = 'inet6'
            if ifaceobj.addr_family != 'inet6':
                ifaceobjcurr.status = ifaceStatus.ERROR
            ifaceobjcurr.addr_method = 'dhcp'
        else:
            ifaceobjcurr.addr_family = None
            ifaceobjcurr.status = ifaceStatus.ERROR

    def _query_running(self, ifaceobjrunning):
        if not self.ipcmd.link_exists(ifaceobjrunning.name):
            self.logger.debug('iface %s not found' %ifaceobjrunning.name)
            ifaceobjrunning.status = ifaceStatus.NOTFOUND
            return
        if self.dhclientcmd.is_running(ifaceobjrunning.name):
            ifaceobjrunning.addr_family = 'inet'
            ifaceobjrunning.addr_method = 'dhcp'
        elif self.dhclientcmd.is_running6(ifaceobjrunning.name):
            ifaceobjrunning.addr_family = 'inet6'
            ifaceobjrunning.addr_method = 'dhcp6'

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
        """ run dhcp configuration on the interface object passed as argument

        Args:
            **ifaceobj** (object): iface object

            **operation** (str): any of 'up', 'down', 'query-checkcurr',
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
        try:
            if (operation != 'query-running' and
                   (ifaceobj.addr_method != 'dhcp' and 
                       ifaceobj.addr_method != 'dhcp6')):
                return
        except:
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
