#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
import ifupdownaddons

from ifupdown.utils import utils
import ifupdown.ifupdownflags as ifupdownflags

class usercmds(ifupdownaddons.modulebase.moduleBase):
    """  ifupdown2 addon module to configure user specified commands """

    _modinfo = {'mhelp' : 'user commands for interfaces',
                'attrs' : {
                   'pre-up' :
                        {'help' : 'run command before bringing the interface up',
                         'multiline' : True},
                   'up' :
                        {'help' : 'run command at interface bring up',
                         'multiline' : True},
                   'post-up' :
                        {'help' : 'run command after interface bring up',
                         'multiline' : True},
                   'pre-down' :
                        {'help' : 'run command before bringing the interface down',
                         'multiline' : True},
                   'down' :
                        {'help' : 'run command at interface down',
                         'multiline' : True},
                   'post-down' :
                        {'help' : 'run command after bringing interface down',
                         'multiline' : True}}}

    def _run_command(self, ifaceobj, op):
        cmd_list = ifaceobj.get_attr_value(op)
        if cmd_list:
            os.environ['IFACE'] = ifaceobj.name if ifaceobj.name else ''
            os.environ['LOGICAL'] = ifaceobj.name if ifaceobj.name else ''
            os.environ['METHOD'] = ifaceobj.addr_method if ifaceobj.addr_method else ''
            os.environ['ADDRFAM'] = ifaceobj.addr_family if ifaceobj.addr_family else ''
            for cmd in cmd_list:
                try:
                    utils.exec_user_command(cmd)
                except Exception, e:
                    if not self.ignore_error(str(e)):
                        self.logger.warn('%s: %s %s' % (ifaceobj.name, op,
                                                        str(e).strip('\n')))
                    pass

    _run_ops = {'pre-up' : _run_command,
               'pre-down' : _run_command,
               'up' : _run_command,
               'post-up' : _run_command,
               'down' : _run_command,
               'post-down' : _run_command}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        """ run user commands

        Args:
            **ifaceobj** (object): iface object

            **operation** (str): list of ops

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
        op_handler(self, ifaceobj, operation)
