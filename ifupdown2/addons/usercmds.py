#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os

try:
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    from ifupdown.utils import utils

    from ifupdownaddons.modulebase import moduleBase


class usercmds(moduleBase):
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
            env = dict(os.environ)
            env.update({
                    'LOGICAL': ifaceobj.name if ifaceobj.name else '',
                    'METHOD': ifaceobj.addr_method if ifaceobj.addr_method else '',
                    'ADDRFAM': ','.join(ifaceobj.addr_family) if ifaceobj.addr_family else ''
                })
            env.update(ifaceobj.get_env())
            for cmd in cmd_list:
                try:
                    utils.exec_user_command(cmd, env=env)
                except Exception as e:
                    if not self.ignore_error(str(e)):
                        self.logger.warning('%s: %s %s' % (ifaceobj.name, op,
                                                        str(e).strip('\n')))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if ifaceobj.config:
            for ops in ['pre-up',
                        'up',
                        'post-up',
                        'pre-down',
                        'down',
                        'post-down']:
                for cmd in ifaceobj.config.get(ops, []):
                    ifaceobjcurr.update_config_with_status(ops, cmd, -1)

    _run_ops = {'pre-up' : _run_command,
               'pre-down' : _run_command,
               'up' : _run_command,
               'post-up' : _run_command,
               'down' : _run_command,
               'post-down' : _run_command,
               'query-checkcurr': _query_check}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return list(self._run_ops.keys())

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
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj, operation)
