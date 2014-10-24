#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import subprocess
import ifupdownaddons

class usercmds(ifupdownaddons.modulebase.moduleBase):
    """  ifupdown2 addon module to configure user specified commands """

    _modinfo = {'mhelp' : 'user commands for interfaces',
                'attrs' : {
                   'pre-up' :
                        {'help' : 'run command before bringing the interface up'},
                   'up' :
                        {'help' : 'run command at interface bring up'},
                   'post-up' :
                        {'help' : 'run command after interface bring up'},
                   'pre-down' :
                        {'help' : 'run command before bringing the interface down'},
                   'down' :
                        {'help' : 'run command at interface down'},
                   'post-down' :
                        {'help' : 'run command after bringing interface down'}}}

    def _exec_user_cmd(self, cmd):
        """ exec's commands using subprocess Popen

        special wrapper using use closefds=True and shell=True
        for user commands
        """

        cmd_returncode = 0
        try:
            self.logger.info('executing %s' %cmd)
            if self.DRYRUN:
                return
            ch = subprocess.Popen(cmd,
                    stdout=subprocess.PIPE,
                    shell=True,
                    stderr=subprocess.STDOUT,
                    close_fds=True)
            cmd_returncode = ch.wait()
            cmdout = ch.communicate()[0]
        except Exception, e:
            raise Exception('failed to execute cmd \'%s\' (%s)'
                            %(cmd, str(e)))
        if cmd_returncode != 0:
            raise Exception(cmdout)
        return cmdout

    def _run_command(self, ifaceobj, op):
        cmd_list = ifaceobj.get_attr_value(op)
        if cmd_list:
            for cmd in cmd_list:
                self.logger.info('executing cmd \'%s\'' %cmd)
                try:
                    self._exec_user_cmd(cmd)
                except Exception, e:
                    if not self.ignore_error(str(e)):
                        self.logger.warn('%s: %s cmd \'%s\' failed (%s)'
                                %(ifaceobj.name, op, cmd, str(e).strip('\n')))
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
