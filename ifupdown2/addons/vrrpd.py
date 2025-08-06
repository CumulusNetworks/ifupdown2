#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
import re
import glob
import signal

try:
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

    from ifupdown2.ifupdownaddons.modulebase import moduleBase

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
except ImportError:
    import ifupdown.ifupdownflags as ifupdownflags

    from ifupdownaddons.modulebase import moduleBase

    from ifupdown.iface import *
    from ifupdown.utils import utils


class vrrpd(moduleBase):
    """  ifupdown2 addon module to configure vrrpd attributes """

    _modinfo = {'mhelp' : 'ethtool configuration module for interfaces',
                'attrs': {
                      'vrrp-id' :
                            {'help' : 'vrrp instance id',
                             'validrange' : ['1', '4096'],
                             'example' : ['vrrp-id 1']},
                      'vrrp-priority' :
                            {'help': 'set vrrp priority',
                             'validrange' : ['0', '255'],
                             'example' : ['vrrp-priority 20']},
                      'vrrp-virtual-ip' :
                            {'help': 'set vrrp virtual ip',
                             'validvals' : ['<ipv4>', ],
                             'example' : ['vrrp-virtual-ip 10.0.1.254']}}}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)

    def _check_if_process_is_running(self, cmdname, cmdline):
        targetpids = []
        pidstr = ''
        try:
            cmdl = [utils.pidof_cmd, cmdname]
            pidstr = utils.exec_commandl(cmdl, stderr=None).strip('\n')
        except Exception:
            pass
        if not pidstr:
           return []

        pids = pidstr.split()
        if not pids:
           return targetpids
        for pid in pids:
            tmpcmdline = cmdline.replace(' ', '')
            try:
                pcmdline = self.read_file_oneline('/proc/%s/cmdline' %pid)
                pcmdline = re.sub(r'\\(.)', r'\1', pcmdline)
                self.logger.info('(%s)' %(pcmdline))
                self.logger.info('(%s)' %(tmpcmdline))
                self.logger.info('(%d) (%d)' %(len(pcmdline), len(tmpcmdline)))
                if pcmdline and pcmdline == tmpcmdline:
                   targetpids.append(pid)
            except Exception:
                pass
        return targetpids

    def _up(self, ifaceobj):
        """ up vrrpd -n -D -i $IFACE -v 1 -p 20 10.0.1.254
            up ifplugd -i $IFACE -b -f -u0 -d1 -I -p -q """

        if (not ifupdownflags.flags.DRYRUN and
            not os.path.exists('/sys/class/net/%s' %ifaceobj.name)):
            return

        cmd = ''
        attrval = ifaceobj.get_attr_value_first('vrrp-id')
        if attrval:
            cmd += ' -v %s' %attrval
        else:
            return
        attrval = ifaceobj.get_attr_value_first('vrrp-priority')
        if attrval:
            cmd += ' -p %s' %attrval
        else:
            self.logger.warning('%s: incomplete vrrp parameters ' %ifaceobj.name,
                    '(priority not found)')
        attrval = ifaceobj.get_attr_value_first('vrrp-virtual-ip')
        if attrval:
            cmd += ' %s' %attrval
        else:
            self.logger.warning('%s: incomplete vrrp arguments ' %ifaceobj.name,
                    '(virtual ip not found)')
            return
        cmd = ('%s -n -D -i %s %s' %
               (utils.vrrpd_cmd, ifaceobj.name, cmd))
        utils.exec_command(cmd)

        cmd = ('%s -i %s -b -f -u0 -d1 -I -p -q' %
               (utils.ifplugd_cmd, ifaceobj.name))
        if self._check_if_process_is_running(utils.ifplugd_cmd, cmd):
           self.logger.info('%s: ifplugd already running' %ifaceobj.name)
           return
        utils.exec_command(cmd)

    def _kill_pid_from_file(self, pidfilename):
        if os.path.exists(pidfilename):
            pid = self.read_file_oneline(pidfilename)
            if os.path.exists('/proc/%s' %pid):
               os.kill(int(pid), signal.SIGTERM)

    def _down(self, ifaceobj):
        """ down ifplugd -k -i $IFACE
             down kill $(cat /var/run/vrrpd_$IFACE_*.pid) """
        attrval = ifaceobj.get_attr_value_first('vrrp-id')
        if not attrval:
            return
        try:
            utils.exec_command('%s -k -i %s' %
                               (utils.ifplugd_cmd, ifaceobj.name))
        except Exception as e:
            self.logger.debug('%s: ifplugd down error (%s)'
                              %(ifaceobj.name, str(e)))

        for pidfile in glob.glob('/var/run/vrrpd_%s_*.pid' %ifaceobj.name):
            try:
                self._kill_pid_from_file(pidfile)
            except Exception as e:
                self.logger.debug('%s: vrrpd down error (%s)'
                                  %(ifaceobj.name, str(e)))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        # XXX
        return


    _run_ops = {'post-up' : _up,
                'pre-down' : _down}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return list(self._run_ops.keys())

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
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
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
