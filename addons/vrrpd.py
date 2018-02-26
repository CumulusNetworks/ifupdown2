#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

try:
    from ipaddr import IPNetwork
    from sets import Set
    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdownaddons.modulebase import moduleBase
    from ifupdownaddons.iproute2 import iproute2
    import ifupdown.ifupdownflags as ifupdownflags
    import os
    import glob
    import logging
    import signal
    import re
except ImportError, e:
    raise ImportError(str(e) + "- required module not found")


class vrrpd(moduleBase):
    """  ifupdown2 addon module to configure vrrpd attributes """

    _modinfo = {'mhelp': 'ethtool configuration module for interfaces',
                'attrs': {
                    'vrrp-id':
                    {'help': 'vrrp instance id',
                     'validrange': ['1', '4096'],
                             'example': ['vrrp-id 1']},
                    'vrrp-priority':
                    {'help': 'set vrrp priority',
                             'validrange': ['0', '255'],
                             'example': ['vrrp-priority 20']},
                    'vrrp-virtual-ip':
                    {'help': 'set vrrp virtual ip',
                             'validvals': ['<ipv4>', ],
                             'example': ['vrrp-virtual-ip 10.0.1.254']}}}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None

    def _check_if_process_is_running(self, cmdname, cmdline):
        targetpids = []
        pidstr = ''
        try:
            cmdl = ['/bin/pidof', cmdname]
            pidstr = utils.exec_commandl(cmdl, stderr=None).strip('\n')
        except:
            pass
        if not pidstr:
            return []

        pids = pidstr.split()
        if not pids:
            return targetpids
        for pid in pids:
            tmpcmdline = cmdline.replace(' ', '')
            try:
                pcmdline = self.read_file_oneline('/proc/%s/cmdline' % pid)
                pcmdline = re.sub(r'\\(.)', r'\1', pcmdline)
                self.logger.info('(%s)' % (pcmdline))
                self.logger.info('(%s)' % (tmpcmdline))
                self.logger.info('(%d) (%d)' %
                                 (len(pcmdline), len(tmpcmdline)))
                if pcmdline and pcmdline == tmpcmdline:
                    targetpids.append(pid)
            except:
                pass
        return targetpids

    def _up(self, ifaceobj):
        """ up vrrpd -n -D -i $IFACE -v 1 -p 20 10.0.1.254
            up ifplugd -i $IFACE -b -f -u0 -d1 -I -p -q """

        if (not ifupdownflags.flags.DRYRUN and
                not os.path.exists('/sys/class/net/%s' % ifaceobj.name)):
            return

        cmd = ''
        attrval = ifaceobj.get_attr_value_first('vrrp-id')
        if attrval:
            cmd += ' -v %s' % attrval
        else:
            return
        attrval = ifaceobj.get_attr_value_first('vrrp-priority')
        if attrval:
            cmd += ' -p %s' % attrval
        else:
            self.logger.warn('%s: incomplete vrrp parameters ' % ifaceobj.name,
                             '(priority not found)')
        attrval = ifaceobj.get_attr_value_first('vrrp-virtual-ip')
        if attrval:
            cmd += ' %s' % attrval
        else:
            self.logger.warn('%s: incomplete vrrp arguments ' % ifaceobj.name,
                             '(virtual ip not found)')
            return
        cmd = '/usr/sbin/vrrpd -n -D -i %s %s' % (ifaceobj.name, cmd)
        utils.exec_command(cmd)

        cmd = '/usr/sbin/ifplugd -i %s -b -f -u0 -d1 -I -p -q' % ifaceobj.name
        if self._check_if_process_is_running('/usr/sbin/ifplugd', cmd):
            self.logger.info('%s: ifplugd already running' % ifaceobj.name)
            return
        utils.exec_command(cmd)

    def _kill_pid_from_file(self, pidfilename):
        if os.path.exists(pidfilename):
            pid = self.read_file_oneline(pidfilename)
            if os.path.exists('/proc/%s' % pid):
                os.kill(int(pid), signal.SIGTERM)

    def _down(self, ifaceobj):
        """ down ifplugd -k -i $IFACE
             down kill $(cat /var/run/vrrpd_$IFACE_*.pid) """
        attrval = ifaceobj.get_attr_value_first('vrrp-id')
        if not attrval:
            return
        try:
            utils.exec_command('/usr/sbin/ifplugd -k -i %s' % ifaceobj.name)
        except Exception, e:
            self.logger.debug('%s: ifplugd down error (%s)'
                              % (ifaceobj.name, str(e)))
            pass

        for pidfile in glob.glob('/var/run/vrrpd_%s_*.pid' % ifaceobj.name):
            try:
                self._kill_pid_from_file(pidfile)
            except Exception, e:
                self.logger.debug('%s: vrrpd down error (%s)'
                                  % (ifaceobj.name, str(e)))
                pass

    def _query_check(self, ifaceobj, ifaceobjcurr):
        # XXX
        return

    _run_ops = {'post-up': _up,
                'pre-down': _down}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

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
