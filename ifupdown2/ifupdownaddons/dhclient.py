#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os

try:
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdownaddons.utilsbase import *
except ImportError:
    from ifupdown.utils import utils
    from ifupdownaddons.utilsbase import *


class dhclient(utilsBase):
    """ This class contains helper methods to interact with the dhclient
    utility """

    def _pid_exists(self, pidfilename):
        if os.path.exists(pidfilename):
            pid = self.read_file_oneline(pidfilename)
            if not os.path.exists('/proc/%s' %pid):
                return False
        else:
            return False
        return True

    def is_running(self, ifacename):
        return self._pid_exists('/run/dhclient.%s.pid' %ifacename)

    def is_running6(self, ifacename):
        return self._pid_exists('/run/dhclient6.%s.pid' %ifacename)

    def _run_dhclient_cmd(self, cmd, cmd_prefix=None):
        if not cmd_prefix:
            cmd_aslist = []
        else:
            cmd_aslist = cmd_prefix.split()
        if cmd_aslist:
            cmd_aslist.extend(cmd)
        else:
            cmd_aslist = cmd
        utils.exec_commandl(cmd_aslist, stdout=None, stderr=None)

    def stop(self, ifacename, cmd_prefix=None):
        if os.path.exists('/sbin/dhclient3'):
            cmd = ['/sbin/dhclient3', '-x', '-pf',
                   '/run/dhclient.%s.pid' %ifacename, '-lf',
                   '/var/lib/dhcp3/dhclient.%s.leases' %ifacename,
                   '%s' %ifacename]
        else:
            cmd = ['/sbin/dhclient', '-x', '-pf',
                   '/run/dhclient.%s.pid' %ifacename,
                   '-lf', '/var/lib/dhcp/dhclient.%s.leases' %ifacename,
                   '%s' %ifacename]
        self._run_dhclient_cmd(cmd, cmd_prefix)

    def start(self, ifacename, wait=True, cmd_prefix=None):
        if os.path.exists('/sbin/dhclient3'):
            cmd = ['/sbin/dhclient3', '-pf',
                   '/run/dhclient.%s.pid' %ifacename,
                   '-lf', '/var/lib/dhcp3/dhclient.%s.leases' %ifacename,
                   '%s' %ifacename]
        else:
            cmd = ['/sbin/dhclient', '-pf',
                   '/run/dhclient.%s.pid' %ifacename, '-lf',
                   '/var/lib/dhcp/dhclient.%s.leases' %ifacename,
                   '%s' %ifacename]
        if not wait:
            cmd.append('-nw')
        self._run_dhclient_cmd(cmd, cmd_prefix)

    def release(self, ifacename, cmd_prefix=None):
        if os.path.exists('/sbin/dhclient3'):
            cmd = ['/sbin/dhclient3', '-r', '-pf',
                   '/run/dhclient.%s.pid' %ifacename, '-lf',
                   '/var/lib/dhcp3/dhclient.%s.leases' %ifacename,
                   '%s' %ifacename]
        else:
            cmd = ['/sbin/dhclient', '-r', '-pf',
                   '/run/dhclient.%s.pid' %ifacename,
                   '-lf', '/var/lib/dhcp/dhclient.%s.leases' %ifacename,
                   '%s' %ifacename]
        self._run_dhclient_cmd(cmd, cmd_prefix)

    def start6(self, ifacename, wait=True, cmd_prefix=None):
        cmd = ['/sbin/dhclient', '-6', '-pf',
                '/run/dhclient6.%s.pid' %ifacename, '-lf',
                '/var/lib/dhcp/dhclient6.%s.leases' % ifacename,
                '%s' %ifacename]
        if not wait:
            cmd.append('-nw')
        self._run_dhclient_cmd(cmd, cmd_prefix)

    def stop6(self, ifacename, cmd_prefix=None):
        cmd = ['/sbin/dhclient', '-6', '-x', '-pf',
               '/run/dhclient6.%s.pid' % ifacename, '-lf',
               '/var/lib/dhcp/dhclient6.%s.leases' % ifacename,
               '%s' %ifacename]
        self._run_dhclient_cmd(cmd, cmd_prefix)

    def release6(self, ifacename, cmd_prefix=None):
        cmd = ['/sbin/dhclient', '-6', '-r', '-pf',
               '/run/dhclient6.%s.pid' %ifacename,
              '-lf', '/var/lib/dhcp/dhclient6.%s.leases' % ifacename,
               '%s' %ifacename]
        self._run_dhclient_cmd(cmd, cmd_prefix)
