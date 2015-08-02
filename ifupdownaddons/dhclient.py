#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from utilsbase import *
import subprocess
import os

FNULL = open(os.devnull, 'w')

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

    def stop(self, ifacename):
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
        self.subprocess_check_call(cmd)

    def start(self, ifacename):
        if os.path.exists('/sbin/dhclient3'):
            cmd = ['/sbin/dhclient3', '-pf',
                   '/run/dhclient.%s.pid' %ifacename,
                   '-lf', '/var/lib/dhcp3/dhclient.%s.leases' %ifacename,
                   '%s' %ifacename]
        else:
            cmd = ['/sbin/dhclient', '-pf', '/run/dhclient.%s.pid' %ifacename,
                   '-lf', '/var/lib/dhcp/dhclient.%s.leases' %ifacename,
                   '%s' %ifacename]
        self.subprocess_check_call(cmd)

    def release(self, ifacename):
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
        self.subprocess_check_call(cmd)

    def start6(self, ifacename):
        self.subprocess_check_call(['dhclient', '-6', '-pf',
                '/run/dhclient6.%s.pid' %ifacename, '-lf',
                '/var/lib/dhcp/dhclient.%s.leases ' %ifacename,
                '%s' %ifacename])

    def stop6(self, ifacename):
        self.subprocess_check_call(['dhclient', '-6', '-x', '-pf',
                '/run/dhclient.%s.pid' %ifacename, '-lf',
                '/var/lib/dhcp/dhclient.%s.leases ' %ifacename,
                '%s' %ifacename])

    def release6(self, ifacename):
        self.subprocess_check_call(['dhclient', '-6', '-r', '-pf',
                '/run/dhclient6.%s.pid' %ifacename, '-lf',
                '/var/lib/dhcp/dhclient6.%s.leases' %ifacename,
                '%s' %ifacename])
