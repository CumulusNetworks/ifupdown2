#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
import errno

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
            try:
                return os.readlink(
                    "/proc/%s/exe" % self.read_file_oneline(pidfilename)
                ).endswith("dhclient")
            except OSError as e:
                try:
                    if e.errno == errno.EACCES:
                        return os.path.exists("/proc/%s" % self.read_file_oneline(pidfilename))
                except Exception:
                    return False
            except Exception:
                return False
        return False

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
        retries = 0
        out = "0"

        # wait if interface isn't up yet
        while '1' not in out and retries < 5:
            path = '/sys/class/net/%s/carrier' %ifacename
            out = self.read_file_oneline(path)
            if out is None:
                break # No sysfs file found for this iface
            retries += 1
            time.sleep(1)

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

    def start6(self, ifacename, wait=True, cmd_prefix=None, duid=None):
        cmd = ['/sbin/dhclient', '-6', '-pf',
                '/run/dhclient6.%s.pid' %ifacename, '-lf',
                '/var/lib/dhcp/dhclient6.%s.leases' % ifacename,
                '%s' %ifacename]
        if not wait:
            cmd.append('-nw')
        if duid is not None:
            cmd.append('-D')
            cmd.append(duid)
        self._run_dhclient_cmd(cmd, cmd_prefix)

    def stop6(self, ifacename, cmd_prefix=None, duid=None):
        cmd = ['/sbin/dhclient', '-6', '-x', '-pf',
               '/run/dhclient6.%s.pid' % ifacename, '-lf',
               '/var/lib/dhcp/dhclient6.%s.leases' % ifacename,
               '%s' %ifacename]
        if duid is not None:
            cmd.append('-D')
            cmd.append(duid)
        self._run_dhclient_cmd(cmd, cmd_prefix)

    def release6(self, ifacename, cmd_prefix=None, duid=None):
        cmd = ['/sbin/dhclient', '-6', '-r', '-pf',
               '/run/dhclient6.%s.pid' %ifacename,
              '-lf', '/var/lib/dhcp/dhclient6.%s.leases' % ifacename,
               '%s' %ifacename]
        if duid is not None:
            cmd.append('-D')
            cmd.append(duid)
        self._run_dhclient_cmd(cmd, cmd_prefix)
