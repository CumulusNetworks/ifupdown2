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
    from ifupdown2.lib.sysfs import Sysfs
except (ImportError, ModuleNotFoundError):
    from ifupdown.utils import utils
    from ifupdownaddons.utilsbase import *
    from lib.sysfs import Sysfs

class dhclient(utilsBase):
    """ This class contains helper methods to interact with the dhclient
    utility """

    MAX_RETRIES = 5

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not os.path.exists('/sbin/dhclient3') and not os.path.exists('/sbin/dhclient'):
            raise RuntimeError(f'missing required executable: /sbin/dhclient3 or /sbin/dhclient')

    def is_running(self, ifacename: str) -> bool:
        pid = self.read_file_oneline(f'/run/dhclient.{ifacename}.pid')
        try:
            return utils.pid_exists(int(pid))
        except (TypeError, ValueError):
            return False

    def is_running6(self, ifacename: str) -> bool:
        pid = self.read_file_oneline(f'/run/dhclient6.{ifacename}.pid')
        try:
            return utils.pid_exists(int(pid))
        except (TypeError, ValueError):
            return False

    def stop(self, ifacename: str, cmd_prefix: list[str] = []):
        self.logger.debug(f'stopping dhclient on {ifacename}')

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
        utils.exec_commandl(cmd_prefix + cmd, stdout=None, stderr=None)

    def start(self, ifacename: str, wait: bool = True, cmd_prefix: list[str] = []):
        self.logger.debug(f'starting dhclient on {ifacename}')
        retries = 0

        # wait if interface isn't up yet
        while not Sysfs.link_has_carrier(ifacename) and retries < self.MAX_RETRIES:
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
        utils.exec_commandl(cmd_prefix + cmd, stdout=None, stderr=None)

    def release(self, ifacename: str, cmd_prefix: list[str] = []):
        self.logger.debug(f'releasing lease on {ifacename}')

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
        utils.exec_commandl(cmd_prefix + cmd, stdout=None, stderr=None)

    def start6(self, ifacename: str, wait: bool = True, cmd_prefix: list[str] = [], duid: str | None = None):
        self.logger.debug(f'starting v6 dhclient on {ifacename}')

        cmd = ['/sbin/dhclient', '-6', '-pf',
                '/run/dhclient6.%s.pid' %ifacename, '-lf',
                '/var/lib/dhcp/dhclient6.%s.leases' % ifacename,
                '%s' %ifacename]
        if not wait:
            cmd.append('-nw')
        if duid is not None:
            cmd.append('-D')
            cmd.append(duid)
        utils.exec_commandl(cmd_prefix + cmd, stdout=None, stderr=None)

    def stop6(self, ifacename: str, cmd_prefix: list[str] = [], duid: str | None = None):
        self.logger.debug(f'stopping v6 dhclient on {ifacename}')

        cmd = ['/sbin/dhclient', '-6', '-x', '-pf',
               '/run/dhclient6.%s.pid' % ifacename, '-lf',
               '/var/lib/dhcp/dhclient6.%s.leases' % ifacename,
               '%s' %ifacename]
        if duid is not None:
            cmd.append('-D')
            cmd.append(duid)
        utils.exec_commandl(cmd_prefix + cmd, stdout=None, stderr=None)

    def release6(self, ifacename: str, cmd_prefix: list[str] = [], duid: str | None = None):
        self.logger.debug(f'releasing v6 lease on {ifacename}')

        cmd = ['/sbin/dhclient', '-6', '-r', '-pf',
               '/run/dhclient6.%s.pid' %ifacename,
              '-lf', '/var/lib/dhcp/dhclient6.%s.leases' % ifacename,
               '%s' %ifacename]
        if duid is not None:
            cmd.append('-D')
            cmd.append(duid)
        utils.exec_commandl(cmd_prefix + cmd, stdout=None, stderr=None)
