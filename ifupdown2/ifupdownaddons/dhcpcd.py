#!/usr/bin/env python3

import os
import time

try:
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdownaddons.utilsbase import *
    from ifupdown2.lib.sysfs import Sysfs
except (ImportError, ModuleNotFoundError):
    from ifupdown.utils import utils
    from ifupdownaddons.utilsbase import *
    from lib.sysfs import Sysfs

class DhcpcdClient(utilsBase):
    """
    This class contains helper methods to interact with the dhcpcd(8) client
    """
    MAX_RETRIES = 5

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not os.path.exists(utils.dhcpcd_cmd):
            raise RuntimeError(f'missing required executable: {utils.dhcpcd_cmd}')

    def _start(self, cmd_prefix: list[str], ifacename: str, wait: bool, ipv6: bool, duid: str | None = None):
        """
        Starts the dhcpcd(8) with the given arguments.
        :param cmd_prefix: Optional list of strings to prefix the dhcpcd command with
        :param ifacename: Interface name
        :param wait: Whether to wait until a lease has been acquired before dhcpcd becomes a daemon.
        :param ipv6: Whether to request a IPv6 address, otherwise IPv4.
        :param duid: Optional DUID type for IPv6, must be 'LL' or 'LLT'
        """
        retries = 0

        # wait if interface isn't up yet
        while not Sysfs.link_has_carrier(ifacename) and retries < self.MAX_RETRIES:
            retries += 1
            time.sleep(1)

        cmd = [utils.dhcpcd_cmd]

        if ipv6:
            cmd.append('--ipv6only')
        else:
            cmd.append('--ipv4only')

        if wait:
            cmd.append('--waitip')

        if duid:
            cmd.extend(['--duid', duid])

        cmd.append(ifacename)
        utils.exec_commandl(cmd_prefix + cmd, stdout=None)

    def is_running(self, ifacename: str) -> bool:
        """
        Checks whether an IPv4 dhcpcd(8) daemon is running for the given interface.
        :param ifacename: Interface name
        """
        pid = self.read_file_oneline(f'/run/dhcpcd/{ifacename}-4.pid')
        try:
            return utils.pid_exists(int(pid))
        except (TypeError, ValueError):
            return False

    def is_running6(self, ifacename: str) -> bool:
        """
        Checks whether an IPv6 dhcpcd(8) daemon is running for the given interface.
        :param ifacename: Interface name
        """
        pid = self.read_file_oneline(f'/run/dhcpcd/{ifacename}-6.pid')
        try:
            return utils.pid_exists(int(pid))
        except (TypeError, ValueError):
            return False

    def start(self, ifacename: str, wait: bool = True, cmd_prefix: list[str] = []):
        """
        Starts the dhcpcd(8) for leasing an IPv4 address.
        :param ifacename: Interface name
        :param wait: Whether to wait until a lease has been acquired before dhcpcd becomes a daemon.
        :param cmd_prefix: Optional list of strings to prefix the dhcpcd command with
        """
        self.logger.debug(f'starting dhcpcd client on {ifacename}')
        self._start(cmd_prefix, ifacename, wait, ipv6=False)

    def stop(self, ifacename: str, cmd_prefix: list[str] = []):
        """
        Stops the IPv4 dhcpcd daemon for the given interface.
        Does not release the current lease.
        :param ifacename: Interface name
        :param cmd_prefix: Optional list of strings to prefix the dhcpcd command with
        """
        self.logger.debug(f'stopping dhcpcd client on {ifacename}')

        cmd = [utils.dhcpcd_cmd, '--ipv4only', '--exit', ifacename]
        utils.exec_commandl(cmd_prefix + cmd, stdout=None)

    def release(self, ifacename: str, cmd_prefix: list[str] = []):
        """
        Releases the current IPv4 lease for the given interface.
        :param ifacename: Interface name
        :param cmd_prefix: Optional list of strings to prefix the dhcpcd command with
        """
        self.logger.debug(f'releasing lease on {ifacename}')

        cmd = [utils.dhcpcd_cmd, '--ipv4only', '--release', ifacename]
        utils.exec_commandl(cmd_prefix + cmd, stdout=None)

    def start6(self, ifacename: str, wait: bool = True, cmd_prefix: list[str] = [], duid: str | None = None):
        """
        Starts the dhcpcd(8) for leasing an IPv6 address.
        :param ifacename: Interface name
        :param wait: Whether to wait until a lease has been acquired before dhcpcd becomes a daemon.
        :param cmd_prefix: Optional list of strings to prefix the dhcpcd command with
        :param duid: Optional DUID type for IPv6, must be 'LL' or 'LLT'
        """
        self.logger.debug(f'starting v6 dhcpcd client on {ifacename}')
        self._start(cmd_prefix, ifacename, wait, True, duid)

    def stop6(self, ifacename: str, cmd_prefix: list[str] = [], duid: str | None = None):
        """
        Stops the IPv6 dhcpcd daemon for the given interface.
        Does not release the current lease.
        :param ifacename: Interface name
        :param cmd_prefix: Optional list of strings to prefix the dhcpcd command with
        :param duid: Optional DUID type for IPv6, must be 'LL' or 'LLT'
        """
        self.logger.debug(f'stopping v6 dhcpcd client on {ifacename}')

        cmd = [utils.dhcpcd_cmd, '--ipv6only', '--exit', ifacename]
        utils.exec_commandl(cmd_prefix + cmd, stdout=None)

    def release6(self, ifacename: str, cmd_prefix: list[str] = [], duid: str | None = None):
        """
        Releases the current IPv4 lease for the given interface.
        :param ifacename: Interface name
        :param cmd_prefix: Optional list of strings to prefix the dhcpcd command with
        :param duid: Optional DUID type for IPv6, must be 'LL' or 'LLT'
        """
        self.logger.debug(f'releasing v6 lease on {ifacename}')

        cmd = [utils.dhcpcd_cmd, '--ipv6only', '--release', ifacename]
        utils.exec_commandl(cmd_prefix + cmd, stdout=None)
