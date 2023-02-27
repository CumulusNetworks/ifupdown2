#!/usr/bin/env python3

import os
import signal
import time

try:
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.policymanager import policymanager_api
    from ifupdown2.ifupdownaddons.utilsbase import utilsBase

except (ImportError, ModuleNotFoundError):
    from ifupdown.utils import utils
    from ifupdown.policymanager import policymanager_api
    from ifupdownaddons.utilsbase import utilsBase


class udhcpc(utilsBase):
    """
    This class contains helper methods to interact with udhcpc
    """

    def is_running(self, ifacename):
        return self.pid_exists(f'/run/udhcpc.{ifacename}.pid', 'busybox')

    def is_running6(self, ifacename):
        return False

    def _run_udhcpc_cmd(self, cmd, cmd_prefix=None):
        cmd_aslist = cmd_prefix.split() if cmd_prefix else []
        cmd_aslist.extend(cmd)
        utils.exec_commandl(cmd_aslist, stdout=None, stderr=None)

    def stop(self, ifacename, cmd_prefix=None):
        if not self.is_running(ifacename):
            return
        with open(f'/run/udhcpc.{ifacename}.pid', 'r') as fd:
            pid = int(fd.read())
        os.kill(pid, signal.SIGTERM)
        # wait until udhcpc is stopped
        it, maxt = 0, 10
        while self.is_running(ifacename) and it < maxt:
            time.sleep(1)
            it += 1

    def _get_send_packets_number(self, timeout_secs=10):
        """ Get sendable number of packets in timeout_sec """
        # We cannot ask udhcpc to send packets until a time is reached,
        # but we can ask udhcpc to send a number of predetermined packets
        # to match our given time.

        PACKETS_INTERVAL_SECS = 3  # default udhcpc wait in between packets
        if timeout_secs <= 0:
            return 0  # 0 is an unlimited packets numbers
        return timeout_secs // PACKETS_INTERVAL_SECS

    def start(self, ifacename, wait=True, cmd_prefix=None):
        if os.path.exists('/sbin/udhcpc'):
            cmd = ['/sbin/udhcpc']
        else:
            cmd = ['/usr/bin/busybox', 'udhcpc']
        if not wait:
            # udhcpc can't fork without sending at least one packet.
            # Send one packet then unlimited background discovery.
            cmd += ['-b', '-t', '1', '-A', '0']
        else:
            packets = self._get_send_packets_number()
            cmd += ['-n', '-t', str(packets)]
        self._run_udhcpc_cmd(cmd + [
            '-S', '-i', ifacename, '-p', f'/run/udhcpc.{ifacename}.pid'
        ], cmd_prefix)

    def release(self, ifacename, cmd_prefix=None):
        if not self.is_running(ifacename):
            return
        with open(f'/run/udhcpc.{ifacename}.pid', 'r') as fd:
            pid = int(fd.read())
        os.kill(pid, signal.SIGUSR2)
        self.stop(ifacename, cmd_prefix)

    def start6(self, ifname, *args, **kwargs):
        raise NotImplementedError(
            f'{ifname}: dhcp: udhcpc does not support inet6 family'
        )

    def stop6(self, ifname, *args, **kwargs):
        raise NotImplementedError(
            f'{ifname}: dhcp: udhcpc does not support inet6 family'
        )

    def release6(self, ifname, *args, **kwargs):
        raise NotImplementedError(
            f'{ifname}: dhcp: udhcpc does not support inet6 family'
        )
