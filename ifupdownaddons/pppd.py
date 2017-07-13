#!/usr/bin/python
#
# Author: Joerg Dorchain <joerg@dorchain.net>
#

from ifupdown.utils import utils
from utilsbase import *
import os


class pppd(utilsBase):
    """ This class contains helper methods to interact with the pppd """

    def _pid_exists(self, pidfilename):
        if os.path.exists(pidfilename):
            pid = self.read_file_oneline(pidfilename)
            if not os.path.exists('/proc/%s' %pid):
                return False
        else:
            return False
        return True

    def is_running(self, ifacename):
        return self._pid_exists('/run/%s.pid' %ifacename)

    def _run_cmd(self, cmd, cmd_prefix=None):
        if not cmd_prefix:
            cmd_aslist = []
        else:
            cmd_aslist = cmd_prefix.split()
        if cmd_aslist:
            cmd_aslist.extend(cmd)
        else:
            cmd_aslist = cmd
        utils.exec_commandl(cmd_aslist)

    def stop(self, ifaceobj, cmd_prefix=None):
        cmd = ['/usr/bin/poff', '%s' % ifaceobj.get_attr_value_first('provider') ]
        self._run_cmd(cmd, cmd_prefix)

    def start(self, ifaceobj, cmd_prefix=None):
        cmd = ['/usr/bin/pon', '%s' % ifaceobj.get_attr_value_first('provider') ]
	if ifaceobj.get_attr_value_first ('unit'):
		cmd += ['unit', '%s' % ifaceobj.get_attr_value_first('unit')]
	if ifaceobj.get_attr_value_first ('options'):
		cmd += ['%s' % ifaceobj.get_attr_value_first('options')]
        self._run_cmd(cmd, cmd_prefix)
