#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifupdownBase --
#    base object for various ifupdown objects
#

import logging
import subprocess
import re
import os
import rtnetlink_api as rtnetlink_api
import signal
import shlex

from iface import *
from ifupdown.utils import utils


class ifupdownBase(object):

    def __init__(self):
        modulename = self.__class__.__name__
        self.logger = logging.getLogger('ifupdown.' + modulename)

    def exec_command(self, cmd, cmdenv=None, nowait=False):
        cmd_returncode = 0
        cmdout = ''
        try:
            self.logger.info('executing ' + cmd)
            if self.DRYRUN:
                return cmdout
            ch = subprocess.Popen(shlex.split(cmd),
                    stdout=subprocess.PIPE,
                    shell=False, env=cmdenv,
                    stderr=subprocess.STDOUT,
                    close_fds=True)
            utils.enable_subprocess_signal_forwarding(ch, signal.SIGINT)
            cmdout = ch.communicate()[0]
            cmd_returncode = ch.wait()
        except OSError, e:
            raise Exception('could not execute ' + cmd +
                    '(' + str(e) + ')')
        finally:
            utils.disable_subprocess_signal_forwarding(signal.SIGINT)
        if cmd_returncode != 0:
            raise Exception('error executing cmd \'%s\'' %cmd +
                '\n(' + cmdout.strip('\n ') + ')')
        return cmdout

    def ignore_error(self, errmsg):
        if (self.FORCE == True or re.search(r'exists', errmsg,
            re.IGNORECASE | re.MULTILINE) is not None):
            return True
        return False

    def log_warn(self, str):
        if self.ignore_error(str) == False:
            if self.logger.getEffectiveLevel() == logging.DEBUG:
                traceback.print_stack()
            self.logger.warn(str)
        pass

    def log_error(self, str):
        if self.ignore_error(str) == False:
            raise
            #raise Exception(str)
        else:
            pass

    def link_exists(self, ifacename):
        return os.path.exists('/sys/class/net/%s' %ifacename)

    def link_up(self, ifacename):
        rtnetlink_api.rtnl_api.link_set(ifacename, "up")

    def link_down(self, ifacename):
        rtnetlink_api.rtnl_api.link_set(ifacename, "down")
