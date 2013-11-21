#!/usr/bin/python
#
# Copyright 2013.  Cumulus Networks, Inc.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifupdownBase --
#    base object for various ifupdown objects
#

import logging
import subprocess
import re
from ifupdown.iface import *

class ifupdownBase(object):

    def __init__(self):
        modulename = self.__class__.__name__
        self.logger = logging.getLogger('ifupdown.' + modulename)

    def exec_command(self, cmd, cmdenv=None, nowait=False):
        cmd_returncode = 0
        cmdout = ''

        try:
            self.logger.debug('Executing ' + cmd)
            ch = subprocess.Popen(cmd.split(),
                    stdout=subprocess.PIPE,
                    shell=False, env=cmdenv,
                    stderr=subprocess.STDOUT)
            cmdout = ch.communicate()[0]
            cmd_returncode = ch.wait()

        except OSError, e:
            raise Exception('could not execute ' + cmd +
                    '(' + str(e) + ')')

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
            raise Exception(str)
        else:
            pass

