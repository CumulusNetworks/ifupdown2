#!/usr/bin/python

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
