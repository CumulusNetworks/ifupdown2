#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import logging
import subprocess
import re
import io
import signal
import shlex

from ifupdown.utils import utils
import ifupdown.ifupdownflags as ifupdownflags
from ifupdown.iface import *
from cache import *
import time
import logging

def profile(func):
    def wrap(*args, **kwargs):
        started_at = time.time()
        result = func(*args, **kwargs)
        print str(func)
        print (time.time() - started_at)
        return result
    return wrap

class utilsBase(object):
    """ Base class for ifupdown addon utilities """

    def __init__(self, *args, **kargs):
        modulename = self.__class__.__name__
        self.logger = logging.getLogger('ifupdown.' + modulename)

    def exec_commandl(self, cmdl, cmdenv=None):
        """ Executes command """

        cmd_returncode = 0
        cmdout = ''
        try:
            self.logger.info('executing ' + ' '.join(cmdl))
            if ifupdownflags.flags.DRYRUN:
                return cmdout
            ch = subprocess.Popen(cmdl,
                    stdout=subprocess.PIPE,
                    shell=False, env=cmdenv,
                    stderr=subprocess.STDOUT,
                    close_fds=True)
            utils.enable_subprocess_signal_forwarding(ch, signal.SIGINT)
            cmdout = ch.communicate()[0]
            cmd_returncode = ch.wait()
        except OSError, e:
            raise Exception('failed to execute cmd \'%s\' (%s)'
                            %(' '.join(cmdl), str(e)))
        finally:
            utils.disable_subprocess_signal_forwarding(signal.SIGINT)
        if cmd_returncode != 0:
            raise Exception('failed to execute cmd \'%s\''
                 %' '.join(cmdl) + '(' + cmdout.strip('\n ') + ')')
        return cmdout

    def exec_command(self, cmd, cmdenv=None):
        """ Executes command given as string in the argument cmd """

        return self.exec_commandl(shlex.split(cmd), cmdenv)

    def exec_command_talk_stdin(self, cmd, stdinbuf):
        """ Executes command and writes to stdin of the process """
        cmd_returncode = 0
        cmdout = ''
        try:
            self.logger.info('executing %s [%s]' %(cmd, stdinbuf))
            if ifupdownflags.flags.DRYRUN:
                return cmdout
            ch = subprocess.Popen(shlex.split(cmd),
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    shell=False,
                    stderr=subprocess.STDOUT,
                    close_fds=True)
            utils.enable_subprocess_signal_forwarding(ch, signal.SIGINT)
            cmdout = ch.communicate(input=stdinbuf)[0]
            cmd_returncode = ch.wait()
        except OSError, e:
            raise Exception('failed to execute cmd \'%s\' (%s)'
                            %(cmd, str(e)))
        finally:
            utils.disable_subprocess_signal_forwarding(signal.SIGINT)
        if cmd_returncode != 0:
            raise Exception('failed to execute cmd \'%s [%s]\''
                %(cmd, stdinbuf) + '(' + cmdout.strip('\n ') + ')')
        return cmdout

    def subprocess_check_output(self, cmdl):
        self.logger.info('executing ' + ' '.join(cmdl))
        if ifupdownflags.flags.DRYRUN:
            return
        try:
            return subprocess.check_output(cmdl, stderr=subprocess.STDOUT)
        except Exception, e:
            raise Exception('failed to execute cmd \'%s\' (%s)'
                        %(' '.join(cmdl), e.output))

    def subprocess_check_call(self, cmdl):
        """ subprocess check_call implementation using popen
        
        Uses popen because it needs the close_fds argument
        """

        cmd_returncode = 0
        try:
            self.logger.info('executing ' + ' '.join(cmdl))
            if ifupdownflags.flags.DRYRUN:
                return
            ch = subprocess.Popen(cmdl,
                    stdout=None,
                    shell=False,
                    stderr=None,
                    close_fds=True)
            utils.enable_subprocess_signal_forwarding(ch, signal.SIGINT)
            cmd_returncode = ch.wait()
        except Exception, e:
            raise Exception('failed to execute cmd \'%s\' (%s)'
                            %(' '.join(cmdl), str(e)))
        finally:
            utils.disable_subprocess_signal_forwarding(signal.SIGINT)
        if cmd_returncode != 0:
            raise Exception('failed to execute cmd \'%s\''
                 %' '.join(cmdl))
        return

    def write_file(self, filename, strexpr):
        try:
            self.logger.info('writing \'%s\'' %strexpr +
                ' to file %s' %filename)
            if ifupdownflags.flags.DRYRUN:
                return 0
            with open(filename, 'w') as f:
                f.write(strexpr)
        except IOError, e:
            self.logger.warn('error writing to file %s'
                %filename + '(' + str(e) + ')')
            return -1
        return 0

    def read_file(self, filename):
        try:
            self.logger.debug('reading \'%s\'' %filename)
            with open(filename, 'r') as f:
                return f.readlines()
        except:
            return None
        return None

    def read_file_oneline(self, filename):
        try:
            self.logger.debug('reading \'%s\'' %filename)
            with open(filename, 'r') as f:
                return f.readline().strip('\n')
        except:
            return None
        return None

    def sysctl_set(self, variable, value):
        self.exec_command('sysctl %s=' %variable + '%s' %value)

    def sysctl_get(self, variable):
        return self.exec_command('sysctl %s' %variable).split('=')[1].strip()
