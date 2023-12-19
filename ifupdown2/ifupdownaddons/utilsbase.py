#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
import time
import errno
import logging

try:
    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdownaddons.cache import *

    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
except (ImportError, ModuleNotFoundError):
    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdownaddons.cache import *

    import ifupdown.ifupdownflags as ifupdownflags


def profile(func):
    def wrap(*args, **kwargs):
        started_at = time.time()
        result = func(*args, **kwargs)
        print(str(func))
        print((time.time() - started_at))
        return result
    return wrap

class utilsBase(object):
    """ Base class for ifupdown addon utilities """

    def __init__(self, *args, **kargs):
        modulename = self.__class__.__name__
        self.logger = logging.getLogger('ifupdown.' + modulename)

    def pid_exists(self, pidfilename, progname):
        if os.path.exists(pidfilename):
            pid = self.read_file_oneline(pidfilename)
            try:
                return os.readlink(f"/proc/{pid}/exe").endswith(progname)
            except OSError as e:
                try:
                    if e.errno == errno.EACCES:
                        return os.path.exists(f"/proc/{pid}")
                except Exception:
                    return False
            except Exception:
                return False
        return False

    def write_file(self, filename, strexpr):
        try:
            self.logger.info('writing \'%s\'' %strexpr +
                ' to file %s' %filename)
            if ifupdownflags.flags.DRYRUN:
                return 0
            with open(filename, 'w') as f:
                f.write(strexpr)
        except IOError as e:
            self.logger.warning('error writing to file %s'
                %filename + '(' + str(e) + ')')
            return -1
        return 0

    def read_file(self, filename):
        try:
            self.logger.debug('reading \'%s\'' %filename)
            with open(filename, 'r') as f:
                return f.readlines()
        except Exception:
            return None
        return None

    def read_file_oneline(self, filename):
        try:
            self.logger.debug('reading \'%s\'' %filename)
            with open(filename, 'r') as f:
                return f.readline().strip('\n')
        except Exception:
            return None
        return None

    def sysctl_set(self, variable, value):
        utils.exec_command('%s %s=%s' %
                           (utils.sysctl_cmd, variable, value))

    def sysctl_get(self, variable):
        return utils.exec_command('%s %s' %
                                  (utils.sysctl_cmd,
                                   variable)).split('=')[1].strip()
