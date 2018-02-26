#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifupdownBase --
#    base object for various ifupdown objects
#

import logging
import re
import os
import traceback
from ifupdown.netlink import netlink

from iface import *
import ifupdownflags as ifupdownflags


class ifupdownBase(object):

    def __init__(self):
        modulename = self.__class__.__name__
        self.logger = logging.getLogger('ifupdown.' + modulename)

    def ignore_error(self, errmsg):
        if (ifupdownflags.flags.FORCE == True or re.search(r'exists', errmsg,
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
        return os.path.exists('/sys/class/net/%s' % ifacename)

    def link_up(self, ifacename):
        netlink.link_set_updown(ifacename, "up")

    def link_down(self, ifacename):
        netlink.link_set_updown(ifacename, "down")
