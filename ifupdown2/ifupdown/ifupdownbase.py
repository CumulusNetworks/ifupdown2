#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifupdownBase --
#    base object for various ifupdown objects
#

import re
import os
import logging
import traceback

try:
    from ifupdown2.ifupdown.netlink import netlink

    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
except ImportError:
    from ifupdown.netlink import netlink

    import ifupdown.ifupdownflags as ifupdownflags


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
                traceback.print_exc()
            self.logger.warn(str)
        pass

    def log_error(self, str):
        if self.ignore_error(str) == False:
            raise Exception(str)
        else:
            pass

    def link_exists(self, ifacename):
        return os.path.exists('/sys/class/net/%s' %ifacename)

    def link_up(self, ifacename):
        netlink.link_set_updown(ifacename, "up")

    def link_down(self, ifacename):
        netlink.link_set_updown(ifacename, "down")
