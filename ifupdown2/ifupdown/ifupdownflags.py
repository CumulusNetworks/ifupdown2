#!/usr/bin/env python3
#
# Copyright 2015-2017 Cumulus Networks, Inc. All rights reserved.
#
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

class ifupdownFlags():

	def __init__(self):
                self.ALL = False
                self.CLASS = False
                self.FORCE = False
                self.DRYRUN = False
                self.NOWAIT = False
                self.PERFMODE = False
                self.CACHE = False
                self.WITHDEFAULTS = False
                self.IGNORE_ERRORS = False

                # Flags
                self.CACHE_FLAGS = 0x0

flags = ifupdownFlags()


def reset():
    global flags
    flags = ifupdownFlags()
