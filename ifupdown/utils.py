#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# utils --
#    helper class
#
import os
import fcntl
import re

class utils():

    @classmethod
    def importName(cls, modulename, name):
        """ Import a named object """
        try:
            module = __import__(modulename, globals(), locals(), [name])
        except ImportError:
            return None
        return getattr(module, name)

    @classmethod
    def lockFile(cls, lockfile):
        try:
            fp = os.open(lockfile, os.O_CREAT | os.O_TRUNC | os.O_WRONLY)
            fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            return False
        return True

    @classmethod
    def parse_iface_range(cls, name):
        range_match = re.match("^([\w]+)-\[([\d]+)-([\d]+)\]", name)
        if range_match:
            range_groups = range_match.groups()
            if range_groups[1] and range_groups[2]:
                return (range_groups[0], int(range_groups[1], 10),
                        int(range_groups[2], 10))
        return None

    @classmethod
    def expand_iface_range(cls, name):
        ifacenames = []
        iface_range = cls.parse_iface_range(name)
        if iface_range:
            for i in range(iface_range[1], iface_range[2]):
                ifacenames.append('%s-%d' %(iface_range[0], i))
        return ifacenames


