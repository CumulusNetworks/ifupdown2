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
import signal

from functools import partial

def signal_handler_f(ps, sig, frame):
    if ps:
        ps.send_signal(sig)
    if sig == signal.SIGINT:
        raise KeyboardInterrupt

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
        range_match = re.match("^([\w\.]+)\[([\d]+)-([\d]+)\]", name)
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

    @classmethod
    def check_ifname_size_invalid(cls, name=''):
        """ IFNAMSIZ in include/linux/if.h is 16 so we check this """
        IFNAMSIZ = 16
        if len(name) > IFNAMSIZ - 1:
            return True
        else:
            return False

    @classmethod
    def enable_subprocess_signal_forwarding(cls, ps, sig):
        signal.signal(sig, partial(signal_handler_f, ps))

    @classmethod
    def disable_subprocess_signal_forwarding(cls, sig):
        signal.signal(sig, signal.SIG_DFL)

