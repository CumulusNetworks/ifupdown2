#!/usr/bin/python

import os
import fcntl

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


