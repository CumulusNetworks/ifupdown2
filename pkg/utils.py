#!/usr/bin/python


class utils():

    @classmethod
    def importName(cls, modulename, name):
        """ Import a named object """
        try:
            module = __import__(modulename, globals(), locals(), [name])
        except ImportError:
            return None
        return getattr(module, name)
