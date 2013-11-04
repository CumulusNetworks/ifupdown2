#!/usr/bin/python


class Error(Exception):
    """Base class for exceptions in ifupdown"""

    pass

class ifaceNotFoundError(Error):
    pass


class invalidValueError(Error):
    pass

class errorReadingStateError(Error):
    pass
