#!/usr/bin/python
#
# Copyright 2013.  Cumulus Networks, Inc.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifupdown --
#    exceptions
#

class Error(Exception):
    """Base class for exceptions in ifupdown"""

    pass

class ifaceNotFoundError(Error):
    pass


class invalidValueError(Error):
    pass

class errorReadingStateError(Error):
    pass
