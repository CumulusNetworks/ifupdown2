#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
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

class moduleNotSupported(Error):
    pass
