#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifupdown --
#    exceptions
#

from ifupdown.log import log


class Error(Exception):
    """Base class for exceptions in ifupdown"""

    def log_error(self):
        log.error(self.message)

    def log_warning(self):
        log.warning(self.message)

    def log_info(self):
        log.info(self.message)

    def log_debug(self):
        log.debug(self.message)


class ArgvParseError(Error):
    """
        Exception coming from argv parsing
    """
    pass


class ifaceNotFoundError(Error):
    pass


class invalidValueError(Error):
    pass


class errorReadingStateError(Error):
    pass


class moduleNotSupported(Error):
    pass
