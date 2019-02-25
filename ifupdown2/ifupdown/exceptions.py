# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Authors:
#           Roopa Prabhu, roopa@cumulusnetworks.com
#           Julien Fortin, julien@cumulusnetworks.com
#
# ifupdown --
#    exceptions
#

import logging

log = logging.getLogger()


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


class ArgvParseHelp(Error):
    """
    When ifupdown2 is called with --help argparse raise SystemExit
    we need to catch this to properly print the help and exit 0 not 1
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


class ReservedVlanException(Error):
    pass
