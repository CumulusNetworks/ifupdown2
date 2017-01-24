#!/usr/bin/env python
#
# Copyright 2016 Cumulus Networks, Inc. All rights reserved.
# Author: Julien Fortin, julien@cumulusnetworks.com
#
#

import sys
import logging
import logging.handlers

from cStringIO import StringIO


class Log:
    LOGGER_NAME = 'ifupdown2d'

    def __init__(self):
        """
            - On start the daemon will log on syslog.
            - For each client commands we might need to adjust the target
            (stderr/stdout):
                if -v --verbose or -d --debug are provided we override
                sys.stdout and sys.stderr with string buffers to be able to send
                back the content of these buffer on the UNIX socket back to the
                client.
                if -l or --syslog we make sure to use syslog.
        """
        self.logger = None

        self.stdout_buffer = None
        self.stderr_buffer = None

        self.root_logger = logging.getLogger()
        self.log_level = Log.get_log_level(args=None, verbose=True)

        facility = logging.handlers.SysLogHandler.LOG_DAEMON
        self.syslog_handler = logging.handlers.SysLogHandler(address='/dev/log',
                                                             facility=facility)

        logging.addLevelName(logging.ERROR, 'error')
        logging.addLevelName(logging.WARNING, 'warning')
        logging.addLevelName(logging.DEBUG, 'debug')
        logging.addLevelName(logging.INFO, 'info')

        format = '%(name)s: %(levelname)s: %(message)s'
        self.syslog_handler.setFormatter(logging.Formatter(format))
        self.root_logger.addHandler(self.syslog_handler)
        self.root_logger.setLevel(self.log_level)

        self.logger = logging.getLogger(Log.LOGGER_NAME)
        self.logging_syslog = True

    @staticmethod
    def get_log_level(args=None, verbose=True):
        if not args and verbose:
            return logging.INFO
        log_level = logging.WARNING
        if args.debug:
            log_level = logging.DEBUG
        elif args.verbose:
            log_level = logging.INFO
        return log_level

    @staticmethod
    def request_syslog(args=None, syslog=True):
        return args.syslog if args else syslog

    def update_logger(self, args=None, syslog=True, verbose=True):
        """
            Check if we need to update the current logger+level (syslog or std)
        """
        self.log_level = Log.get_log_level(args=args, verbose=verbose)
        request_syslog = self.request_syslog(args=args, syslog=syslog)

        if self.logging_syslog and not request_syslog:
            # set regular logger
            self.logging_syslog = False
            self.flush()

        elif not self.logging_syslog and request_syslog:
            # set syslog logger
            self.root_logger.addHandler(self.syslog_handler)
            self.logging_syslog = True

            self.stdout_buffer = None
            self.stderr_buffer = None

            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

        elif self.logging_syslog:
            self.root_logger.setLevel(self.log_level)

        self.logger.setLevel(self.log_level)

    def set_basic_config(self):
        logging.basicConfig(level=self.log_level,
                            format='%(levelname)s: %(message)s')

    def flush(self):
        """
            We need to flush the buffers between each command execution:

            logging is using stderr, we previously overrided sys.stderr with a
            StringIO buffer to be able to redirect the output of the process to
            the UNIX socket.
            For some reasons logging is not using sys.stderr direct, it must be
            storing a copy of the object in sys.stderr because simply resetting
            the buffer in sys.stderr doesn't work.

            The workaround is to remove all existing handlers and restart from
            scratch with:
                logging.basicConfig

        """
        [logging.root.removeHandler(handler) for handler in logging.root.handlers[:]]
        [self.logger.removeHandler(handler) for handler in self.logger.handlers[:]]

        self.stderr_buffer = sys.stderr = StringIO()
        self.stdout_buffer = sys.stdout = StringIO()
        self.set_basic_config()

        if self.logging_syslog:
            self.root_logger.addHandler(self.syslog_handler)

    def info(self, str):
        self.logger.info(str)

    def debug(self, str):
        self.logger.debug(str)

    def warning(self, str):
        self.logger.warning(str)

    def error(self, str):
        self.logger.error(str)

    def get_stdout_buffer(self):
        return self.stdout_buffer.getvalue() if self.stdout_buffer else ''

    def get_stderr_buffer(self):
        return self.stderr_buffer.getvalue() if self.stderr_buffer else ''

    def syslog_mode(self):
        return self.logging_syslog


log = Log()
