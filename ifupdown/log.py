#!/usr/bin/env python
#
# Copyright 2016-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Julien Fortin, julien@cumulusnetworks.com
#

try:
    import sys
    import json
    import struct
    import select
    import logging
    import logging.handlers

    from cStringIO import StringIO
except ImportError, e:
    raise ImportError('%s - required module not found' % str(e))


class Log:
    LOGGER_NAME = sys.argv[0].split('/')[-1]

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

        self.stdout_buffer = None
        self.stderr_buffer = None

        self.root = logging.getLogger()
        self.root.name = Log.LOGGER_NAME
        self.root.setLevel(logging.INFO)

        self.root_info = self.root.info
        self.root_debug = self.root.debug
        self.root_error = self.root.error
        self.root_warning = self.root.warning
        self.root_critical = self.root.critical

        self.root.info = self.info
        self.root.debug = self.debug
        self.root.error = self.error
        self.root.warning = self.warning
        self.root.critical = self.critical

        logging.addLevelName(logging.CRITICAL, 'critical')
        logging.addLevelName(logging.WARNING, 'warning')
        logging.addLevelName(logging.ERROR, 'error')
        logging.addLevelName(logging.DEBUG, 'debug')
        logging.addLevelName(logging.INFO, 'info')

        self.syslog = True
        self.socket = None

        # syslog
        facility = logging.handlers.SysLogHandler.LOG_DAEMON
        address = '/dev/log'
        format = '%(name)s: %(levelname)s: %(message)s'

        self.syslog_handler = logging.handlers.SysLogHandler(address=address, facility=facility)
        self.syslog_handler.setFormatter(logging.Formatter(format))

        # console
        format = '%(levelname)s: %(message)s'
        self.console_handler = logging.StreamHandler(sys.stderr)
        self.console_handler.setFormatter(logging.Formatter(format))

        if self.LOGGER_NAME[-1] == 'd':
            self.update_current_logger(syslog=True, verbose=True, debug=False)
        else:
            self.update_current_logger(syslog=False, verbose=False, debug=False)

    def update_current_logger(self, syslog, verbose, debug):
        self.syslog = syslog
        self.root.setLevel(self.get_log_level(verbose=verbose, debug=debug))
        self.root.handlers = [self.syslog_handler if self.syslog else self.console_handler]
        self.flush()

    def flush(self):
        if self.socket:
            result = dict()
            stdout = self._flush_buffer('stdout', self.stdout_buffer, result)
            stderr = self._flush_buffer('stderr', self.stderr_buffer, result)
            if stdout or stderr:
                try:
                    self.tx_data(json.dumps(result))
                    self.redirect_stdouput()
                except select.error as e:
                    # haven't seen the case yet
                    self.socket = None
                    self.update_current_logger(syslog=True, verbose=True)
                    self.critical(str(e))
                    exit(84)
        self.console_handler.flush()
        self.syslog_handler.flush()

    def tx_data(self, data, socket=None):
        socket_obj = socket if socket else self.socket
        ready = select.select([], [socket_obj], [])
        if ready and ready[1] and ready[1][0] == socket_obj:
            frmt = "=%ds" % len(data)
            packed_msg = struct.pack(frmt, data)
            packed_hdr = struct.pack('=I', len(packed_msg))
            socket_obj.sendall(packed_hdr)
            socket_obj.sendall(packed_msg)

    def set_socket(self, socket):
        self.socket = socket
        self.redirect_stdouput()

    def redirect_stdouput(self):
        self.stdout_buffer = sys.stdout = StringIO()
        self.stderr_buffer = self.console_handler.stream = sys.stderr = StringIO()

    def error(self, msg, *args, **kwargs):
        self.root_error(msg, *args, **kwargs)
        self.flush()

    def critical(self, msg, *args, **kwargs):
        self.root_critical(msg, *args, **kwargs)
        self.flush()

    def warning(self, msg, *args, **kwargs):
        self.root_warning(msg, *args, **kwargs)
        self.flush()

    def info(self, msg, *args, **kwargs):
        self.root_info(msg, *args, **kwargs)
        self.flush()

    def debug(self, msg, *args, **kwargs):
        self.root_debug(msg, *args, **kwargs)
        self.flush()

    def get_current_log_level(self):
        return self.root.level

    def is_syslog(self): return self.syslog

    @staticmethod
    def get_log_level(verbose=False, debug=False):
        log_level = logging.WARNING
        if debug:
            log_level = logging.DEBUG
        elif verbose:
            log_level = logging.INFO
        return log_level

    @staticmethod
    def _flush_buffer(stream, buff, dictionary):
        if buff:
            data = buff.getvalue()
            if data:
                dictionary[stream] = data
                return True


log = Log()


"""

#logging.basicConfig( format="%(filename)s: %(username)s says '%(message)s' in %(funcname)s" )

Logger.debug(msg, *args, **kwargs)
Logs a message with level DEBUG on this logger. The msg is the message format string, and the args are the arguments which are merged into msg using the string formatting operator. (Note that this means that you can use keywords in the format string, together with a single dictionary argument.)

There are two keyword arguments in kwargs which are inspected: exc_info which, if it does not evaluate as false, causes exception information to be added to the logging message. If an exception tuple (in the format returned by sys.exc_info()) is provided, it is used; otherwise, sys.exc_info() is called to get the exception information.

"""

"""
USE FILTER TO IGNORE "EXITS" MESSAGES
Now that you know the basic plot, let me introduce one more character - the Filter.
Filter as the name suggests, allows you to filter a message before you log it. Yes, messages are filtered based on the level setting, but adding a Filter gives you more fine grained control of messages you log.
Both Loggers and Handlers can have multiple Filters. You can add Filters using addFilter and removeFilter methods.
When a Logger/Handler receives a message, it consults all of its filters. If the filter(record) method on any of the Filters attached returns False (or 0) the message is dropped.
The official documentation, though detailed, is actually pretty confusing about the role of Filters. This is a pity; because Filters can be handy when you want to drop a message based on a regular expression, error code, contextual information and pretty much anything else. The default Filter is pretty much useless (and the doc string is very confusing too). Just inherit from the default filter and override the filter method according to what you want to filter out. (Be sure to download the source for logging module and check out the unit tests which have some good examples. See the references at the end of this post.)"""
