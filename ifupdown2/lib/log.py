# Copyright (C) 2016, 2017, 2018, 2019 Cumulus Networks, Inc. all rights reserved
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# https://www.gnu.org/licenses/gpl-2.0-standalone.html
#
# Author:
#       Julien Fortin, julien@cumulusnetworks.com
#

import os
import sys
import traceback

import logging
import logging.handlers

root_logger = logging.getLogger()


class LogManager:
    LOGGER_NAME = "ifupdown2"
    LOGGER_NAME_DAEMON = "ifupdown2d"

    DEFAULT_TCP_LOGGING_PORT = 42422
    DEFAULT_LOGGING_LEVEL_DAEMON = logging.INFO
    DEFAULT_LOGGING_LEVEL_NORMAL = logging.WARNING

    __instance = None

    @staticmethod
    def get_instance():
        if not LogManager.__instance:
            try:
                LogManager.__instance = LogManager()
            except Exception as e:
                sys.stderr.write("warning: ifupdown2.Log: %s\n" % str(e))
                traceback.print_exc()
        return LogManager.__instance

    def __init__(self):
        """
        Setup root logger and console handler (stderr). To enable daemon, client
        or standalone logging please call the proper function, see:
            "start_(daemon|client|standlone)_logging"
        """
        if LogManager.__instance:
            raise RuntimeError("Log: invalid access. Please use Log.getInstance()")
        else:
            LogManager.__instance = self

        self.__fmt = "%(levelname)s: %(message)s"

        self.__debug_fmt = "%(asctime)s: %(threadName)s: %(name)s: " \
                           "%(filename)s:%(lineno)d:%(funcName)s(): " \
                           "%(levelname)s: %(message)s"

        self.__root_logger = logging.getLogger()
        self.__root_logger.name = self.LOGGER_NAME

        self.__socket_handler = None
        self.__syslog_handler = None
        self.__console_handler = None

        self.daemon = None

        # by default we attach a console handler that logs on stderr
        # the daemon can manually remove this handler on startup
        self.__console_handler = logging.StreamHandler(sys.stderr)
        self.__console_handler.setFormatter(logging.Formatter(self.__fmt))
        self.__root_logger.addHandler(self.__console_handler)

        if os.path.exists("/dev/log"):
            try:
                self.__syslog_handler = logging.handlers.SysLogHandler(
                    address="/dev/log",
                    facility=logging.handlers.SysLogHandler.LOG_DAEMON
                )
                self.__syslog_handler.setFormatter(logging.Formatter(self.__fmt))
            except Exception as e:
                sys.stderr.write("warning: syslog: %s\n" % str(e))
                self.__syslog_handler = None

        logging.addLevelName(logging.CRITICAL, "critical")
        logging.addLevelName(logging.WARNING, "warning")
        logging.addLevelName(logging.ERROR, "error")
        logging.addLevelName(logging.DEBUG, "debug")
        logging.addLevelName(logging.INFO, "info")

    def set_level(self, default, error=False, warning=False, info=False, debug=False):
        """
        Set root handler logging level
        :param default:
        :param error:
        :param warning:
        :param info:
        :param debug:
        """
        if debug:
            log_level = logging.DEBUG
        elif info:
            log_level = logging.INFO
        elif warning:
            log_level = logging.WARNING
        elif error:
            log_level = logging.ERROR
        else:
            log_level = default

        for handler in self.__root_logger.handlers:
            handler.setLevel(log_level)
        self.__root_logger.setLevel(log_level)

    def enable_console(self):
        """ Add console handler to root logger """
        self.__root_logger.addHandler(self.__console_handler)

    def disable_console(self):
        """ Remove console handler from root logger """
        self.__root_logger.removeHandler(self.__console_handler)

    def enable_syslog(self):
        """ Add syslog handler to root logger """
        if self.__syslog_handler:
            self.__root_logger.addHandler(self.__syslog_handler)

    def disable_syslog(self):
        """ Remove syslog handler from root logger """
        if self.__syslog_handler:
            self.__root_logger.removeHandler(self.__syslog_handler)

    def close_log_stream(self):
        """ Close socket to disconnect client.
        We first have to perform this little hack: it seems like the socket is
        not opened until data (LogRecord) are transmitted. In our most basic use
        case (client sends "ifup -a") the daemon doesn't send back any LogRecord
        but we can't predict that in the client. The client is already in a
        blocking-select waiting for data on it's socket handler
        (StreamRequestHandler). For this special case we need to manually call
        "createSocket" to open the channel to the client so that we can properly
        close it. That way the client can exit cleanly.
        """
        self.__root_logger.removeHandler(self.__socket_handler)
        self.__socket_handler.acquire()
        self.__socket_handler.retryTime = None
        try:
            if not self.__socket_handler.sock:
                self.__socket_handler.createSocket()
        finally:
            self.__socket_handler.close()
            self.__socket_handler.release()

    def start_stream(self):
        self.__root_logger.addHandler(self.__socket_handler)

    def set_daemon_logging_level(self, args):
        self.set_level(self.DEFAULT_LOGGING_LEVEL_DAEMON, info=args.verbose, debug=args.debug)

    def set_request_logging_level(self, args):
        if not hasattr(args, "syslog") or not args.syslog:
            self.disable_syslog()
        else:
            self.__root_logger.removeHandler(self.__socket_handler)
        self.set_level(self.DEFAULT_LOGGING_LEVEL_NORMAL, info=args.verbose, debug=args.debug)

    def start_client_logging(self, args):
        """ Setup root logger name and client log level
        syslog is handled by the daemon directly
        """
        self.__root_logger.name = self.LOGGER_NAME

        if hasattr(args, "syslog") and args.syslog:
            self.enable_syslog()
            self.disable_console()

        self.set_level(self.DEFAULT_LOGGING_LEVEL_NORMAL, info=args.verbose, debug=args.debug)

    def start_standalone_logging(self, args):
        self.__root_logger.name = self.LOGGER_NAME

        if hasattr(args, "syslog") and args.syslog:
            self.enable_syslog()
            self.disable_console()

            self.__root_logger.removeHandler(self.__console_handler)

        self.set_level(self.DEFAULT_LOGGING_LEVEL_NORMAL, info=args.verbose, debug=args.debug)

    def start_daemon_logging(self, args):
        """
        Daemon mode initialize a socket handler to transmit logging to the
        client, we can also do syslog logging and/or console logging (probably
        just for debugging purpose)
        :param args:
        :return:
        """
        self.__root_logger.name = self.LOGGER_NAME_DAEMON
        self.daemon = True

        self.enable_syslog()

        # Create SocketHandler for daemon-client communication
        self.__socket_handler = logging.handlers.SocketHandler(
            "localhost",
            port=self.DEFAULT_TCP_LOGGING_PORT
        )
        self.__root_logger.addHandler(self.__socket_handler)

        if not args.console:
            self.disable_console()

        self.set_daemon_logging_level(args)

    def write(self, msg):
        root_logger.info(msg)
