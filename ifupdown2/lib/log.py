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
import shutil
import traceback

import logging
import logging.handlers

from datetime import date, datetime
from systemd.journal import JournalHandler


try:
    from ifupdown2.ifupdown.utils import utils
except ImportError:
    from ifupdown.utils import utils


root_logger = logging.getLogger()


class LogManager:
    LOGGER_NAME = "ifupdown2"
    LOGGER_NAME_DAEMON = "ifupdown2d"

    LOGGING_DIRECTORY = "/var/log/ifupdown2"
    LOGGING_DIRECTORY_PREFIX = "network_config_ifupdown2_"
    LOGGING_DIRECTORY_LIMIT = 42

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

        self.new_dir_path = None

        self.__debug_handler = None
        self.__socket_handler = None
        self.__syslog_handler = None
        self.__console_handler = None
        self.__journald_handler = None

        self.daemon = None

        # by default we attach a console handler that logs on stderr
        # the daemon can manually remove this handler on startup
        self.__console_handler = logging.StreamHandler(sys.stderr)
        self.__console_handler.setFormatter(logging.Formatter(self.__fmt))
        self.__console_handler.setLevel(logging.INFO)

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

        try:
            self.__init_debug_logging()
        except Exception as e:
            self.__root_logger.debug("couldn't initialize persistent debug logging: %s" % str(e))

    def __get_enable_persistent_debug_logging(self):
        # ifupdownconfig.config is not yet initialized so we need to cat and grep ifupdown2.conf
        # by default we limit logging to LOGGING_DIRECTORY_LIMIT number of files
        # the user can specify a different amount in /etc/network/ifupdown2/ifupdown2.conf
        # or just yes/no to enable/disable the feature.
        try:
            user_config_limit_str = (
                utils.exec_user_command(
                    "cat /etc/network/ifupdown2/ifupdown2.conf | grep enable_persistent_debug_logging") or ""
            ).strip().split("=", 1)[1]

            try:
                # get the integer amount
                return int(user_config_limit_str)
            except ValueError:
                # the user didn't specify an integer but a boolean
                # if the input is not recognized we are disabling the feature
                user_config_limit = {
                    True: self.LOGGING_DIRECTORY_LIMIT,
                    False: 0,
                }.get(utils.get_boolean_from_string(user_config_limit_str))

        except Exception:
            user_config_limit = self.LOGGING_DIRECTORY_LIMIT

        return user_config_limit

    def __init_debug_logging(self):
        # check if enable_persistent_debug_logging is enabled
        user_config_limit = self.__get_enable_persistent_debug_logging()

        # disable debug logging for ifquery
        for s in sys.argv:
            if "ifquery" in s:
                return

        if not user_config_limit:
            # user has disabled the feature
            return

        # create logging directory
        self.__create_dir(self.LOGGING_DIRECTORY)

        # list all ifupdown2 logging directories
        ifupdown2_log_dirs = [
            directory[len(self.LOGGING_DIRECTORY_PREFIX):].split("_", 1) for directory in os.listdir(self.LOGGING_DIRECTORY) if directory.startswith(self.LOGGING_DIRECTORY_PREFIX)
        ]
        ifupdown2_log_dirs.sort(key=lambda x: int(x[0]))

        # get the last log id
        if ifupdown2_log_dirs:
            last_id = int(ifupdown2_log_dirs[-1][0])
        else:
            last_id = 0

        # create new log directory to store eni and debug logs
        # format: network_config_ifupdown2_1_Aug-17-2021_23:42:00.000000
        self.new_dir_path = "%s/%s%s_%s" % (
            self.LOGGING_DIRECTORY,
            self.LOGGING_DIRECTORY_PREFIX,
            last_id + 1,
            "%s_%s" % (date.today().strftime("%b-%d-%Y"), str(datetime.now()).split(" ", 1)[1])
        )
        self.__create_dir(self.new_dir_path)

        # start logging in the new directory
        self.__debug_handler = logging.FileHandler("%s/ifupdown2.debug.log" % self.new_dir_path, mode="w+")
        self.__debug_handler.setFormatter(logging.Formatter(self.__debug_fmt))
        self.__debug_handler.setLevel(logging.DEBUG)

        self.__root_logger.addHandler(self.__debug_handler)
        self.__root_logger.setLevel(logging.DEBUG)

        self.__root_logger.debug("persistent debugging is initialized")
        self.__root_logger.debug("argv: %s" % sys.argv)

        # cp ENI and ENI.d in the log directory
        shutil.copy2("/etc/network/interfaces", self.new_dir_path)
        try:
            shutil.copytree("/etc/network/interfaces.d/", "%s/interfaces.d" % self.new_dir_path)
        except Exception:
            pass

        # remove extra directory logs if we are reaching the 'user_config_limit'
        len_ifupdown2_log_dirs = len(ifupdown2_log_dirs)
        if len_ifupdown2_log_dirs > user_config_limit:
            for index in range(0, len_ifupdown2_log_dirs - user_config_limit):
                try:
                    directory_to_remove = "%s/%s%s_%s" % (self.LOGGING_DIRECTORY, self.LOGGING_DIRECTORY_PREFIX, ifupdown2_log_dirs[index][0], ifupdown2_log_dirs[index][1])
                    shutil.rmtree(directory_to_remove, ignore_errors=True)
                except Exception:
                    pass

    @staticmethod
    def __create_dir(path):
        if not os.path.isdir(path):
            os.mkdir(path)

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
            if handler == self.__debug_handler:
                continue
            handler.setLevel(log_level)

        # make sure that the root logger has the lowest logging level possible
        # otherwise some messages might not go through
        if self.__root_logger.level > log_level:
            self.__root_logger.setLevel(log_level)

    def enable_console(self):
        """ Add console handler to root logger """
        self.__root_logger.addHandler(self.__console_handler)

    def disable_console(self):
        """ Remove console handler from root logger """
        self.__root_logger.removeHandler(self.__console_handler)

    def enable_systemd(self):
        """ Add journalctl handler to root logger """
        self.__journald_handler = JournalHandler()
        self.__journald_handler.setFormatter(logging.Formatter(self.__fmt))
        self.__root_logger.addHandler(self.__journald_handler)

    def enable_syslog(self):
        """ Add syslog handler to root logger """
        if self.__syslog_handler and self.__syslog_handler not in self.__root_logger.handlers:
            self.__root_logger.addHandler(self.__syslog_handler)

    def disable_syslog(self):
        """ Remove syslog handler from root logger """
        if self.__syslog_handler:
            self.__root_logger.removeHandler(self.__syslog_handler)

    def is_syslog_enabled(self):
        return self.__syslog_handler in self.__root_logger.handlers

    def get_syslog_log_level(self):
        return self.__syslog_handler.level if self.__syslog_handler else None

    def set_level_syslog(self, level):
        if self.__syslog_handler:
            self.__syslog_handler.setLevel(level)

            if self.__root_logger.level > level:
                self.__root_logger.setLevel(level)

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

        if hasattr(args, "systemd") and args.systemd:
            self.enable_systemd()

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

    def root_logger(self):
        return self.__root_logger

    def report_error_to_systemd(self):
        if self.__journald_handler:
            self.__journald_handler.setFormatter(logging.Formatter("%(message)s"))
            self.__root_logger.error(">>> Full logs available in: %s <<<" % self.new_dir_path)
