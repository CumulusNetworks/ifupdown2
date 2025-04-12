#!/usr/bin/env python3
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
# ifupdown2 - Network Manager
#

import os
import sys

sys.path.insert(0, "/root/ifupdown2/ifupdown2")
#sys.path.append("/usr/share/ifupdown2/")

try:
    from ifupdown2.lib.log import LogManager, root_logger
    from ifupdown2.lib.status import Status
except ModuleNotFoundError:
    from lib.log import LogManager, root_logger
    from lib.status import Status

# first thing first, setup the logging infra
LogManager.get_instance()

try:
    import ifupdown2.ifupdown.config as config

    from ifupdown2 import __version__

    config.__version__ = __version__

    from ifupdown2.lib.exceptions import ExitWithStatus, ExitWithStatusAndError

    from ifupdown2.ifupdown.client import Client
    from ifupdown2.ifupdown.exceptions import ArgvParseHelp, ArgvParseError
except ModuleNotFoundError:
    import ifupdown.config as config

    config.__version__ = __import__("__init__").__version__

    from lib.exceptions import ExitWithStatus, ExitWithStatusAndError

    from ifupdown.client import Client
    from ifupdown.exceptions import ArgvParseHelp, ArgvParseError


def daemon_mode():
    """ Check ifupdown2 config to see if we should start the client """
    try:
        with open(config.IFUPDOWN2_CONF_PATH) as f:
            return "use_daemon=yes" in f.read()
    except Exception:
        return False


def client():
    try:
        status = Client(sys.argv).run()
    except ExitWithStatusAndError as e:
        root_logger.error(e.message)
        status = e.status
    except ExitWithStatus as e:
        status = e.status
    return status


def stand_alone():
    from datetime import datetime
    start_time = datetime.now()

    if not sys.argv[0].endswith("query") and os.geteuid() != 0:
        sys.stderr.write('must be root to run this command\n')
        return 1
    try:
        from ifupdown2.ifupdown.main import Ifupdown2
        from ifupdown2.lib.nlcache import NetlinkListenerWithCache, NetlinkListenerWithCacheErrorNotInitialized
    except Exception:
        from ifupdown.main import Ifupdown2
        from lib.nlcache import NetlinkListenerWithCache, NetlinkListenerWithCacheErrorNotInitialized
    ifupdown2 = Ifupdown2(daemon=False, uid=os.geteuid())
    try:
        ifupdown2.parse_argv(sys.argv)
        LogManager.get_instance().start_standalone_logging(ifupdown2.args)
    except ArgvParseError as e:
        LogManager.get_instance().root_logger().error(str(e))
        return Status.Client.STATUS_ARGV_ERROR
    except ArgvParseHelp:
        # on --help parse_args raises SystemExit, we catch it and raise a
        # custom exception ArgvParseHelp to return 0
        return 0
    try:
        status = ifupdown2.main()
    finally:
        try:
            if NetlinkListenerWithCache.is_init():
                NetlinkListenerWithCache.get_instance().cleanup()
        except NetlinkListenerWithCacheErrorNotInitialized:
            status = Status.Client.STATUS_NLERROR

    LogManager.get_instance().write(f"exit status {status} in {datetime.now() - start_time}")

    if status != 0:
        LogManager.get_instance().report_error_to_systemd()

    return status


def main():
    try:
        if daemon_mode():
            return client()
        else:
            return stand_alone()
    except ArgvParseHelp:
        return Status.Client.STATUS_SUCCESS
    except KeyboardInterrupt:
        return Status.Client.STATUS_KEYBOARD_INTERRUPT
    except Exception as e:
        root_logger.exception("main: %s" % str(e))
        return Status.Client.STATUS_EXCEPTION_MAIN


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(Status.Client.STATUS_KEYBOARD_INTERRUPT)
