# Copyright (C) 2017, 2018 Cumulus Networks, Inc. all rights reserved
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
# base_objects -- Base classes used by higher level classes
#

import os
import logging

try:
    from ifupdown2.lib.dry_run import DryRun
    from ifupdown2.ifupdown.utils import utils
except ImportError:
    from lib.dry_run import DryRun
    from ifupdown.utils import utils


class BaseObject(DryRun):
    """
    BaseObject should be the parent of any ifupdown2 object that wishes to
    implement any "dry run" specific code and have a default logger.
    More classes can inherit BaseObject and add features like Addon, FileIO or Sysfs...
    """

    def __init__(self):
        DryRun.__init__(self)
        self.logger = logging.getLogger("ifupdown2.%s" % self.__class__.__name__)


def _import_NetlinkListenerWithCache():
    try:
        from ifupdown2.lib.nlcache import NetlinkListenerWithCache
    except ImportError:
        from lib.nlcache import NetlinkListenerWithCache
    return NetlinkListenerWithCache


class Cache(BaseObject):
    def __init__(self):
        BaseObject.__init__(self)
        self.cache = _import_NetlinkListenerWithCache().get_instance().cache


class Netlink(BaseObject):
    def __init__(self):
        BaseObject.__init__(self)
        self.netlink = _import_NetlinkListenerWithCache().get_instance()


class Requirements(BaseObject):
    bridge_utils_is_installed = os.path.exists(utils.brctl_cmd)
