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
# sysfs -- contains all sysfs related operation
#

try:
    from ifupdown2.lib.io import IO
    from ifupdown2.lib.base_objects import Cache
except ImportError:
    from lib.io import IO
    from lib.base_objects import Cache


class Sysfs(IO, Cache):
    def __init__(self):
        IO.__init__(self)
        Cache.__init__(self)
