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
# io -- all io (file) handlers
#

try:
    from ifupdown2.lib.base_objects import BaseObject
except ImportError:
    from lib.base_objects import BaseObject


class IO(BaseObject):
    def __init__(self):
        BaseObject.__init__(self)

    def write_to_file(self, path, string):
        try:
            self.logger.info("writing \"%s\" to file %s" % (string, path))
            with open(path, "w") as f:
                f.write(string)
            return True
        except IOError, e:
            self.logger.warn("error while writing to file %s: %s" % (path, str(e)))
            return False

    def write_to_file_dry_run(self, path, string):
        self.logger.info("dryrun: writing \"%s\" to file %s" % (string, path))
        return True

    def read_file_oneline(self, path):
        try:
            self.logger.info("reading '%s'" % path)
            with open(path, "r") as f:
                return f.readline().strip("\n")
        except:
            return None

    def read_file_oneline_dry_run(self, path):
        self.logger.info("dryrun: reading \"%s\"" % path)
        return None

    def read_file(self, path):
        """ read file and return lines from the file """
        try:
            self.logger.info("reading '%s'" % path)
            with open(path, "r") as f:
                return f.readlines()
        except:
            return None
