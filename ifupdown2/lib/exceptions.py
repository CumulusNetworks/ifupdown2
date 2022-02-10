# Copyright (C) 2017, 2018, 2019 Cumulus Networks, Inc. all rights reserved
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
# ifupdown2 custom exceptions
#


class Ifupdown2Exception(Exception):
    pass


class ExitWithStatus(Ifupdown2Exception):

    def __init__(self, status):
        Ifupdown2Exception.__init__(self)
        self.status = status

    def get_status(self):
        return self.status


class ExitWithStatusAndError(ExitWithStatus):
    def __init__(self, status, message):
        ExitWithStatus.__init__(self, status)
        self.message = message


class RetryCMD(Ifupdown2Exception):
    def __init__(self, cmd):
        Ifupdown2Exception.__init__(self)
        self.cmd = cmd
