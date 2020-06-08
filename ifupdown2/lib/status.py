# Copyright (C) 2019 Cumulus Networks, Inc. all rights reserved
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


class Status(object):
    """
    Defining client and daemon exit status to better identify
    client and daemon issue and exceptions.
    80 > unknown > 90 > client status > 100 > daemon status
    """

    class Client(object):
        STATUS_SUCCESS = 0
        STATUS_INIT = 91
        STATUS_COULD_NOT_CONNECT = 92
        STATUS_NO_PID = 93
        STATUS_EMPTY = 94
        STATUS_KEYBOARD_INTERRUPT = 95
        STATUS_NLERROR = 96
        STATUS_EXCEPTION_MAIN = 99

        STATUS_ARGV_ERROR = 90
        STATUS_ALREADY_RUNNING = 89

    class Daemon(object):
        STATUS_SUCCESS = 0
        STATUS_INIT = 101
        STATUS_UNKNOWN = 102
        STATUS_SOCKET_ERROR = 103
        STATUS_PROCESS_REQUEST = 104
        STATUS_KEYBOARD_INTERRUPT = 105
        STATUS_NLERROR = 106

        STATUS_REQUEST_PARSE_ERROR = 106
        STATUS_REQUEST_EXCEPTION = 107
        STATUS_REQUEST_BASE_EXCEPTION = 108
