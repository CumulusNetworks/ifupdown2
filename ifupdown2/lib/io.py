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
# io -- all io (file) handlers
#

import json
import struct
import socket
import select

try:
    from ifupdown2.lib.base_objects import BaseObject
except ImportError:
    from lib.base_objects import BaseObject


class IOException(Exception):
    pass


class IO(BaseObject):
    def __init__(self):
        BaseObject.__init__(self)

    def write_to_file(self, path, string):
        try:
            self.logger.info("writing \"%s\" to file %s" % (string, path))
            with open(path, "w") as f:
                f.write(string)
            return True
        except IOError as e:
            self.logger.warning("error while writing to file %s: %s" % (path, str(e)))
            return False

    def write_to_file_dry_run(self, path, string):
        self.log_info_dry_run("writing \"%s\" to file %s" % (string, path))
        return True

    def read_file_oneline(self, path):
        try:
            self.logger.info("reading '%s'" % path)
            with open(path, "r") as f:
                return f.readline().strip("\n")
        except Exception:
            return None

    def read_file_oneline_dry_run(self, path):
        self.log_info_dry_run("reading \"%s\"" % path)
        return None

    def read_file(self, path):
        """ read file and return lines from the file """
        try:
            self.logger.info("reading '%s'" % path)
            with open(path, "r") as f:
                return f.readlines()
        except Exception:
            return None


class SocketIO(object):
    """
    Helper class to provide common TX/RX methods for socket
    communication to both client and daemon.
    """

    @staticmethod
    def tx_data(_socket, data):
        """
        We don't send raw data over the socket, we pack it with the length
        (first 4 bytes) then with the data. That way the the transfer is more
        reliable
        """
        ready = select.select([], [_socket], [])
        if ready and ready[1] and ready[1][0] == _socket:
            frmt = "=%ds" % len(data)
            packed_msg = struct.pack(frmt, data)
            packed_hdr = struct.pack("=I", len(packed_msg))
            _socket.sendall(packed_hdr + packed_msg)

    @staticmethod
    def rx_json_packet(_socket):
        """
        Reading data from socket. Unpacking the packets sent by "tx_data"
        first 4 bytes are the length of the following data. The data should
        be in json format
        """
        ready = select.select([_socket], [], [])

        if ready and ready[0] and ready[0][0] == _socket:

            header_data = _socket.recv(4)

            if not header_data:
                raise IOException("rx_json_packet: socket closed")
            if len(header_data) < 4:
                raise IOException("rx_json_packet: invalid data received")

            data_len = struct.unpack("=I", header_data)[0]
            data = _socket.recv(data_len)

            while len(data) < data_len:
                data = data + _socket.recv(data_len - len(data))

            return json.loads(data)

        return None

    def get_socket_peer_cred(self, _socket):
        """
        Returns tuple of (pid, uid, gid) of connected AF_UNIX stream socket
        :param _socket:
        :return:
        """
        return struct.unpack("3i", _socket.getsockopt(socket.SOL_SOCKET, self.SO_PEERCRED, struct.calcsize("3i")))
