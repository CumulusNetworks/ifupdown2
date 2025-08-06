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
# ifupdown2 client-side
#

import struct
import pickle

import socketserver

import logging
import logging.handlers

import os
import re
import sys
import json
import socket
import signal

try:
    from ifupdown2.lib.io import SocketIO
    from ifupdown2.lib.status import Status
    from ifupdown2.lib.log import LogManager, root_logger
    from ifupdown2.lib.exceptions import ExitWithStatus, ExitWithStatusAndError

    from ifupdown2.ifupdown.argv import Parse
except ImportError:
    from lib.status import Status
    from lib.io import SocketIO
    from lib.log import LogManager, root_logger
    from lib.exceptions import ExitWithStatus, ExitWithStatusAndError

    from ifupdown.argv import Parse


class LogRecordStreamHandler(socketserver.StreamRequestHandler):
    """
    Handler for a streaming logging request.
    This basically logs the record using whatever logging policy is configured
    locally.
    """

    def handle(self):
        """
        Handle multiple requests - each expected to be a 4-byte length,
        followed by the LogRecord in pickle format.
        """
        while True:
            chunk = self.connection.recv(4)
            if len(chunk) < 4:
                break
            slen = struct.unpack(">L", chunk)[0]
            chunk = self.connection.recv(slen)

            while len(chunk) < slen:
                chunk = chunk + self.connection.recv(slen - len(chunk))

            record = logging.makeLogRecord(pickle.loads(chunk))
            logging.getLogger(record.name).handle(record)


class LogRecordSocketReceiver(socketserver.TCPServer):
    """
    Simple TCP socket-based logging receiver. In ifupdown2d context, the running
    daemon is the "sender" and the client is the "receiver". The TCPServer is
    setup on the client/receiver side, the daemon will connect to the server to
    transmit and stream LogRecord to a socket.
    """
    allow_reuse_address = True

    def __init__(
            self,
            host="localhost",
            handler=LogRecordStreamHandler,
            port=LogManager.DEFAULT_TCP_LOGGING_PORT
    ):
        socketserver.TCPServer.__init__(self, (host, port), handler)


class ClientException(Exception):
    pass


class Client(SocketIO):
    def __init__(self, argv):
        SocketIO.__init__(self)

        # we setup our log receiver which reads LogRecord from a socket
        # thus handing the logging-handling to the logging module and it's
        # dedicated classes.
        self.socket_receiver = LogRecordSocketReceiver()

        self.stdin = None
        self.argv = argv

        # First we need to set the correct log level for the client.
        # Unfortunately the only reliable way to do this is to use our main
        # argument parser. We can't simply have a parse to catch -v and -d, a
        # simple command like "ifup -av" wouldn't be recognized...
        # Ideally it would be great to be able to send the Namespace returned by
        # parse_args, and send it on the socket in pickle format. Unfortunately
        # this might be a serious security issue. It needs to be studied and
        # evaluated a bit more, that way we would save time and resources only
        # parsing argv once.
        args_parse = Parse(argv)
        args_parse.validate()
        # store the args namespace to send it to the daemon, we don't want
        # the daemon to spend time to parsing argv again...
        self.args = args_parse.get_args()

        LogManager.get_instance().start_client_logging(self.args)

        root_logger.info("starting ifupdown2 client...")

        self.uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.uds.connect("/var/run/ifupdown2d/uds")
        except socket.error:
            self.__shutdown()
            sys.stderr.write("""
    ERROR: %s could not connect to ifupdown2 daemon

    Try starting ifupdown2 daemon with:
    sudo systemctl start ifupdown2

    To configure ifupdown2d to start when the box boots:
    sudo systemctl enable ifupdown2\n\n""" % argv[0])
            raise ExitWithStatus(status=Status.Client.STATUS_COULD_NOT_CONNECT)

        signal.signal(signal.SIGINT, self.__signal_handler)
        signal.signal(signal.SIGTERM, self.__signal_handler)
        signal.signal(signal.SIGQUIT, self.__signal_handler)

        try:
            self.SO_PEERCRED = socket.SO_PEERCRED
        except AttributeError:
            # powerpc is the only non-generic we care about. alpha, mips,
            # sparc, and parisc also have non-generic values.
            machine = os.uname()[4]
            if re.search(r"^(ppc|powerpc)", machine):
                self.SO_PASSCRED = 20
                self.SO_PEERCRED = 21
            else:
                self.SO_PASSCRED = 16
                self.SO_PEERCRED = 17
        try:
            self.uds.setsockopt(socket.SOL_SOCKET, self.SO_PASSCRED, 1)
        except Exception as e:
            self.__shutdown()
            raise ClientException("setsockopt: %s" % str(e))

        self.daemon_pid, _, _ = self.get_socket_peer_cred(self.uds)

        if self.daemon_pid < 0:
            self.__shutdown()
            raise ExitWithStatusAndError(
                status=Status.Client.STATUS_NO_PID,
                message="could not get ifupdown2 daemon PID"
            )

        root_logger.info("connection to ifupdown2d successful (server pid %s)" % self.daemon_pid)

    def __shutdown(self):
        try:
            self.uds.close()
            self.uds = None
        except Exception:
            pass
        try:
            self.socket_receiver.server_close()
            self.socket_receiver = None
        except Exception:
            pass

    def __signal_handler(self, sig, frame):
        """ Forward all signals to daemon """
        if self.daemon_pid > 0:
            os.kill(self.daemon_pid, sig)

    def __get_stdin(self):
        """
        If stdin data is provided we need to store it to forward it to the
        daemon
        """
        if hasattr(self.args, "interfacesfile") and self.args.interfacesfile == "-":
            return sys.stdin.read()

    def run(self):
        try:
            # First we need to send the user request to the daemon (argv + stdin)
            self.tx_data(self.uds, json.dumps({
                "argv": self.argv,
                "stdin": self.__get_stdin()
            }))

            # Then "handle_request" will block until the daemon closes
            # the channel, meaning that the request was processed.
            self.socket_receiver.handle_request()
            self.socket_receiver.server_close()

            # Next the daemon should send us a dictionary containing stdout and
            # stderr buffers as well as the request's exit status. We print those
            # buffers in the correct channel and exit with the request status.
            response = self.rx_json_packet(self.uds)

            if response:
                sys.stdout.write(response.get("stdout", ""))
                sys.stderr.write(response.get("stderr", ""))

                status = response.get("status", Status.Client.STATUS_EMPTY)
            else:
                status = Status.Client.STATUS_EMPTY

            return status
        finally:
            self.__shutdown()
