#!/usr/bin/env python3
#
# Copyright (C) 2015-2020 Cumulus Networks, Inc. all rights reserved
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
# Authors:
#       Daniel Walton, dwalton@cumulusnetworks.com
#       Julien Fortin, julien@cumulusnetworks.com
#
# Netlink Listener --
#

from .nlpacket import *
from .nlmanager import NetlinkManager
from select import select
from struct import pack, unpack, calcsize
from threading import Thread, Event, Lock
from queue import Queue
import logging
import signal
import socket
import errno
import os

log = logging.getLogger(__name__)


class NetlinkListener(Thread):
    # As defined in asm/socket.h
    _SO_ATTACH_FILTER = 26

    RECV_BUFFER = 65536  # 1024 * 1024

    def __init__(self, manager, groups, pid_offset=1, error_notification=False, rcvbuf_sz=10000000, bpf_filter=None):
        """
        groups controls what types of messages we are interested in hearing
        To get everything pass:
            RTMGRP_LINK | \
            RTMGRP_IPV4_IFADDR | \
            RTMGRP_IPV4_ROUTE | \
            RTMGRP_IPV6_IFADDR | \
            RTMGRP_IPV6_ROUTE
        """
        Thread.__init__(self, name='NetlinkListener')
        self.manager = manager
        self.shutdown_event = Event()
        self.groups = groups
        self.pid_offset = pid_offset
        self.rcvbuf_sz = rcvbuf_sz
        self.bpf_filter = bpf_filter
        self.rx_socket = None
        self.rx_socket_prev_seq = {}

        # if the app has requested for error notification socket errors will
        # be sent via the SERVICE_ERROR event
        self.error_notification = error_notification

        self.supported_messages = [RTM_NEWLINK, RTM_DELLINK, RTM_NEWADDR,
                                   RTM_DELADDR, RTM_NEWNEIGH, RTM_DELNEIGH,
                                   RTM_NEWROUTE, RTM_DELROUTE,
                                   RTM_NEWMDB, RTM_DELMDB, RTM_GETMDB]
        self.ignore_messages = [RTM_GETLINK, RTM_GETADDR, RTM_GETNEIGH,
                                RTM_GETROUTE, RTM_GETQDISC, NLMSG_ERROR, NLMSG_DONE]

    def __str__(self):
        return 'NetlinkListener'

    def supported_messages_add(self, msgtype):

        if msgtype not in self.supported_messages:
            self.supported_messages.append(msgtype)

        if msgtype in self.ignore_messages:
            self.ignore_messages.remove(msgtype)

    def supported_messages_del(self, msgtype):

        if msgtype in self.supported_messages:
            self.supported_messages.remove(msgtype)

        if msgtype not in self.ignore_messages:
            self.ignore_messages.append(msgtype)

    def __bind_rx_socket(self, pid):
        """
        bind rx_socket and retry mechanism in case of failure and collision
        i.e.: [Errno 98] Address already in use

        We will retry NLMANAGER_BIND_RETRY times (defaults to 4242)

        :param pid:
        :return:
        """
        pid_offset = self.pid_offset
        for i in range(0, int(os.getenv("NLMANAGER_BIND_RETRY", 4242))):
            try:
                pid_offset += i
                self.rx_socket.bind((pid | (pid_offset << 22), self.groups))
                self.pid_offset = pid_offset
                return
            except Exception:
                pass
        # if we reach this line it means we've reach NLMANAGER_BIND_RETRY limit
        # and couldn't successfully bind the rx_socket... We will try one more
        # time but without catching the related exception.
        self.rx_socket.bind((pid | (self.pid_offset << 22), self.groups))

    def run(self):
        manager = self.manager
        try:
            header_PACK = 'IHHII'
            header_LEN = calcsize(header_PACK)

            # The RX socket is used to listen to all netlink messages that fly by
            # as things change in the kernel. We need a very large SO_RCVBUF here
            # else we tend to miss messages.
            # PID_MAX_LIMIT is 2^22 allowing 1024 sockets per-pid. We default to
            # use 2 in the upper space (top 10 bits) instead of 0 to avoid conflicts
            # with the netlink manager which always attempts to bind with the pid.
            self.rx_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
            try:
                self.rx_socket.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_RCVBUFFORCE if hasattr(socket, 'SO_RCVBUFFORCE') else 33,
                    self.rcvbuf_sz
                )
                if self.bpf_filter is not None:
                    self.rx_socket.setsockopt(
                        socket.SOL_SOCKET,
                        NetlinkListener._SO_ATTACH_FILTER,
                        self.bpf_filter
                    )
            except Exception as e:
                log.debug("nllistener: rx socket: setsockopt: %s" % str(e))

            self.__bind_rx_socket(manager.pid)

            with manager.target_lock:
                if not manager.tx_socket:
                    manager.tx_socket_allocate()

            my_sockets = (manager.tx_socket, self.rx_socket)

            socket_string = {
                manager.tx_socket: "TX",
                self.rx_socket: "RX"
            }
        except Exception as e:
            if self.rx_socket:
                self.rx_socket.close()
                self.rx_socket = None

            # before notifying the main thread we need to set
            # manager.listener_ready properly to signal the failure
            manager.listener_ready = False
            manager.listener_event_ready.set()

            if logging.root.level == logging.DEBUG:
                # in debug mode we raise the exception so it can be displayed
                # in the terminal: "Exception in thread NetlinkListener..."
                raise
            else:
                log.error("netlink: listener thread: rx socket: %s" % str(e))
                return

        # Notify main thread that the NetlinkListener thread
        # has started and is ready to start processing data
        manager.listener_ready = True
        manager.listener_event_ready.set()

        while True:

            if self.shutdown_event.is_set():
                log.info("%s: shutting down" % self)
                break

            # Only block for 1 second so we can wake up to see if shutdown_event is set
            try:
                (readable, writeable, exceptional) = select(my_sockets, [], my_sockets, 0.1)
                # when ifupdown2 is not running we could change the timeout to 1 sec or more
            except Exception as e:
                log.error('select() error: ' + str(e))
                continue

            if not readable:
                continue

            set_alarm = False
            set_overrun = False
            set_tx_socket_rxed_ack_alarm = False

            for s in readable:
                data = []

                try:
                    data = s.recv(self.RECV_BUFFER)
                except socket.error as e:
                    log.error('recv() error: ' + str(e))
                    data = []
                    if e.errno is errno.ENOBUFS and self.error_notification:
                        set_overrun = True
                except Exception as e:
                    log.error('recv() error: ' + str(e))
                    data = []

                total_length = len(data)
                while data:

                    # Extract the length, etc from the header
                    (length, msgtype, flags, seq, pid) = unpack(header_PACK, data[:header_LEN])

                    msgtype_str = NetlinkPacket.type_to_string.get(msgtype)

                    if not msgtype_str:
                        data = data[length:]
                        log.debug('%s %s: RXed unknown/unsupported msg type %s skipping netlink message...' % (self, socket_string[s], msgtype))
                        continue

                    log.debug('%s %s: RXed %s seq %d, pid %d, %d bytes (%d total)' %
                              (self, socket_string[s], msgtype_str,
                               seq, pid, length, total_length))
                    possible_ack = False

                    if msgtype == NLMSG_DONE:
                        possible_ack = True

                    elif msgtype == NLMSG_ERROR:
                        possible_ack = True

                        # The error code is a signed negative number.
                        error_code = abs(unpack('=i', data[header_LEN:header_LEN+4])[0])
                        msg = Error(msgtype, True)
                        msg.decode_packet(length, flags, seq, pid, data)

                        if error_code:
                            log.debug("%s %s: RXed NLMSG_ERROR code %s (%d): %s" % (self, socket_string[s], msg.error_to_string.get(error_code), error_code, msg.error_to_human_readable_string.get(error_code)))
                        else:
                            log.debug("%s %s: RXed NLMSG_ERROR code %s (%d): %s... this is an ACK" % (self, socket_string[s], msg.error_to_string.get(error_code), error_code, msg.error_to_human_readable_string.get(error_code)))

                        if manager.errorq_enabled:
                            with manager.errorq_lock:
                                manager.errorq.append(msg)

                    if possible_ack and seq == manager.target_seq and pid == manager.target_pid:
                        log.debug("%s %s: Setting RXed ACK alarm for seq %d, pid %d" %
                                  (self, socket_string[s], seq, pid))
                        set_tx_socket_rxed_ack_alarm = True

                    # Put the message on the manager's netlinkq
                    if msgtype in self.supported_messages:
                        set_alarm = True
                        manager.netlinkq.append((msgtype, length, flags, seq, pid, data[0:length]))

                    # There are certain message types we do not care about
                    # (RTM_GETs for example)
                    elif msgtype in self.ignore_messages:
                        pass

                    # And there are certain message types we have not added
                    # support for yet (QDISC). Log an error for these just
                    # as a reminder to add support for them.
                    else:
                        if msgtype in NetlinkPacket.type_to_string:
                            log.warning('%s %s: RXed unsupported message %s (type %d)' %
                                        (self, socket_string[s], NetlinkPacket.type_to_string[msgtype], msgtype))
                        else:
                            log.warning('%s %s: RXed unknown message type %d' %
                                        (self, socket_string[s], msgtype))

                    # Track the previous PID sequence number for RX and TX sockets
                    if s == self.rx_socket:
                        prev_seq = self.rx_socket_prev_seq
                    elif s == manager.tx_socket:
                        prev_seq = manager.tx_socket_prev_seq

                    if pid in prev_seq and prev_seq[pid] and prev_seq[pid] != seq and (prev_seq[pid]+1 != seq):
                        log.debug('%s %s: went from seq %d to %d' % (self, socket_string[s], prev_seq[pid], seq))
                    prev_seq[pid] = seq

                    data = data[length:]

            if set_tx_socket_rxed_ack_alarm:
                with manager.target_lock:
                    manager.target_seq = None
                    manager.target_pid = None
                manager.tx_socket_rxed_ack.set()

            if set_alarm:
                manager.workq.put((manager.WORKQ_SERVICE_NETLINK_QUEUE, None))

            if set_overrun:
                manager.workq.put((manager.WORKQ_SERVICE_ERROR, "OVERFLOW"))

            if set_alarm or set_overrun:
                manager.alarm.set()

        self.rx_socket.close()


class NetlinkManagerWithListener(NetlinkManager):

    WORKQ_SERVICE_NETLINK_QUEUE = 1
    WORKQ_SERVICE_ERROR         = 2

    def __init__(self, groups, start_listener=True, use_color=True, pid_offset=0, error_notification=False, rcvbuf_sz=10000000, bpf_filter=None):
        NetlinkManager.__init__(self, use_color=use_color, pid_offset=pid_offset)
        self.groups = groups
        self.workq = Queue()
        self.netlinkq = []
        self.alarm = Event()
        self.shutdown_event = Event()
        self.tx_socket_rxed_ack = Event()
        self.tx_socket_rxed_ack.clear()
        self.target_seq = None
        self.target_pid = None
        self.target_seq_pid_debug = False
        self.target_lock = Lock()
        self.tx_socket_prev_seq = {}
        self.debug_listener = False
        self.debug_seq_pid = {}
        self.ifname_by_index = {}
        self.blacklist_filter = {}
        self.whitelist_filter = {}
        self.rcvbuf_sz = rcvbuf_sz
        self.error_notification = error_notification
        self.pid_offset = pid_offset
        self.bpf_filter = bpf_filter

        self.errorq = None
        self.errorq_lock = None
        self.errorq_enabled = False

        self.listener_event_ready = None
        self.listener_ready = None

        # Listen to netlink messages
        if start_listener:
            self.restart_listener()
        else:
            self.listener = None

    def __str__(self):
        return 'NetlinkManagerWithListener'

    def restart_listener(self):
        """
        (re)Start Netlink listener thread and make sure to wait until
        the newly created thread is ready.
        :return:
        """
        self.listener_event_ready = Event()
        self.listener_ready = False

        self.listener = NetlinkListener(self, self.groups, self.pid_offset + 1, self.error_notification, self.rcvbuf_sz, self.bpf_filter)
        self.listener.start()

        self.listener_event_ready.wait()
        if not self.listener_ready:
            self.listener.join()
            # TODO: add custom exception (easier to ignore and recognize)
            raise Exception()

    def signal_term_handler(self, sig, frame):
        if sig == signal.SIGTERM:
            log.info("NetlinkManagerWithListener: Caught SIGTERM")

        if self.listener:
            self.listener.shutdown_event.set()

        self.shutdown_flag = True  # For NetlinkManager shutdown
        self.shutdown_event.set()
        self.alarm.set()

    def signal_int_handler(self, signal, frame):
        log.info("NetlinkManagerWithListener: Caught SIGINT")

        if self.listener:
            self.listener.shutdown_event.set()

        self.shutdown_flag = True  # For NetlinkManager shutdown
        self.shutdown_event.set()
        self.alarm.set()

    def tx_nlpacket_get_response(self, nlpacket):
        # WARNING: having multiple threads waiting for ACKs might result in
        # undefined behavior. To make this work we should probably have a
        # (thread-safe) list of all the target SEQs and PIDs along side a
        # reference to their alarms (thead.Event) to notify the right thread
        # of the RXed ACK.
        """
        TX the message and wait for an ack
        """

        # NetlinkListener looks at the manager's target_seq and target_pid
        # to know when we've RXed the ack that we want
        with self.target_lock:
            self.target_seq = nlpacket.seq
            self.target_pid = nlpacket.pid

            if not self.tx_socket:
                self.tx_socket_allocate()

        log.debug('%s TX: TXed %s seq %d, pid %d, %d bytes' %
                   (self,  NetlinkPacket.type_to_string[nlpacket.msgtype],
                    nlpacket.seq, nlpacket.pid, nlpacket.length))

        self.tx_socket.sendall(nlpacket.message)

        # Wait for NetlinkListener to RX an ACK or DONE for this (seq, pid)
        self.tx_socket_rxed_ack.wait()
        self.tx_socket_rxed_ack.clear()

    # These are here to show some basic examples of how one might react to RXing
    # various netlink message types. Odds are our child class will redefine these
    # to do more than log a message.
    def rx_rtm_newlink(self, msg):
        log.debug("RXed RTM_NEWLINK seq %d, pid %d, %d bytes, for %s, state %s" %
                  (msg.seq, msg.pid, msg.length, msg.get_attribute_value(msg.IFLA_IFNAME), "up" if msg.is_up() else "down"))

    def rx_rtm_dellink(self, msg):
        log.debug("RXed RTM_DELLINK seq %d, pid %d, %d bytes, for %s, state %s" %
                  (msg.seq, msg.pid, msg.length, msg.get_attribute_value(msg.IFLA_IFNAME), "up" if msg.is_up() else "down"))

    def rx_rtm_newnetconf(self, msg):
        ifindex = msg.get_attribute_value(msg.NETCONFA_IFINDEX)
        ifname = self.ifname_by_index.get(ifindex)

        if ifname:
            log.debug("RXed RTM_NEWNETCONF seq %d, pid %d, %d bytes on ifname %s" % (msg.seq, msg.pid, msg.length, ifname))
        else:
            log.debug("RXed RTM_NEWNETCONF seq %d, pid %d, %d bytes on ifindex %s" % (msg.seq, msg.pid, msg.length, ifindex))

    def rx_rtm_delnetconf(self, msg):
        ifindex = msg.get_attribute_value(msg.NETCONFA_IFINDEX)
        ifname = self.ifname_by_index.get(ifindex)

        if ifname:
            log.debug("RXed RTM_DELNETCONF seq %d, pid %d, %d bytes on ifname %s" % (msg.seq, msg.pid, msg.length, ifname))
        else:
            log.debug("RXed RTM_DELNETCONF seq %d, pid %d, %d bytes on ifindex %s" % (msg.seq, msg.pid, msg.length, ifindex))

    def rx_rtm_newaddr(self, msg):
        log.debug("RXed RTM_NEWADDR seq %d, pid %d, %d bytes, for %s on %s" % (msg.seq, msg.pid, msg.length, msg.get_attribute_value(msg.IFA_ADDRESS), self.ifname_by_index.get(msg.ifindex)))

    def rx_rtm_deladdr(self, msg):
        log.debug("RXed RTM_DELADDR seq %d, pid %d, %d bytes, for %s on %s" % (msg.seq, msg.pid, msg.length, msg.get_attribute_value(msg.IFA_ADDRESS), self.ifname_by_index.get(msg.ifindex)))

    def rx_rtm_newneigh(self, msg):
        log.debug("RXed RTM_NEWNEIGH seq %d, pid %d, %d bytes, for %s on %s" %
                  (msg.seq, msg.pid, msg.length, msg.get_attribute_value(msg.NDA_DST), self.ifname_by_index.get(msg.ifindex)))

    def rx_rtm_delneigh(self, msg):
        log.debug("RXed RTM_DELNEIGH seq %d, pid %d, %d bytes, for %s on %s" %
                  (msg.seq, msg.pid, msg.length, msg.get_attribute_value(msg.NDA_DST), self.ifname_by_index.get(msg.ifindex)))

    def rx_rtm_newroute(self, msg):
        log.debug("RXed RTM_NEWROUTE seq %d, pid %d, %d bytes, for %s%s" %
                  (msg.seq, msg.pid, msg.length, msg.get_prefix_string(), msg.get_nexthops_string(self.ifname_by_index)))

    def rx_rtm_delroute(self, msg):
        log.debug("RXed RTM_DELROUTE seq %d, pid %d, %d bytes, for %s%s" %
                  (msg.seq, msg.pid, msg.length, msg.get_prefix_string(), msg.get_nexthops_string(self.ifname_by_index)))

    def rx_rtm_newmdb(self, msg):
        log.debug("RXed RTM_NEWMDB")

    def rx_rtm_delmdb(self, msg):
        log.debug("RXed RTM_DELMDB")

    def rx_nlmsg_done(self, msg):
        log.debug("RXed NLMSG_DONE seq %d, pid %d, %d bytes" % (msg.seq, msg.pid, msg.length))

    # Note that tx_nlpacket_get_response will block until NetlinkListener has RXed
    # an Ack/DONE for the message we TXed
    def get_all_addresses(self):
        family = socket.AF_UNSPEC
        debug = RTM_GETADDR in self.debug

        addr = Address(RTM_GETADDR, debug, use_color=self.use_color)
        addr.flags = NLM_F_REQUEST | NLM_F_DUMP
        addr.body = pack('Bxxxi', family, 0)
        addr.build_message(next(self.sequence), self.pid)

        if debug:
            self.debug_seq_pid[(addr.seq, addr.pid)] = True

        self.tx_nlpacket_get_response(addr)

    def get_all_links(self):
        family = socket.AF_UNSPEC
        debug = RTM_GETLINK in self.debug

        link = Link(RTM_GETLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_DUMP
        link.body = pack('Bxxxiii', family, 0, 0, 0)
        link.build_message(next(self.sequence), self.pid)

        if debug:
            self.debug_seq_pid[(link.seq, link.pid)] = True

        self.tx_nlpacket_get_response(link)

    def get_all_br_links(self, compress_vlans=True):
        family = socket.AF_BRIDGE
        debug = RTM_GETLINK in self.debug

        link = Link(RTM_GETLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_DUMP
        link.body = pack('Bxxxiii', family, 0, 0, 0)
        if compress_vlans:
            link.add_attribute(Link.IFLA_EXT_MASK, Link.RTEXT_FILTER_BRVLAN_COMPRESSED)
        else:
            link.add_attribute(Link.IFLA_EXT_MASK, Link.RTEXT_FILTER_BRVLAN)
        link.build_message(next(self.sequence), self.pid)

        if debug:
            self.debug_seq_pid[(link.seq, link.pid)] = True

        self.tx_nlpacket_get_response(link)

    def get_all_neighbors(self):
        family = socket.AF_UNSPEC
        debug = RTM_GETNEIGH in self.debug

        neighbor = Neighbor(RTM_GETNEIGH, debug, use_color=self.use_color)
        neighbor.flags = NLM_F_REQUEST | NLM_F_DUMP
        neighbor.body = pack('Bxxxii', family, 0, 0)
        neighbor.build_message(next(self.sequence), self.pid)

        if debug:
            self.debug_seq_pid[(neighbor.seq, neighbor.pid)] = True

        self.tx_nlpacket_get_response(neighbor)

    def get_all_routes(self):
        family = socket.AF_UNSPEC
        debug = RTM_GETROUTE in self.debug

        route = Route(RTM_GETROUTE, debug, use_color=self.use_color)
        route.flags = NLM_F_REQUEST | NLM_F_DUMP
        route.body = pack('Bxxxii', family, 0, 0)
        route.build_message(next(self.sequence), self.pid)

        if debug:
            self.debug_seq_pid[(route.seq, route.pid)] = True

        self.tx_nlpacket_get_response(route)

    def nested_attributes_match(self, msg, attr_filter):
        """
        attr_filter will be a dictionary such as:
        attr_filter = {
            Link.IFLA_LINKINFO: {
                Link.IFLA_INFO_KIND: 'vlan'
            }
        }
        """
        for (key, value) in list(attr_filter.items()):
            if type(value) is dict:
                if not self.nested_attributes_match(msg, value):
                    return False
            else:
                attr_value = msg.get_attribute_value(key)
                if attr_value != value:
                    return False
        return True

    def filter_rule_matches(self, msg, rule):
        field = rule[0]
        options = rule[1:]

        if field == 'IFINDEX':
            ifindex = options[0]

            if msg.ifindex == ifindex:
                return True

        elif field == 'ATTRIBUTE':
            (attr_type, target_value) = options[0:2]
            attr_value = msg.get_attribute_value(attr_type)

            if attr_value == target_value:
                return True

        elif field == 'NESTED_ATTRIBUTE':
            if self.nested_attributes_match(msg, options[0]):
                return True

        elif field == 'FAMILY':
            family = options[0]

            if msg.family == family:
                return True
        else:
            raise Exception("Add support to filter based on %s" % field)

        return False

    def filter_permit(self, msg):
        """
        Return True if our whitelist/blacklist filters permit this netlink msg
        """
        if msg.msgtype in self.whitelist_filter:
            found_it = False

            for rule in self.whitelist_filter[msg.msgtype]:
                if self.filter_rule_matches(msg, rule):
                    found_it = True
                    break

            return found_it

        elif msg.msgtype in self.blacklist_filter:
            for rule in self.blacklist_filter[msg.msgtype]:
                if self.filter_rule_matches(msg, rule):
                    return False
            return True

        else:
            return True

    def _filter_update(self, add, filter_type, msgtype, filter_guts):
        assert filter_type in ('whitelist', 'blacklist'), "whitelist and blacklist are the only supported filter options"

        if add:
            if filter_type == 'whitelist':

                # Keep things simple, do not allow both whitelist and blacklist
                if self.blacklist_filter and self.blacklist_filter.get(msgtype):
                    raise Exception("whitelist and blacklist filters cannot be used at the same time")

                if msgtype not in self.whitelist_filter:
                    self.whitelist_filter[msgtype] = []
                self.whitelist_filter[msgtype].append(filter_guts)

            elif filter_type == 'blacklist':

                # Keep things simple, do not allow both whitelist and blacklist
                if self.whitelist_filter and self.whitelist_filter.get(msgtype):
                    raise Exception("whitelist and blacklist filters cannot be used at the same time")

                if msgtype not in self.blacklist_filter:
                    self.blacklist_filter[msgtype] = []
                self.blacklist_filter[msgtype].append(filter_guts)

        else:
            if filter_type == 'whitelist':
                if msgtype in self.whitelist_filter:
                    self.whitelist_filter[msgtype].remove(filter_guts)

                    if not self.whitelist_filter[msgtype]:
                        del self.whitelist_filter[msgtype]

            elif filter_type == 'blacklist':
                if msgtype in self.blacklist_filter:
                    self.blacklist_filter[msgtype].remove(filter_guts)

                    if not self.blacklist_filter[msgtype]:
                        del self.blacklist_filter[msgtype]

    def filter_by_address_family(self, add, filter_type, msgtype, family):
        self._filter_update(add, filter_type, msgtype, ('FAMILY', family))

    def filter_by_ifindex(self, add, filter_type, msgtype, ifindex):
        self._filter_update(add, filter_type, msgtype, ('IFINDEX', ifindex))

    def filter_by_attribute(self, add, filter_type, msgtype, attribute, attribute_value):
        self._filter_update(add, filter_type, msgtype, ('ATTRIBUTE', attribute, attribute_value))

    def filter_by_nested_attribute(self, add, filter_type, msgtype, attr_filter):
        self._filter_update(add, filter_type, msgtype, ('NESTED_ATTRIBUTE', attr_filter))

    def service_netlinkq(self, notify_event=None):
        msg_count = {}
        processed = 0

        for (msgtype, length, flags, seq, pid, data) in self.netlinkq:
            processed += 1

            # If this is a reply to a TX message that debugs were enabled for then debug the reply
            if (seq, pid) in self.debug_seq_pid:
                debug = True
            else:
                debug = self.debug_this_packet(msgtype)

            if msgtype == RTM_NEWLINK or msgtype == RTM_DELLINK:
                msg = Link(msgtype, debug, use_color=self.use_color)

            elif msgtype == RTM_NEWADDR or msgtype == RTM_DELADDR:
                msg = Address(msgtype, debug, use_color=self.use_color)

            elif msgtype == RTM_NEWNEIGH or msgtype == RTM_DELNEIGH:
                msg = Neighbor(msgtype, debug, use_color=self.use_color)

            elif msgtype == RTM_NEWROUTE or msgtype == RTM_DELROUTE:
                msg = Route(msgtype, debug, use_color=self.use_color)

            elif msgtype in (RTM_GETNETCONF, RTM_NEWNETCONF, RTM_DELNETCONF):
                msg = Netconf(msgtype, debug, use_color=self.use_color)

            elif msgtype == RTM_NEWMDB or msgtype == RTM_DELMDB:
                msg = MDB(msgtype, debug, use_color=self.use_color)

            elif msgtype == NLMSG_DONE:
                msg = Done(msgtype, debug, use_color=self.use_color)

            else:
                log.warning('RXed unknown netlink message type %s' % msgtype)
                continue

            msg.decode_packet(length, flags, seq, pid, data)

            if not self.filter_permit(msg):
                continue

            if debug:
                msg.dump()

            # Only used for printing debugs about how many we RXed of each type
            if msg.msgtype not in msg_count:
                msg_count[msg.msgtype] = 0
            msg_count[msg.msgtype] += 1

            # Call the appropriate handler method based on the msgtype.  The handler
            # functions are defined in our child class.
            if msg.msgtype == RTM_NEWLINK:

                # We will use ifname_by_index to display the interface name in debug output
                self.ifname_by_index[msg.ifindex] = msg.get_attribute_value(msg.IFLA_IFNAME)
                self.rx_rtm_newlink(msg)

            elif msg.msgtype == RTM_DELLINK:

                # We will use ifname_by_index to display the interface name in debug output
                if msg.ifindex in self.ifname_by_index:
                    del self.ifname_by_index[msg.ifindex]
                self.rx_rtm_dellink(msg)

            elif msg.msgtype == RTM_NEWADDR:
                self.rx_rtm_newaddr(msg)

            elif msg.msgtype == RTM_DELADDR:
                self.rx_rtm_deladdr(msg)

            elif msg.msgtype == RTM_NEWNEIGH:
                self.rx_rtm_newneigh(msg)

            elif msg.msgtype == RTM_DELNEIGH:
                self.rx_rtm_delneigh(msg)

            elif msg.msgtype == RTM_NEWROUTE:
                self.rx_rtm_newroute(msg)

            elif msg.msgtype == RTM_DELROUTE:
                self.rx_rtm_delroute(msg)

            elif msg.msgtype == RTM_NEWNETCONF:
                self.rx_rtm_newnetconf(msg)

            elif msg.msgtype == RTM_DELNETCONF:
                self.rx_rtm_delnetconf(msg)

            elif msg.msgtype == RTM_NEWMDB:
                self.rx_rtm_newmdb(msg)

            elif msg.msgtype == RTM_DELMDB:
                self.rx_rtm_delmdb(msg)

            elif msg.msgtype == NLMSG_DONE:
                self.rx_nlmsg_done(msg)

            else:
                log.warning('RXed unknown netlink message type %s' % msgtype)

        if processed:
            self.netlinkq = self.netlinkq[processed:]

        if notify_event:
            notify_event.set()

        # too chatty
        # for msgtype in msg_count:
        #     log.debug('RXed %d %s messages' % (msg_count[msgtype], NetlinkPacket.type_to_string[msgtype]))
