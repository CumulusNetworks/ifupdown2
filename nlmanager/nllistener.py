#!/usr/bin/env python

from nlpacket import *
from nlmanager import NetlinkManager
from select import select
from struct import pack, unpack, calcsize
from threading import Thread, Event, Lock
from Queue import Queue
import logging
import socket

log = logging.getLogger(__name__)


class NetlinkListener(Thread):

    def __init__(self, manager, groups):
        """
        groups controls what types of messages we are interested in hearing
        To get everything pass:
            RTMGRP_LINK | \
            RTMGRP_IPV4_IFADDR | \
            RTMGRP_IPV4_ROUTE | \
            RTMGRP_IPV6_IFADDR | \
            RTMGRP_IPV6_ROUTE
        """
        Thread.__init__(self)
        self.manager = manager
        self.shutdown_event = Event()
        self.groups = groups

    def __str__(self):
        return 'NetlinkListener'

    def run(self):
        manager = self.manager
        header_PACK = 'IHHII'
        header_LEN = calcsize(header_PACK)

        # The RX socket is used to listen to all netlink messages that fly by
        # as things change in the kernel. We need a very large SO_RCVBUF here
        # else we tend to miss messages.
        self.rx_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
        self.rx_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_RCVBUF, 10000000)
        self.rx_socket.bind((manager.pid+1, self.groups))
        self.rx_socket_prev_seq = {}

        if not manager.tx_socket:
            manager.tx_socket_allocate()

        my_sockets = (manager.tx_socket, self.rx_socket)

        socket_string = {
            manager.tx_socket: "TX",
            self.rx_socket: "RX"
        }

        supported_messages = (RTM_NEWLINK, RTM_DELLINK, RTM_NEWADDR,
                              RTM_DELADDR, RTM_NEWNEIGH, RTM_DELNEIGH,
                              RTM_NEWROUTE, RTM_DELROUTE)

        ignore_messages = (RTM_GETLINK, RTM_GETADDR, RTM_GETNEIGH,
                           RTM_GETROUTE, RTM_GETQDISC, NLMSG_ERROR, NLMSG_DONE)

        while True:

            if self.shutdown_event.is_set():
                log.info("%s: shutting down" % self)
                return

            # Only block for 1 second so we can wake up to see if shutdown_event is set
            try:
                (readable, writeable, exceptional) = select(
                    my_sockets, [], my_sockets, 1)
            except Exception as e:
                log.error('select() error: ' + str(e))
                continue

            if not readable:
                continue

            set_alarm = False
            set_tx_socket_rxed_ack_alarm = False

            for s in readable:
                data = []

                try:
                    data = s.recv(4096)
                except Exception as e:
                    log.error('recv() error: ' + str(e))
                    continue

                total_length = len(data)
                while data:

                    # Extract the length, etc from the header
                    (length, msgtype, flags, seq, pid) = unpack(
                        header_PACK, data[:header_LEN])

                    log.debug('%s %s: RXed %s seq %d, pid %d, %d bytes (%d total)' %
                              (self, socket_string[s], NetlinkPacket.type_to_string[msgtype],
                               seq, pid, length, total_length))
                    possible_ack = False

                    if msgtype == NLMSG_DONE:
                        possible_ack = True

                    elif msgtype == NLMSG_ERROR:
                        possible_ack = True

                        # The error code is a signed negative number.
                        error_code = abs(
                            unpack('=i', data[header_LEN:header_LEN+4])[0])
                        msg = Error(msgtype, True)
                        msg.decode_packet(length, flags, seq, pid, data)

                        if error_code:
                            log.debug("%s %s: RXed NLMSG_ERROR code %s (%d)" % (
                                self, socket_string[s], msg.error_to_string.get(error_code), error_code))

                    if possible_ack and seq == manager.target_seq and pid == manager.target_pid:
                        log.debug("%s %s: Setting RXed ACK alarm for seq %d, pid %d" %
                                  (self, socket_string[s], seq, pid))
                        set_tx_socket_rxed_ack_alarm = True

                    # Put the message on the manager's netlinkq
                    if msgtype in supported_messages:
                        set_alarm = True
                        manager.netlinkq.append(
                            (msgtype, length, flags, seq, pid, data[0:length]))

                    # There are certain message types we do not care about
                    # (RTM_GETs for example)
                    elif msgtype in ignore_messages:
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
                        log.debug('%s %s: went from seq %d to %d' %
                                  (self, socket_string[s], prev_seq[pid], seq))
                    prev_seq[pid] = seq

                    data = data[length:]

            if set_tx_socket_rxed_ack_alarm:
                manager.target_lock.acquire()
                manager.target_seq = None
                manager.target_pid = None
                manager.target_lock.release()
                manager.tx_socket_rxed_ack.set()

            if set_alarm:
                manager.workq.put(('SERVICE_NETLINK_QUEUE', None))
                manager.alarm.set()

        self.rx_socket.close()


class NetlinkManagerWithListener(NetlinkManager):

    def __init__(self, groups, start_listener=True):
        NetlinkManager.__init__(self)
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

        # Listen to netlink messages
        if start_listener:
            self.listener = NetlinkListener(self, self.groups)
            self.listener.start()
        else:
            self.listener = None

    def __str__(self):
        return 'NetlinkManagerWithListener'

    def signal_term_handler(self, signal, frame):
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
        """
        TX the message and wait for an ack
        """

        # NetlinkListener looks at the manager's target_seq and target_pid
        # to know when we've RXed the ack that we want
        self.target_lock.acquire()
        self.target_seq = nlpacket.seq
        self.target_pid = nlpacket.pid
        self.target_lock.release()

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

    def rx_rtm_newaddr(self, msg):
        log.debug("RXed RTM_NEWADDR seq %d, pid %d, %d bytes, for %s/%d on %s" %
                  (msg.seq, msg.pid, msg.length, msg.get_attribute_value(msg.IFA_ADDRESS), msg.prefixlen, self.ifname_by_index.get(msg.ifindex)))

    def rx_rtm_deladdr(self, msg):
        log.debug("RXed RTM_DELADDR seq %d, pid %d, %d bytes, for %s/%d on %s" %
                  (msg.seq, msg.pid, msg.length, msg.get_attribute_value(msg.IFA_ADDRESS), msg.prefixlen, self.ifname_by_index.get(msg.ifindex)))

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

    # Note that tx_nlpacket_get_response will block until NetlinkListener has RXed
    # an Ack/DONE for the message we TXed
    def get_all_addresses(self):
        family = socket.AF_UNSPEC
        debug = RTM_GETADDR in self.debug

        addr = Address(RTM_GETADDR, debug)
        addr.flags = NLM_F_REQUEST | NLM_F_DUMP
        addr.body = pack('Bxxxi', family, 0)
        addr.build_message(self.sequence.next(), self.pid)

        if debug:
            self.debug_seq_pid[(addr.seq, addr.pid)] = True

        self.tx_nlpacket_get_response(addr)

    def get_all_links(self):
        family = socket.AF_UNSPEC
        debug = RTM_GETLINK in self.debug

        link = Link(RTM_GETLINK, debug)
        link.flags = NLM_F_REQUEST | NLM_F_DUMP
        link.body = pack('Bxxxiii', family, 0, 0, 0)
        link.build_message(self.sequence.next(), self.pid)

        if debug:
            self.debug_seq_pid[(link.seq, link.pid)] = True

        self.tx_nlpacket_get_response(link)

    def get_all_neighbors(self):
        family = socket.AF_UNSPEC
        debug = RTM_GETNEIGH in self.debug

        neighbor = Neighbor(RTM_GETNEIGH, debug)
        neighbor.flags = NLM_F_REQUEST | NLM_F_DUMP
        neighbor.body = pack('Bxxxii', family, 0, 0)
        neighbor.build_message(self.sequence.next(), self.pid)

        if debug:
            self.debug_seq_pid[(neighbor.seq, neighbor.pid)] = True

        self.tx_nlpacket_get_response(neighbor)

    def get_all_routes(self):
        family = socket.AF_UNSPEC
        debug = RTM_GETROUTE in self.debug

        route = Route(RTM_GETROUTE, debug)
        route.flags = NLM_F_REQUEST | NLM_F_DUMP
        route.body = pack('Bxxxii', family, 0, 0)
        route.build_message(self.sequence.next(), self.pid)

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
        for (key, value) in attr_filter.items():
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
        assert filter_type in (
            'whitelist', 'blacklist'), "whitelist and blacklist are the only supported filter options"

        if add:
            if filter_type == 'whitelist':

                # Keep things simple, do not allow both whitelist and blacklist
                if self.blacklist_filter and self.blacklist_filter.get(msgtype):
                    raise Exception(
                        "whitelist and blacklist filters cannot be used at the same time")

                if msgtype not in self.whitelist_filter:
                    self.whitelist_filter[msgtype] = []
                self.whitelist_filter[msgtype].append(filter_guts)

            elif filter_type == 'blacklist':

                # Keep things simple, do not allow both whitelist and blacklist
                if self.whitelist_filter and self.whitelist_filter.get(msgtype):
                    raise Exception(
                        "whitelist and blacklist filters cannot be used at the same time")

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
        self._filter_update(add, filter_type, msgtype,
                            ('ATTRIBUTE', attribute, attribute_value))

    def filter_by_nested_attribute(self, add, filter_type, msgtype, attr_filter):
        self._filter_update(add, filter_type, msgtype,
                            ('NESTED_ATTRIBUTE', attr_filter))

    def service_netlinkq(self):
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
                msg = Link(msgtype, debug)

            elif msgtype == RTM_NEWADDR or msgtype == RTM_DELADDR:
                msg = Address(msgtype, debug)

            elif msgtype == RTM_NEWNEIGH or msgtype == RTM_DELNEIGH:
                msg = Neighbor(msgtype, debug)

            elif msgtype == RTM_NEWROUTE or msgtype == RTM_DELROUTE:
                msg = Route(msgtype, debug)

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
                self.ifname_by_index[msg.ifindex] = msg.get_attribute_value(
                    msg.IFLA_IFNAME)
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

            else:
                log.warning('RXed unknown netlink message type %s' % msgtype)

        if processed:
            self.netlinkq = self.netlinkq[processed:]

        # too chatty
        # for msgtype in msg_count:
        #     log.debug('RXed %d %s messages' % (msg_count[msgtype], NetlinkPacket.type_to_string[msgtype]))
