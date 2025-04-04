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
# Netlink Manager --
#

from collections import OrderedDict
from .nlpacket import *
from select import select
from struct import pack, unpack
import logging
import os
import socket

log = logging.getLogger(__name__)


class NetlinkError(Exception):
    pass


class NetlinkNoAddressError(NetlinkError):
    pass


class NetlinkInterruptedSystemCall(NetlinkError):
    pass


class InvalidInterfaceNameVlanCombo(Exception):
    pass


class Sequence(object):

    def __init__(self):
        self._next = 0

    def __next__(self):
        self._next += 1
        return self._next


class NetlinkManager(object):

    def __init__(self, pid_offset=0, use_color=True, log_level=None):
        # PID_MAX_LIMIT is 2^22 allowing 1024 sockets per-pid. We default to 0
        # in the upper space (top 10 bits), which will simply be the PID. Other
        # NetlinkManager instantiations in the same process can choose other
        # offsets to avoid conflicts with each other.
        self.pid = os.getpid() | (pid_offset << 22)
        self.sequence = Sequence()
        self.shutdown_flag = False
        self.ifindexmap = {}
        self.tx_socket = None
        self.use_color = use_color

        # debugs
        self.debug = {}
        self.debug_link(False)
        self.debug_address(False)
        self.debug_neighbor(False)
        self.debug_route(False)

        if log_level:
            log.setLevel(log_level)
            set_log_level(log_level)

    def __str__(self):
        return 'NetlinkManager'

    def signal_term_handler(self, signal, frame):
        log.info("NetlinkManager: Caught SIGTERM")
        self.shutdown_flag = True

    def signal_int_handler(self, signal, frame):
        log.info("NetlinkManager: Caught SIGINT")
        self.shutdown_flag = True

    def shutdown(self):
        if self.tx_socket:
            self.tx_socket.close()
            self.tx_socket = None
        log.info("NetlinkManager: shutdown complete")

    def _debug_set_clear(self, msg_types, enabled):
        """
        Enable or disable debugs for all msgs_types messages
        """

        for x in msg_types:
            if enabled:
                self.debug[x] = True
            else:
                if x in self.debug:
                    del self.debug[x]

    def debug_link(self, enabled):
        self._debug_set_clear((RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK, RTM_SETLINK), enabled)

    def debug_address(self, enabled):
        self._debug_set_clear((RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR), enabled)

    def debug_neighbor(self, enabled):
        self._debug_set_clear((RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH), enabled)

    def debug_route(self, enabled):
        self._debug_set_clear((RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE), enabled)

    def debug_netconf(self, enabled):
        self._debug_set_clear((RTM_GETNETCONF, RTM_NEWNETCONF, RTM_DELNETCONF), enabled)

    def debug_mdb(self, enabled):
        self._debug_set_clear((RTM_GETMDB, RTM_NEWMDB, RTM_DELMDB), enabled)

    def debug_this_packet(self, mtype):
        if mtype in self.debug:
            return True
        return False

    def tx_socket_allocate(self):
        """
        The TX socket is used for install requests, sending RTM_GETXXXX
        requests, etc
        """
        try:
            self.tx_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)

            # bind retry mechanism:
            # in some cases we are running into weird issues... Address already in use
            # to counter this problem, we will retry up to NLMANAGER_BIND_RETRY times to
            # bind our socket, every time increasing the address (or pid) that we bind it
            # to. NLMANAGER_BIND_RETRY default to 4242
            for i in range(0, int(os.getenv("NLMANAGER_BIND_RETRY", 4242))):
                try:
                    self.tx_socket.bind((self.pid + i, 0))
                    # the bind call succeeded, we need to update self.pid
                    # to reflect the correct value we are binded to. If we
                    # couldn't bind to our real pid (os.getpid()) warn user
                    # to avoid confusion (via debug logs).
                    if i != 0:
                        log.debug(
                            "nlmanager: pid %s already in use - binding netlink socket to pid %s"
                            % (self.pid, self.pid + i)
                        )
                    self.pid = self.pid + i
                    return
                except Exception:
                    pass
            # if we reach this code it means all our bind calls failed. We are trying to
            # bind the socket one last time on the original parameters if not we will not
            # be catching the exception
            self.tx_socket.bind((self.pid, 0))
        except Exception:
            if self.tx_socket:
                self.tx_socket.close()
                self.tx_socket = None
            raise

    def tx_nlpacket_raw(self, message):
        """
        TX a bunch of concatenated nlpacket.messages....do NOT wait for an ACK
        """
        if not self.tx_socket:
            self.tx_socket_allocate()
        self.tx_socket.sendall(message)

    def tx_nlpacket(self, nlpacket):
        """
        TX a netlink packet but do NOT wait for an ACK
        """
        if not nlpacket.message:
            log.error('You must first call build_message() to create the packet')
            return

        if not self.tx_socket:
            self.tx_socket_allocate()
        self.tx_socket.sendall(nlpacket.message)

    def tx_nlpacket_get_response(self, nlpacket):

        if not nlpacket.message:
            log.error('You must first call build_message() to create the packet')
            return

        if not self.tx_socket:
            self.tx_socket_allocate()
        self.tx_socket.sendall(nlpacket.message)

        # If nlpacket.debug is True we already printed the following in the
        # build_message() call...so avoid printing two messages for one packet.
        if not nlpacket.debug:
            log.debug("TXed %12s, pid %d, seq %d, %d bytes" %
                     (nlpacket.get_type_string(), nlpacket.pid, nlpacket.seq, nlpacket.length))

        header_PACK = NetlinkPacket.header_PACK
        header_LEN = NetlinkPacket.header_LEN
        null_read = 0
        nle_intr_count = 0
        MAX_NULL_READS = 3
        MAX_ERROR_NLE_INTR = 3
        msgs = []

        # Now listen to our socket and wait for the reply
        while True:

            if self.shutdown_flag:
                log.info('shutdown flag is True, exiting')
                return msgs

            # Only block for 1 second so we can wake up to see if self.shutdown_flag is True
            try:
                (readable, writeable, exceptional) = select([self.tx_socket, ], [], [self.tx_socket, ], 1)
            except Exception as e:
                # 4 is Interrupted system call
                if isinstance(e.args, tuple) and e[0] == 4:
                    nle_intr_count += 1
                    log.info("select() Interrupted system call %d/%d" % (nle_intr_count, MAX_ERROR_NLE_INTR))

                    if nle_intr_count >= MAX_ERROR_NLE_INTR:
                        raise NetlinkInterruptedSystemCall(error_str)
                    else:
                        continue
                else:
                    raise

            if readable:
                null_read = 0
            else:
                null_read += 1

                # Safety net to make sure we do not spend too much time in
                # this while True loop
                if null_read >= MAX_NULL_READS:
                    log.info('Socket was not readable for %d attempts' % null_read)
                    return msgs
                else:
                    continue

            for s in readable:
                data = []

                try:
                    data = s.recv(4096)
                except Exception as e:
                    # 4 is Interrupted system call
                    if isinstance(e.args, tuple) and e[0] == 4:
                        nle_intr_count += 1
                        log.info("%s: recv() Interrupted system call %d/%d" % (s, nle_intr_count, MAX_ERROR_NLE_INTR))

                        if nle_intr_count >= MAX_ERROR_NLE_INTR:
                            raise NetlinkInterruptedSystemCall(error_str)
                        else:
                            continue
                    else:
                        raise

                if not data:
                    log.info('RXed zero length data, the socket is closed')
                    return msgs

                while data:

                    # Extract the length, etc from the header
                    (length, msgtype, flags, seq, pid) = unpack(header_PACK, data[:header_LEN])

                    debug_str = "RXed %12s, pid %d, seq %d, %d bytes" % (NetlinkPacket.type_to_string[msgtype], pid, seq, length)

                    # This shouldn't happen but it would be nice to be aware of it if it does
                    if pid != nlpacket.pid:
                        log.debug(debug_str + '...we are not interested in this pid %s since ours is %s' %
                                    (pid, nlpacket.pid))
                        data = data[length:]
                        continue

                    if seq != nlpacket.seq:
                        log.debug(debug_str + '...we are not interested in this seq %s since ours is %s' %
                                    (seq, nlpacket.seq))
                        data = data[length:]
                        continue

                    # See if we RXed an ACK for our RTM_GETXXXX
                    if msgtype == NLMSG_DONE:
                        log.debug(debug_str + '...this is an ACK')
                        return msgs

                    elif msgtype == NLMSG_ERROR:

                        msg = Error(msgtype, nlpacket.debug)
                        msg.decode_packet(length, flags, seq, pid, data)

                        # The error code is a signed negative number.
                        error_code = abs(msg.negative_errno)

                        # 0 is NLE_SUCCESS...everything else is a true error
                        if error_code:

                            if self.debug:
                                msg.dump()

                            try:
                                # os.strerror might raise ValueError
                                strerror = os.strerror(error_code)

                                if strerror:
                                    error_str = "operation failed with '%s' (%s)" % (strerror, error_code)
                                else:
                                    error_str = "operation failed with code %s" % error_code

                            except ValueError:
                                error_str = "operation failed with code %s" % error_code

                            raise NetlinkError(error_str)
                        else:
                            log.debug('%s code NLE_SUCCESS...this is an ACK' % debug_str)
                            return msgs

                    # No ACK...create a nlpacket object and append it to msgs
                    else:
                        nle_intr_count = 0

                        if msgtype == RTM_NEWLINK or msgtype == RTM_DELLINK:
                            msg = Link(msgtype, nlpacket.debug, use_color=self.use_color)

                        elif msgtype == RTM_NEWADDR or msgtype == RTM_DELADDR:
                            msg = Address(msgtype, nlpacket.debug, use_color=self.use_color)

                        elif msgtype == RTM_NEWNEIGH or msgtype == RTM_DELNEIGH:
                            msg = Neighbor(msgtype, nlpacket.debug, use_color=self.use_color)

                        elif msgtype == RTM_NEWROUTE or msgtype == RTM_DELROUTE:
                            msg = Route(msgtype, nlpacket.debug, use_color=self.use_color)

                        elif msgtype in (RTM_GETNETCONF, RTM_NEWNETCONF):
                            msg = Netconf(msgtype, nlpacket.debug, use_color=self.use_color)

                        elif msgtype in (RTM_GETMDB, RTM_NEWMDB, RTM_DELMDB):
                            msg = MDB(msgtype, nlpacket.debug, use_color=self.use_color)

                        else:
                            raise Exception("RXed unknown netlink message type %s" % msgtype)

                        msg.decode_packet(length, flags, seq, pid, data)
                        msgs.append(msg)

                        if nlpacket.debug:
                            msg.dump()

                    data = data[length:]

    def ip_to_afi(self, ip):
        if ip.version == 4:
            return socket.AF_INET
        elif ip.version == 6:
            return socket.AF_INET6
        else:
            raise Exception("%s is an invalid IP type" % type(ip))

    def request_dump(self, rtm_type, family, debug):
        """
        Issue a RTM_GETROUTE, etc with the NLM_F_DUMP flag
        set and return the results
        """

        if rtm_type == RTM_GETADDR:
            msg = Address(rtm_type, debug, use_color=self.use_color)
            msg.body = pack('Bxxxi', family, 0)

        elif rtm_type == RTM_GETLINK:
            msg = Link(rtm_type, debug, use_color=self.use_color)
            msg.body = pack('Bxxxiii', family, 0, 0, 0)

        elif rtm_type == RTM_GETNEIGH:
            msg = Neighbor(rtm_type, debug, use_color=self.use_color)
            msg.body = pack('Bxxxii', family, 0, 0)

        elif rtm_type == RTM_GETROUTE:
            msg = Route(rtm_type, debug, use_color=self.use_color)
            msg.body = pack('Bxxxii', family, 0, 0)

        elif rtm_type == RTM_GETMDB:
            msg = MDB(rtm_type, debug, use_color=self.use_color)
            msg.body = pack('Bxxxii', family, 0, 0)

        else:
            log.error("request_dump RTM_GET %s is not supported" % rtm_type)
            return None

        msg.flags = NLM_F_REQUEST | NLM_F_DUMP
        msg.attributes = {}
        msg.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(msg)

    # ======
    # Routes
    # ======
    def _routes_add_or_delete(self, add_route, routes, ecmp_routes, table, protocol, route_scope, route_type):

        def tx_or_concat_message(total_message, route):
            """
            Adding an ipv4 route only takes 60 bytes, if we are adding thousands
            of them this can add up to a lot of send calls.  Concat several of
            them together before TXing.
            """

            if not total_message:
                total_message = route.message
            else:
                total_message += route.message

            if len(total_message) >= PACKET_CONCAT_SIZE:
                self.tx_nlpacket_raw(total_message)
                total_message = None

            return total_message

        if add_route:
            rtm_command = RTM_NEWROUTE
        else:
            rtm_command = RTM_DELROUTE

        total_message = None
        PACKET_CONCAT_SIZE = 16384
        debug = rtm_command in self.debug

        if routes:
            for (afi, ip, mask, nexthop, interface_index) in routes:
                route = Route(rtm_command, debug, use_color=self.use_color)
                route.flags = NLM_F_REQUEST | NLM_F_CREATE
                route.body = pack('BBBBBBBBi', afi, mask, 0, 0, table, protocol,
                                  route_scope, route_type, 0)
                route.family = afi
                route.add_attribute(Route.RTA_DST, ip)
                if nexthop:
                    route.add_attribute(Route.RTA_GATEWAY, nexthop)
                route.add_attribute(Route.RTA_OIF, interface_index)
                route.build_message(next(self.sequence), self.pid)
                total_message = tx_or_concat_message(total_message, route)

            if total_message:
                self.tx_nlpacket_raw(total_message)

        if ecmp_routes:

            for (route_key, value) in ecmp_routes.items():
                (afi, ip, mask) = route_key

                route = Route(rtm_command, debug, use_color=self.use_color)
                route.flags = NLM_F_REQUEST | NLM_F_CREATE
                route.body = pack('BBBBBBBBi', afi, mask, 0, 0, table, protocol,
                                  route_scope, route_type, 0)
                route.family = afi
                route.add_attribute(Route.RTA_DST, ip)
                route.add_attribute(Route.RTA_MULTIPATH, value)
                route.build_message(next(self.sequence), self.pid)
                total_message = tx_or_concat_message(total_message, route)

            if total_message:
                self.tx_nlpacket_raw(total_message)

    def routes_add(self, routes, ecmp_routes,
                   table=Route.RT_TABLE_MAIN,
                   protocol=Route.RT_PROT_XORP,
                   route_scope=Route.RT_SCOPE_UNIVERSE,
                   route_type=Route.RTN_UNICAST):
        self._routes_add_or_delete(True, routes, ecmp_routes, table, protocol, route_scope, route_type)

    def routes_del(self, routes, ecmp_routes,
                   table=Route.RT_TABLE_MAIN,
                   protocol=Route.RT_PROT_XORP,
                   route_scope=Route.RT_SCOPE_UNIVERSE,
                   route_type=Route.RTN_UNICAST):
        self._routes_add_or_delete(False, routes, ecmp_routes, table, protocol, route_scope, route_type)

    def route_get(self, ip, debug=False):
        """
        ip must be ipnetwork.IPNetwork
        """
        # Transmit a RTM_GETROUTE to query for the route we want
        route = Route(RTM_GETROUTE, debug, use_color=self.use_color)
        route.flags = NLM_F_REQUEST | NLM_F_ACK

        # Set everything in the service header as 0 other than the afi
        afi = self.ip_to_afi(ip)
        route.body = pack('Bxxxxxxxi', afi, 0)
        route.family = afi
        route.add_attribute(Route.RTA_DST, ip)
        route.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(route)

    def routes_dump(self, family=socket.AF_UNSPEC, debug=True):
        return self.request_dump(RTM_GETROUTE, family, debug)

    def routes_print(self, routes):
        """
        Print a table of 'routes'
        """
        print("Prefix            Nexthop           ifindex")

        for x in routes:
            if Route.RTA_DST not in x.attributes:
                log.warning("Route is missing RTA_DST")
                continue

            ip = "%s/%d" % (x.attributes[Route.RTA_DST].value, x.src_len)
            print("%-15s   %-15s   %s" %\
                (ip,
                 str(x.attributes[Route.RTA_GATEWAY].value) if Route.RTA_GATEWAY in x.attributes else None,
                 x.attributes[Route.RTA_OIF].value))

    # =====
    # Links
    # =====
    def _get_iface_by_name(self, ifname):
        """
        Return a Link object for ifname
        """
        debug = RTM_GETLINK in self.debug

        link = Link(RTM_GETLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('=Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
        link.add_attribute(Link.IFLA_IFNAME, ifname)
        link.build_message(next(self.sequence), self.pid)

        try:
            return self.tx_nlpacket_get_response(link)[0]

        except NetlinkNoAddressError:
            log.info("Netlink did not find interface %s" % ifname)
            return None

    def _get_iface_by_index(self, ifindex):
        """
        Return a Link object for ifindex
        """
        debug = RTM_GETLINK in self.debug

        link = Link(RTM_GETLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('=Bxxxiii', socket.AF_UNSPEC, ifindex, 0, 0)
        link.build_message(next(self.sequence), self.pid)
        try:
            return self.tx_nlpacket_get_response(link)[0]
        except NetlinkNoAddressError:
            log.info("Netlink did not find interface %s" % ifindex)
            return None

    def get_iface_index(self, ifname):
        """
        Return the interface index for ifname
        """
        iface = self._get_iface_by_name(ifname)

        if iface:
            return iface.ifindex
        return None

    def get_iface_name(self, ifindex):
        iface = self._get_iface_by_index(ifindex)

        if iface:
            return iface.attributes[Link.IFLA_IFNAME].get_pretty_value(str)
        return None

    def link_dump(self, ifname=None):
        debug = RTM_GETLINK in self.debug
        msg = Link(RTM_GETLINK, debug, use_color=self.use_color)
        msg.body = pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
        msg.flags = NLM_F_REQUEST | NLM_F_ACK

        if ifname:
            msg.add_attribute(Link.IFLA_IFNAME, ifname)
        else:
            msg.flags |= NLM_F_DUMP

        msg.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(msg)

    def link_set_attrs(self, ifname, kind=None, slave_kind=None, ifindex=0, ifla={}, ifla_info_data={}, ifla_info_slave_data={}):
        debug = RTM_NEWLINK in self.debug

        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('Bxxxiii', socket.AF_UNSPEC, ifindex, 0, 0)

        for nl_attr, value in list(ifla.items()):
            link.add_attribute(nl_attr, value)

        if ifname:
            link.add_attribute(Link.IFLA_IFNAME, ifname)

        linkinfo = dict()

        if kind:
            linkinfo[Link.IFLA_INFO_KIND] = kind
            linkinfo[Link.IFLA_INFO_DATA] = ifla_info_data
        elif slave_kind:
            linkinfo[Link.IFLA_INFO_SLAVE_KIND] = slave_kind,
            linkinfo[Link.IFLA_INFO_SLAVE_DATA] = ifla_info_slave_data

        link.add_attribute(Link.IFLA_LINKINFO, linkinfo)
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(link)

    def link_add_set(self, kind,
                     ifname=None,
                     ifindex=0,
                     slave_kind=None,
                     ifla={},
                     ifla_info_data={},
                     ifla_info_slave_data={}):
        """
        Build and TX a RTM_NEWLINK message to add the desired interface
        """
        debug = RTM_NEWLINK in self.debug

        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('Bxxxiii', socket.AF_UNSPEC, ifindex, 0, 0)

        for nl_attr, value in list(ifla.items()):
            link.add_attribute(nl_attr, value)

        if ifname:
            link.add_attribute(Link.IFLA_IFNAME, ifname)

        linkinfo = dict()
        if kind:
            linkinfo[Link.IFLA_INFO_KIND] = kind
            linkinfo[Link.IFLA_INFO_DATA] = ifla_info_data
        if slave_kind:
            linkinfo[Link.IFLA_INFO_SLAVE_KIND] = slave_kind
            linkinfo[Link.IFLA_INFO_SLAVE_DATA] = ifla_info_slave_data
        link.add_attribute(Link.IFLA_LINKINFO, linkinfo)

        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(link)

    def link_del(self, ifindex=None, ifname=None):
        if not ifindex and not ifname:
            raise ValueError('invalid ifindex and/or ifname')

        if not ifindex:
            ifindex = self.get_iface_index(ifname)

        debug = RTM_DELLINK in self.debug

        link = Link(RTM_DELLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('Bxxxiii', socket.AF_UNSPEC, ifindex, 0, 0)
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(link)

    def _link_add(self, ifindex, ifname, kind, ifla_info_data, mtu=None):
        """
        Build and TX a RTM_NEWLINK message to add the desired interface
        """
        debug = RTM_NEWLINK in self.debug

        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
        link.add_attribute(Link.IFLA_IFNAME, ifname)

        if ifindex:
            link.add_attribute(Link.IFLA_LINK, ifindex)

        if mtu:
            link.add_attribute(Link.IFLA_MTU, mtu)

        link.add_attribute(Link.IFLA_LINKINFO, {
            Link.IFLA_INFO_KIND: kind,
            Link.IFLA_INFO_DATA: ifla_info_data
        })
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(link)

    def link_add_bridge(self, ifname, ifla_info_data={}, mtu=None):
        return self._link_add(ifindex=None, ifname=ifname, kind='bridge', ifla_info_data=ifla_info_data, mtu=mtu)

    def link_add_vlan(self, ifindex, ifname, vlanid, vlan_protocol=None):
        """
        ifindex is the index of the parent interface that this sub-interface
        is being added to
        """

        '''
        If you name an interface swp2.17 but assign it to vlan 12, the kernel
        will return a very misleading NLE_MSG_OVERFLOW error.  It only does
        this check if the ifname uses dot notation.

        Do this check here so we can provide a more intuitive error
        '''
        if '.' in ifname:
            ifname_vlanid = int(ifname.split('.')[-1])

            if ifname_vlanid != vlanid:
                raise InvalidInterfaceNameVlanCombo("Interface %s must belong "
                                                    "to VLAN %d (VLAN %d was requested)" %
                                                    (ifname, ifname_vlanid, vlanid))

        ifla_info_data = {Link.IFLA_VLAN_ID: vlanid}

        if vlan_protocol:
            ifla_info_data[Link.IFLA_VLAN_PROTOCOL] = vlan_protocol

        return self._link_add(ifindex, ifname, 'vlan', ifla_info_data)

    def link_add_macvlan(self, ifindex, ifname, macvlan_mode):
        """
        ifindex is the index of the parent interface that this sub-interface
        is being added to
        """
        return self._link_add(
            ifindex,
            ifname,
            'macvlan',
            {
                Link.IFLA_MACVLAN_MODE: {
                    "private": Link.MACVLAN_MODE_PRIVATE,
                    "vepa": Link.MACVLAN_MODE_VEPA,
                    "bridge": Link.MACVLAN_MODE_BRIDGE,
                    "passthru": Link.MACVLAN_MODE_PASSTHRU
                }.get(macvlan_mode, Link.MACVLAN_MODE_PRIVATE)
            }
        )

    def vlan_get(self, filter_ifindex=None, filter_vlanid=None, compress_vlans=True):
        """
        filter_ifindex should be a tuple if interface indexes, this is a whitelist filter
        filter_vlandid should be a tuple if VLAN IDs, this is a whitelist filter
        """
        debug = RTM_GETLINK in self.debug

        link = Link(RTM_GETLINK, debug, use_color=self.use_color)
        link.family = AF_BRIDGE
        link.flags = NLM_F_DUMP | NLM_F_REQUEST
        link.body = pack('Bxxxiii', socket.AF_BRIDGE, 0, 0, 0)

        if compress_vlans:
            link.add_attribute(Link.IFLA_EXT_MASK, Link.RTEXT_FILTER_BRVLAN_COMPRESSED)
        else:
            link.add_attribute(Link.IFLA_EXT_MASK, Link.RTEXT_FILTER_BRVLAN)

        link.build_message(next(self.sequence), self.pid)
        reply = self.tx_nlpacket_get_response(link)

        iface_vlans = {}

        for msg in reply:
            if msg.family != socket.AF_BRIDGE:
                continue

            if filter_ifindex and msg.ifindex not in filter_ifindex:
                continue

            ifla_af_spec = msg.get_attribute_value(Link.IFLA_AF_SPEC)

            if not ifla_af_spec:
                continue

            ifname = msg.get_attribute_value(Link.IFLA_IFNAME)

            '''
            Example IFLA_AF_SPEC

              20: 0x1c001a00  ....  Length 0x001c (28), Type 0x001a (26) IFLA_AF_SPEC
              21: 0x08000200  ....  Nested Attribute - Length 0x0008 (8),  Type 0x0002 (2) IFLA_BRIDGE_VLAN_INFO
              22: 0x00000a00  ....
              23: 0x08000200  ....  Nested Attribute - Length 0x0008 (8),  Type 0x0002 (2) IFLA_BRIDGE_VLAN_INFO
              24: 0x00001000  ....
              25: 0x08000200  ....  Nested Attribute - Length 0x0008 (8),  Type 0x0002 (2) IFLA_BRIDGE_VLAN_INFO
              26: 0x00001400  ....
            '''
            for (x_type, x_value) in ifla_af_spec.items():
                if x_type == Link.IFLA_BRIDGE_VLAN_INFO:
                    for (vlan_flag, vlan_id) in x_value:
                        if filter_vlanid is None or vlan_id in filter_vlanid:

                            if ifname not in iface_vlans:
                                iface_vlans[ifname] = []

                            # We store these in the tuple as (vlan, flag) instead (flag, vlan)
                            # so that we can sort the list of tuples
                            iface_vlans[ifname].append((vlan_id, vlan_flag))

        return iface_vlans

    def vlan_show(self, filter_ifindex=None, filter_vlanid=None, compress_vlans=True):

        def vlan_flag_to_string(vlan_flag):
            flag_str = []
            if vlan_flag & Link.BRIDGE_VLAN_INFO_PVID:
                flag_str.append('PVID')

            if vlan_flag & Link.BRIDGE_VLAN_INFO_UNTAGGED:
                flag_str.append('Egress Untagged')

            return ', '.join(flag_str)

        iface_vlans = self.vlan_get(filter_ifindex, filter_vlanid, compress_vlans)
        log.debug("iface_vlans:\n%s\n" % pformat(iface_vlans))
        range_begin_vlan_id = None
        range_flag = 0

        print("   Interface  VLAN  Flags")
        print("  ==========  ====  =====")

        for (ifname, vlan_tuples) in sorted(iface_vlans.items()):
            for (vlan_id, vlan_flag) in sorted(vlan_tuples):

                if vlan_flag & Link.BRIDGE_VLAN_INFO_RANGE_BEGIN:
                    range_begin_vlan_id = vlan_id
                    range_flag = vlan_flag

                elif vlan_flag & Link.BRIDGE_VLAN_INFO_RANGE_END:
                    range_flag |= vlan_flag

                    if not range_begin_vlan_id:
                        log.warning("BRIDGE_VLAN_INFO_RANGE_END is %d but we never saw a BRIDGE_VLAN_INFO_RANGE_BEGIN" % vlan_id)
                        range_begin_vlan_id = vlan_id

                    for x in range(range_begin_vlan_id, vlan_id + 1):
                        print("  %10s  %4d  %s" % (ifname, x, vlan_flag_to_string(vlan_flag)))
                        ifname = ''

                    range_begin_vlan_id = None
                    range_flag = 0

                else:
                    print("  %10s  %4d  %s" % (ifname, vlan_id, vlan_flag_to_string(vlan_flag)))
                    ifname = ''


    def vlan_modify(self, msgtype, ifindex, vlanid_start, vlanid_end=None, bridge_self=False, bridge_master=False, pvid=False, untagged=False):
        """
        iproute2 bridge/vlan.c vlan_modify()
        """
        assert msgtype in (RTM_SETLINK, RTM_DELLINK), "Invalid msgtype %s, must be RTM_SETLINK or RTM_DELLINK" % msgtype
        assert vlanid_start >= 1 and vlanid_start <= 4096, "Invalid VLAN start %s" % vlanid_start

        if vlanid_end is None:
            vlanid_end = vlanid_start

        assert vlanid_end >= 1 and vlanid_end <= 4096, "Invalid VLAN end %s" % vlanid_end
        assert vlanid_start <= vlanid_end, "Invalid VLAN range %s-%s, start must be <= end" % (vlanid_start, vlanid_end)

        debug = msgtype in self.debug
        bridge_flags = 0
        vlan_info_flags = 0

        link = Link(msgtype, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('Bxxxiii', socket.AF_BRIDGE, ifindex, 0, 0)

        if bridge_self:
            bridge_flags |= Link.BRIDGE_FLAGS_SELF

        if bridge_master:
            bridge_flags |= Link.BRIDGE_FLAGS_MASTER

        if pvid:
            vlan_info_flags |= Link.BRIDGE_VLAN_INFO_PVID

        if untagged:
            vlan_info_flags |= Link.BRIDGE_VLAN_INFO_UNTAGGED

        ifla_af_spec = OrderedDict()

        if bridge_flags:
            ifla_af_spec[Link.IFLA_BRIDGE_FLAGS] = bridge_flags

        # just one VLAN
        if vlanid_start == vlanid_end:
            ifla_af_spec[Link.IFLA_BRIDGE_VLAN_INFO] = [(vlan_info_flags, vlanid_start), ]

        # a range of VLANs
        else:
            ifla_af_spec[Link.IFLA_BRIDGE_VLAN_INFO] = [
                (vlan_info_flags | Link.BRIDGE_VLAN_INFO_RANGE_BEGIN, vlanid_start),
                (vlan_info_flags | Link.BRIDGE_VLAN_INFO_RANGE_END, vlanid_end)
            ]

        link.add_attribute(Link.IFLA_AF_SPEC, ifla_af_spec)
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(link)

    def link_add_bridge_vlan(self, ifindex, vlanid_start, vlanid_end=None, pvid=False, untagged=False, master=False):
        """
        Add VLAN(s) to a bridge interface
        """
        bridge_self = False if master else True
        self.vlan_modify(RTM_SETLINK, ifindex, vlanid_start, vlanid_end, bridge_self, master, pvid, untagged)

    def link_del_bridge_vlan(self, ifindex, vlanid_start, vlanid_end=None, pvid=False, untagged=False, master=False):
        """
        Delete VLAN(s) from a bridge interface
        """
        bridge_self = False if master else True
        self.vlan_modify(RTM_DELLINK, ifindex, vlanid_start, vlanid_end, bridge_self, master, pvid, untagged)

    def link_set_updown(self, ifname, state):
        """
        Either bring ifname up or take it down
        """

        if state == 'up':
            if_flags = Link.IFF_UP
        elif state == 'down':
            if_flags = 0
        else:
            raise Exception('Unsupported state %s, valid options are "up" and "down"' % state)

        debug = RTM_NEWLINK in self.debug
        if_change = Link.IFF_UP

        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('=BxxxiLL', socket.AF_UNSPEC, 0, if_flags, if_change)
        link.add_attribute(Link.IFLA_IFNAME, ifname)
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(link)

    def link_set_protodown(self, ifname, state):
        """
        Either bring ifname up or take it down by setting IFLA_PROTO_DOWN on or off
        """
        flags = 0
        protodown = 1 if state == "on" else 0

        debug = RTM_NEWLINK in self.debug

        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('=BxxxiLL', socket.AF_UNSPEC, 0, 0, 0)
        link.add_attribute(Link.IFLA_IFNAME, ifname)
        link.add_attribute(Link.IFLA_PROTO_DOWN, protodown)
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(link)

    def link_set_master(self, ifname, master_ifindex=0, state=None):
        """
            ip link set %ifname master %master_ifindex %state
            use master_ifindex=0 for nomaster
        """
        if state == 'up':
            if_change = Link.IFF_UP
            if_flags = Link.IFF_UP
        elif state == 'down':
            if_change = Link.IFF_UP
            if_flags = 0
        else:
            if_change = 0
            if_flags = 0

        debug = RTM_NEWLINK in self.debug

        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('=BxxxiLL', socket.AF_UNSPEC, 0, if_flags, if_change)
        link.add_attribute(Link.IFLA_IFNAME, ifname)
        link.add_attribute(Link.IFLA_MASTER, master_ifindex)
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(link)

    # =========
    # Neighbors
    # =========
    def neighbor_add(self, afi, ifindex, ip, mac):
        debug = RTM_NEWNEIGH in self.debug
        service_hdr_flags = 0

        nbr = Neighbor(RTM_NEWNEIGH, debug, use_color=self.use_color)
        nbr.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
        nbr.family = afi
        nbr.body = pack('=BxxxiHBB', afi, ifindex, Neighbor.NUD_REACHABLE, service_hdr_flags, Route.RTN_UNICAST)
        nbr.add_attribute(Neighbor.NDA_DST, ip)
        nbr.add_attribute(Neighbor.NDA_LLADDR, mac)
        nbr.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(nbr)

    def neighbor_del(self, afi, ifindex, ip, mac):
        debug = RTM_DELNEIGH in self.debug
        service_hdr_flags = 0

        nbr = Neighbor(RTM_DELNEIGH, debug, use_color=self.use_color)
        nbr.flags = NLM_F_REQUEST | NLM_F_ACK
        nbr.family = afi
        nbr.body = pack('=BxxxiHBB', afi, ifindex, Neighbor.NUD_REACHABLE, service_hdr_flags, Route.RTN_UNICAST)
        nbr.add_attribute(Neighbor.NDA_DST, ip)
        nbr.add_attribute(Neighbor.NDA_LLADDR, mac)
        nbr.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(nbr)

    def link_add_vxlan(self, ifname, vxlanid, dstport=None, local=None,
                       group=None, learning=True, ageing=None, physdev=None, ttl=None, tos=None, udp_csum=True):

        debug = RTM_NEWLINK in self.debug

        info_data = {Link.IFLA_VXLAN_ID: int(vxlanid)}
        if dstport:
            info_data[Link.IFLA_VXLAN_PORT] = int(dstport)
        if local:
            info_data[Link.IFLA_VXLAN_LOCAL] = local
        if group:
            info_data[Link.IFLA_VXLAN_GROUP] = group
        if tos:
            info_data[Link.IFLA_VXLAN_TOS] = int(tos)
        
        info_data[Link.IFLA_VXLAN_UDP_CSUM] = int(udp_csum)
        info_data[Link.IFLA_VXLAN_LEARNING] = int(learning)
        info_data[Link.IFLA_VXLAN_TTL] = ttl

        if ageing:
            info_data[Link.IFLA_VXLAN_AGEING] = int(ageing)

        if physdev:
            info_data[Link.IFLA_VXLAN_LINK] = int(physdev)

        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
        link.body = pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
        link.add_attribute(Link.IFLA_IFNAME, ifname)
        link.add_attribute(Link.IFLA_LINKINFO, {
            Link.IFLA_INFO_KIND: "vxlan",
            Link.IFLA_INFO_DATA: info_data
        })

        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(link)

    # =========
    # Addresses
    # =========
    def addr_dump(self):
        """
            TODO: add ifname/ifindex filtering:
                        - via the RTM_GETADDR request packet
                        - or in python if kernel doesn't support per intf dump
        """
        debug = RTM_GETADDR in self.debug

        msg = Address(RTM_GETADDR, debug, use_color=self.use_color)
        msg.body = pack('=Bxxxi', socket.AF_UNSPEC, 0)
        msg.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP

        msg.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(msg)

    # =======
    # Netconf
    # =======
    def netconf_dump(self):
        """
            The attribute Netconf.NETCONFA_IFINDEX is available but don't let it fool you
            it seems like the kernel doesn't really care about this attribute and will dump
            everything according of the requested family (AF_UNSPEC for everything).
            Device filtering needs to be done afterwards by the user.
        """
        debug = RTM_GETNETCONF in self.debug
        msg = Netconf(RTM_GETNETCONF, debug, use_color=self.use_color)
        msg.body = pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
        msg.flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK
        msg.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(msg)

    # ===
    # MDB
    # ===
    def mdb_dump(self):
        debug = RTM_GETMDB in self.debug
        msg = MDB(RTM_GETMDB, debug, use_color=self.use_color)
        msg.body = pack('Bxxxiii', socket.AF_BRIDGE, 0, 0, 0)
        msg.flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK
        msg.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response(msg)
