#!/usr/bin/env python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Scott Feldman, sfeldma@cumulusnetworks.com
#

from os import strerror
import select
from time import time
import socket
from ctypes import *
from errno import *
import logging

logger = logging.getLogger(__name__)

#
# from /usr/include/linux/netlink.h
#

NETLINK_ROUTE = 0            # Routing/device hook
NETLINK_UNUSED = 1           # Unused number
NETLINK_USERSOCK = 2         # Reserved for user mode socket protocols 
NETLINK_FIREWALL = 3         # Firewalling hook
NETLINK_INET_DIAG = 4        # INET socket monitoring
NETLINK_NFLOG = 5            # netfilter/iptables ULOG 
NETLINK_XFRM = 6             # ipsec 
NETLINK_SELINUX = 7          # SELinux event notifications 
NETLINK_ISCSI = 8            # Open-iSCSI 
NETLINK_AUDIT = 9            # auditing 
NETLINK_FIB_LOOKUP = 10	
NETLINK_CONNECTOR = 11
NETLINK_NETFILTER = 12       # netfilter subsystem 
NETLINK_IP6_FW = 13
NETLINK_DNRTMSG = 14         # DECnet routing messages 
NETLINK_KOBJECT_UEVENT = 15  # Kernel messages to userspace 
NETLINK_GENERIC = 16
NETLINK_SCSITRANSPORT = 18   # SCSI Transports 
NETLINK_ECRYPTFS = 19
NETLINK_RDMA = 20
NETLINK_CRYPTO = 21          # Crypto layer 

NLMSG_NOOP = 1        # Nothing.
NLMSG_ERROR = 2       # Error
NLMSG_DONE = 3        # End of a dump
NLMSG_OVERRUN = 4     # Data lost

NETLINK_NO_ENOBUFS = 5

SOL_NETLINK = 270

class Nlmsghdr(Structure):

    _fields_ = [
        ('nlmsg_len', c_uint32),
        ('nlmsg_type', c_uint16),
        ('nlmsg_flags', c_uint16),
        ('nlmsg_seq', c_uint32),
        ('nlmsg_pid', c_uint32)
    ]

    def dump(self):
        print 'nlmsg_len', self.nlmsg_len
        print 'nlmsg_type', self.nlmsg_type
        print 'nlmsg_flags 0x%04x' % self.nlmsg_flags
        print 'nlmsg_seq', self.nlmsg_seq
        print 'nlmsg_pid', self.nlmsg_pid

# Flags values

NLM_F_REQUEST = 1          # It is request message.
NLM_F_MULTI = 2            # Multipart message, terminated by NLMSG_DONE
NLM_F_ACK = 4              # Reply with ack, with zero or error code
NLM_F_ECHO = 8             # Echo this request
NLM_F_DUMP_INTR = 16       # Dump was inconsistent due to sequence change

# Modifiers to GET request
NLM_F_ROOT = 0x100         # specify tree root
NLM_F_MATCH = 0x200        # return all matching
NLM_F_ATOMIC = 0x400       # atomic GET
NLM_F_DUMP = (NLM_F_ROOT|NLM_F_MATCH)

# Modifiers to NEW request
NLM_F_REPLACE = 0x100      # Override existing
NLM_F_EXCL = 0x200         # Do not touch, if it exists
NLM_F_CREATE = 0x400       # Create, if it does not exist
NLM_F_APPEND = 0x800       # Add to end of list

NLMSG_ALIGNTO = 4
def NLMSG_ALIGN(len):
    return (len + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)
def NLMSG_HDRLEN():
    return NLMSG_ALIGN(sizeof(Nlmsghdr))
def NLMSG_LENGTH(len):
    return len + NLMSG_ALIGN(NLMSG_HDRLEN())
def NLMSG_SPACE(len):
    return NLMSG_ALIGN(NLMSG_LENGTH(len))
def NLMSG_DATA(nlh):
    return addressof(nlh) + NLMSG_LENGTH(0)
def NLMSG_NEXT(nlh, len):
    cur = NLMSG_ALIGN(nlh.nlmsg_len)
    nlh = Nlmsghdr.from_address(addressof(nlh) + cur)
    return len - cur, nlh
def NLMSG_OK(nlh, len):
    return len >= sizeof(Nlmsghdr) and \
        nlh.nlmsg_len >= sizeof(Nlmsghdr) and \
        nlh.nlmsg_len <= len

class Nlmsgerr(Structure):

    _fields_ = [
        ('error', c_int),
        ('msg', Nlmsghdr),
    ]

class NetlinkError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)
        #print(message)

class Netlink(socket.socket):

    def __init__(self, pid, proto):

        self.pid = pid
        self.recvbuf = bytearray(8 * 1024)
        self.sendbuf = bytearray(8 * 1024)
        self.seq = int(time())

        try:

            socket.socket.__init__(self, socket.AF_NETLINK, \
                socket.SOCK_RAW, proto)
            self.setblocking(0)

            # Need to turn off ENOBUFS for netlink socket otherwise
            # in a kernel overrun situation, the socket will return
            # ENOBUFS on socket recv and be stuck for future recvs.

            self.setsockopt(SOL_NETLINK, NETLINK_NO_ENOBUFS, 1)

        except socket.error as (errno, string):
            raise NetlinkError("open: socket err[%d]: %s" % \
                (errno, string))

    def bind(self, groups, cb):

        self._nl_cb = cb

        try:
            socket.socket.bind(self, (self.pid, groups))

        except socket.error as (errno, string):
            raise NetlinkError("bind: socket err[%d]: %s" % \
                (errno, string))

    def sendall(self, string):
        try:
            socket.socket.sendall(self, string)
        except socket.error as (errno, string):
            raise NetlinkError("send: socket err[%d]: %s" % \
                (errno, string))

    def _process_nlh(self, recv, nlh):
        while NLMSG_OK(nlh, recv):
            yield recv, nlh
            recv, nlh = NLMSG_NEXT(nlh, recv)

    def process(self, tokens=[]):

        found_done = False

        try:
            recv, src_addr = self.recvfrom_into(self.recvbuf)
            if not recv:
                # EOF
                print "EOF"
                return False

        except socket.error as (errno, string):
            if errno in [EINTR, EAGAIN]:
                return False
            raise NetlinkError("netlink: socket err[%d]: %s" % \
                (errno, string))

        nlh = Nlmsghdr.from_buffer(self.recvbuf)
        for recv, nlh in self._process_nlh(recv, nlh):

#            print "type %u, seq %u, pid %u" % \
#                (nlh.nlmsg_type, nlh.nlmsg_seq, nlh.nlmsg_pid)

            l = nlh.nlmsg_len - sizeof(Nlmsghdr)

            if l < 0 or nlh.nlmsg_len > recv:
                raise NetlinkError("netlink: malformed msg: len %d" % \
                    nlh.nlmsg_len)

            if tokens:
                current = (nlh.nlmsg_pid, nlh.nlmsg_seq)
                if current not in tokens:
                    continue

            if nlh.nlmsg_type == NLMSG_DONE:
                found_done = True
                break

            if nlh.nlmsg_type == NLMSG_ERROR:
                err = Nlmsgerr.from_address(NLMSG_DATA(nlh))
                if err.error == 0:
                    return False
                raise NetlinkError("netlink: %s" % strerror(abs(err.error)))

            if self._nl_cb:
                self._nl_cb(nlh)

        if found_done:
            return False 

        remnant = recv - NLMSG_ALIGN(nlh.nlmsg_len) > 0
        if remnant:
            raise NetlinkError("netlink: remnant of size %d" % \
                remnant)

        return True

    def process_wait(self, tokens):
        while self.process(tokens):
            pass

    def process_forever(self):
        epoll = select.epoll()
        epoll.register(self.fileno(), select.EPOLLIN)
        while True:
            events = epoll.poll()
            for fileno, event in events:
                if fileno == self.fileno():
                    self.process()

    def process_event(self, event):
        return self.process()
