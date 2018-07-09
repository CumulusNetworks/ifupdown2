# Copyright (c) 2009-2013, Exa Networks Limited
# Copyright (c) 2009-2013, Thomas Mangin
# Copyright (c) 2015-2017 Cumulus Networks, Inc.
#
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# The names of the Exa Networks Limited, Cumulus Networks, Inc. nor the names
# of its contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import logging
import struct
from ipaddr import IPv4Address, IPv6Address, IPAddress
from binascii import hexlify
from pprint import pformat
from socket import AF_UNSPEC, AF_INET, AF_INET6, AF_BRIDGE, htons
from string import printable
from struct import pack, unpack, calcsize

log = logging.getLogger(__name__)
SYSLOG_EXTRA_DEBUG = 5


# Interface name buffer size #define IFNAMSIZ 16 (kernel source)
IF_NAME_SIZE = 15 # 15 because python doesn't have \0

# Netlink message types
NLMSG_NOOP    = 0x01
NLMSG_ERROR   = 0x02
NLMSG_DONE    = 0x03
NLMSG_OVERRUN = 0x04

RTM_NEWLINK   = 0x10  # Create a new network interface
RTM_DELLINK   = 0x11  # Destroy a network interface
RTM_GETLINK   = 0x12  # Retrieve information about a network interface(ifinfomsg)
RTM_SETLINK   = 0x13  #

RTM_NEWADDR   = 0x14
RTM_DELADDR   = 0x15
RTM_GETADDR   = 0x16

RTM_NEWNEIGH  = 0x1C
RTM_DELNEIGH  = 0x1D
RTM_GETNEIGH  = 0x1E

RTM_NEWROUTE  = 0x18
RTM_DELROUTE  = 0x19
RTM_GETROUTE  = 0x1A

RTM_NEWQDISC  = 0x24
RTM_DELQDISC  = 0x25
RTM_GETQDISC  = 0x26

# Netlink message flags
NLM_F_REQUEST = 0x01  # It is query message.
NLM_F_MULTI   = 0x02  # Multipart message, terminated by NLMSG_DONE
NLM_F_ACK     = 0x04  # Reply with ack, with zero or error code
NLM_F_ECHO    = 0x08  # Echo this query

# Modifiers to GET query
NLM_F_ROOT   = 0x100  # specify tree root
NLM_F_MATCH  = 0x200  # return all matching
NLM_F_DUMP   = NLM_F_ROOT | NLM_F_MATCH
NLM_F_ATOMIC = 0x400  # atomic GET

# Modifiers to NEW query
NLM_F_REPLACE = 0x100  # Override existing
NLM_F_EXCL    = 0x200  # Do not touch, if it exists
NLM_F_CREATE  = 0x400  # Create, if it does not exist
NLM_F_APPEND  = 0x800  # Add to end of list

NLA_F_NESTED        = 0x8000
NLA_F_NET_BYTEORDER = 0x4000
NLA_TYPE_MASK       = ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

# Groups
RTMGRP_LINK          = 0x1
RTMGRP_NOTIFY        = 0x2
RTMGRP_NEIGH         = 0x4
RTMGRP_TC            = 0x8
RTMGRP_IPV4_IFADDR   = 0x10
RTMGRP_IPV4_MROUTE   = 0x20
RTMGRP_IPV4_ROUTE    = 0x40
RTMGRP_IPV4_RULE     = 0x80
RTMGRP_IPV6_IFADDR   = 0x100
RTMGRP_IPV6_MROUTE   = 0x200
RTMGRP_IPV6_ROUTE    = 0x400
RTMGRP_IPV6_IFINFO   = 0x800
RTMGRP_DECnet_IFADDR = 0x1000
RTMGRP_DECnet_ROUTE  = 0x4000
RTMGRP_IPV6_PREFIX   = 0x20000

RTMGRP_ALL = (RTMGRP_LINK | RTMGRP_NOTIFY | RTMGRP_NEIGH | RTMGRP_TC |
              RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_MROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_RULE |
              RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_MROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFINFO |
              RTMGRP_DECnet_IFADDR | RTMGRP_DECnet_ROUTE |
              RTMGRP_IPV6_PREFIX)

AF_MPLS = 28

# Colors for logging
red    = 91
green  = 92
yellow = 93
blue   = 94

value_to_bool_dict = {
    False: False,
    None: False,
    0: False,
    '0': False,
    'no': False,
    'off': False,
    'slow': False,
    'None': False,
    True: True,
    1: True,
    '1': True,
    'on': True,
    'yes': True,
    'fast': True
}


def set_log_level(level):
    log.setLevel(level)


def zfilled_hex(value, digits):
    return '0x' + hex(value)[2:].zfill(digits)


def remove_trailing_null(line):
    """
    Remove the last character if it is a NULL...having that NULL
    causes python to print a garbage character
    """

    if ord(line[-1]) == 0:
        line = line[:-1]

    return line


def mac_int_to_str(mac_int):
    """
    Return an integer in MAC string format
    """

    # [2:] to remove the leading 0x, then fill out to 12 zeroes, then uppercase
    all_caps = hex(int(mac_int))[2:].zfill(12).upper()

    if all_caps[-1] == 'L':
        all_caps = all_caps[:-1]
        all_caps = all_caps.zfill(12).upper()

    return "%s.%s.%s" % (all_caps[0:4], all_caps[4:8], all_caps[8:12])


def data_to_color_text(line_number, color, data, extra=''):
    (c1, c2, c3, c4) = unpack('BBBB', data[0:4])
    in_ascii = []

    for c in (c1, c2, c3, c4):
        char_c = chr(c)

        if char_c in printable[:-5]:
            in_ascii.append(char_c)
        else:
            in_ascii.append('.')

    if color:
        return '  %2d: \033[%dm0x%02x%02x%02x%02x\033[0m  %s  %s' % (line_number, color, c1, c2, c3, c4, ''.join(in_ascii), extra)

    return '  %2d: 0x%02x%02x%02x%02x  %s  %s' % (line_number, c1, c2, c3, c4, ''.join(in_ascii), extra)


def padded_length(length):
    return int((length + 3) / 4) * 4


class Attribute(object):

    def __init__(self, atype, string, logger):
        self.atype = atype
        self.string = string
        self.HEADER_PACK = '=HH'
        self.HEADER_LEN = calcsize(self.HEADER_PACK)
        self.PACK = None
        self.LEN = None
        self.value = None
        self.nested = False
        self.net_byteorder = False
        self.log = logger

    def __str__(self):
        return self.string

    def set_value(self, value):
        self.value = value

    def set_nested(self, nested):
        self.nested = nested

    def set_net_byteorder(self, net_byteorder):
        self.net_byteorder = net_byteorder

    def pad_bytes_needed(self, length):
        """
        Return the number of bytes that should be added to align on a 4-byte boundry
        """
        remainder = length % 4

        if remainder:
            return 4 - remainder

        return 0

    def pad(self, length, raw):
        pad = self.pad_bytes_needed(length)

        if pad:
            raw += '\0' * pad

        return raw

    def encode(self):

        if not self.LEN:
            raise Exception('Please define an encode() method in your child attribute class, or do not use AttributeGeneric')

        length = self.HEADER_LEN + self.LEN
        attr_type_with_flags = self.atype

        if self.nested:
            attr_type_with_flags = attr_type_with_flags | NLA_F_NESTED

        if self.net_byteorder:
            attr_type_with_flags = attr_type_with_flags | NLA_F_NET_BYTEORDER

        raw = pack(self.HEADER_PACK, length, attr_type_with_flags) + pack(self.PACK, self.value)
        raw = self.pad(length, raw)
        return raw

    def decode_length_type(self, data):
        """
        The first two bytes of an attribute are the length, the next two bytes are the type
        """
        self.data = data
        prev_atype = self.atype
        (data1, data2) = unpack(self.HEADER_PACK, data[:self.HEADER_LEN])
        self.length = int(data1)
        self.atype = int(data2)
        self.attr_end = padded_length(self.length)

        self.nested = True if self.atype & NLA_F_NESTED else False
        self.net_byteorder = True if self.atype & NLA_F_NET_BYTEORDER else False
        self.atype = self.atype & NLA_TYPE_MASK

        # Should never happen
        assert self.atype == prev_atype, "This object changes attribute type from %d to %d, this is bad" % (prev_atype, self.atype)

    def dump_first_line(self, dump_buffer, line_number, color):
        """
        Add the "Length....Type..." line to the dump buffer
        """
        if self.attr_end == self.length:
            padded_to = ', '
        else:
            padded_to = ' padded to %d, ' % self.attr_end

        extra = 'Length %s (%d)%sType %s%s%s (%d) %s' % \
                 (zfilled_hex(self.length, 4), self.length,
                  padded_to,
                  zfilled_hex(self.atype, 4),
                  " (NLA_F_NESTED set)" if self.nested else "",
                  " (NLA_F_NET_BYTEORDER set)" if self.net_byteorder else "",
                  self.atype,
                  self)

        dump_buffer.append(data_to_color_text(line_number, color, self.data[0:4], extra))
        return line_number + 1

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)

        for x in xrange(1, self.attr_end/4):
            start = x * 4
            end = start + 4
            dump_buffer.append(data_to_color_text(line_number, color, self.data[start:end], ''))
            line_number += 1

        return line_number

    def get_pretty_value(self, obj=None):
        if obj and callable(obj):
            return obj(self.value)
        return self.value


class AttributeFourByteList(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        wordcount = (self.attr_end - 4)/4
        self.PACK = '=%dL' % wordcount
        self.LEN = calcsize(self.PACK)

        try:
            self.value = unpack(self.PACK, self.data[4:])
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        idx = 1
        for val in self.value:
            dump_buffer.append(data_to_color_text(line_number, color, self.data[4*idx:4*(idx+1)], val))
            line_number += 1
            idx += 1
        return line_number


class AttributeFourByteValue(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = '=L'
        self.LEN = calcsize(self.PACK)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        assert self.attr_end == 8, "Attribute length for %s must be 8, it is %d" % (self, self.attr_end)

        try:
            self.value = int(unpack(self.PACK, self.data[4:])[0])
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
        return line_number + 1


class AttributeTwoByteValue(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = '=Hxx'
        self.LEN = calcsize(self.PACK)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        assert self.attr_end == 8, "Attribute length for %s must be 8, it is %d" % (self, self.attr_end)

        try:
            self.value = int(unpack(self.PACK, self.data[4:8])[0])
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:6])))
            raise

    def encode(self):
        length = self.HEADER_LEN + self.LEN
        raw = pack(self.HEADER_PACK, length-2, self.atype) + pack(self.PACK, self.value)
        raw = self.pad(length, raw)
        return raw

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
        return line_number + 1


class AttributeString(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = None
        self.LEN = None

    def encode(self):
        # some interface names come from JSON as unicode strings
        # and cannot be packed as is so we must convert them to strings
        if isinstance(self.value, unicode):
            self.value = str(self.value)
        self.PACK = '%ds' % len(self.value)
        self.LEN = calcsize(self.PACK)

        length = self.HEADER_LEN + self.LEN
        raw = pack(self.HEADER_PACK, length, self.atype) + pack(self.PACK, self.value)
        raw = self.pad(length, raw)
        return raw

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        self.PACK = '%ds' % (self.length - 4)
        self.LEN = calcsize(self.PACK)

        try:
            self.value = remove_trailing_null(unpack(self.PACK, self.data[4:self.length])[0])
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:self.length])))
            raise


class AttributeStringInterfaceName(AttributeString):

    def __init__(self, atype, string, family, logger):
        AttributeString.__init__(self, atype, string, family, logger)

    def set_value(self, value):
        if value and len(value) > IF_NAME_SIZE:
            raise Exception('interface name exceeds max length of %d' % IF_NAME_SIZE)
        self.value = value


class AttributeIPAddress(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.value_int = None
        self.value_int_str = None
        self.family = family

        if self.family == AF_INET:
            self.PACK = '>L'

        elif self.family == AF_INET6:
            self.PACK = '>QQ'

        elif self.family == AF_BRIDGE:
            self.PACK = '>L'

        else:
            raise Exception("%s is not a supported address family" % self.family)

        self.LEN = calcsize(self.PACK)

    def set_value(self, value):
        if value is None:
            self.value = None
        else:
            self.value = IPAddress(value)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)

        try:
            if self.family == AF_INET:
                self.value = IPv4Address(unpack(self.PACK, self.data[4:])[0])

            elif self.family == AF_INET6:
                (data1, data2) = unpack(self.PACK, self.data[4:])
                self.value = IPv6Address(data1 << 64 | data2)

            elif self.family == AF_BRIDGE:
                self.value = IPv4Address(unpack(self.PACK, self.data[4:])[0])

            self.value_int = int(self.value)
            self.value_int_str = str(self.value_int)

        except struct.error:
            self.value = None
            self.value_int = None
            self.value_int_str = None
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise

    def encode(self):
        length = self.HEADER_LEN + self.LEN

        if self.family not in [AF_INET, AF_INET6, AF_BRIDGE]:
            raise Exception("%s is not a supported address family" % self.family)

        raw = pack(self.HEADER_PACK, length, self.atype) + self.value.packed
        raw = self.pad(length, raw)
        return raw

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)

        if self.family == AF_INET:
            dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
            line_number += 1

        elif self.family == AF_INET6:

            for x in xrange(1, self.attr_end/4):
                start = x * 4
                end = start + 4
                dump_buffer.append(data_to_color_text(line_number, color, self.data[start:end], self.value))
                line_number += 1

        elif self.family == AF_BRIDGE:
            dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
            line_number += 1

        return line_number


class AttributeMACAddress(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = '>LHxx'
        self.LEN = calcsize(self.PACK)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        
        # IFLA_ADDRESS and IFLA_BROADCAST attributes for all interfaces has been a
        # 6-byte MAC address. But the GRE interface uses a 4-byte IP address and 
        # GREv6 uses a 16-byte IPv6 address for this attribute.
        try:
            # GRE interface uses a 4-byte IP address for this attribute
            if self.length == 8:
                self.value = IPv4Address(unpack('>L', self.data[4:])[0])
                self.value_int = int(self.value)
                self.value_int_str = str(self.value_int)
            # MAC Address 
            elif self.length == 10:
                (data1, data2) = unpack(self.PACK, self.data[4:])
                self.value = mac_int_to_str(data1 << 16 | data2)
            # GREv6 interface uses a 16-byte IP address for this attribute 
            elif self.length == 20:
                self.value = IPv6Address(unpack('>L', self.data[16:])[0])
                self.value_int = int(self.value)
                self.value_int_str = str(self.value_int)
            else:
                raise Exception("Length of MACAddress attribute not supported: %d" % self.length)

        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise

    def encode(self):
        length = self.HEADER_LEN + self.LEN
        mac_raw = int(self.value.replace('.', '').replace(':', ''), 16)
        raw = pack(self.HEADER_PACK, length-2, self.atype) + pack(self.PACK, mac_raw >> 16, mac_raw & 0x0000FFFF)
        raw = self.pad(length, raw)
        return raw

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
        line_number += 1
        if len(self.data) >= 12:
            dump_buffer.append(data_to_color_text(line_number, color, self.data[8:12]))
            line_number += 1
        return line_number


class AttributeMplsLabel(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.value_int = None
        self.value_int_str = None
        self.family = family
        self.PACK = '>HBB'

    def decode(self, parent_msg, data):
        self.decode_length_type(data)

        try:
            (label_high, label_low_tc_s, self.ttl) = unpack(self.PACK, self.data[4:])
            self.s_bit = label_low_tc_s & 0x1
            self.traffic_class = ((label_low_tc_s & 0xf) >> 1)
            self.label = (label_high << 4) | (label_low_tc_s >> 4)
            self.value = self.label
            self.value_int = self.value
            self.value_int_str = str(self.value_int)

        except struct.error:
            self.value = None
            self.value_int = None
            self.value_int_str = None
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8],
                                              'label %s, TC %s, bottom-of-stack %s, TTL %d' %
                                              (self.label, self.traffic_class, self.s_bit, self.ttl)))
        line_number += 1

        return line_number


class AttributeGeneric(Attribute):

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.PACK = None
        self.LEN = None

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        wordcount = (self.attr_end - 4)/4
        self.PACK = '=%dL' % wordcount
        self.LEN = calcsize(self.PACK)

        try:
            self.value = ''.join(map(str, unpack(self.PACK, self.data[4:])))
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:])))
            raise


class AttributeOneByteValue(AttributeGeneric):

    def __init__(self, atype, string, family, logger):
        AttributeGeneric.__init__(self, atype, string, family, logger)
        self.PACK = '=Bxxx'
        self.LEN = calcsize(self.PACK)

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        assert self.attr_end == 8, "Attribute length for %s must be 8, it is %d" % (self, self.attr_end)

        try:
            self.value = int(unpack(self.PACK, self.data[4:8])[0])
        except struct.error:
            self.log.error("%s unpack of %s failed, data 0x%s" % (self, self.PACK, hexlify(self.data[4:5])))
            raise

    def encode(self):
        length = self.HEADER_LEN + self.LEN
        raw = pack(self.HEADER_PACK, length-3, self.atype) + pack(self.PACK, self.value)
        raw = self.pad(length, raw)
        return raw

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        dump_buffer.append(data_to_color_text(line_number, color, self.data[4:8], self.value))
        return line_number + 1


class AttributeIFLA_AF_SPEC(Attribute):
    """
    value will be a dictionary such as:
    {
        Link.IFLA_BRIDGE_FLAGS: flags,
        Link.IFLA_BRIDGE_VLAN_INFO: (vflags, vlanid)
    }
    """
    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.family = family

    def encode(self):
        pack_layout = [self.HEADER_PACK]
        payload = [0, self.atype | NLA_F_NESTED]
        attr_length_index = 0

        # For now this assumes that all data will be packed in the native endian
        # order (=). If a field is added that needs to be packed via network
        # order (>) then some smarts will need to be added to split the pack_layout
        # string at the >, split the payload and make the needed pack() calls.
        #
        # Until we cross that bridge though we will keep things nice and simple and
        # pack everything via a single pack() call.
        sub_attr_to_add = []

        for (sub_attr_type, sub_attr_value) in self.value.iteritems():

            if sub_attr_type == Link.IFLA_BRIDGE_FLAGS:
                sub_attr_to_add.append((sub_attr_type, sub_attr_value))

            elif sub_attr_type == Link.IFLA_BRIDGE_VLAN_INFO:
                for (vlan_flag, vlan_id) in sub_attr_value:
                    sub_attr_to_add.append((sub_attr_type, (vlan_flag, vlan_id)))

            else:
                self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_AF_SPEC sub-attribute type %d' % sub_attr_type)
                continue

        for (sub_attr_type, sub_attr_value) in sub_attr_to_add:
            sub_attr_pack_layout = ['=', 'HH']
            sub_attr_payload = [0, sub_attr_type]
            sub_attr_length_index = 0

            if sub_attr_type == Link.IFLA_BRIDGE_FLAGS:
                sub_attr_pack_layout.append('H')
                sub_attr_payload.append(sub_attr_value)

            elif sub_attr_type == Link.IFLA_BRIDGE_VLAN_INFO:
                sub_attr_pack_layout.append('HH')
                sub_attr_payload.append(sub_attr_value[0])
                sub_attr_payload.append(sub_attr_value[1])

            sub_attr_length = calcsize(''.join(sub_attr_pack_layout))
            sub_attr_payload[sub_attr_length_index] = sub_attr_length

            # add padding
            for x in xrange(self.pad_bytes_needed(sub_attr_length)):
                sub_attr_pack_layout.append('x')

            # The [1:] is to remove the leading = so that when we do the ''.join() later
            # we do not end up with an = in the middle of the pack layout string. There
            # will be an = at the beginning via self.HEADER_PACK
            sub_attr_pack_layout = sub_attr_pack_layout[1:]

            # Now extend the ovarall attribute pack_layout/payload to include this sub-attribute
            pack_layout.extend(sub_attr_pack_layout)
            payload.extend(sub_attr_payload)

        pack_layout = ''.join(pack_layout)

        # Fill in the length field
        length = calcsize(pack_layout)
        payload[attr_length_index] = length

        raw = pack(pack_layout, *payload)
        raw = self.pad(length, raw)
        return raw

    def decode(self, parent_msg, data):
        """
        value is a dictionary such as:
        {
            Link.IFLA_BRIDGE_FLAGS: flags,
            Link.IFLA_BRIDGE_VLAN_INFO: (vflags, vlanid)
        }

        FROM: David Ahern
        The encoding of the IFLA_AF_SPEC attribute varies depending on the family
        used for the request (RTM_GETLINK) message. For AF_UNSPEC the encoding
        has another level of nesting for each address family with the type encoded
        first. i.e.,
            af_spec = nla_nest_start(skb, IFLA_AF_SPEC)
            for each family:
                af = nla_nest_start(skb, af_ops->family)
                af_ops->fill_link_af(skb, dev, ext_filter_mask)
                nest_end
            nest_end

        This allows the parser to find the address family by looking at the first
        type.

        Whereas AF_BRIDGE encoding is just:
            af_spec = nla_nest_start(skb, IFLA_AF_SPEC)
            br_fill_ifvlaninfo{_compressed}(skb, vg)
            nest_end

        which means the parser can not use the attribute itself to know the family
        to which the attribute belongs.

        /include/uapi/linux/if_link.h
        /*
         * IFLA_AF_SPEC
         *   Contains nested attributes for address family specific attributes.
         *   Each address family may create a attribute with the address family
         *   number as type and create its own attribute structure in it.
         *
         *   Example:
         *   [IFLA_AF_SPEC] = {
         *       [AF_INET] = {
         *           [IFLA_INET_CONF] = ...,
         *       },
         *       [AF_INET6] = {
         *           [IFLA_INET6_FLAGS] = ...,
         *           [IFLA_INET6_CONF] = ...,
         *       }
         *   }
         */

        """
        self.decode_length_type(data)
        self.value = {}

        data = self.data[4:]

        while data:
            (sub_attr_length, sub_attr_type) = unpack('=HH', data[:4])
            sub_attr_end = padded_length(sub_attr_length)

            if not sub_attr_length:
                self.log.error('parsed a zero length sub-attr')
                return

            sub_attr_data = data[4:sub_attr_end]

            if self.family == AF_BRIDGE:
                if sub_attr_type == Link.IFLA_BRIDGE_FLAGS:
                    self.value[Link.IFLA_BRIDGE_FLAGS] = unpack("=H", sub_attr_data[0:2])[0]

                elif sub_attr_type == Link.IFLA_BRIDGE_VLAN_INFO:
                    if Link.IFLA_BRIDGE_VLAN_INFO not in self.value:
                        self.value[Link.IFLA_BRIDGE_VLAN_INFO] = []
                    self.value[Link.IFLA_BRIDGE_VLAN_INFO].append(tuple(unpack("=HH", sub_attr_data[0:4])))

                else:
                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_AF_SPEC sub-attribute '
                                                     'type %s (%d), length %d, padded to %d' %
                                 (parent_msg.get_ifla_bridge_af_spec_to_string(sub_attr_type),
                                  sub_attr_type, sub_attr_length, sub_attr_end))

            elif self.family == AF_UNSPEC:

                if sub_attr_type == AF_INET6:
                    inet6_attr = {}

                    while sub_attr_data:
                        (inet6_attr_length, inet6_attr_type) = unpack('=HH', sub_attr_data[:4])
                        inet6_attr_end = padded_length(inet6_attr_length)

                        # 1 byte attr
                        if inet6_attr_type == Link.IFLA_INET6_ADDR_GEN_MODE:
                            inet6_attr[inet6_attr_type] = unpack('=B', sub_attr_data[4])[0]
                            # nlmanager doesn't support multiple kernel version
                            # all the other attributes like IFLA_INET6_CONF are
                            # based on DEVCONF_MAX from _UAPI_IPV6_H.
                            # we can opti the code and break this loop once we
                            # found the attribute that we are interested in.
                            # It's not really worth going through all the other
                            # attributes to log that we don't support them yet
                            break
                        else:
                            self.log.log(
                                SYSLOG_EXTRA_DEBUG,
                                'Add support for decoding AF_INET6 IFLA_AF_SPEC '
                                'sub-attribute type %s (%d), length %d, padded to %d'
                                % (
                                    parent_msg.get_ifla_inet6_af_spec_to_string(inet6_attr_type),
                                    inet6_attr_type, inet6_attr_length, inet6_attr_end
                                )
                            )

                        sub_attr_data = sub_attr_data[inet6_attr_end:]
                    self.value[AF_INET6] = inet6_attr
                else:
                    self.value[sub_attr_type] = {}

                # Uncomment the following block to implement the AF_INET attributes
                # see Link.get_ifla_inet_af_spec_to_string (dict)
                #elif sub_attr_type == AF_INET:
                #    inet_attr = {}
                #
                #    while sub_attr_data:
                #        (inet_attr_length, inet_attr_type) = unpack('=HH', sub_attr_data[:4])
                #        inet_attr_end = padded_length(inet_attr_length)
                #
                #        self.log.error(
                #            # SYSLOG_EXTRA_DEBUG,
                #            'Add support for decoding AF_INET IFLA_AF_SPEC '
                #            'sub-attribute type %s (%d), length %d, padded to %d'
                #            % (
                #                parent_msg.get_ifla_inet_af_spec_to_string(inet_attr_type),
                #                inet_attr_type, inet_attr_length, inet_attr_end
                #            )
                #        )
                #
                #        sub_attr_data = sub_attr_data[inet_attr_end:]
                #
                #    self.value[AF_INET] = inet_attr
            else:
                self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_AF_SPEC sub-attribute '
                                                 'family %d, length %d, padded to %d'
                             % (self.family, sub_attr_length, sub_attr_end))

            data = data[sub_attr_end:]

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        extra = ''

        next_sub_attr_line = 0
        sub_attr_line = True

        for x in xrange(1, self.attr_end/4):
            start = x * 4
            end = start + 4

            if line_number == next_sub_attr_line:
                sub_attr_line = True

            if sub_attr_line:
                sub_attr_line = False

                (sub_attr_length, sub_attr_type) = unpack('=HH', self.data[start:start+4])
                sub_attr_end = padded_length(sub_attr_length)

                next_sub_attr_line = line_number + (sub_attr_end/4)

                if sub_attr_end == sub_attr_length:
                    padded_to = ','
                else:
                    padded_to = ' padded to %d,' % sub_attr_end

                if self.family == AF_BRIDGE:
                    extra = 'Nested Attribute - Length %s (%d)%s Type %s (%d) %s' % \
                            (zfilled_hex(sub_attr_length, 4), sub_attr_length,
                             padded_to,
                             zfilled_hex(sub_attr_type, 4), sub_attr_type,
                             Link.ifla_bridge_af_spec_to_string.get(sub_attr_type))
                elif self.family == AF_UNSPEC:
                    if sub_attr_type == AF_INET6:
                        family = 'AF_INET6'
                    elif sub_attr_type == AF_INET:
                        family = 'AF_INET'
                    else:
                        family = 'Unsupported family %d' % sub_attr_type

                    extra = 'Nested Attribute Structure for %s - Length %s (%d)%s Type %s (%d)' % (
                        family, zfilled_hex(sub_attr_length, 4), sub_attr_length, padded_to,
                        zfilled_hex(sub_attr_type, 4), sub_attr_type,
                    )
            else:
                extra = ''

            dump_buffer.append(data_to_color_text(line_number, color, self.data[start:end], extra))
            line_number += 1

        return line_number

    def get_pretty_value(self, obj=None):

        if obj and callable(obj):
            return obj(self.value)

        # We do this so we can print a more human readable dictionary
        # with the names of the nested keys instead of their numbers
        value_pretty = {}

        if self.family == AF_BRIDGE:
            for (sub_key, sub_value) in self.value.iteritems():
                sub_key_pretty = "(%2d) %s" % (sub_key, Link.ifla_bridge_af_spec_to_string.get(sub_key))
                value_pretty[sub_key_pretty] = sub_value
        elif self.family == AF_UNSPEC:
            for (family, family_attr) in self.value.iteritems():
                family_value_pretty = {}

                if family == AF_INET6:
                    family_af_spec_to_string = Link.ifla_inet6_af_spec_to_string
                elif family == AF_INET:
                    family_af_spec_to_string = Link.ifla_inet_af_spec_to_string
                else:
                    continue # log error?

                for (sub_key, sub_value) in family_attr.iteritems():
                    sub_key_pretty = "(%2d) %s" % (sub_key, family_af_spec_to_string.get(sub_key))
                    family_value_pretty[sub_key_pretty] = sub_value
                value_pretty = family_value_pretty

        return value_pretty



class AttributeRTA_MULTIPATH(Attribute):
    """
/* RTA_MULTIPATH --- array of struct rtnexthop.
 *
 * "struct rtnexthop" describes all necessary nexthop information,
 * i.e. parameters of path to a destination via this nexthop.
 *
 * At the moment it is impossible to set different prefsrc, mtu, window
 * and rtt for different paths from multipath.
 */

struct rtnexthop {
    unsigned short rtnh_len;
    unsigned char  rtnh_flags;
    unsigned char  rtnh_hops;
    int            rtnh_ifindex;
};
    """

    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.family = family
        self.PACK = None
        self.LEN = None
        self.RTNH_PACK = '=HBBL'  # rtnh_len, flags, hops, ifindex
        self.RTNH_LEN = calcsize(self.RTNH_PACK)
        self.IPV4_LEN = 4
        self.IPV6_LEN = 16

    def encode(self):

        # Calculate the length
        if self.family == AF_INET:
            ip_len = self.IPV4_LEN
        elif self.family == AF_INET6:
            ip_len = self.IPV6_LEN

        # Attribute header
        length = self.HEADER_LEN + ((self.RTNH_LEN + self.HEADER_LEN + ip_len) * len(self.value))
        raw = pack(self.HEADER_PACK, length, self.atype)

        rtnh_flags = 0
        rtnh_hops = 0
        rtnh_len = self.RTNH_LEN + self.HEADER_LEN + ip_len

        for (nexthop, rtnh_ifindex) in self.value:

            # rtnh structure
            raw += pack(self.RTNH_PACK, rtnh_len, rtnh_flags, rtnh_hops, rtnh_ifindex)

            # Gateway
            raw += pack(self.HEADER_PACK, self.HEADER_LEN + ip_len, Route.RTA_GATEWAY)

            if self.family == AF_INET:
                raw += pack('>L', nexthop)
            elif self.family == AF_INET6:
                raw += pack('>QQ', nexthop >> 64, nexthop & 0x0000000000000000FFFFFFFFFFFFFFFF)

        raw = self.pad(length, raw)
        return raw

    def decode(self, parent_msg, data):
        self.decode_length_type(data)
        self.value = []

        data = self.data[4:]

        while data:
            (rtnh_len, rtnh_flags, rtnh_hops, rtnh_ifindex) = unpack(self.RTNH_PACK, data[:self.RTNH_LEN])
            data = data[self.RTNH_LEN:]

            (attr_type, attr_length) = unpack(self.HEADER_PACK, self.data[:self.HEADER_LEN])
            data = data[self.HEADER_LEN:]

            if self.family == AF_INET:
                if len(data) < self.IPV4_LEN:
                    break
                nexthop = IPv4Address(unpack('>L', data[:self.IPV4_LEN])[0])
                self.value.append((nexthop, rtnh_ifindex, rtnh_flags, rtnh_hops))

            elif self.family == AF_INET6:
                if len(data) < self.IPV6_LEN:
                    break
                (data1, data2) = unpack('>QQ', data[:self.IPV6_LEN])
                nexthop = IPv6Address(data1 << 64 | data2)
                self.value.append((nexthop, rtnh_ifindex, rtnh_flags, rtnh_hops))

            data = data[(rtnh_len-self.RTNH_LEN-self.HEADER_LEN):]

        self.value = tuple(self.value)


class AttributeIFLA_LINKINFO(Attribute):
    """
    value is a dictionary such as:

    {
        Link.IFLA_INFO_KIND : 'vlan',
        Link.IFLA_INFO_DATA : {
            Link.IFLA_VLAN_ID : vlanid,
        }
    }
    """
    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)

    def encode(self):
        pack_layout = [self.HEADER_PACK]
        payload = [0, self.atype | NLA_F_NESTED]
        attr_length_index = 0

        kind        = self.value.get(Link.IFLA_INFO_KIND)
        slave_kind  = self.value.get(Link.IFLA_INFO_SLAVE_KIND)

        if not slave_kind and kind not in ('vlan', 'macvlan', 'vxlan', 'bond', 'bridge'):
            raise Exception('Unsupported IFLA_INFO_KIND %s' % kind)
        elif not kind and slave_kind != 'bridge':
            # only support brport for now.
            raise Exception('Unsupported IFLA_INFO_SLAVE_KIND %s' % slave_kind)

        # For now this assumes that all data will be packed in the native endian
        # order (=). If a field is added that needs to be packed via network
        # order (>) then some smarts will need to be added to split the pack_layout
        # string at the >, split the payload and make the needed pack() calls.
        #
        # Until we cross that bridge though we will keep things nice and simple and
        # pack everything via a single pack() call.
        for (sub_attr_type, sub_attr_value) in self.value.iteritems():
            sub_attr_pack_layout = ['=', 'HH']
            sub_attr_payload = [0, sub_attr_type]
            sub_attr_length_index = 0

            if sub_attr_type == Link.IFLA_INFO_KIND:
                sub_attr_pack_layout.append('%ds' % len(sub_attr_value))
                sub_attr_payload.append(sub_attr_value)

            elif sub_attr_type == Link.IFLA_INFO_DATA:

                sub_attr_payload = [0, sub_attr_type | NLA_F_NESTED]

                for (info_data_type, info_data_value) in sub_attr_value.iteritems():

                    if kind == 'vlan':
                        if info_data_type == Link.IFLA_VLAN_ID:
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(6)  # length
                            sub_attr_payload.append(info_data_type)

                            # The vlan-id
                            sub_attr_pack_layout.append('H')
                            sub_attr_payload.append(info_data_value)

                            # pad 2 bytes
                            sub_attr_pack_layout.extend('xx')

                        elif info_data_type == Link.IFLA_VLAN_PROTOCOL:
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(6)  # length
                            sub_attr_payload.append(info_data_type)

                            # vlan protocol
                            vlan_protocol = Link.ifla_vlan_protocol_dict.get(info_data_value)
                            if not vlan_protocol:
                                raise NotImplementedError('vlan protocol %s not implemented' % info_data_value)

                            sub_attr_pack_layout.append('H')
                            sub_attr_payload.append(htons(vlan_protocol))

                            # pad 2 bytes
                            sub_attr_pack_layout.extend('xx')
                        else:
                            self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_INFO_DATA vlan sub-attribute type %d' % info_data_type)

                    elif kind == 'macvlan':
                        if info_data_type == Link.IFLA_MACVLAN_MODE:
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(8)  # length
                            sub_attr_payload.append(info_data_type)

                            # macvlan mode
                            sub_attr_pack_layout.append('L')
                            sub_attr_payload.append(info_data_value)

                        else:
                            self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_INFO_DATA macvlan sub-attribute type %d' % info_data_type)

                    elif kind == 'vxlan':
                        if info_data_type in (Link.IFLA_VXLAN_ID,
                                              Link.IFLA_VXLAN_LINK,
                                              Link.IFLA_VXLAN_AGEING,
                                              Link.IFLA_VXLAN_LIMIT,
                                              Link.IFLA_VXLAN_PORT_RANGE):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(8)  # length
                            sub_attr_payload.append(info_data_type)

                            sub_attr_pack_layout.append('L')
                            sub_attr_payload.append(info_data_value)

                        elif info_data_type in (Link.IFLA_VXLAN_GROUP,
                                                Link.IFLA_VXLAN_LOCAL):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(8)  # length
                            sub_attr_payload.append(info_data_type)

                            sub_attr_pack_layout.append('L')

                            reorder = unpack('<L', IPv4Address(info_data_value).packed)[0]
                            sub_attr_payload.append(IPv4Address(reorder))

                        elif info_data_type in (Link.IFLA_VXLAN_PORT,):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(6)
                            sub_attr_payload.append(info_data_type)

                            sub_attr_pack_layout.append('H')

                            # byte swap
                            swaped = pack(">H", info_data_value)
                            sub_attr_payload.append(unpack("<H", swaped)[0])

                            sub_attr_pack_layout.extend('xx')

                        elif info_data_type in (Link.IFLA_VXLAN_TTL,
                                                Link.IFLA_VXLAN_TOS,
                                                Link.IFLA_VXLAN_LEARNING,
                                                Link.IFLA_VXLAN_PROXY,
                                                Link.IFLA_VXLAN_RSC,
                                                Link.IFLA_VXLAN_L2MISS,
                                                Link.IFLA_VXLAN_L3MISS,
                                                Link.IFLA_VXLAN_UDP_CSUM,
                                                Link.IFLA_VXLAN_UDP_ZERO_CSUM6_TX,
                                                Link.IFLA_VXLAN_UDP_ZERO_CSUM6_RX,
                                                Link.IFLA_VXLAN_REMCSUM_TX,
                                                Link.IFLA_VXLAN_REMCSUM_RX,
                                                Link.IFLA_VXLAN_REPLICATION_TYPE):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(6)
                            sub_attr_payload.append(info_data_type)

                            sub_attr_pack_layout.append('B')
                            sub_attr_payload.append(info_data_value)
                            sub_attr_pack_layout.extend('xxx')

                        else:
                            self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_INFO_DATA vxlan sub-attribute type %d' % info_data_type)

                    elif kind == 'bond':
                        if info_data_type in (Link.IFLA_BOND_AD_ACTOR_SYSTEM, ):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(10)  # length
                            sub_attr_payload.append(info_data_type)

                            sub_attr_pack_layout.append('6B')
                            for mbyte in info_data_value.replace('.', ' ').replace(':', ' ').split():
                                sub_attr_payload.append(int(mbyte, 16))
                            sub_attr_pack_layout.extend('xx')

                        elif info_data_type == Link.IFLA_BOND_AD_ACTOR_SYS_PRIO:
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(6)  # length
                            sub_attr_payload.append(info_data_type)

                            # 2 bytes
                            sub_attr_pack_layout.append('H')
                            sub_attr_payload.append(int(info_data_value))

                            # pad 2 bytes
                            sub_attr_pack_layout.extend('xx')

                        elif info_data_type == Link.IFLA_BOND_NUM_PEER_NOTIF:
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(5)  # length
                            sub_attr_payload.append(info_data_type)

                            # 1 byte
                            sub_attr_pack_layout.append('B')
                            sub_attr_payload.append(int(info_data_value))

                            # pad 3 bytes
                            sub_attr_pack_layout.extend('xxx')


                        elif info_data_type in (Link.IFLA_BOND_AD_LACP_RATE,
                                                Link.IFLA_BOND_AD_LACP_BYPASS,
                                                Link.IFLA_BOND_USE_CARRIER):
                            # converts yes/no/on/off/0/1 strings to boolean value
                            bool_value = self.get_bool_value(info_data_value)

                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(5)  # length
                            sub_attr_payload.append(info_data_type)

                            # 1 byte
                            sub_attr_pack_layout.append('B')
                            sub_attr_payload.append(bool_value)

                            # pad 3 bytes
                            sub_attr_pack_layout.extend('xxx')

                        elif info_data_type == Link.IFLA_BOND_XMIT_HASH_POLICY:
                            index = self.get_index(Link.ifla_bond_xmit_hash_policy_tbl,
                                                   'bond xmit hash policy',
                                                   info_data_value)

                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(5)  # length
                            sub_attr_payload.append(info_data_type)

                            # 1 byte
                            sub_attr_pack_layout.append('B')
                            sub_attr_payload.append(index)

                            # pad 3 bytes
                            sub_attr_pack_layout.extend('xxx')

                        elif info_data_type == Link.IFLA_BOND_MODE:
                            index = self.get_index(Link.ifla_bond_mode_tbl,
                                                   'bond mode',
                                                   info_data_value)

                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(5)  # length
                            sub_attr_payload.append(info_data_type)

                            # 1 byte
                            sub_attr_pack_layout.append('B')
                            sub_attr_payload.append(index)

                            # pad 3 bytes
                            sub_attr_pack_layout.extend('xxx')

                        elif info_data_type in (Link.IFLA_BOND_MIIMON,
                                                Link.IFLA_BOND_UPDELAY,
                                                Link.IFLA_BOND_DOWNDELAY,
                                                Link.IFLA_BOND_MIN_LINKS):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(8)  # length
                            sub_attr_payload.append(info_data_type)

                            sub_attr_pack_layout.append('L')
                            sub_attr_payload.append(int(info_data_value))

                        else:
                            self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_INFO_DATA bond sub-attribute type %d' % info_data_type)

                    elif kind == 'bridge':
                        if info_data_type == Link.IFLA_BR_VLAN_PROTOCOL:
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(6)  # length
                            sub_attr_payload.append(info_data_type)

                            # vlan protocol
                            vlan_protocol = Link.ifla_vlan_protocol_dict.get(info_data_value)
                            if not vlan_protocol:
                                raise NotImplementedError('vlan protocol %s not implemented' % info_data_value)

                            sub_attr_pack_layout.append('H')
                            sub_attr_payload.append(htons(vlan_protocol))

                            # pad 2 bytes
                            sub_attr_pack_layout.extend('xx')

                        # 1 byte
                        elif info_data_type in (Link.IFLA_BR_VLAN_FILTERING,
                                              Link.IFLA_BR_TOPOLOGY_CHANGE,
                                              Link.IFLA_BR_TOPOLOGY_CHANGE_DETECTED,
                                              Link.IFLA_BR_MCAST_ROUTER,
                                              Link.IFLA_BR_MCAST_SNOOPING,
                                              Link.IFLA_BR_MCAST_QUERY_USE_IFADDR,
                                              Link.IFLA_BR_MCAST_QUERIER,
                                              Link.IFLA_BR_NF_CALL_IPTABLES,
                                              Link.IFLA_BR_NF_CALL_IP6TABLES,
                                              Link.IFLA_BR_NF_CALL_ARPTABLES,
                                              Link.IFLA_BR_VLAN_STATS_ENABLED,
                                              Link.IFLA_BR_MCAST_STATS_ENABLED,
                                              Link.IFLA_BR_MCAST_IGMP_VERSION,
                                              Link.IFLA_BR_MCAST_MLD_VERSION):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(5)  # length
                            sub_attr_payload.append(info_data_type)

                            # 1 byte
                            sub_attr_pack_layout.append('B')
                            sub_attr_payload.append(int(info_data_value))

                            # pad 3 bytes
                            sub_attr_pack_layout.extend('xxx')

                        # 2 bytes
                        elif info_data_type in (Link.IFLA_BR_PRIORITY,
                                              Link.IFLA_BR_GROUP_FWD_MASK,
                                              Link.IFLA_BR_ROOT_PORT,
                                              Link.IFLA_BR_VLAN_DEFAULT_PVID):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(6)  # length
                            sub_attr_payload.append(info_data_type)

                            # 2 bytes
                            sub_attr_pack_layout.append('H')
                            sub_attr_payload.append(int(info_data_value))

                            # pad 2 bytes
                            sub_attr_pack_layout.extend('xx')

                        # 4 bytes
                        elif info_data_type in (Link.IFLA_BR_FORWARD_DELAY,
                                                Link.IFLA_BR_HELLO_TIME,
                                                Link.IFLA_BR_MAX_AGE,
                                                Link.IFLA_BR_AGEING_TIME,
                                                Link.IFLA_BR_STP_STATE,
                                                Link.IFLA_BR_ROOT_PATH_COST,
                                                Link.IFLA_BR_MCAST_QUERIER,
                                                Link.IFLA_BR_MCAST_HASH_ELASTICITY,
                                                Link.IFLA_BR_MCAST_HASH_MAX,
                                                Link.IFLA_BR_MCAST_LAST_MEMBER_CNT,
                                                Link.IFLA_BR_MCAST_STARTUP_QUERY_CNT):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(8)  # length
                            sub_attr_payload.append(info_data_type)

                            sub_attr_pack_layout.append('L')
                            sub_attr_payload.append(int(info_data_value))

                        # 8 bytes
                        elif info_data_type in (Link.IFLA_BR_MCAST_LAST_MEMBER_INTVL,
                                                Link.IFLA_BR_MCAST_MEMBERSHIP_INTVL,
                                                Link.IFLA_BR_MCAST_QUERIER_INTVL,
                                                Link.IFLA_BR_MCAST_QUERY_INTVL,
                                                Link.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL,
                                                Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(12)  # length
                            sub_attr_payload.append(info_data_type)

                            sub_attr_pack_layout.append('Q')
                            sub_attr_payload.append(int(info_data_value))

                        else:
                            self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_INFO_DATA bridge sub-attribute type %d' % info_data_type)

            elif sub_attr_type == Link.IFLA_INFO_SLAVE_DATA:

                sub_attr_payload = [0, sub_attr_type | NLA_F_NESTED]

                for (info_slave_data_type, info_slave_data_value) in sub_attr_value.iteritems():

                    if slave_kind == 'bridge':

                        # 1 byte
                        if info_slave_data_type in (Link.IFLA_BRPORT_STATE,
                                                    Link.IFLA_BRPORT_MODE,
                                                    Link.IFLA_BRPORT_GUARD,
                                                    Link.IFLA_BRPORT_PROTECT,
                                                    Link.IFLA_BRPORT_FAST_LEAVE,
                                                    Link.IFLA_BRPORT_LEARNING,
                                                    Link.IFLA_BRPORT_UNICAST_FLOOD,
                                                    Link.IFLA_BRPORT_PROXYARP,
                                                    Link.IFLA_BRPORT_LEARNING_SYNC,
                                                    Link.IFLA_BRPORT_PROXYARP_WIFI,
                                                    Link.IFLA_BRPORT_TOPOLOGY_CHANGE_ACK,
                                                    Link.IFLA_BRPORT_CONFIG_PENDING,
                                                    Link.IFLA_BRPORT_MULTICAST_ROUTER,
                                                    Link.IFLA_BRPORT_MCAST_FLOOD,
                                                    Link.IFLA_BRPORT_MCAST_TO_UCAST,
                                                    Link.IFLA_BRPORT_VLAN_TUNNEL,
                                                    Link.IFLA_BRPORT_BCAST_FLOOD,
                                                    Link.IFLA_BRPORT_PEER_LINK,
                                                    Link.IFLA_BRPORT_DUAL_LINK,
                                                    Link.IFLA_BRPORT_ARP_SUPPRESS,
                                                    Link.IFLA_BRPORT_DOWN_PEERLINK_REDIRECT):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(5)  # length
                            sub_attr_payload.append(info_slave_data_type)

                            # 1 byte
                            sub_attr_pack_layout.append('B')
                            sub_attr_payload.append(int(info_slave_data_value))

                            # pad 3 bytes
                            sub_attr_pack_layout.extend('xxx')

                        # 2 bytes
                        elif info_slave_data_type in (Link.IFLA_BRPORT_PRIORITY,
                                                      Link.IFLA_BRPORT_DESIGNATED_PORT,
                                                      Link.IFLA_BRPORT_DESIGNATED_COST,
                                                      Link.IFLA_BRPORT_ID,
                                                      Link.IFLA_BRPORT_NO,
                                                      Link.IFLA_BRPORT_GROUP_FWD_MASK,
                                                      Link.IFLA_BRPORT_GROUP_FWD_MASKHI):
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(6)  # length
                            sub_attr_payload.append(info_slave_data_type)

                            # 2 bytes
                            sub_attr_pack_layout.append('H')
                            sub_attr_payload.append(int(info_slave_data_value))

                            # pad 2 bytes
                            sub_attr_pack_layout.extend('xx')

                        # 4 bytes
                        elif info_slave_data_type == Link.IFLA_BRPORT_COST:
                            sub_attr_pack_layout.append('HH')
                            sub_attr_payload.append(8)  # length
                            sub_attr_payload.append(info_slave_data_type)

                            sub_attr_pack_layout.append('L')
                            sub_attr_payload.append(int(info_slave_data_value))

                        else:
                            self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_INFO_SLAVE_DATA bond sub-attribute type %d' % info_slave_data_type)

                    else:
                        self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_LINKINFO kind %s' % slave_kind)

            else:
                self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_LINKINFO sub-attribute type %d' % sub_attr_type)
                continue

            sub_attr_length = calcsize(''.join(sub_attr_pack_layout))
            sub_attr_payload[sub_attr_length_index] = sub_attr_length

            # add padding
            for x in xrange(self.pad_bytes_needed(sub_attr_length)):
                sub_attr_pack_layout.append('x')

            # The [1:] is to remove the leading = so that when we do the ''.join() later
            # we do not end up with an = in the middle of the pack layout string. There
            # will be an = at the beginning via self.HEADER_PACK
            sub_attr_pack_layout = sub_attr_pack_layout[1:]

            # Now extend the ovarall attribute pack_layout/payload to include this sub-attribute
            pack_layout.extend(sub_attr_pack_layout)
            payload.extend(sub_attr_payload)

        pack_layout = ''.join(pack_layout)

        # Fill in the length field
        length = calcsize(pack_layout)
        payload[attr_length_index] = length

        raw = pack(pack_layout, *payload)
        raw = self.pad(length, raw)
        return raw

    def get_bool_value(self, value, default=None):
        try:
            return value_to_bool_dict[value]
        except KeyError:
            self.log.debug('%s: unsupported boolean value' % value)
            return default

    def get_index(self, tbl, attr, value, default=None):
        try:
            return tbl[value]
        except KeyError:
            self.log.debug('unsupported %s value %s (%s)' % (attr, value, tbl.keys()))
            return default

    def decode(self, parent_msg, data):
        """
        value is a dictionary such as:

        {
            Link.IFLA_INFO_KIND : 'vlan',
            Link.IFLA_INFO_DATA : {
                Link.IFLA_VLAN_ID : vlanid,
            }
        }
        """
        self.decode_length_type(data)
        self.value = {}

        data = self.data[4:]

        # IFLA_MACVLAN_MODE and IFLA_VLAN_ID both have a value of 1 and both are
        # valid IFLA_INFO_DATA entries :( The sender must TX IFLA_INFO_KIND
        # first in order for us to know if "1" is IFLA_MACVLAN_MODE vs IFLA_VLAN_ID.

        while data:
            (sub_attr_length, sub_attr_type) = unpack('=HH', data[:4])
            sub_attr_end = padded_length(sub_attr_length)

            if not sub_attr_length:
                self.log.error('parsed a zero length sub-attr')
                return

            if sub_attr_type in (Link.IFLA_INFO_KIND, Link.IFLA_INFO_SLAVE_KIND):
                self.value[sub_attr_type] = remove_trailing_null(unpack('%ds' % (sub_attr_length - 4), data[4:sub_attr_length])[0])

            elif sub_attr_type == Link.IFLA_INFO_SLAVE_DATA:
                sub_attr_data = data[4:sub_attr_end]

                ifla_info_slave_data = dict()
                ifla_info_slave_kind = self.value.get(Link.IFLA_INFO_SLAVE_KIND)

                if not ifla_info_slave_kind:
                    self.log.warning('IFLA_INFO_SLAVE_KIND is not known...we cannot parse IFLA_INFO_SLAVE_DATA')
                else:
                    while sub_attr_data:
                        (info_data_length, info_data_type) = unpack('=HH', sub_attr_data[:4])
                        info_data_end = padded_length(info_data_length)
                        try:
                            if ifla_info_slave_kind == 'bridge':
                                # 1 byte
                                if info_data_type in (Link.IFLA_BRPORT_STATE,
                                                      Link.IFLA_BRPORT_MODE,
                                                      Link.IFLA_BRPORT_GUARD,
                                                      Link.IFLA_BRPORT_PROTECT,
                                                      Link.IFLA_BRPORT_FAST_LEAVE,
                                                      Link.IFLA_BRPORT_LEARNING,
                                                      Link.IFLA_BRPORT_UNICAST_FLOOD,
                                                      Link.IFLA_BRPORT_PROXYARP,
                                                      Link.IFLA_BRPORT_LEARNING_SYNC,
                                                      Link.IFLA_BRPORT_PROXYARP_WIFI,
                                                      Link.IFLA_BRPORT_TOPOLOGY_CHANGE_ACK,
                                                      Link.IFLA_BRPORT_CONFIG_PENDING,
                                                      Link.IFLA_BRPORT_MULTICAST_ROUTER,
                                                      Link.IFLA_BRPORT_MCAST_FLOOD,
                                                      Link.IFLA_BRPORT_MCAST_TO_UCAST,
                                                      Link.IFLA_BRPORT_VLAN_TUNNEL,
                                                      Link.IFLA_BRPORT_PEER_LINK,
                                                      Link.IFLA_BRPORT_DUAL_LINK,
                                                      Link.IFLA_BRPORT_ARP_SUPPRESS,
                                                      Link.IFLA_BRPORT_DOWN_PEERLINK_REDIRECT):
                                    ifla_info_slave_data[info_data_type] = unpack('=B', sub_attr_data[4])[0]

                                # 2 bytes
                                elif info_data_type in (Link.IFLA_BRPORT_PRIORITY,
                                                        Link.IFLA_BRPORT_DESIGNATED_PORT,
                                                        Link.IFLA_BRPORT_DESIGNATED_COST,
                                                        Link.IFLA_BRPORT_ID,
                                                        Link.IFLA_BRPORT_NO,
                                                        Link.IFLA_BRPORT_GROUP_FWD_MASK,
                                                        Link.IFLA_BRPORT_GROUP_FWD_MASKHI):
                                    ifla_info_slave_data[info_data_type] = unpack('=H', sub_attr_data[4:6])[0]

                                # 4 bytes
                                elif info_data_type == Link.IFLA_BRPORT_COST:
                                    ifla_info_slave_data[info_data_type] = unpack('=L', sub_attr_data[4:8])[0]

                            elif ifla_info_slave_kind == 'bond':

                                # 1 byte
                                if info_data_type in (
                                        Link.IFLA_BOND_SLAVE_STATE,
                                        Link.IFLA_BOND_SLAVE_MII_STATUS,
                                        Link.IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE,
                                        Link.IFLA_BOND_SLAVE_AD_RX_BYPASS,
                                ):
                                    ifla_info_slave_data[info_data_type] = unpack('=B', sub_attr_data[4])[0]

                                # 2 bytes
                                elif info_data_type in (
                                        Link.IFLA_BOND_SLAVE_QUEUE_ID,
                                        Link.IFLA_BOND_SLAVE_AD_AGGREGATOR_ID
                                ):
                                    ifla_info_slave_data[info_data_type] = unpack('=H', sub_attr_data[4:6])[0]

                                # 4 bytes
                                elif info_data_type == (
                                        Link.IFLA_BOND_SLAVE_PERM_HWADDR,
                                        Link.IFLA_BOND_SLAVE_LINK_FAILURE_COUNT
                                ):
                                    ifla_info_slave_data[info_data_type] = unpack('=L', sub_attr_data[4:8])[0]

                        except Exception as e:
                            self.log.debug('%s: attribute %s: %s'
                                            % (self.value[Link.IFLA_INFO_SLAVE_KIND],
                                               info_data_type,
                                               str(e)))
                        sub_attr_data = sub_attr_data[info_data_end:]

                self.value[Link.IFLA_INFO_SLAVE_DATA] = ifla_info_slave_data

            elif sub_attr_type == Link.IFLA_INFO_DATA:
                sub_attr_data = data[4:sub_attr_end]
                self.value[Link.IFLA_INFO_DATA] = {}

                ifla_info_kind = self.value.get(Link.IFLA_INFO_KIND)
                if not ifla_info_kind:
                    self.log.warning('IFLA_INFO_KIND is not known...we cannot parse IFLA_INFO_DATA')
                else:
                    while sub_attr_data:
                        (info_data_length, info_data_type) = unpack('=HH', sub_attr_data[:4])
                        info_data_end = padded_length(info_data_length)
                        try:
                            if ifla_info_kind == 'vlan':
                                if info_data_type == Link.IFLA_VLAN_ID:
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=H', sub_attr_data[4:6])[0]

                                elif info_data_type == Link.IFLA_VLAN_PROTOCOL:
                                    hex_value = '0x%s' % sub_attr_data[4:6].encode('hex')
                                    vlan_protocol = Link.ifla_vlan_protocol_dict.get(int(hex_value, base=16))

                                    if vlan_protocol:
                                        self.value[Link.IFLA_INFO_DATA][info_data_type] = vlan_protocol
                                    else:
                                        self.log.warning('IFLA_VLAN_PROTOCOL: cannot decode vlan protocol %s' % hex_value)

                                else:
                                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_INFO_KIND vlan type %s (%d), length %d, padded to %d' %
                                                (parent_msg.get_ifla_vlan_string(info_data_type), info_data_type, info_data_length, info_data_end))

                            elif ifla_info_kind == 'macvlan':
                                if info_data_type == Link.IFLA_MACVLAN_MODE:
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=L', sub_attr_data[4:8])[0]
                                else:
                                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_INFO_KIND macvlan type %s (%d), length %d, padded to %d' %
                                                (parent_msg.get_ifla_macvlan_string(info_data_type), info_data_type, info_data_length, info_data_end))

                            elif ifla_info_kind == 'vxlan':

                                # IPv4Address
                                if info_data_type in (Link.IFLA_VXLAN_GROUP,
                                                      Link.IFLA_VXLAN_LOCAL):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = IPv4Address(unpack('>L', sub_attr_data[4:8])[0])

                                # 4-byte int
                                elif info_data_type in (Link.IFLA_VXLAN_ID,
                                                        Link.IFLA_VXLAN_LINK,
                                                        Link.IFLA_VXLAN_AGEING,
                                                        Link.IFLA_VXLAN_LIMIT,
                                                        Link.IFLA_VXLAN_PORT_RANGE):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=L', sub_attr_data[4:8])[0]

                                # 2-byte int
                                elif info_data_type in (Link.IFLA_VXLAN_PORT, ):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('!H', sub_attr_data[4:6])[0]
                                    # The form '!' is available for those poor souls who claim they can't
                                    # remember whether network byte order is big-endian or little-endian.

                                # 1-byte int
                                elif info_data_type in (Link.IFLA_VXLAN_TTL,
                                                        Link.IFLA_VXLAN_TOS,
                                                        Link.IFLA_VXLAN_LEARNING,
                                                        Link.IFLA_VXLAN_PROXY,
                                                        Link.IFLA_VXLAN_RSC,
                                                        Link.IFLA_VXLAN_L2MISS,
                                                        Link.IFLA_VXLAN_L3MISS,
                                                        Link.IFLA_VXLAN_UDP_CSUM,
                                                        Link.IFLA_VXLAN_UDP_ZERO_CSUM6_TX,
                                                        Link.IFLA_VXLAN_UDP_ZERO_CSUM6_RX,
                                                        Link.IFLA_VXLAN_REMCSUM_TX,
                                                        Link.IFLA_VXLAN_REMCSUM_RX,
                                                        Link.IFLA_VXLAN_REPLICATION_TYPE):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=B', sub_attr_data[4])[0]

                                else:
                                    # sub_attr_end = padded_length(sub_attr_length)
                                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_INFO_KIND vxlan type %s (%d), length %d, padded to %d' %
                                                (parent_msg.get_ifla_vxlan_string(info_data_type), info_data_type, info_data_length, info_data_end))

                            elif ifla_info_kind == 'bond':

                                if info_data_type in (Link.IFLA_BOND_AD_INFO, ):
                                    ad_attr_data = sub_attr_data[4:info_data_end]
                                    self.value[Link.IFLA_INFO_DATA][Link.IFLA_BOND_AD_INFO] = {}

                                    while ad_attr_data:
                                        (ad_data_length, ad_data_type) = unpack('=HH', ad_attr_data[:4])
                                        ad_data_end = padded_length(ad_data_length)

                                        if ad_data_type in (Link.IFLA_BOND_AD_INFO_PARTNER_MAC,):
                                            (data1, data2) = unpack('>LHxx', ad_attr_data[4:12])
                                            self.value[Link.IFLA_INFO_DATA][Link.IFLA_BOND_AD_INFO][ad_data_type] = mac_int_to_str(data1 << 16 | data2)

                                        ad_attr_data = ad_attr_data[ad_data_end:]

                                # 1-byte int
                                elif info_data_type in (Link.IFLA_BOND_MODE,
                                                        Link.IFLA_BOND_USE_CARRIER,
                                                        Link.IFLA_BOND_AD_LACP_RATE,
                                                        Link.IFLA_BOND_AD_LACP_BYPASS,
                                                        Link.IFLA_BOND_XMIT_HASH_POLICY,
                                                        Link.IFLA_BOND_NUM_PEER_NOTIF):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=B', sub_attr_data[4])[0]

                                # 2-bytes int
                                elif info_data_type == Link.IFLA_BOND_AD_ACTOR_SYS_PRIO:
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=H', sub_attr_data[4:6])[0]

                                # 4-bytes int
                                elif info_data_type in (Link.IFLA_BOND_MIIMON,
                                                        Link.IFLA_BOND_UPDELAY,
                                                        Link.IFLA_BOND_DOWNDELAY,
                                                        Link.IFLA_BOND_MIN_LINKS):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=L', sub_attr_data[4:8])[0]

                                # mac address
                                elif info_data_type in (Link.IFLA_BOND_AD_ACTOR_SYSTEM, ):
                                    (data1, data2) = unpack('>LHxx', sub_attr_data[4:12])
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = mac_int_to_str(data1 << 16 | data2)

                                else:
                                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_INFO_KIND bond type %s (%d), length %d, padded to %d' %
                                                (parent_msg.get_ifla_bond_string(info_data_type), info_data_type, info_data_length, info_data_end))

                            elif ifla_info_kind == 'bridge':
                                # 4 bytes
                                if info_data_type in (Link.IFLA_BR_AGEING_TIME,
                                                      Link.IFLA_BR_FORWARD_DELAY,
                                                      Link.IFLA_BR_HELLO_TIME,
                                                      Link.IFLA_BR_MAX_AGE,
                                                      Link.IFLA_BR_STP_STATE,
                                                      Link.IFLA_BR_ROOT_PATH_COST,
                                                      Link.IFLA_BR_MCAST_HASH_ELASTICITY,
                                                      Link.IFLA_BR_MCAST_HASH_MAX,
                                                      Link.IFLA_BR_MCAST_LAST_MEMBER_CNT,
                                                      Link.IFLA_BR_MCAST_STARTUP_QUERY_CNT):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=L', sub_attr_data[4:8])[0]

                                # 2 bytes
                                elif info_data_type in (Link.IFLA_BR_PRIORITY,
                                                        Link.IFLA_BR_GROUP_FWD_MASK,
                                                        Link.IFLA_BR_ROOT_PORT,
                                                        Link.IFLA_BR_VLAN_DEFAULT_PVID):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=H', sub_attr_data[4:6])[0]

                                elif info_data_type == Link.IFLA_BR_VLAN_PROTOCOL:
                                    hex_value = '0x%s' % sub_attr_data[4:6].encode('hex')
                                    vlan_protocol = Link.ifla_vlan_protocol_dict.get(int(hex_value, base=16))

                                    if vlan_protocol:
                                        self.value[Link.IFLA_INFO_DATA][info_data_type] = vlan_protocol
                                    else:
                                        self.log.warning('IFLA_VLAN_PROTOCOL: cannot decode vlan protocol %s' % hex_value)

                                # 8 bytes
                                elif info_data_type in (Link.IFLA_BR_MCAST_MEMBERSHIP_INTVL,
                                                        Link.IFLA_BR_MCAST_QUERIER_INTVL,
                                                        Link.IFLA_BR_MCAST_LAST_MEMBER_INTVL,
                                                        Link.IFLA_BR_MCAST_MEMBERSHIP_INTVL,
                                                        Link.IFLA_BR_MCAST_QUERIER_INTVL,
                                                        Link.IFLA_BR_MCAST_QUERY_INTVL,
                                                        Link.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL,
                                                        Link.IFLA_BR_MCAST_STARTUP_QUERY_INTVL):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=Q', sub_attr_data[4:12])[0]

                                # 1 bytes
                                elif info_data_type in (Link.IFLA_BR_VLAN_FILTERING,
                                                        Link.IFLA_BR_TOPOLOGY_CHANGE,
                                                        Link.IFLA_BR_TOPOLOGY_CHANGE_DETECTED,
                                                        Link.IFLA_BR_MCAST_ROUTER,
                                                        Link.IFLA_BR_MCAST_SNOOPING,
                                                        Link.IFLA_BR_MCAST_QUERY_USE_IFADDR,
                                                        Link.IFLA_BR_MCAST_QUERIER,
                                                        Link.IFLA_BR_NF_CALL_IPTABLES,
                                                        Link.IFLA_BR_NF_CALL_IP6TABLES,
                                                        Link.IFLA_BR_NF_CALL_ARPTABLES,
                                                        Link.IFLA_BR_VLAN_STATS_ENABLED,
                                                        Link.IFLA_BR_MCAST_STATS_ENABLED,
                                                        Link.IFLA_BR_MCAST_IGMP_VERSION,
                                                        Link.IFLA_BR_MCAST_MLD_VERSION):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=B', sub_attr_data[4])[0]
                                else:
                                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_INFO_KIND bridge type %s (%d), length %d, padded to %d' %
                                                (parent_msg.get_ifla_br_string(info_data_type), info_data_type, info_data_length, info_data_end))

                            elif ifla_info_kind == 'vrf':

                                if info_data_type in (Link.IFLA_VRF_TABLE,):
                                    self.value[Link.IFLA_INFO_DATA][info_data_type] = unpack('=L', sub_attr_data[4:8])[0]


                            else:
                                self.log.log(SYSLOG_EXTRA_DEBUG, "Add support for decoding IFLA_INFO_KIND %s (%d), length %d, padded to %d" %
                                            (ifla_info_kind, info_data_type, info_data_length, info_data_end))

                        except Exception as e:
                            self.log.debug('%s: attribute %s: %s'
                                           % (self.value[Link.IFLA_INFO_KIND],
                                              info_data_type,
                                              str(e)))
                        sub_attr_data = sub_attr_data[info_data_end:]

            else:
                self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_LINKINFO sub-attribute type %s (%d), length %d, padded to %d' %
                            (parent_msg.get_ifla_info_string(sub_attr_type), sub_attr_type, sub_attr_length, sub_attr_end))

            data = data[sub_attr_end:]

        # self.log.info('IFLA_LINKINFO values %s' % pformat(self.value))

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        extra = ''

        next_sub_attr_line = 0
        sub_attr_line = True

        for x in xrange(1, self.attr_end/4):
            start = x * 4
            end = start + 4

            if line_number == next_sub_attr_line:
                sub_attr_line = True

            if sub_attr_line:
                sub_attr_line = False

                (sub_attr_length, sub_attr_type) = unpack('=HH', self.data[start:start+4])
                sub_attr_end = padded_length(sub_attr_length)

                next_sub_attr_line = line_number + (sub_attr_end/4)

                if sub_attr_end == sub_attr_length:
                    padded_to = ', '
                else:
                    padded_to = ' padded to %d, ' % sub_attr_end

                extra = 'Nested Attribute - Length %s (%d)%s Type %s (%d) %s' % \
                        (zfilled_hex(sub_attr_length, 4), sub_attr_length,
                         padded_to,
                         zfilled_hex(sub_attr_type, 4), sub_attr_type,
                         Link.ifla_info_to_string.get(sub_attr_type))
            else:
                extra = ''

            dump_buffer.append(data_to_color_text(line_number, color, self.data[start:end], extra))
            line_number += 1

        return line_number

    def get_pretty_value(self, obj=None):

        if obj and callable(obj):
            return obj(self.value)

        value_pretty            = self.value
        ifla_info_kind          = self.value.get(Link.IFLA_INFO_KIND)
        ifla_info_slave_kind    = self.value.get(Link.IFLA_INFO_SLAVE_KIND)

        kind_dict = dict()

        # We do this so we can print a more human readable dictionary
        # with the names of the nested keys instead of their numbers

        # Most of these are placeholders...we need to add support
        # for more human readable dictionaries for bond, bridge, etc
        kind_dict[Link.IFLA_INFO_DATA] = {
            'bond':     Link.ifla_bond_to_string,
            'vlan':     Link.ifla_vlan_to_string,
            'vxlan':    Link.ifla_vxlan_to_string,
            'bridge':   Link.ifla_br_to_string,
            'macvlan':  Link.ifla_macvlan_to_string
        }.get(ifla_info_kind, {})

        kind_dict[Link.IFLA_INFO_SLAVE_DATA] = {
            'bridge': Link.ifla_brport_to_string,
            'bond': Link.ifla_bond_slave_to_string
        }.get(ifla_info_slave_kind, {})

        if ifla_info_kind or ifla_info_slave_kind:
            value_pretty = {}

            for (sub_key, sub_value) in self.value.iteritems():
                sub_key_pretty = "(%2d) %s" % (sub_key, Link.ifla_info_to_string.get(sub_key, 'UNKNOWN'))
                sub_value_pretty = sub_value

                if sub_key in (Link.IFLA_INFO_DATA, Link.IFLA_INFO_SLAVE_DATA):
                    kind_to_string_dict = kind_dict.get(sub_key, {})
                    sub_value_pretty = {}

                    for (sub_sub_key, sub_sub_value) in sub_value.iteritems():
                        sub_sub_key_pretty = "(%2d) %s" % (sub_sub_key, kind_to_string_dict.get(sub_sub_key, 'UNKNOWN'))
                        sub_value_pretty[sub_sub_key_pretty] = sub_sub_value

                value_pretty[sub_key_pretty] = sub_value_pretty

        return value_pretty


class AttributeIFLA_PROTINFO(Attribute):
    """
    IFLA_PROTINFO nested attributes.
    """
    def __init__(self, atype, string, family, logger):
        Attribute.__init__(self, atype, string, logger)
        self.family = family

    def encode(self):
        pack_layout = [self.HEADER_PACK]
        payload = [0, self.atype | NLA_F_NESTED]
        attr_length_index = 0

        if self.family not in (AF_BRIDGE,):
            raise Exception('Unsupported IFLA_PROTINFO family %d' % self.family)

        # For now this assumes that all data will be packed in the native endian
        # order (=). If a field is added that needs to be packed via network
        # order (>) then some smarts will need to be added to split the pack_layout
        # string at the >, split the payload and make the needed pack() calls.
        #
        # Until we cross that bridge though we will keep things nice and simple and
        # pack everything via a single pack() call.
        for (sub_attr_type, sub_attr_value) in self.value.iteritems():
            sub_attr_pack_layout = ['=', 'HH']
            sub_attr_payload = [0, sub_attr_type]
            sub_attr_length_index = 0

            if self.family == AF_BRIDGE:
                # 1 Byte attributes
                if sub_attr_type in (Link.IFLA_BRPORT_STATE,
                                     Link.IFLA_BRPORT_MODE,
                                     Link.IFLA_BRPORT_GUARD,
                                     Link.IFLA_BRPORT_PROTECT,
                                     Link.IFLA_BRPORT_FAST_LEAVE,
                                     Link.IFLA_BRPORT_LEARNING,
                                     Link.IFLA_BRPORT_UNICAST_FLOOD,
                                     Link.IFLA_BRPORT_PROXYARP,
                                     Link.IFLA_BRPORT_LEARNING_SYNC,
                                     Link.IFLA_BRPORT_PROXYARP_WIFI,
                                     Link.IFLA_BRPORT_TOPOLOGY_CHANGE_ACK,
                                     Link.IFLA_BRPORT_CONFIG_PENDING,
                                     Link.IFLA_BRPORT_FLUSH,
                                     Link.IFLA_BRPORT_MULTICAST_ROUTER,
                                     Link.IFLA_BRPORT_PEER_LINK,
                                     Link.IFLA_BRPORT_DUAL_LINK,
                                     Link.IFLA_BRPORT_ARP_SUPPRESS,
                                     Link.IFLA_BRPORT_DOWN_PEERLINK_REDIRECT):
                    sub_attr_pack_layout.append('B')
                    sub_attr_payload.append(sub_attr_value)
                    sub_attr_pack_layout.extend('xxx')

                # 2 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_PRIORITY,
                                       Link.IFLA_BRPORT_DESIGNATED_PORT,
                                       Link.IFLA_BRPORT_DESIGNATED_COST,
                                       Link.IFLA_BRPORT_ID,
                                       Link.IFLA_BRPORT_NO):
                    sub_attr_pack_layout.append('H')
                    sub_attr_payload.append(sub_attr_value)
                    sub_attr_pack_layout.extend('xx')

                # 4 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_COST,):
                    sub_attr_pack_layout.append('L')
                    sub_attr_payload.append(sub_attr_value)

                # 8 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_MESSAGE_AGE_TIMER,
                                       Link.IFLA_BRPORT_FORWARD_DELAY_TIMER,
                                       Link.IFLA_BRPORT_HOLD_TIMER):
                    sub_attr_pack_layout.append('Q')
                    sub_attr_payload.append(sub_attr_value)

                else:
                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for encoding IFLA_PROTINFO sub-attribute type %d' % sub_attr_type)

            sub_attr_length = calcsize(''.join(sub_attr_pack_layout))
            sub_attr_payload[sub_attr_length_index] = sub_attr_length

            # add padding
            for x in xrange(self.pad_bytes_needed(sub_attr_length)):
                sub_attr_pack_layout.append('x')

            # The [1:] is to remove the leading = so that when we do the ''.join() later
            # we do not end up with an = in the middle of the pack layout string. There
            # will be an = at the beginning via self.HEADER_PACK
            sub_attr_pack_layout = sub_attr_pack_layout[1:]

            # Now extend the ovarall attribute pack_layout/payload to include this sub-attribute
            pack_layout.extend(sub_attr_pack_layout)
            payload.extend(sub_attr_payload)

        pack_layout = ''.join(pack_layout)

        # Fill in the length field
        length = calcsize(pack_layout)
        payload[attr_length_index] = length

        raw = pack(pack_layout, *payload)
        raw = self.pad(length, raw)
        return raw

    def decode(self, parent_msg, data):
        """
        value is a dictionary such as:
        {
            Link.IFLA_BRPORT_STATE : 3,
            Link.IFLA_BRPORT_PRIORITY : 8
            Link.IFLA_BRPORT_COST : 2
            ...
        }
        """
        self.decode_length_type(data)
        self.value = {}

        data = self.data[4:]

        while data:
            (sub_attr_length, sub_attr_type) = unpack('=HH', data[:4])
            sub_attr_end = padded_length(sub_attr_length)

            if not sub_attr_length:
                self.log.error('parsed a zero length sub-attr')
                return

            if self.family == AF_BRIDGE:

                # 1 Byte attributes
                if sub_attr_type in (Link.IFLA_BRPORT_STATE,
                                     Link.IFLA_BRPORT_MODE,
                                     Link.IFLA_BRPORT_GUARD,
                                     Link.IFLA_BRPORT_PROTECT,
                                     Link.IFLA_BRPORT_FAST_LEAVE,
                                     Link.IFLA_BRPORT_LEARNING,
                                     Link.IFLA_BRPORT_UNICAST_FLOOD,
                                     Link.IFLA_BRPORT_PROXYARP,
                                     Link.IFLA_BRPORT_LEARNING_SYNC,
                                     Link.IFLA_BRPORT_PROXYARP_WIFI,
                                     Link.IFLA_BRPORT_TOPOLOGY_CHANGE_ACK,
                                     Link.IFLA_BRPORT_CONFIG_PENDING,
                                     Link.IFLA_BRPORT_FLUSH,
                                     Link.IFLA_BRPORT_MULTICAST_ROUTER,
                                     Link.IFLA_BRPORT_PEER_LINK,
                                     Link.IFLA_BRPORT_DUAL_LINK,
                                     Link.IFLA_BRPORT_ARP_SUPPRESS,
                                     Link.IFLA_BRPORT_DOWN_PEERLINK_REDIRECT):
                    self.value[sub_attr_type] = unpack('=B', data[4])[0]

                # 2 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_PRIORITY,
                                       Link.IFLA_BRPORT_DESIGNATED_PORT,
                                       Link.IFLA_BRPORT_DESIGNATED_COST,
                                       Link.IFLA_BRPORT_ID,
                                       Link.IFLA_BRPORT_NO):
                    self.value[sub_attr_type] = unpack('=H', data[4:6])[0]

                # 4 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_COST,):
                    self.value[sub_attr_type] = unpack('=L', data[4:8])[0]

                # 8 Byte attributes
                elif sub_attr_type in (Link.IFLA_BRPORT_MESSAGE_AGE_TIMER,
                                       Link.IFLA_BRPORT_FORWARD_DELAY_TIMER,
                                       Link.IFLA_BRPORT_HOLD_TIMER):
                    self.value[sub_attr_type] = unpack('=Q', data[4:12])[0]

                else:
                    self.log.log(SYSLOG_EXTRA_DEBUG, 'Add support for decoding IFLA_PROTINFO sub-attribute type %s (%d), length %d, padded to %d' %
                                (parent_msg.get_ifla_brport_string(sub_attr_type), sub_attr_type, sub_attr_length, sub_attr_end))

            data = data[sub_attr_end:]

    def dump_lines(self, dump_buffer, line_number, color):
        line_number = self.dump_first_line(dump_buffer, line_number, color)
        extra = ''

        next_sub_attr_line = 0
        sub_attr_line = True

        for x in xrange(1, self.attr_end/4):
            start = x * 4
            end = start + 4

            if line_number == next_sub_attr_line:
                sub_attr_line = True

            if sub_attr_line:
                sub_attr_line = False

                (sub_attr_length, sub_attr_type) = unpack('=HH', self.data[start:start+4])
                sub_attr_end = padded_length(sub_attr_length)

                next_sub_attr_line = line_number + (sub_attr_end/4)

                if sub_attr_end == sub_attr_length:
                    padded_to = ', '
                else:
                    padded_to = ' padded to %d, ' % sub_attr_end

                extra = 'Nested Attribute - Length %s (%d)%s Type %s (%d) %s' % \
                        (zfilled_hex(sub_attr_length, 4), sub_attr_length,
                         padded_to,
                         zfilled_hex(sub_attr_type, 4), sub_attr_type,
                         Link.ifla_brport_to_string.get(sub_attr_type))
            else:
                extra = ''

            dump_buffer.append(data_to_color_text(line_number, color, self.data[start:end], extra))
            line_number += 1

        return line_number

    def get_pretty_value(self, obj=None):

        if obj and callable(obj):
            return obj(self.value)

        value_pretty = {}

        for (sub_key, sub_value) in self.value.iteritems():
            sub_key_pretty = "(%2d) %s" % (sub_key, Link.ifla_brport_to_string.get(sub_key, 'UNKNOWN'))
            sub_value_pretty = sub_value
            value_pretty[sub_key_pretty] = sub_value_pretty

        return value_pretty



class NetlinkPacket(object):
    """
    Netlink Header

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Length                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Type              |           Flags              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Process ID (PID)                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    header_PACK = 'IHHII'
    header_LEN  = calcsize(header_PACK)

    # Netlink packet types
    # /usr/include/linux/rtnetlink.h
    type_to_string = {
        NLMSG_NOOP    : 'NLMSG_NOOP',
        NLMSG_ERROR   : 'NLMSG_ERROR',
        NLMSG_DONE    : 'NLMSG_DONE',
        NLMSG_OVERRUN : 'NLMSG_OVERRUN',
        RTM_NEWLINK   : 'RTM_NEWLINK',
        RTM_DELLINK   : 'RTM_DELLINK',
        RTM_GETLINK   : 'RTM_GETLINK',
        RTM_SETLINK   : 'RTM_SETLINK',
        RTM_NEWADDR   : 'RTM_NEWADDR',
        RTM_DELADDR   : 'RTM_DELADDR',
        RTM_GETADDR   : 'RTM_GETADDR',
        RTM_NEWNEIGH  : 'RTM_NEWNEIGH',
        RTM_DELNEIGH  : 'RTM_DELNEIGH',
        RTM_GETNEIGH  : 'RTM_GETNEIGH',
        RTM_NEWROUTE  : 'RTM_NEWROUTE',
        RTM_DELROUTE  : 'RTM_DELROUTE',
        RTM_GETROUTE  : 'RTM_GETROUTE',
        RTM_NEWQDISC  : 'RTM_NEWQDISC',
        RTM_DELQDISC  : 'RTM_DELQDISC',
        RTM_GETQDISC  : 'RTM_GETQDISC'
    }

    af_family_to_string = {
        AF_INET     : 'inet',
        AF_INET6    : 'inet6'
    }

    def __init__(self, msgtype, debug, owner_logger=None, use_color=True):
        self.msgtype     = msgtype
        self.attributes  = {}
        self.dump_buffer = ['']
        self.line_number = 1
        self.debug       = debug
        self.message     = None
        self.use_color   = use_color
        self.family      = None

        if owner_logger:
            self.log = owner_logger
        else:
            self.log = log

    def __str__(self):
        return self.get_type_string()

    def get_string(self, to_string, index):
        """
        Used to do lookups in all of the various FOO_to_string dictionaries
        but returns 'UNKNOWN' if the key is bogus
        """
        if index in to_string:
            return to_string[index]
        return 'UNKNOWN'

    def get_type_string(self, msgtype=None):
        if not msgtype:
            msgtype = self.msgtype
        return self.get_string(self.type_to_string, msgtype)

    def get_flags_string(self):
        foo = []

        for (flag, flag_string) in self.flag_to_string.iteritems():
            if self.flags & flag:
                foo.append(flag_string)

        return ', '.join(foo)

    def decode_packet(self, length, flags, seq, pid, data):
        self.length      = length
        self.flags       = flags
        self.seq         = seq
        self.pid         = pid
        self.header_data = data[0:self.header_LEN]
        self.msg_data    = data[self.header_LEN:length]

        self.decode_netlink_header()
        self.decode_service_header()

        # NLMSG_ERROR is special case, it does not have attributes to decode
        if self.msgtype != NLMSG_ERROR:
            self.decode_attributes()

    def get_netlink_header_flags_string(self, msg_type, flags):
        foo = []

        if flags & NLM_F_REQUEST:
            foo.append('NLM_F_REQUEST')

        if flags & NLM_F_MULTI:
            foo.append('NLM_F_MULTI')

        if flags & NLM_F_ACK:
            foo.append('NLM_F_ACK')

        if flags & NLM_F_ECHO:
            foo.append('NLM_F_ECHO')

        # Modifiers to GET query
        if msg_type in (RTM_GETLINK, RTM_GETADDR, RTM_GETNEIGH, RTM_GETROUTE, RTM_GETQDISC):
            if flags & NLM_F_DUMP:
                foo.append('NLM_F_DUMP')
            else:
                if flags & NLM_F_MATCH:
                    foo.append('NLM_F_MATCH')

                if flags & NLM_F_ROOT:
                    foo.append('NLM_F_ROOT')

            if flags & NLM_F_ATOMIC:
                foo.append('NLM_F_ATOMIC')

        # Modifiers to NEW query
        elif msg_type in (RTM_NEWLINK, RTM_NEWADDR, RTM_NEWNEIGH, RTM_NEWROUTE, RTM_NEWQDISC):
            if flags & NLM_F_REPLACE:
                foo.append('NLM_F_REPLACE')

            if flags & NLM_F_EXCL:
                foo.append('NLM_F_EXCL')

            if flags & NLM_F_CREATE:
                foo.append('NLM_F_CREATE')

            if flags & NLM_F_APPEND:
                foo.append('NLM_F_APPEND')

        return ', '.join(foo)

    # When we first RXed the netlink message we had to decode the header to
    # determine what type of netlink message we were dealing with.  So the
    # header has actually already been decoded...what we do here is
    # populate the dump_buffer lines with the header content.
    def decode_netlink_header(self):

        if not self.debug:
            return

        header_data = self.header_data

        # Print the netlink header in red
        netlink_header_length = 16
        color = red if self.use_color else None
        color_start = "\033[%dm" % color if color else ""
        color_end = "\033[0m" if color else ""
        self.dump_buffer.append("  %sNetlink Header%s" % (color_start, color_end))

        for x in range(0, netlink_header_length/4):
            start = x * 4
            end = start + 4

            if self.line_number == 1:
                data = unpack('=L', header_data[start:end])[0]
                extra = "Length %s (%d)" % (zfilled_hex(data, 8), data)

            elif self.line_number == 2:
                (data1, data2) = unpack('HH', header_data[start:end])
                extra = "Type %s (%d - %s), Flags %s (%s)" % \
                    (zfilled_hex(data1, 4), data1, self.get_type_string(data1),
                     zfilled_hex(data2, 4), self.get_netlink_header_flags_string(data1, data2))

            elif self.line_number == 3:
                data = unpack('=L', header_data[start:end])[0]
                extra = "Sequence Number %s (%d)" % (zfilled_hex(data, 8), data)

            elif self.line_number == 4:
                data = unpack('=L', header_data[start:end])[0]
                extra = "Process ID %s (%d)" % (zfilled_hex(data, 8), data)
            else:
                extra = "Unexpected line number %d" % self.line_number

            self.dump_buffer.append(data_to_color_text(self.line_number, color, header_data[start:end], extra))
            self.line_number += 1

    def decode_attributes(self):
        """
        Decode the attributes and populate the dump_buffer
        """

        if self.debug:
            self.dump_buffer.append("  Attributes")
            color = green if self.use_color else None

        data = self.msg_data[self.LEN:]

        while data:
            (length, attr_type) = unpack('=HH', data[:4])

            # If this is zero we will stay in this loop for forever
            if not length:
                self.log.error('Length is zero')
                return

            if len(data) < length:
                self.log.error("Buffer underrun %d < %d" % (len(data), length))
                return

            attr = self.add_attribute(attr_type, None)

            # Find the end of 'data' for this attribute and decode our section
            # of 'data'. attributes are padded for alignment thus the attr_end.
            #
            # How the attribute is decoded/unpacked is specific per AttributeXXXX class.
            attr_end = padded_length(length)
            attr.decode(self, data[0:attr_end])

            if self.debug:
                self.line_number = attr.dump_lines(self.dump_buffer, self.line_number, color)

                # Alternate back and forth between green and blue
                if self.use_color:
                    if color == green:
                        color = blue
                    else:
                        color = green

            data = data[attr_end:]

    def add_attribute(self, attr_type, value):
        nested = True if attr_type & NLA_F_NESTED else False
        net_byteorder = True if attr_type & NLA_F_NET_BYTEORDER else False
        attr_type = attr_type & NLA_TYPE_MASK

        # Given an attr_type (say RTA_DST) find the type of AttributeXXXX class
        # that we will use to store this attribute...AttributeIPAddress in the
        # case of RTA_DST.
        if attr_type in self.attribute_to_class:
            (attr_string, attr_class) = self.attribute_to_class[attr_type]

            '''
            attribute_to_class is a dictionary where the key is the attr_type, it doesn't
            take the family into account. For now we'll handle this as a special case for
            MPLS but long term we may need to make key a tuple of the attr_type and family.
            '''
            if attr_type == Route.RTA_DST and self.family == AF_MPLS:
                attr_string = 'RTA_DST'
                attr_class = AttributeMplsLabel

        else:
            attr_string = "UNKNOWN_ATTRIBUTE_%d" % attr_type
            attr_class = AttributeGeneric
            self.log.debug("Attribute %d is not defined in %s.attribute_to_class, assuming AttributeGeneric" %
                           (attr_type, self.__class__.__name__))

        attr = attr_class(attr_type, attr_string, self.family, self.log)

        attr.set_value(value)
        attr.set_nested(nested)
        attr.set_net_byteorder(net_byteorder)

        # self.attributes is a dictionary keyed by the attribute type where
        # the value is an instance of the corresponding AttributeXXXX class.
        self.attributes[attr_type] = attr

        return attr

    def get_attribute_value(self, attr_type, default=None):
        if attr_type not in self.attributes:
            return default

        return self.attributes[attr_type].value

    def get_attr_string(self, attr_type):
        """
        Example: If attr_type is Address.IFA_CACHEINFO return the string 'IFA_CACHEINFO'
        """
        if attr_type in self.attribute_to_class:
            (attr_string, attr_class) = self.attribute_to_class[attr_type]
            return attr_string
        return str(attr_type)

    def build_message(self, seq, pid):
        self.seq = seq
        self.pid = pid
        attrs = ''

        for attr in self.attributes.itervalues():
            attrs += attr.encode()

        self.length = self.header_LEN + len(self.body) + len(attrs)
        self.header_data = pack(self.header_PACK, self.length, self.msgtype, self.flags, self.seq, self.pid)
        self.msg_data = self.body + attrs
        self.message = self.header_data + self.msg_data

        if self.debug:
            self.decode_netlink_header()
            self.decode_service_header()
            self.decode_attributes()
            self.dump("TXed %s, length %d, seq %d, pid %d, flags 0x%x (%s)" %
                      (self, self.length, self.seq, self.pid, self.flags,
                       self.get_netlink_header_flags_string(self.msgtype, self.flags)))

    def pretty_display_dict(self, dic, level):
        for k,v in dic.iteritems():
            if isinstance(v, dict):
                self.log.debug(' '*level + str(k) + ':')
                self.pretty_display_dict(v, level+5)
            else:
                self.log.debug(' '*level + str(k) + ': ' + str(v))

    # Print the netlink message in hex. This is only used for debugging.
    def dump(self, desc=None):
        attr_string = {}

        if desc is None:
            desc = "RXed %s, length %d, seq %d, pid %d, flags 0x%x" % (self, self.length, self.seq, self.pid, self.flags)

        for (attr_type, attr_obj) in self.attributes.iteritems():
            key_string = "(%2d) %s" % (attr_type, self.get_attr_string(attr_type))
            attr_string[key_string] = attr_obj.get_pretty_value()

        if self.use_color:
            self.log.debug("%s\n%s\n\nAttributes Summary\n%s\n" %
                           (desc, '\n'.join(self.dump_buffer), pformat(attr_string)))
        else:
            # Assume if we are not allowing color output we also don't want embedded
            # newline characters in the output. Output each line individually.
            self.log.debug(desc)
            for line in self.dump_buffer:
                self.log.debug(line)
            self.log.debug("")
            self.log.debug("Attributes Summary")
            self.pretty_display_dict(attr_string, 1)


class Address(NetlinkPacket):
    """
    Service Header
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Family    |     Length    |     Flags     |    Scope      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Interface Index                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    # Address attributes
    # /usr/include/linux/if_addr.h
    IFA_UNSPEC    = 0x00
    IFA_ADDRESS   = 0x01
    IFA_LOCAL     = 0x02
    IFA_LABEL     = 0x03
    IFA_BROADCAST = 0x04
    IFA_ANYCAST   = 0x05
    IFA_CACHEINFO = 0x06
    IFA_MULTICAST = 0x07
    IFA_FLAGS     = 0x08

    attribute_to_class = {
        IFA_UNSPEC    : ('IFA_UNSPEC', AttributeGeneric),
        IFA_ADDRESS   : ('IFA_ADDRESS', AttributeIPAddress),
        IFA_LOCAL     : ('IFA_LOCAL', AttributeIPAddress),
        IFA_LABEL     : ('IFA_LABEL', AttributeString),
        IFA_BROADCAST : ('IFA_BROADCAST', AttributeIPAddress),
        IFA_ANYCAST   : ('IFA_ANYCAST', AttributeIPAddress),
        IFA_CACHEINFO : ('IFA_CACHEINFO', AttributeGeneric),
        IFA_MULTICAST : ('IFA_MULTICAST', AttributeIPAddress),
        IFA_FLAGS     : ('IFA_FLAGS', AttributeGeneric)
    }

    # Address flags
    # /usr/include/linux/if_addr.h
    IFA_F_SECONDARY   = 0x01
    IFA_F_NODAD       = 0x02
    IFA_F_OPTIMISTIC  = 0x04
    IFA_F_DADFAILED   = 0x08
    IFA_F_HOMEADDRESS = 0x10
    IFA_F_DEPRECATED  = 0x20
    IFA_F_TENTATIVE   = 0x40
    IFA_F_PERMANENT   = 0x80

    flag_to_string = {
        IFA_F_SECONDARY   : 'IFA_F_SECONDARY',
        IFA_F_NODAD       : 'IFA_F_NODAD',
        IFA_F_OPTIMISTIC  : 'IFA_F_OPTIMISTIC',
        IFA_F_DADFAILED   : 'IFA_F_DADFAILED',
        IFA_F_HOMEADDRESS : 'IFA_F_HOMEADDRESS',
        IFA_F_DEPRECATED  : 'IFA_F_DEPRECATED',
        IFA_F_TENTATIVE   : 'IFA_F_TENTATIVE',
        IFA_F_PERMANENT   : 'IFA_F_PERMANENT'
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = '4Bi'
        self.LEN = calcsize(self.PACK)

    def decode_service_header(self):

        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.family, self.prefixlen, self.flags, self.scope,
         self.ifindex) = \
            unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN/4):
                if self.line_number == 5:
                    extra = "Family %s (%d), Length %s (%d), Flags %s, Scope %s (%d)" % \
                            (zfilled_hex(self.family, 2), self.family,
                             zfilled_hex(self.prefixlen, 2), self.prefixlen,
                             zfilled_hex(self.flags, 2),
                             zfilled_hex(self.scope, 2), self.scope)
                elif self.line_number == 6:
                    extra = "Interface Index %s (%d)" % (zfilled_hex(self.ifindex, 8), self.ifindex)
                else:
                    extra = "Unexpected line number %d" % self.line_number

                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1


class Error(NetlinkPacket):

    # Error codes
    # /include/netlink/errno.h
    NLE_SUCCESS           = 0x00
    NLE_FAILURE           = 0x01
    NLE_INTR              = 0x02
    NLE_BAD_SOCK          = 0x03
    NLE_AGAIN             = 0x04
    NLE_NOMEM             = 0x05
    NLE_EXIST             = 0x06
    NLE_INVAL             = 0x07
    NLE_RANGE             = 0x08
    NLE_MSGSIZE           = 0x09
    NLE_OPNOTSUPP         = 0x0A
    NLE_AF_NOSUPPORT      = 0x0B
    NLE_OBJ_NOTFOUND      = 0x0C
    NLE_NOATTR            = 0x0D
    NLE_MISSING_ATTR      = 0x0E
    NLE_AF_MISMATCH       = 0x0F
    NLE_SEQ_MISMATCH      = 0x10
    NLE_MSG_OVERFLOW      = 0x11
    NLE_MSG_TRUNC         = 0x12
    NLE_NOADDR            = 0x13
    NLE_SRCRT_NOSUPPORT   = 0x14
    NLE_MSG_TOOSHORT      = 0x15
    NLE_MSGTYPE_NOSUPPORT = 0x16
    NLE_OBJ_MISMATCH      = 0x17
    NLE_NOCACHE           = 0x18
    NLE_BUSY              = 0x19
    NLE_PROTO_MISMATCH    = 0x1A
    NLE_NOACCESS          = 0x1B
    NLE_PERM              = 0x1C
    NLE_PKTLOC_FILE       = 0x1D
    NLE_PARSE_ERR         = 0x1E
    NLE_NODEV             = 0x1F
    NLE_IMMUTABLE         = 0x20
    NLE_DUMP_INTR         = 0x21

    error_to_string = {
        NLE_SUCCESS           : 'NLE_SUCCESS',
        NLE_FAILURE           : 'NLE_FAILURE',
        NLE_INTR              : 'NLE_INTR',
        NLE_BAD_SOCK          : 'NLE_BAD_SOCK',
        NLE_AGAIN             : 'NLE_AGAIN',
        NLE_NOMEM             : 'NLE_NOMEM',
        NLE_EXIST             : 'NLE_EXIST',
        NLE_INVAL             : 'NLE_INVAL',
        NLE_RANGE             : 'NLE_RANGE',
        NLE_MSGSIZE           : 'NLE_MSGSIZE',
        NLE_OPNOTSUPP         : 'NLE_OPNOTSUPP',
        NLE_AF_NOSUPPORT      : 'NLE_AF_NOSUPPORT',
        NLE_OBJ_NOTFOUND      : 'NLE_OBJ_NOTFOUND',
        NLE_NOATTR            : 'NLE_NOATTR',
        NLE_MISSING_ATTR      : 'NLE_MISSING_ATTR',
        NLE_AF_MISMATCH       : 'NLE_AF_MISMATCH',
        NLE_SEQ_MISMATCH      : 'NLE_SEQ_MISMATCH',
        NLE_MSG_OVERFLOW      : 'NLE_MSG_OVERFLOW',
        NLE_MSG_TRUNC         : 'NLE_MSG_TRUNC',
        NLE_NOADDR            : 'NLE_NOADDR',
        NLE_SRCRT_NOSUPPORT   : 'NLE_SRCRT_NOSUPPORT',
        NLE_MSG_TOOSHORT      : 'NLE_MSG_TOOSHORT',
        NLE_MSGTYPE_NOSUPPORT : 'NLE_MSGTYPE_NOSUPPORT',
        NLE_OBJ_MISMATCH      : 'NLE_OBJ_MISMATCH',
        NLE_NOCACHE           : 'NLE_NOCACHE',
        NLE_BUSY              : 'NLE_BUSY',
        NLE_PROTO_MISMATCH    : 'NLE_PROTO_MISMATCH',
        NLE_NOACCESS          : 'NLE_NOACCESS',
        NLE_PERM              : 'NLE_PERM',
        NLE_PKTLOC_FILE       : 'NLE_PKTLOC_FILE',
        NLE_PARSE_ERR         : 'NLE_PARSE_ERR',
        NLE_NODEV             : 'NLE_NODEV',
        NLE_IMMUTABLE         : 'NLE_IMMUTABLE',
        NLE_DUMP_INTR         : 'NLE_DUMP_INTR'
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = '=iLHHLL'
        self.LEN = calcsize(self.PACK)

    def decode_service_header(self):

        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.negative_errno, self.bad_msg_len, self.bad_msg_type,
         self.bad_msg_flag, self.bad_msg_seq, self.bad_msg_pid) =\
            unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN/4):

                if self.line_number == 5:
                    extra = "Error Number %s is %s" % (self.negative_errno, self.error_to_string.get(abs(self.negative_errno)))
                    # zfilled_hex(self.negative_errno, 2)

                elif self.line_number == 6:
                    extra = "Length %s (%d)" % (zfilled_hex(self.bad_msg_len, 8), self.bad_msg_len)

                elif self.line_number == 7:
                    extra = "Type %s (%d - %s), Flags %s (%s)" % \
                        (zfilled_hex(self.bad_msg_type, 4), self.bad_msg_type, self.get_type_string(self.bad_msg_type),
                         zfilled_hex(self.bad_msg_flag, 4), self.get_netlink_header_flags_string(self.bad_msg_type, self.bad_msg_flag))

                elif self.line_number == 8:
                    extra = "Sequence Number %s (%d)" % (zfilled_hex(self.bad_msg_seq, 8), self.bad_msg_seq)

                elif self.line_number == 9:
                    extra = "Process ID %s (%d)" % (zfilled_hex(self.bad_msg_pid, 8), self.bad_msg_pid)

                else:
                    extra = "Unexpected line number %d" % self.line_number

                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1


class Link(NetlinkPacket):
    """
    Service Header

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Family    |   Reserved  |          Device Type              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Interface Index                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Device Flags                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Change Mask                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    # Link attributes
    # /usr/include/linux/if_link.h
    IFLA_UNSPEC          = 0
    IFLA_ADDRESS         = 1
    IFLA_BROADCAST       = 2
    IFLA_IFNAME          = 3
    IFLA_MTU             = 4
    IFLA_LINK            = 5
    IFLA_QDISC           = 6
    IFLA_STATS           = 7
    IFLA_COST            = 8
    IFLA_PRIORITY        = 9
    IFLA_MASTER          = 10
    IFLA_WIRELESS        = 11
    IFLA_PROTINFO        = 12
    IFLA_TXQLEN          = 13
    IFLA_MAP             = 14
    IFLA_WEIGHT          = 15
    IFLA_OPERSTATE       = 16
    IFLA_LINKMODE        = 17
    IFLA_LINKINFO        = 18
    IFLA_NET_NS_PID      = 19
    IFLA_IFALIAS         = 20
    IFLA_NUM_VF          = 21
    IFLA_VFINFO_LIST     = 22
    IFLA_STATS64         = 23
    IFLA_VF_PORTS        = 24
    IFLA_PORT_SELF       = 25
    IFLA_AF_SPEC         = 26
    IFLA_GROUP           = 27
    IFLA_NET_NS_FD       = 28
    IFLA_EXT_MASK        = 29
    IFLA_PROMISCUITY     = 30
    IFLA_NUM_TX_QUEUES   = 31
    IFLA_NUM_RX_QUEUES   = 32
    IFLA_CARRIER         = 33
    IFLA_PHYS_PORT_ID    = 34
    IFLA_CARRIER_CHANGES = 35
    IFLA_PHYS_SWITCH_ID  = 36
    IFLA_LINK_NETNSID    = 37
    IFLA_PHYS_PORT_NAME  = 38
    IFLA_PROTO_DOWN      = 39
    IFLA_GSO_MAX_SEGS    = 40
    IFLA_GSO_MAX_SIZE    = 41

    attribute_to_class = {
        IFLA_UNSPEC          : ('IFLA_UNSPEC', AttributeGeneric),
        IFLA_ADDRESS         : ('IFLA_ADDRESS', AttributeMACAddress),
        IFLA_BROADCAST       : ('IFLA_BROADCAST', AttributeMACAddress),
        IFLA_IFNAME          : ('IFLA_IFNAME', AttributeStringInterfaceName),
        IFLA_MTU             : ('IFLA_MTU', AttributeFourByteValue),
        IFLA_LINK            : ('IFLA_LINK', AttributeFourByteValue),
        IFLA_QDISC           : ('IFLA_QDISC', AttributeString),
        IFLA_STATS           : ('IFLA_STATS', AttributeGeneric),
        IFLA_COST            : ('IFLA_COST', AttributeGeneric),
        IFLA_PRIORITY        : ('IFLA_PRIORITY', AttributeGeneric),
        IFLA_MASTER          : ('IFLA_MASTER', AttributeFourByteValue),
        IFLA_WIRELESS        : ('IFLA_WIRELESS', AttributeGeneric),
        IFLA_PROTINFO        : ('IFLA_PROTINFO', AttributeIFLA_PROTINFO),
        IFLA_TXQLEN          : ('IFLA_TXQLEN', AttributeFourByteValue),
        IFLA_MAP             : ('IFLA_MAP', AttributeGeneric),
        IFLA_WEIGHT          : ('IFLA_WEIGHT', AttributeGeneric),
        IFLA_OPERSTATE       : ('IFLA_OPERSTATE', AttributeOneByteValue),
        IFLA_LINKMODE        : ('IFLA_LINKMODE', AttributeOneByteValue),
        IFLA_LINKINFO        : ('IFLA_LINKINFO', AttributeIFLA_LINKINFO),
        IFLA_NET_NS_PID      : ('IFLA_NET_NS_PID', AttributeGeneric),
        IFLA_IFALIAS         : ('IFLA_IFALIAS', AttributeGeneric),
        IFLA_NUM_VF          : ('IFLA_NUM_VF', AttributeGeneric),
        IFLA_VFINFO_LIST     : ('IFLA_VFINFO_LIST', AttributeGeneric),
        IFLA_STATS64         : ('IFLA_STATS64', AttributeGeneric),
        IFLA_VF_PORTS        : ('IFLA_VF_PORTS', AttributeGeneric),
        IFLA_PORT_SELF       : ('IFLA_PORT_SELF', AttributeGeneric),
        IFLA_AF_SPEC         : ('IFLA_AF_SPEC', AttributeIFLA_AF_SPEC),
        IFLA_GROUP           : ('IFLA_GROUP', AttributeFourByteValue),
        IFLA_NET_NS_FD       : ('IFLA_NET_NS_FD', AttributeGeneric),
        IFLA_EXT_MASK        : ('IFLA_EXT_MASK', AttributeFourByteValue),
        IFLA_PROMISCUITY     : ('IFLA_PROMISCUITY', AttributeGeneric),
        IFLA_NUM_TX_QUEUES   : ('IFLA_NUM_TX_QUEUES', AttributeGeneric),
        IFLA_NUM_RX_QUEUES   : ('IFLA_NUM_RX_QUEUES', AttributeGeneric),
        IFLA_CARRIER         : ('IFLA_CARRIER', AttributeGeneric),
        IFLA_PHYS_PORT_ID    : ('IFLA_PHYS_PORT_ID', AttributeGeneric),
        IFLA_CARRIER_CHANGES : ('IFLA_CARRIER_CHANGES', AttributeGeneric),
        IFLA_PHYS_SWITCH_ID  : ('IFLA_PHYS_SWITCH_ID', AttributeGeneric),
        IFLA_LINK_NETNSID    : ('IFLA_LINK_NETNSID', AttributeGeneric),
        IFLA_PHYS_PORT_NAME  : ('IFLA_PHYS_PORT_NAME', AttributeGeneric),
        IFLA_PROTO_DOWN      : ('IFLA_PROTO_DOWN', AttributeOneByteValue),
        IFLA_GSO_MAX_SEGS    : ('IFLA_GSO_MAX_SEGS', AttributeFourByteValue),
        IFLA_GSO_MAX_SIZE    : ('IFLA_GSO_MAX_SIZE', AttributeFourByteValue)
    }

    # Link flags
    # /usr/include/linux/if.h
    IFF_UP          = 0x0001     # Interface is administratively up.
    IFF_BROADCAST   = 0x0002     # Valid broadcast address set.
    IFF_DEBUG       = 0x0004     # Internal debugging flag.
    IFF_LOOPBACK    = 0x0008     # Interface is a loopback interface.
    IFF_POINTOPOINT = 0x0010     # Interface is a point-to-point link.
    IFF_NOTRAILERS  = 0x0020     # Avoid use of trailers.
    IFF_RUNNING     = 0x0040     # Interface is operationally up.
    IFF_NOARP       = 0x0080     # No ARP protocol needed for this interface.
    IFF_PROMISC     = 0x0100     # Interface is in promiscuous mode.
    IFF_ALLMULTI    = 0x0200     # Receive all multicast packets.
    IFF_MASTER      = 0x0400     # Master of a load balancing bundle.
    IFF_SLAVE       = 0x0800     # Slave of a load balancing bundle.
    IFF_MULTICAST   = 0x1000     # Supports multicast.
    IFF_PORTSEL     = 0x2000     # Is able to select media type via ifmap.
    IFF_AUTOMEDIA   = 0x4000     # Auto media selection active.
    IFF_DYNAMIC     = 0x8000     # Interface was dynamically created.
    IFF_LOWER_UP    = 0x10000    # driver signals L1 up
    IFF_DORMANT     = 0x20000    # driver signals dormant
    IFF_ECHO        = 0x40000    # echo sent packet
    IFF_PROTO_DOWN  = 0x1000000  # protocol is down on the interface

    flag_to_string = {
        IFF_UP          : 'IFF_UP',
        IFF_BROADCAST   : 'IFF_BROADCAST',
        IFF_DEBUG       : 'IFF_DEBUG',
        IFF_LOOPBACK    : 'IFF_LOOPBACK',
        IFF_POINTOPOINT : 'IFF_POINTOPOINT',
        IFF_NOTRAILERS  : 'IFF_NOTRAILERS',
        IFF_RUNNING     : 'IFF_RUNNING',
        IFF_NOARP       : 'IFF_NOARP',
        IFF_PROMISC     : 'IFF_PROMISC',
        IFF_ALLMULTI    : 'IFF_ALLMULTI',
        IFF_MASTER      : 'IFF_MASTER',
        IFF_SLAVE       : 'IFF_SLAVE',
        IFF_MULTICAST   : 'IFF_MULTICAST',
        IFF_PORTSEL     : 'IFF_PORTSEL',
        IFF_AUTOMEDIA   : 'IFF_AUTOMEDIA',
        IFF_DYNAMIC     : 'IFF_DYNAMIC',
        IFF_LOWER_UP    : 'IFF_LOWER_UP',
        IFF_DORMANT     : 'IFF_DORMANT',
        IFF_ECHO        : 'IFF_ECHO',
        IFF_PROTO_DOWN  : 'IFF_PROTO_DOWN'
    }

    # RFC 2863 operational status
    IF_OPER_UNKNOWN        = 0
    IF_OPER_NOTPRESENT     = 1
    IF_OPER_DOWN           = 2
    IF_OPER_LOWERLAYERDOWN = 3
    IF_OPER_TESTING        = 4
    IF_OPER_DORMANT        = 5
    IF_OPER_UP             = 6

    oper_to_string = {
        IF_OPER_UNKNOWN        : 'IF_OPER_UNKNOWN',
        IF_OPER_NOTPRESENT     : 'IF_OPER_NOTPRESENT',
        IF_OPER_DOWN           : 'IF_OPER_DOWN',
        IF_OPER_LOWERLAYERDOWN : 'IF_OPER_LOWERLAYERDOWN',
        IF_OPER_TESTING        : 'IF_OPER_TESTING',
        IF_OPER_DORMANT        : 'IF_OPER_DORMANT',
        IF_OPER_UP             : 'IF_OPER_UP'
    }

    # Link types
    # /usr/include/linux/if_arp.h
    # ARP protocol HARDWARE identifiers
    ARPHRD_NETROM             = 0      # from KA9Q: NET/ROM pseudo
    ARPHRD_ETHER              = 1      # Ethernet 10Mbps
    ARPHRD_EETHER             = 2      # Experimental Ethernet
    ARPHRD_AX25               = 3      # AX.25 Level 2
    ARPHRD_PRONET             = 4      # PROnet token ring
    ARPHRD_CHAOS              = 5      # Chaosnet
    ARPHRD_IEEE802            = 6      # IEEE 802.2 Ethernet/TR/TB
    ARPHRD_ARCNET             = 7      # ARCnet
    ARPHRD_APPLETLK           = 8      # APPLEtalk
    ARPHRD_DLCI               = 15     # Frame Relay DLCI
    ARPHRD_ATM                = 19     # ATM
    ARPHRD_METRICOM           = 23     # Metricom STRIP (new IANA id)
    ARPHRD_IEEE1394           = 24     # IEEE 1394 IPv4 - RFC 2734
    ARPHRD_EUI64              = 27     # EUI-64
    ARPHRD_INFINIBAND         = 32     # InfiniBand
    # Dummy types for non ARP hardware
    ARPHRD_SLIP               = 256
    ARPHRD_CSLIP              = 257
    ARPHRD_SLIP6              = 258
    ARPHRD_CSLIP6             = 259
    ARPHRD_RSRVD              = 260    # Notional KISS type
    ARPHRD_ADAPT              = 264
    ARPHRD_ROSE               = 270
    ARPHRD_X25                = 271    # CCITT X.25
    ARPHRD_HWX25              = 272    # Boards with X.25 in firmware
    ARPHRD_CAN                = 280    # Controller Area Network
    ARPHRD_PPP                = 512
    ARPHRD_CISCO              = 513    # Cisco HDLC
    ARPHRD_HDLC               = ARPHRD_CISCO
    ARPHRD_LAPB               = 516    # LAPB
    ARPHRD_DDCMP              = 517    # Digital's DDCMP protocol
    ARPHRD_RAWHDLC            = 518    # Raw HDLC
    ARPHRD_TUNNEL             = 768    # IPIP tunnel
    ARPHRD_TUNNEL6            = 769    # IP6IP6 tunnel
    ARPHRD_FRAD               = 770    # Frame Relay Access Device
    ARPHRD_SKIP               = 771    # SKIP vif
    ARPHRD_LOOPBACK           = 772    # Loopback device
    ARPHRD_LOCALTLK           = 773    # Localtalk device
    ARPHRD_FDDI               = 774    # Fiber Distributed Data Interface
    ARPHRD_BIF                = 775    # AP1000 BIF
    ARPHRD_SIT                = 776    # sit0 device - IPv6-in-IPv4
    ARPHRD_IPDDP              = 777    # IP over DDP tunneller
    ARPHRD_IPGRE              = 778    # GRE over IP
    ARPHRD_PIMREG             = 779    # PIMSM register interface
    ARPHRD_HIPPI              = 780    # High Performance Parallel Interface
    ARPHRD_ASH                = 781    # Nexus 64Mbps Ash
    ARPHRD_ECONET             = 782    # Acorn Econet
    ARPHRD_IRDA               = 783    # Linux-IrDA
    ARPHRD_FCPP               = 784    # Point to point fibrechannel
    ARPHRD_FCAL               = 785    # Fibrechannel arbitrated loop
    ARPHRD_FCPL               = 786    # Fibrechannel public loop
    ARPHRD_FCFABRIC           = 787    # Fibrechannel fabric
    # 787->799 reserved for fibrechannel media types
    ARPHRD_IEEE802_TR         = 800    # Magic type ident for TR
    ARPHRD_IEEE80211          = 801    # IEEE 802.11
    ARPHRD_IEEE80211_PRISM    = 802    # IEEE 802.11 + Prism2 header
    ARPHRD_IEEE80211_RADIOTAP = 803    # IEEE 802.11 + radiotap header
    ARPHRD_IEEE802154         = 804
    ARPHRD_PHONET             = 820    # PhoNet media type
    ARPHRD_PHONET_PIPE        = 821    # PhoNet pipe header
    ARPHRD_CAIF               = 822    # CAIF media type
    ARPHRD_VOID               = 0xFFFF  # Void type, nothing is known
    ARPHRD_NONE               = 0xFFFE  # zero header length

    link_type_to_string = {
        ARPHRD_NETROM             : 'ARPHRD_NETROM',
        ARPHRD_ETHER              : 'ARPHRD_ETHER',
        ARPHRD_EETHER             : 'ARPHRD_EETHER',
        ARPHRD_AX25               : 'ARPHRD_AX25',
        ARPHRD_PRONET             : 'ARPHRD_PRONET',
        ARPHRD_CHAOS              : 'ARPHRD_CHAOS',
        ARPHRD_IEEE802            : 'ARPHRD_IEEE802',
        ARPHRD_ARCNET             : 'ARPHRD_ARCNET',
        ARPHRD_APPLETLK           : 'ARPHRD_APPLETLK',
        ARPHRD_DLCI               : 'ARPHRD_DLCI',
        ARPHRD_ATM                : 'ARPHRD_ATM',
        ARPHRD_METRICOM           : 'ARPHRD_METRICOM',
        ARPHRD_IEEE1394           : 'ARPHRD_IEEE1394',
        ARPHRD_EUI64              : 'ARPHRD_EUI64',
        ARPHRD_INFINIBAND         : 'ARPHRD_INFINIBAND',
        ARPHRD_SLIP               : 'ARPHRD_SLIP',
        ARPHRD_CSLIP              : 'ARPHRD_CSLIP',
        ARPHRD_SLIP6              : 'ARPHRD_SLIP6',
        ARPHRD_CSLIP6             : 'ARPHRD_CSLIP6',
        ARPHRD_RSRVD              : 'ARPHRD_RSRVD',
        ARPHRD_ADAPT              : 'ARPHRD_ADAPT',
        ARPHRD_ROSE               : 'ARPHRD_ROSE',
        ARPHRD_X25                : 'ARPHRD_X25',
        ARPHRD_HWX25              : 'ARPHRD_HWX25',
        ARPHRD_CAN                : 'ARPHRD_CAN',
        ARPHRD_PPP                : 'ARPHRD_PPP',
        ARPHRD_CISCO              : 'ARPHRD_CISCO',
        ARPHRD_HDLC               : 'ARPHRD_HDLC',
        ARPHRD_LAPB               : 'ARPHRD_LAPB',
        ARPHRD_DDCMP              : 'ARPHRD_DDCMP',
        ARPHRD_RAWHDLC            : 'ARPHRD_RAWHDLC',
        ARPHRD_TUNNEL             : 'ARPHRD_TUNNEL',
        ARPHRD_TUNNEL6            : 'ARPHRD_TUNNEL6',
        ARPHRD_FRAD               : 'ARPHRD_FRAD',
        ARPHRD_SKIP               : 'ARPHRD_SKIP',
        ARPHRD_LOOPBACK           : 'ARPHRD_LOOPBACK',
        ARPHRD_LOCALTLK           : 'ARPHRD_LOCALTLK',
        ARPHRD_FDDI               : 'ARPHRD_FDDI',
        ARPHRD_BIF                : 'ARPHRD_BIF',
        ARPHRD_SIT                : 'ARPHRD_SIT',
        ARPHRD_IPDDP              : 'ARPHRD_IPDDP',
        ARPHRD_IPGRE              : 'ARPHRD_IPGRE',
        ARPHRD_PIMREG             : 'ARPHRD_PIMREG',
        ARPHRD_HIPPI              : 'ARPHRD_HIPPI',
        ARPHRD_ASH                : 'ARPHRD_ASH',
        ARPHRD_ECONET             : 'ARPHRD_ECONET',
        ARPHRD_IRDA               : 'ARPHRD_IRDA',
        ARPHRD_FCPP               : 'ARPHRD_FCPP',
        ARPHRD_FCAL               : 'ARPHRD_FCAL',
        ARPHRD_FCPL               : 'ARPHRD_FCPL',
        ARPHRD_FCFABRIC           : 'ARPHRD_FCFABRIC',
        ARPHRD_IEEE802_TR         : 'ARPHRD_IEEE802_TR',
        ARPHRD_IEEE80211          : 'ARPHRD_IEEE80211',
        ARPHRD_IEEE80211_PRISM    : 'ARPHRD_IEEE80211_PRISM',
        ARPHRD_IEEE80211_RADIOTAP : 'ARPHRD_IEEE80211_RADIOTAP',
        ARPHRD_IEEE802154         : 'ARPHRD_IEEE802154',
        ARPHRD_PHONET             : 'ARPHRD_PHONET',
        ARPHRD_PHONET_PIPE        : 'ARPHRD_PHONET_PIPE',
        ARPHRD_CAIF               : 'ARPHRD_CAIF',
        ARPHRD_VOID               : 'ARPHRD_VOID',
        ARPHRD_NONE               : 'ARPHRD_NONE'
    }

    # =========================================
    # IFLA_LINKINFO attributes
    # =========================================
    IFLA_INFO_UNSPEC     = 0
    IFLA_INFO_KIND       = 1
    IFLA_INFO_DATA       = 2
    IFLA_INFO_XSTATS     = 3
    IFLA_INFO_SLAVE_KIND = 4
    IFLA_INFO_SLAVE_DATA = 5
    IFLA_INFO_MAX        = 6

    ifla_info_to_string = {
        IFLA_INFO_UNSPEC     : 'IFLA_INFO_UNSPEC',
        IFLA_INFO_KIND       : 'IFLA_INFO_KIND',
        IFLA_INFO_DATA       : 'IFLA_INFO_DATA',
        IFLA_INFO_XSTATS     : 'IFLA_INFO_XSTATS',
        IFLA_INFO_SLAVE_KIND : 'IFLA_INFO_SLAVE_KIND',
        IFLA_INFO_SLAVE_DATA : 'IFLA_INFO_SLAVE_DATA',
        IFLA_INFO_MAX        : 'IFLA_INFO_MAX'
    }

    # =========================================
    # IFLA_INFO_DATA attributes for vlan
    # =========================================
    IFLA_VLAN_UNSPEC      = 0
    IFLA_VLAN_ID          = 1
    IFLA_VLAN_FLAGS       = 2
    IFLA_VLAN_EGRESS_QOS  = 3
    IFLA_VLAN_INGRESS_QOS = 4
    IFLA_VLAN_PROTOCOL    = 5

    ifla_vlan_to_string = {
        IFLA_VLAN_UNSPEC      : 'IFLA_VLAN_UNSPEC',
        IFLA_VLAN_ID          : 'IFLA_VLAN_ID',
        IFLA_VLAN_FLAGS       : 'IFLA_VLAN_FLAGS',
        IFLA_VLAN_EGRESS_QOS  : 'IFLA_VLAN_EGRESS_QOS',
        IFLA_VLAN_INGRESS_QOS : 'IFLA_VLAN_INGRESS_QOS',
        IFLA_VLAN_PROTOCOL    : 'IFLA_VLAN_PROTOCOL'
    }

    ifla_vlan_protocol_dict = {
        '802.1Q':   0x8100,
        '802.1q':   0x8100,

        '802.1ad':  0x88A8,
        '802.1AD':  0x88A8,
        '802.1Ad':  0x88A8,
        '802.1aD':  0x88A8,

        0x8100:     '802.1Q',
        0x88A8:     '802.1ad'
    }

    # =========================================
    # IFLA_INFO_DATA attributes for macvlan
    # =========================================
    IFLA_MACVLAN_UNSPEC = 0
    IFLA_MACVLAN_MODE   = 1

    ifla_macvlan_to_string = {
        IFLA_MACVLAN_UNSPEC : 'IFLA_MACVLAN_UNSPEC',
        IFLA_MACVLAN_MODE   : 'IFLA_MACVLAN_MODE'
    }

    # macvlan modes
    MACVLAN_MODE_PRIVATE  = 1
    MACVLAN_MODE_VEPA     = 2
    MACVLAN_MODE_BRIDGE   = 3
    MACVLAN_MODE_PASSTHRU = 4

    macvlan_mode_to_string = {
        MACVLAN_MODE_PRIVATE  : 'MACVLAN_MODE_PRIVATE',
        MACVLAN_MODE_VEPA     : 'MACVLAN_MODE_VEPA',
        MACVLAN_MODE_BRIDGE   : 'MACVLAN_MODE_BRIDGE',
        MACVLAN_MODE_PASSTHRU : 'MACVLAN_MODE_PASSTHRU'
    }

    # =========================================
    # IFLA_INFO_DATA attributes for vxlan
    # =========================================
    IFLA_VXLAN_UNSPEC            = 0
    IFLA_VXLAN_ID                = 1
    IFLA_VXLAN_GROUP             = 2
    IFLA_VXLAN_LINK              = 3
    IFLA_VXLAN_LOCAL             = 4
    IFLA_VXLAN_TTL               = 5
    IFLA_VXLAN_TOS               = 6
    IFLA_VXLAN_LEARNING          = 7
    IFLA_VXLAN_AGEING            = 8
    IFLA_VXLAN_LIMIT             = 9
    IFLA_VXLAN_PORT_RANGE        = 10
    IFLA_VXLAN_PROXY             = 11
    IFLA_VXLAN_RSC               = 12
    IFLA_VXLAN_L2MISS            = 13
    IFLA_VXLAN_L3MISS            = 14
    IFLA_VXLAN_PORT              = 15
    IFLA_VXLAN_GROUP6            = 16
    IFLA_VXLAN_LOCAL6            = 17
    IFLA_VXLAN_UDP_CSUM          = 18
    IFLA_VXLAN_UDP_ZERO_CSUM6_TX = 19
    IFLA_VXLAN_UDP_ZERO_CSUM6_RX = 20
    IFLA_VXLAN_REMCSUM_TX        = 21
    IFLA_VXLAN_REMCSUM_RX        = 22
    IFLA_VXLAN_GBP               = 23
    IFLA_VXLAN_REMCSUM_NOPARTIAL = 24
    IFLA_VXLAN_COLLECT_METADATA  = 25
    IFLA_VXLAN_REPLICATION_NODE  = 253
    IFLA_VXLAN_REPLICATION_TYPE  = 254

    ifla_vxlan_to_string = {
        IFLA_VXLAN_UNSPEC            : 'IFLA_VXLAN_UNSPEC',
        IFLA_VXLAN_ID                : 'IFLA_VXLAN_ID',
        IFLA_VXLAN_GROUP             : 'IFLA_VXLAN_GROUP',
        IFLA_VXLAN_LINK              : 'IFLA_VXLAN_LINK',
        IFLA_VXLAN_LOCAL             : 'IFLA_VXLAN_LOCAL',
        IFLA_VXLAN_TTL               : 'IFLA_VXLAN_TTL',
        IFLA_VXLAN_TOS               : 'IFLA_VXLAN_TOS',
        IFLA_VXLAN_LEARNING          : 'IFLA_VXLAN_LEARNING',
        IFLA_VXLAN_AGEING            : 'IFLA_VXLAN_AGEING',
        IFLA_VXLAN_LIMIT             : 'IFLA_VXLAN_LIMIT',
        IFLA_VXLAN_PORT_RANGE        : 'IFLA_VXLAN_PORT_RANGE',
        IFLA_VXLAN_PROXY             : 'IFLA_VXLAN_PROXY',
        IFLA_VXLAN_RSC               : 'IFLA_VXLAN_RSC',
        IFLA_VXLAN_L2MISS            : 'IFLA_VXLAN_L2MISS',
        IFLA_VXLAN_L3MISS            : 'IFLA_VXLAN_L3MISS',
        IFLA_VXLAN_PORT              : 'IFLA_VXLAN_PORT',
        IFLA_VXLAN_GROUP6            : 'IFLA_VXLAN_GROUP6',
        IFLA_VXLAN_LOCAL6            : 'IFLA_VXLAN_LOCAL6',
        IFLA_VXLAN_UDP_CSUM          : 'IFLA_VXLAN_UDP_CSUM',
        IFLA_VXLAN_UDP_ZERO_CSUM6_TX : 'IFLA_VXLAN_UDP_ZERO_CSUM6_TX',
        IFLA_VXLAN_UDP_ZERO_CSUM6_RX : 'IFLA_VXLAN_UDP_ZERO_CSUM6_RX',
        IFLA_VXLAN_REMCSUM_TX        : 'IFLA_VXLAN_REMCSUM_TX',
        IFLA_VXLAN_REMCSUM_RX        : 'IFLA_VXLAN_REMCSUM_RX',
        IFLA_VXLAN_GBP               : 'IFLA_VXLAN_GBP',
        IFLA_VXLAN_REMCSUM_NOPARTIAL : 'IFLA_VXLAN_REMCSUM_NOPARTIAL',
        IFLA_VXLAN_COLLECT_METADATA  : 'IFLA_VXLAN_COLLECT_METADATA',
        IFLA_VXLAN_REPLICATION_NODE  : 'IFLA_VXLAN_REPLICATION_NODE',
        IFLA_VXLAN_REPLICATION_TYPE  : 'IFLA_VXLAN_REPLICATION_TYPE'
    }

    # =========================================
    # IFLA_INFO_DATA attributes for bonds
    # =========================================
    IFLA_BOND_UNSPEC                    = 0
    IFLA_BOND_MODE                      = 1
    IFLA_BOND_ACTIVE_SLAVE              = 2
    IFLA_BOND_MIIMON                    = 3
    IFLA_BOND_UPDELAY                   = 4
    IFLA_BOND_DOWNDELAY                 = 5
    IFLA_BOND_USE_CARRIER               = 6
    IFLA_BOND_ARP_INTERVAL              = 7
    IFLA_BOND_ARP_IP_TARGET             = 8
    IFLA_BOND_ARP_VALIDATE              = 9
    IFLA_BOND_ARP_ALL_TARGETS           = 10
    IFLA_BOND_PRIMARY                   = 11
    IFLA_BOND_PRIMARY_RESELECT          = 12
    IFLA_BOND_FAIL_OVER_MAC             = 13
    IFLA_BOND_XMIT_HASH_POLICY          = 14
    IFLA_BOND_RESEND_IGMP               = 15
    IFLA_BOND_NUM_PEER_NOTIF            = 16
    IFLA_BOND_ALL_SLAVES_ACTIVE         = 17
    IFLA_BOND_MIN_LINKS                 = 18
    IFLA_BOND_LP_INTERVAL               = 19
    IFLA_BOND_PACKETS_PER_SLAVE         = 20
    IFLA_BOND_AD_LACP_RATE              = 21
    IFLA_BOND_AD_SELECT                 = 22
    IFLA_BOND_AD_INFO                   = 23
    IFLA_BOND_AD_ACTOR_SYS_PRIO         = 24
    IFLA_BOND_AD_USER_PORT_KEY          = 25
    IFLA_BOND_AD_ACTOR_SYSTEM           = 26
    IFLA_BOND_AD_LACP_BYPASS            = 100

    ifla_bond_to_string = {
        IFLA_BOND_UNSPEC                    : 'IFLA_BOND_UNSPEC',
        IFLA_BOND_MODE                      : 'IFLA_BOND_MODE',
        IFLA_BOND_ACTIVE_SLAVE              : 'IFLA_BOND_ACTIVE_SLAVE',
        IFLA_BOND_MIIMON                    : 'IFLA_BOND_MIIMON',
        IFLA_BOND_UPDELAY                   : 'IFLA_BOND_UPDELAY',
        IFLA_BOND_DOWNDELAY                 : 'IFLA_BOND_DOWNDELAY',
        IFLA_BOND_USE_CARRIER               : 'IFLA_BOND_USE_CARRIER',
        IFLA_BOND_ARP_INTERVAL              : 'IFLA_BOND_ARP_INTERVAL',
        IFLA_BOND_ARP_IP_TARGET             : 'IFLA_BOND_ARP_IP_TARGET',
        IFLA_BOND_ARP_VALIDATE              : 'IFLA_BOND_ARP_VALIDATE',
        IFLA_BOND_ARP_ALL_TARGETS           : 'IFLA_BOND_ARP_ALL_TARGETS',
        IFLA_BOND_PRIMARY                   : 'IFLA_BOND_PRIMARY',
        IFLA_BOND_PRIMARY_RESELECT          : 'IFLA_BOND_PRIMARY_RESELECT',
        IFLA_BOND_FAIL_OVER_MAC             : 'IFLA_BOND_FAIL_OVER_MAC',
        IFLA_BOND_XMIT_HASH_POLICY          : 'IFLA_BOND_XMIT_HASH_POLICY',
        IFLA_BOND_RESEND_IGMP               : 'IFLA_BOND_RESEND_IGMP',
        IFLA_BOND_NUM_PEER_NOTIF            : 'IFLA_BOND_NUM_PEER_NOTIF',
        IFLA_BOND_ALL_SLAVES_ACTIVE         : 'IFLA_BOND_ALL_SLAVES_ACTIVE',
        IFLA_BOND_MIN_LINKS                 : 'IFLA_BOND_MIN_LINKS',
        IFLA_BOND_LP_INTERVAL               : 'IFLA_BOND_LP_INTERVAL',
        IFLA_BOND_PACKETS_PER_SLAVE         : 'IFLA_BOND_PACKETS_PER_SLAVE',
        IFLA_BOND_AD_LACP_RATE              : 'IFLA_BOND_AD_LACP_RATE',
        IFLA_BOND_AD_SELECT                 : 'IFLA_BOND_AD_SELECT',
        IFLA_BOND_AD_INFO                   : 'IFLA_BOND_AD_INFO',
        IFLA_BOND_AD_ACTOR_SYS_PRIO         : 'IFLA_BOND_AD_ACTOR_SYS_PRIO',
        IFLA_BOND_AD_USER_PORT_KEY          : 'IFLA_BOND_AD_USER_PORT_KEY',
        IFLA_BOND_AD_ACTOR_SYSTEM           : 'IFLA_BOND_AD_ACTOR_SYSTEM',
        IFLA_BOND_AD_LACP_BYPASS            : 'IFLA_BOND_AD_LACP_BYPASS'
    }

    IFLA_BOND_AD_INFO_UNSPEC            = 0
    IFLA_BOND_AD_INFO_AGGREGATOR        = 1
    IFLA_BOND_AD_INFO_NUM_PORTS         = 2
    IFLA_BOND_AD_INFO_ACTOR_KEY         = 3
    IFLA_BOND_AD_INFO_PARTNER_KEY       = 4
    IFLA_BOND_AD_INFO_PARTNER_MAC       = 5

    ifla_bond_ad_to_string = {
        IFLA_BOND_AD_INFO_UNSPEC            : 'IFLA_BOND_AD_INFO_UNSPEC',
        IFLA_BOND_AD_INFO_AGGREGATOR        : 'IFLA_BOND_AD_INFO_AGGREGATOR',
        IFLA_BOND_AD_INFO_NUM_PORTS         : 'IFLA_BOND_AD_INFO_NUM_PORTS',
        IFLA_BOND_AD_INFO_ACTOR_KEY         : 'IFLA_BOND_AD_INFO_ACTOR_KEY',
        IFLA_BOND_AD_INFO_PARTNER_KEY       : 'IFLA_BOND_AD_INFO_PARTNER_KEY',
        IFLA_BOND_AD_INFO_PARTNER_MAC       : 'IFLA_BOND_AD_INFO_PARTNER_MAC'
    }

    ifla_bond_mode_tbl = {
        'balance-rr': 0,
        'active-backup': 1,
        'balance-xor': 2,
        'broadcast': 3,
        '802.3ad': 4,
        'balance-tlb': 5,
        'balance-alb': 6,
        '0': 0,
        '1': 1,
        '2': 2,
        '3': 3,
        '4': 4,
        '5': 5,
        '6': 6,
        0: 0,
        1: 1,
        2: 2,
        3: 3,
        4: 4,
        5: 5,
        6: 6
    }

    ifla_bond_mode_pretty_tbl = {
        0: 'balance-rr',
        1: 'active-backup',
        2: 'balance-xor',
        3: 'broadcast',
        4: '802.3ad',
        5: 'balance-tlb',
        6: 'balance-alb'
    }

    ifla_bond_xmit_hash_policy_tbl = {
        'layer2': 0,
        'layer3+4': 1,
        'layer2+3': 2,
        'encap2+3': 3,
        'encap3+4': 4,
        '0': 0,
        '1': 1,
        '2': 2,
        '3': 3,
        '4': 4,
        0: 0,
        1: 1,
        2: 2,
        3: 3,
        4: 4
    }

    ifla_bond_xmit_hash_policy_pretty_tbl = {
        0: 'layer2',
        1: 'layer3+4',
        2: 'layer2+3',
        3: 'encap2+3',
        4: 'encap3+4',
    }

    # =========================================
    # IFLA_INFO_SLAVE_DATA attributes for bonds
    # =========================================
    IFLA_BOND_SLAVE_UNSPEC                      = 0
    IFLA_BOND_SLAVE_STATE                       = 1
    IFLA_BOND_SLAVE_MII_STATUS                  = 2
    IFLA_BOND_SLAVE_LINK_FAILURE_COUNT          = 3
    IFLA_BOND_SLAVE_PERM_HWADDR                 = 4
    IFLA_BOND_SLAVE_QUEUE_ID                    = 5
    IFLA_BOND_SLAVE_AD_AGGREGATOR_ID            = 6
    IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE    = 7
    IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE  = 8
    IFLA_BOND_SLAVE_CL_START                    = 50
    IFLA_BOND_SLAVE_AD_RX_BYPASS                = IFLA_BOND_SLAVE_CL_START

    ifla_bond_slave_to_string = {
        IFLA_BOND_SLAVE_UNSPEC                      : 'IFLA_BOND_SLAVE_UNSPEC',
        IFLA_BOND_SLAVE_STATE                       : 'IFLA_BOND_SLAVE_STATE',
        IFLA_BOND_SLAVE_MII_STATUS                  : 'IFLA_BOND_SLAVE_MII_STATUS',
        IFLA_BOND_SLAVE_LINK_FAILURE_COUNT          : 'IFLA_BOND_SLAVE_LINK_FAILURE_COUNT',
        IFLA_BOND_SLAVE_PERM_HWADDR                 : 'IFLA_BOND_SLAVE_PERM_HWADDR',
        IFLA_BOND_SLAVE_QUEUE_ID                    : 'IFLA_BOND_SLAVE_QUEUE_ID',
        IFLA_BOND_SLAVE_AD_AGGREGATOR_ID            : 'IFLA_BOND_SLAVE_AD_AGGREGATOR_ID',
        IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE    : 'IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE',
        IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE  : 'IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE',
        IFLA_BOND_SLAVE_CL_START                    : 'IFLA_BOND_SLAVE_CL_START',
        IFLA_BOND_SLAVE_AD_RX_BYPASS                : 'IFLA_BOND_SLAVE_AD_RX_BYPASS'
    }

    # =========================================
    # IFLA_PROTINFO attributes for bridge ports
    # =========================================
    IFLA_BRPORT_UNSPEC              = 0
    IFLA_BRPORT_STATE               = 1
    IFLA_BRPORT_PRIORITY            = 2
    IFLA_BRPORT_COST                = 3
    IFLA_BRPORT_MODE                = 4
    IFLA_BRPORT_GUARD               = 5
    IFLA_BRPORT_PROTECT             = 6
    IFLA_BRPORT_FAST_LEAVE          = 7
    IFLA_BRPORT_LEARNING            = 8
    IFLA_BRPORT_UNICAST_FLOOD       = 9
    IFLA_BRPORT_PROXYARP            = 10
    IFLA_BRPORT_LEARNING_SYNC       = 11
    IFLA_BRPORT_PROXYARP_WIFI       = 12
    IFLA_BRPORT_ROOT_ID             = 13
    IFLA_BRPORT_BRIDGE_ID           = 14
    IFLA_BRPORT_DESIGNATED_PORT     = 15
    IFLA_BRPORT_DESIGNATED_COST     = 16
    IFLA_BRPORT_ID                  = 17
    IFLA_BRPORT_NO                  = 18
    IFLA_BRPORT_TOPOLOGY_CHANGE_ACK = 19
    IFLA_BRPORT_CONFIG_PENDING      = 20
    IFLA_BRPORT_MESSAGE_AGE_TIMER   = 21
    IFLA_BRPORT_FORWARD_DELAY_TIMER = 22
    IFLA_BRPORT_HOLD_TIMER          = 23
    IFLA_BRPORT_FLUSH               = 24
    IFLA_BRPORT_MULTICAST_ROUTER    = 25
    IFLA_BRPORT_PAD                 = 26
    IFLA_BRPORT_MCAST_FLOOD         = 27
    IFLA_BRPORT_MCAST_TO_UCAST      = 28
    IFLA_BRPORT_VLAN_TUNNEL         = 29
    IFLA_BRPORT_BCAST_FLOOD         = 30
    IFLA_BRPORT_GROUP_FWD_MASK      = 31
    IFLA_BRPORT_ARP_SUPPRESS        = 32
    IFLA_BRPORT_PEER_LINK           = 150
    IFLA_BRPORT_DUAL_LINK           = 151
    IFLA_BRPORT_GROUP_FWD_MASKHI    = 153
    IFLA_BRPORT_DOWN_PEERLINK_REDIRECT = 154

    ifla_brport_to_string = {
        IFLA_BRPORT_UNSPEC              : 'IFLA_BRPORT_UNSPEC',
        IFLA_BRPORT_STATE               : 'IFLA_BRPORT_STATE',
        IFLA_BRPORT_PRIORITY            : 'IFLA_BRPORT_PRIORITY',
        IFLA_BRPORT_COST                : 'IFLA_BRPORT_COST',
        IFLA_BRPORT_MODE                : 'IFLA_BRPORT_MODE',
        IFLA_BRPORT_GUARD               : 'IFLA_BRPORT_GUARD',
        IFLA_BRPORT_PROTECT             : 'IFLA_BRPORT_PROTECT',
        IFLA_BRPORT_FAST_LEAVE          : 'IFLA_BRPORT_FAST_LEAVE',
        IFLA_BRPORT_LEARNING            : 'IFLA_BRPORT_LEARNING',
        IFLA_BRPORT_UNICAST_FLOOD       : 'IFLA_BRPORT_UNICAST_FLOOD',
        IFLA_BRPORT_PROXYARP            : 'IFLA_BRPORT_PROXYARP',
        IFLA_BRPORT_LEARNING_SYNC       : 'IFLA_BRPORT_LEARNING_SYNC',
        IFLA_BRPORT_PROXYARP_WIFI       : 'IFLA_BRPORT_PROXYARP_WIFI',
        IFLA_BRPORT_ROOT_ID             : 'IFLA_BRPORT_ROOT_ID',
        IFLA_BRPORT_BRIDGE_ID           : 'IFLA_BRPORT_BRIDGE_ID',
        IFLA_BRPORT_DESIGNATED_PORT     : 'IFLA_BRPORT_DESIGNATED_PORT',
        IFLA_BRPORT_DESIGNATED_COST     : 'IFLA_BRPORT_DESIGNATED_COST',
        IFLA_BRPORT_ID                  : 'IFLA_BRPORT_ID',
        IFLA_BRPORT_NO                  : 'IFLA_BRPORT_NO',
        IFLA_BRPORT_TOPOLOGY_CHANGE_ACK : 'IFLA_BRPORT_TOPOLOGY_CHANGE_ACK',
        IFLA_BRPORT_CONFIG_PENDING      : 'IFLA_BRPORT_CONFIG_PENDING',
        IFLA_BRPORT_MESSAGE_AGE_TIMER   : 'IFLA_BRPORT_MESSAGE_AGE_TIMER',
        IFLA_BRPORT_FORWARD_DELAY_TIMER : 'IFLA_BRPORT_FORWARD_DELAY_TIMER',
        IFLA_BRPORT_HOLD_TIMER          : 'IFLA_BRPORT_HOLD_TIMER',
        IFLA_BRPORT_FLUSH               : 'IFLA_BRPORT_FLUSH',
        IFLA_BRPORT_MULTICAST_ROUTER    : 'IFLA_BRPORT_MULTICAST_ROUTER',
        IFLA_BRPORT_PAD                 : 'IFLA_BRPORT_PAD',
        IFLA_BRPORT_MCAST_FLOOD         : 'IFLA_BRPORT_MCAST_FLOOD',
        IFLA_BRPORT_MCAST_TO_UCAST      : 'IFLA_BRPORT_MCAST_TO_UCAST',
        IFLA_BRPORT_VLAN_TUNNEL         : 'IFLA_BRPORT_VLAN_TUNNEL',
        IFLA_BRPORT_BCAST_FLOOD         : 'IFLA_BRPORT_BCAST_FLOOD',
        IFLA_BRPORT_GROUP_FWD_MASK      : 'IFLA_BRPORT_GROUP_FWD_MASK',
        IFLA_BRPORT_PEER_LINK           : 'IFLA_BRPORT_PEER_LINK',
        IFLA_BRPORT_DUAL_LINK           : 'IFLA_BRPORT_DUAL_LINK',
        IFLA_BRPORT_ARP_SUPPRESS        : 'IFLA_BRPORT_ARP_SUPPRESS',
        IFLA_BRPORT_GROUP_FWD_MASKHI    : 'IFLA_BRPORT_GROUP_FWD_MASKHI',
        IFLA_BRPORT_DOWN_PEERLINK_REDIRECT : 'IFLA_BRPORT_DOWN_PEERLINK_REDIRECT'
    }

    # Subtype attributes for IFLA_AF_SPEC
    IFLA_INET6_UNSPEC           = 0
    IFLA_INET6_FLAGS            = 1  # link flags
    IFLA_INET6_CONF             = 2  # sysctl parameters
    IFLA_INET6_STATS            = 3  # statistics
    IFLA_INET6_MCAST            = 4  # MC things. What of them?
    IFLA_INET6_CACHEINFO        = 5  # time values and max reasm size
    IFLA_INET6_ICMP6STATS       = 6  # statistics (icmpv6)
    IFLA_INET6_TOKEN            = 7  # device token
    IFLA_INET6_ADDR_GEN_MODE    = 8  # implicit address generator mode
    __IFLA_INET6_MAX            = 9

    ifla_inet6_af_spec_to_string = {
        IFLA_INET6_UNSPEC           : 'IFLA_INET6_UNSPEC',
        IFLA_INET6_FLAGS            : 'IFLA_INET6_FLAGS',
        IFLA_INET6_CONF             : 'IFLA_INET6_CONF',
        IFLA_INET6_STATS            : 'IFLA_INET6_STATS',
        IFLA_INET6_MCAST            : 'IFLA_INET6_MCAST',
        IFLA_INET6_CACHEINFO        : 'IFLA_INET6_CACHEINFO',
        IFLA_INET6_ICMP6STATS       : 'IFLA_INET6_ICMP6STATS',
        IFLA_INET6_TOKEN            : 'IFLA_INET6_TOKEN',
        IFLA_INET6_ADDR_GEN_MODE    : 'IFLA_INET6_ADDR_GEN_MODE',
    }

    # Subtype attrbutes AF_INET
    IFLA_INET_UNSPEC    = 0
    IFLA_INET_CONF      = 1
    __IFLA_INET_MAX     = 2

    ifla_inet_af_spec_to_string = {
        IFLA_INET_UNSPEC    : 'IFLA_INET_UNSPEC',
        IFLA_INET_CONF      : 'IFLA_INET_CONF',
    }

    # BRIDGE IFLA_AF_SPEC attributes
    IFLA_BRIDGE_FLAGS     = 0
    IFLA_BRIDGE_MODE      = 1
    IFLA_BRIDGE_VLAN_INFO = 2

    ifla_bridge_af_spec_to_string = {
        IFLA_BRIDGE_FLAGS     : 'IFLA_BRIDGE_FLAGS',
        IFLA_BRIDGE_MODE      : 'IFLA_BRIDGE_MODE',
        IFLA_BRIDGE_VLAN_INFO : 'IFLA_BRIDGE_VLAN_INFO'
    }

    # BRIDGE_VLAN_INFO flags
    BRIDGE_VLAN_INFO_MASTER      = 1 << 0  # Operate on Bridge device as well
    BRIDGE_VLAN_INFO_PVID        = 1 << 1  # VLAN is PVID, ingress untagged
    BRIDGE_VLAN_INFO_UNTAGGED    = 1 << 2  # VLAN egresses untagged
    BRIDGE_VLAN_INFO_RANGE_BEGIN = 1 << 3  # VLAN is start of vlan range
    BRIDGE_VLAN_INFO_RANGE_END   = 1 << 4  # VLAN is end of vlan range
    BRIDGE_VLAN_INFO_BRENTRY     = 1 << 5  # Global bridge VLAN entry

    bridge_vlan_to_string = {
        BRIDGE_VLAN_INFO_MASTER      : 'BRIDGE_VLAN_INFO_MASTER',
        BRIDGE_VLAN_INFO_PVID        : 'BRIDGE_VLAN_INFO_PVID',
        BRIDGE_VLAN_INFO_UNTAGGED    : 'BRIDGE_VLAN_INFO_UNTAGGED',
        BRIDGE_VLAN_INFO_RANGE_BEGIN : 'BRIDGE_VLAN_INFO_RANGE_BEGIN',
        BRIDGE_VLAN_INFO_RANGE_END   : 'BRIDGE_VLAN_INFO_RANGE_END',
        BRIDGE_VLAN_INFO_BRENTRY     : 'BRIDGE_VLAN_INFO_BRENTRY'
    }

    # Bridge flags
    BRIDGE_FLAGS_MASTER = 1
    BRIDGE_FLAGS_SELF   = 2

    bridge_flags_to_string = {
        BRIDGE_FLAGS_MASTER : 'BRIDGE_FLAGS_MASTER',
        BRIDGE_FLAGS_SELF   : 'BRIDGE_FLAGS_SELF'
    }

    # filters for IFLA_EXT_MASK
    RTEXT_FILTER_VF                = 1 << 0
    RTEXT_FILTER_BRVLAN            = 1 << 1
    RTEXT_FILTER_BRVLAN_COMPRESSED = 1 << 2
    RTEXT_FILTER_SKIP_STATS        = 1 << 3

    rtext_to_string = {
        RTEXT_FILTER_VF                : 'RTEXT_FILTER_VF',
        RTEXT_FILTER_BRVLAN            : 'RTEXT_FILTER_BRVLAN',
        RTEXT_FILTER_BRVLAN_COMPRESSED : 'RTEXT_FILTER_BRVLAN_COMPRESSED',
        RTEXT_FILTER_SKIP_STATS        : 'RTEXT_FILTER_SKIP_STATS'
    }

    IFLA_BR_UNSPEC                     =  0
    IFLA_BR_FORWARD_DELAY              =  1
    IFLA_BR_HELLO_TIME                 =  2
    IFLA_BR_MAX_AGE                    =  3
    IFLA_BR_AGEING_TIME                =  4
    IFLA_BR_STP_STATE                  =  5
    IFLA_BR_PRIORITY                   =  6
    IFLA_BR_VLAN_FILTERING             =  7
    IFLA_BR_VLAN_PROTOCOL              =  8
    IFLA_BR_GROUP_FWD_MASK             =  9
    IFLA_BR_ROOT_ID                    = 10
    IFLA_BR_BRIDGE_ID                  = 11
    IFLA_BR_ROOT_PORT                  = 12
    IFLA_BR_ROOT_PATH_COST             = 13
    IFLA_BR_TOPOLOGY_CHANGE            = 14
    IFLA_BR_TOPOLOGY_CHANGE_DETECTED   = 15
    IFLA_BR_HELLO_TIMER                = 16
    IFLA_BR_TCN_TIMER                  = 17
    IFLA_BR_TOPOLOGY_CHANGE_TIMER      = 18
    IFLA_BR_GC_TIMER                   = 19
    IFLA_BR_GROUP_ADDR                 = 20
    IFLA_BR_FDB_FLUSH                  = 21
    IFLA_BR_MCAST_ROUTER               = 22
    IFLA_BR_MCAST_SNOOPING             = 23
    IFLA_BR_MCAST_QUERY_USE_IFADDR     = 24
    IFLA_BR_MCAST_QUERIER              = 25
    IFLA_BR_MCAST_HASH_ELASTICITY      = 26
    IFLA_BR_MCAST_HASH_MAX             = 27
    IFLA_BR_MCAST_LAST_MEMBER_CNT      = 28
    IFLA_BR_MCAST_STARTUP_QUERY_CNT    = 29
    IFLA_BR_MCAST_LAST_MEMBER_INTVL    = 30
    IFLA_BR_MCAST_MEMBERSHIP_INTVL     = 31
    IFLA_BR_MCAST_QUERIER_INTVL        = 32
    IFLA_BR_MCAST_QUERY_INTVL          = 33
    IFLA_BR_MCAST_QUERY_RESPONSE_INTVL = 34
    IFLA_BR_MCAST_STARTUP_QUERY_INTVL  = 35
    IFLA_BR_NF_CALL_IPTABLES           = 36
    IFLA_BR_NF_CALL_IP6TABLES          = 37
    IFLA_BR_NF_CALL_ARPTABLES          = 38
    IFLA_BR_VLAN_DEFAULT_PVID          = 39
    IFLA_BR_PAD                        = 40
    IFLA_BR_VLAN_STATS_ENABLED         = 41
    IFLA_BR_MCAST_STATS_ENABLED        = 42
    IFLA_BR_MCAST_IGMP_VERSION         = 43
    IFLA_BR_MCAST_MLD_VERSION          = 44

    ifla_br_to_string = {
        IFLA_BR_UNSPEC                     : 'IFLA_BR_UNSPEC',
        IFLA_BR_FORWARD_DELAY              : 'IFLA_BR_FORWARD_DELAY',
        IFLA_BR_HELLO_TIME                 : 'IFLA_BR_HELLO_TIME',
        IFLA_BR_MAX_AGE                    : 'IFLA_BR_MAX_AGE',
        IFLA_BR_AGEING_TIME                : 'IFLA_BR_AGEING_TIME',
        IFLA_BR_STP_STATE                  : 'IFLA_BR_STP_STATE',
        IFLA_BR_PRIORITY                   : 'IFLA_BR_PRIORITY',
        IFLA_BR_VLAN_FILTERING             : 'IFLA_BR_VLAN_FILTERING',
        IFLA_BR_VLAN_PROTOCOL              : 'IFLA_BR_VLAN_PROTOCOL',
        IFLA_BR_GROUP_FWD_MASK             : 'IFLA_BR_GROUP_FWD_MASK',
        IFLA_BR_ROOT_ID                    : 'IFLA_BR_ROOT_ID',
        IFLA_BR_BRIDGE_ID                  : 'IFLA_BR_BRIDGE_ID',
        IFLA_BR_ROOT_PORT                  : 'IFLA_BR_ROOT_PORT',
        IFLA_BR_ROOT_PATH_COST             : 'IFLA_BR_ROOT_PATH_COST',
        IFLA_BR_TOPOLOGY_CHANGE            : 'IFLA_BR_TOPOLOGY_CHANGE',
        IFLA_BR_TOPOLOGY_CHANGE_DETECTED   : 'IFLA_BR_TOPOLOGY_CHANGE_DETECTED',
        IFLA_BR_HELLO_TIMER                : 'IFLA_BR_HELLO_TIMER',
        IFLA_BR_TCN_TIMER                  : 'IFLA_BR_TCN_TIMER',
        IFLA_BR_TOPOLOGY_CHANGE_TIMER      : 'IFLA_BR_TOPOLOGY_CHANGE_TIMER',
        IFLA_BR_GC_TIMER                   : 'IFLA_BR_GC_TIMER',
        IFLA_BR_GROUP_ADDR                 : 'IFLA_BR_GROUP_ADDR',
        IFLA_BR_FDB_FLUSH                  : 'IFLA_BR_FDB_FLUSH',
        IFLA_BR_MCAST_ROUTER               : 'IFLA_BR_MCAST_ROUTER',
        IFLA_BR_MCAST_SNOOPING             : 'IFLA_BR_MCAST_SNOOPING',
        IFLA_BR_MCAST_QUERY_USE_IFADDR     : 'IFLA_BR_MCAST_QUERY_USE_IFADDR',
        IFLA_BR_MCAST_QUERIER              : 'IFLA_BR_MCAST_QUERIER',
        IFLA_BR_MCAST_HASH_ELASTICITY      : 'IFLA_BR_MCAST_HASH_ELASTICITY',
        IFLA_BR_MCAST_HASH_MAX             : 'IFLA_BR_MCAST_HASH_MAX',
        IFLA_BR_MCAST_LAST_MEMBER_CNT      : 'IFLA_BR_MCAST_LAST_MEMBER_CNT',
        IFLA_BR_MCAST_STARTUP_QUERY_CNT    : 'IFLA_BR_MCAST_STARTUP_QUERY_CNT',
        IFLA_BR_MCAST_LAST_MEMBER_INTVL    : 'IFLA_BR_MCAST_LAST_MEMBER_INTVL',
        IFLA_BR_MCAST_MEMBERSHIP_INTVL     : 'IFLA_BR_MCAST_MEMBERSHIP_INTVL',
        IFLA_BR_MCAST_QUERIER_INTVL        : 'IFLA_BR_MCAST_QUERIER_INTVL',
        IFLA_BR_MCAST_QUERY_INTVL          : 'IFLA_BR_MCAST_QUERY_INTVL',
        IFLA_BR_MCAST_QUERY_RESPONSE_INTVL : 'IFLA_BR_MCAST_QUERY_RESPONSE_INTVL',
        IFLA_BR_MCAST_STARTUP_QUERY_INTVL  : 'IFLA_BR_MCAST_STARTUP_QUERY_INTVL',
        IFLA_BR_NF_CALL_IPTABLES           : 'IFLA_BR_NF_CALL_IPTABLES',
        IFLA_BR_NF_CALL_IP6TABLES          : 'IFLA_BR_NF_CALL_IP6TABLES',
        IFLA_BR_NF_CALL_ARPTABLES          : 'IFLA_BR_NF_CALL_ARPTABLES',
        IFLA_BR_VLAN_DEFAULT_PVID          : 'IFLA_BR_VLAN_DEFAULT_PVID',
        IFLA_BR_PAD                        : 'IFLA_BR_PAD',
        IFLA_BR_VLAN_STATS_ENABLED         : 'IFLA_BR_VLAN_STATS_ENABLED',
        IFLA_BR_MCAST_STATS_ENABLED        : 'IFLA_BR_MCAST_STATS_ENABLED',
        IFLA_BR_MCAST_IGMP_VERSION         : 'IFLA_BR_MCAST_IGMP_VERSION',
        IFLA_BR_MCAST_MLD_VERSION          : 'IFLA_BR_MCAST_MLD_VERSION'
    }

    # =========================================
    # IFLA_INFO_DATA attributes for vrfs
    # =========================================
    IFLA_VRF_UNSPEC                         = 0
    IFLA_VRF_TABLE                          = 1

    ifla_vrf_to_string = {
        IFLA_VRF_UNSPEC                     : 'IFLA_VRF_UNSPEC',
        IFLA_VRF_TABLE                      : 'IFLA_VRF_TABLE'
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = 'BxHiII'
        self.LEN  = calcsize(self.PACK)

    def get_link_type_string(self, index):
        return self.get_string(self.link_type_to_string, index)

    def get_ifla_inet6_af_spec_to_string(self, index):
        return self.get_string(self.ifla_inet6_af_spec_to_string, index)

    def get_ifla_inet_af_spec_to_string(self, index):
        return self.get_string(self.ifla_inet_af_spec_to_string, index)

    def get_ifla_bridge_af_spec_to_string(self, index):
        return self.get_string(self.ifla_bridge_af_spec_to_string, index)

    def get_ifla_info_string(self, index):
        return self.get_string(self.ifla_info_to_string, index)

    def get_ifla_vlan_string(self, index):
        return self.get_string(self.ifla_vlan_to_string, index)

    def get_ifla_vxlan_string(self, index):
        return self.get_string(self.ifla_vxlan_to_string, index)

    def get_ifla_macvlan_string(self, index):
        return self.get_string(self.ifla_macvlan_to_string, index)

    def get_macvlan_mode_string(self, index):
        return self.get_string(self.macvlan_mode_to_string, index)

    def get_ifla_bond_string(self, index):
        return self.get_string(self.ifla_bond_to_string, index)

    def get_ifla_bond_ad_string(self, index):
        return self.get_string(self.ifla_bond_ad_to_string, index)

    def get_ifla_brport_string(self, index):
        return self.get_string(self.ifla_brport_to_string, index)

    def get_ifla_br_string(self, index):
        return self.get_string(self.ifla_br_to_string, index)

    def get_bridge_vlan_string(self, index):
        return self.get_string(self.bridge_vlan_to_string, index)

    def get_bridge_flags_string(self, index):
        return self.get_string(self.bridge_flags_to_string, index)

    def decode_service_header(self):

        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.family, self.device_type,
         self.ifindex,
         self.flags,
         self.change_mask) = \
            unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN/4):
                if self.line_number == 5:
                    extra = "Family %s (%d), Device Type %s (%d - %s)" % \
                            (zfilled_hex(self.family, 2), self.family,
                             zfilled_hex(self.device_type, 4), self.device_type, self.get_link_type_string(self.device_type))
                elif self.line_number == 6:
                    extra = "Interface Index %s (%d)" % (zfilled_hex(self.ifindex, 8), self.ifindex)
                elif self.line_number == 7:
                    extra = "Device Flags %s (%s)" % (zfilled_hex(self.flags, 8), self.get_flags_string())
                elif self.line_number == 8:
                    extra = "Change Mask %s" % zfilled_hex(self.change_mask, 8)
                else:
                    extra = "Unexpected line number %d" % self.line_number

                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1

    def is_up(self):
        if self.flags & Link.IFF_UP:
            return True
        return False


class Neighbor(NetlinkPacket):
    """
    Service Header

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Family    |    Reserved1  |           Reserved2           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Interface Index                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           State             |     Flags     |     Type      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    # Neighbor attributes
    # /usr/include/linux/neighbour.h
    NDA_UNSPEC       = 0x00  # Unknown type
    NDA_DST          = 0x01  # A neighbour cache network. layer destination address
    NDA_LLADDR       = 0x02  # A neighbor cache link layer address.
    NDA_CACHEINFO    = 0x03  # Cache statistics
    NDA_PROBES       = 0x04
    NDA_VLAN         = 0x05
    NDA_PORT         = 0x06
    NDA_VNI          = 0x07
    NDA_IFINDEX      = 0x08
    NDA_MASTER       = 0x09
    NDA_LINK_NETNSID = 0x0A

    attribute_to_class = {
        NDA_UNSPEC       : ('NDA_UNSPEC', AttributeGeneric),
        NDA_DST          : ('NDA_DST', AttributeIPAddress),
        NDA_LLADDR       : ('NDA_LLADDR', AttributeMACAddress),
        NDA_CACHEINFO    : ('NDA_CACHEINFO', AttributeFourByteList),
        NDA_PROBES       : ('NDA_PROBES', AttributeFourByteValue),
        NDA_VLAN         : ('NDA_VLAN', AttributeTwoByteValue),
        NDA_PORT         : ('NDA_PORT', AttributeGeneric),
        NDA_VNI          : ('NDA_VNI', AttributeFourByteValue),
        NDA_IFINDEX      : ('NDA_IFINDEX', AttributeFourByteValue),
        NDA_MASTER       : ('NDA_MASTER', AttributeFourByteValue),
        NDA_LINK_NETNSID : ('NDA_LINK_NETNSID', AttributeGeneric)
    }

    # Neighbor flags
    # /usr/include/linux/neighbour.h
    NTF_USE         = 0x01
    NTF_SELF        = 0x02
    NTF_MASTER      = 0x04
    NTF_PROXY       = 0x08  # A proxy ARP entry
    NTF_EXT_LEARNED = 0x10  # neigh entry installed by an external APP
    NTF_ROUTER      = 0x80  # An IPv6 router

    flag_to_string = {
        NTF_USE          : 'NTF_USE',
        NTF_SELF         : 'NTF_SELF',
        NTF_MASTER       : 'NTF_MASTER',
        NTF_PROXY        : 'NTF_PROXY',
        NTF_EXT_LEARNED  : 'NTF_EXT_LEARNED',
        NTF_ROUTER       : 'NTF_ROUTER'
    }

    # Neighbor states
    # /usr/include/linux/neighbour.h
    NUD_NONE       = 0x00
    NUD_INCOMPLETE = 0x01  # Still attempting to resolve
    NUD_REACHABLE  = 0x02  # A confirmed working cache entry
    NUD_STALE      = 0x04  # an expired cache entry
    NUD_DELAY      = 0x08  # Neighbor no longer reachable.  Traffic sent, waiting for confirmatio.
    NUD_PROBE      = 0x10  # A cache entry that is currently being re-solicited
    NUD_FAILED     = 0x20  # An invalid cache entry
    NUD_NOARP      = 0x40  # A device which does not do neighbor discovery(ARP)
    NUD_PERMANENT  = 0x80  # A static entry

    state_to_string = {
        NUD_NONE       : 'NUD_NONE',
        NUD_INCOMPLETE : 'NUD_INCOMPLETE',
        NUD_REACHABLE  : 'NUD_REACHABLE',
        NUD_STALE      : 'NUD_STALE',
        NUD_DELAY      : 'NUD_DELAY',
        NUD_PROBE      : 'NUD_PROBE',
        NUD_FAILED     : 'NUD_FAILED',
        NUD_NOARP      : 'NUD_NOARP',
        NUD_PERMANENT  : 'NUD_PERMANENT'
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = 'BxxxiHBB'
        self.LEN = calcsize(self.PACK)

    def get_state_string(self, index):
        return self.get_string(self.state_to_string, index)

    def get_states_string(self, states):
        for_string = []

        if states & Neighbor.NUD_INCOMPLETE:
            for_string.append('NUD_INCOMPLETE')

        if states & Neighbor.NUD_REACHABLE:
            for_string.append('NUD_REACHABLE')

        if states & Neighbor.NUD_STALE:
            for_string.append('NUD_STALE')

        if states & Neighbor.NUD_DELAY:
            for_string.append('NUD_DELAY')

        if states & Neighbor.NUD_PROBE:
            for_string.append('NUD_PROBE')

        if states & Neighbor.NUD_FAILED:
            for_string.append('NUD_FAILED')

        if states & Neighbor.NUD_NOARP:
            for_string.append('NUD_NOARP')

        if states & Neighbor.NUD_PERMANENT:
            for_string.append('NUD_PERMANENT')

        return ', '.join(for_string)

    def get_flags_string(self, flags):
        for_string = []

        if flags & Neighbor.NTF_USE:
            for_string.append('NTF_USE')

        if flags & Neighbor.NTF_SELF:
            for_string.append('NTF_SELF')

        if flags & Neighbor.NTF_MASTER:
            for_string.append('NTF_MASTER')

        if flags & Neighbor.NTF_PROXY:
            for_string.append('NTF_PROXY')

        if flags & Neighbor.NTF_ROUTER:
            for_string.append('NTF_ROUTER')

        return ', '.join(for_string)

    def decode_service_header(self):

        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.family,
         self.ifindex,
         self.state, self.flags, self.neighbor_type) = \
            unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN/4):
                if self.line_number == 5:
                    extra = "Family %s (%d)" % (zfilled_hex(self.family, 2), self.family)
                elif self.line_number == 6:
                    extra = "Interface Index %s (%d)" % (zfilled_hex(self.ifindex, 8), self.ifindex)
                elif self.line_number == 7:
                    extra = "State %s (%d) %s, Flags %s (%s) %s, Type %s (%d)" % \
                        (zfilled_hex(self.state, 4), self.state, self.get_states_string(self.state),
                         zfilled_hex(self.flags, 2), self.flags, self.get_flags_string(self.flags),
                         zfilled_hex(self.neighbor_type, 4), self.neighbor_type)
                else:
                    extra = "Unexpected line number %d" % self.line_number

                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1


class Route(NetlinkPacket):
    """
    Service Header

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Family    |  Dest length  |   Src length  |     TOS       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Table ID   |   Protocol    |     Scope     |     Type      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Flags                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    # Route attributes
    # /usr/include/linux/rtnetlink.h
    RTA_UNSPEC    = 0x00  # Ignored.
    RTA_DST       = 0x01  # Protocol address for route destination address.
    RTA_SRC       = 0x02  # Protocol address for route source address.
    RTA_IIF       = 0x03  # Input interface index.
    RTA_OIF       = 0x04  # Output interface index.
    RTA_GATEWAY   = 0x05  # Protocol address for the gateway of the route
    RTA_PRIORITY  = 0x06  # Priority of broker.
    RTA_PREFSRC   = 0x07  # Preferred source address in cases where more than one source address could be used.
    RTA_METRICS   = 0x08  # Route metrics attributed to route and associated protocols(e.g., RTT, initial TCP window, etc.).
    RTA_MULTIPATH = 0x09  # Multipath route next hop's attributes.
    RTA_PROTOINFO = 0x0A  # Firewall based policy routing attribute.
    RTA_FLOW      = 0x0B  # Route realm.
    RTA_CACHEINFO = 0x0C  # Cached route information.
    RTA_SESSION   = 0x0D
    RTA_MP_ALGO   = 0x0E
    RTA_TABLE     = 0x0F
    RTA_MARK      = 0x10
    RTA_MFC_STATS = 0x11
    RTA_VIA       = 0x12
    RTA_NEWDST    = 0x13
    RTA_PREF      = 0x14
    RTA_ENCAP_TYPE= 0x15
    RTA_ENCAP     = 0x16

    attribute_to_class = {
        RTA_UNSPEC    : ('RTA_UNSPEC', AttributeGeneric),
        RTA_DST       : ('RTA_DST', AttributeIPAddress),
        RTA_SRC       : ('RTA_SRC', AttributeIPAddress),
        RTA_IIF       : ('RTA_IIF', AttributeFourByteValue),
        RTA_OIF       : ('RTA_OIF', AttributeFourByteValue),
        RTA_GATEWAY   : ('RTA_GATEWAY', AttributeIPAddress),
        RTA_PRIORITY  : ('RTA_PRIORITY', AttributeFourByteValue),
        RTA_PREFSRC   : ('RTA_PREFSRC', AttributeIPAddress),
        RTA_METRICS   : ('RTA_METRICS', AttributeGeneric),
        RTA_MULTIPATH : ('RTA_MULTIPATH', AttributeRTA_MULTIPATH),
        RTA_PROTOINFO : ('RTA_PROTOINFO', AttributeGeneric),
        RTA_FLOW      : ('RTA_FLOW', AttributeGeneric),
        RTA_CACHEINFO : ('RTA_CACHEINFO', AttributeGeneric),
        RTA_SESSION   : ('RTA_SESSION', AttributeGeneric),
        RTA_MP_ALGO   : ('RTA_MP_ALGO', AttributeGeneric),
        RTA_TABLE     : ('RTA_TABLE', AttributeFourByteValue),
        RTA_MARK      : ('RTA_MARK', AttributeGeneric),
        RTA_MFC_STATS : ('RTA_MFC_STATS', AttributeGeneric),
        RTA_VIA       : ('RTA_VIA', AttributeGeneric),
        RTA_NEWDST    : ('RTA_NEWDST', AttributeGeneric),
        RTA_PREF      : ('RTA_PREF', AttributeGeneric),
        RTA_ENCAP_TYPE: ('RTA_ENCAP_TYPE', AttributeGeneric),
        RTA_ENCAP     : ('RTA_ENCAP', AttributeGeneric)
    }

    # Route tables
    # /usr/include/linux/rtnetlink.h
    RT_TABLE_UNSPEC  = 0x00  # An unspecified routing table
    RT_TABLE_COMPAT  = 0xFC
    RT_TABLE_DEFAULT = 0xFD  # The default table
    RT_TABLE_MAIN    = 0xFE  # The main table
    RT_TABLE_LOCAL   = 0xFF  # The local table

    table_to_string = {
        RT_TABLE_UNSPEC  : 'RT_TABLE_UNSPEC',
        RT_TABLE_COMPAT  : 'RT_TABLE_COMPAT',
        RT_TABLE_DEFAULT : 'RT_TABLE_DEFAULT',
        RT_TABLE_MAIN    : 'RT_TABLE_MAIN',
        RT_TABLE_LOCAL   : 'RT_TABLE_LOCAL'
    }

    # Route scope
    # /usr/include/linux/rtnetlink.h
    RT_SCOPE_UNIVERSE = 0x00  # Global route
    RT_SCOPE_SITE     = 0xC8  # Interior route in the local autonomous system
    RT_SCOPE_LINK     = 0xFD  # Route on this link
    RT_SCOPE_HOST     = 0xFE  # Route on the local host
    RT_SCOPE_NOWHERE  = 0xFF  # Destination does not exist

    scope_to_string = {
        RT_SCOPE_UNIVERSE : 'RT_SCOPE_UNIVERSE',
        RT_SCOPE_SITE     : 'RT_SCOPE_SITE',
        RT_SCOPE_LINK     : 'RT_SCOPE_LINK',
        RT_SCOPE_HOST     : 'RT_SCOPE_HOST',
        RT_SCOPE_NOWHERE  : 'RT_SCOPE_NOWHERE'
    }

    # Route scope to string
    # iproute2/lib/rt_names.c
    rtnl_rtscope_tab = {
        RT_SCOPE_UNIVERSE: 'global',
        RT_SCOPE_NOWHERE: 'nowhere',
        RT_SCOPE_HOST: 'host',
        RT_SCOPE_LINK: 'link',
        RT_SCOPE_SITE: 'site'
    }

    # Routing stack
    # /usr/include/linux/rtnetlink.h
    RT_PROT_UNSPEC   = 0x00  # Identifies what/who added the route
    RT_PROT_REDIRECT = 0x01  # By an ICMP redirect
    RT_PROT_KERNEL   = 0x02  # By the kernel
    RT_PROT_BOOT     = 0x03  # During bootup
    RT_PROT_STATIC   = 0x04  # By the administrator
    RT_PROT_GATED    = 0x08  # GateD
    RT_PROT_RA       = 0x09  # RDISC/ND router advertissements
    RT_PROT_MRT      = 0x0A  # Merit MRT
    RT_PROT_ZEBRA    = 0x0B  # ZEBRA
    RT_PROT_BIRD     = 0x0C  # BIRD
    RT_PROT_DNROUTED = 0x0D  # DECnet routing daemon
    RT_PROT_XORP     = 0x0E  # XORP
    RT_PROT_NTK      = 0x0F  # Netsukuku
    RT_PROT_DHCP     = 0x10  # DHCP client
    RT_PROT_EXABGP   = 0x11  # Exa Networks ExaBGP

    prot_to_string = {
        RT_PROT_UNSPEC   : 'RT_PROT_UNSPEC',
        RT_PROT_REDIRECT : 'RT_PROT_REDIRECT',
        RT_PROT_KERNEL   : 'RT_PROT_KERNEL',
        RT_PROT_BOOT     : 'RT_PROT_BOOT',
        RT_PROT_STATIC   : 'RT_PROT_STATIC',
        RT_PROT_GATED    : 'RT_PROT_GATED',
        RT_PROT_RA       : 'RT_PROT_RA',
        RT_PROT_MRT      : 'RT_PROT_MRT',
        RT_PROT_ZEBRA    : 'RT_PROT_ZEBRA',
        RT_PROT_BIRD     : 'RT_PROT_BIRD',
        RT_PROT_DNROUTED : 'RT_PROT_DNROUTED',
        RT_PROT_XORP     : 'RT_PROT_XORP',
        RT_PROT_NTK      : 'RT_PROT_NTK',
        RT_PROT_DHCP     : 'RT_PROT_DHCP',
        RT_PROT_EXABGP   : 'RT_PROT_EXABGP'
    }

    # Route types
    # /usr/include/linux/rtnetlink.h
    RTN_UNSPEC      = 0x00  # Unknown broker.
    RTN_UNICAST     = 0x01  # A gateway or direct broker.
    RTN_LOCAL       = 0x02  # A local interface broker.
    RTN_BROADCAST   = 0x03  # A local broadcast route(sent as a broadcast).
    RTN_ANYCAST     = 0x04  # An anycast broker.
    RTN_MULTICAST   = 0x05  # A multicast broker.
    RTN_BLACKHOLE   = 0x06  # A silent packet dropping broker.
    RTN_UNREACHABLE = 0x07  # An unreachable destination.  Packets dropped and
                            # host unreachable ICMPs are sent to the originator.
    RTN_PROHIBIT    = 0x08  # A packet rejection broker.  Packets are dropped and
                            # communication prohibited ICMPs are sent to the originator.
    RTN_THROW       = 0x09  # When used with policy routing, continue routing lookup
                            # in another table.  Under normal routing, packets are
                            # dropped and net unreachable ICMPs are sent to the originator.
    RTN_NAT         = 0x0A  # A network address translation rule.
    RTN_XRESOLVE    = 0x0B  # Refer to an external resolver(not implemented).

    rt_type_to_string = {
        RTN_UNSPEC      : 'RTN_UNSPEC',
        RTN_UNICAST     : 'RTN_UNICAST',
        RTN_LOCAL       : 'RTN_LOCAL',
        RTN_BROADCAST   : 'RTN_BROADCAST',
        RTN_ANYCAST     : 'RTN_ANYCAST',
        RTN_MULTICAST   : 'RTN_MULTICAST',
        RTN_BLACKHOLE   : 'RTN_BLACKHOLE',
        RTN_UNREACHABLE : 'RTN_UNREACHABLE',
        RTN_PROHIBIT    : 'RTN_PROHIBIT',
        RTN_THROW       : 'RTN_THROW',
        RTN_NAT         : 'RTN_NAT',
        RTN_XRESOLVE    : 'RTN_XRESOLVE'
    }

    # Route flags
    # /usr/include/linux/rtnetlink.h
    RTM_F_NOTIFY   = 0x100  # If the route changes, notify the user
    RTM_F_CLONED   = 0x200  # Route is cloned from another route
    RTM_F_EQUALIZE = 0x400  # Allow randomization of next hop path in multi-path routing(currently not implemented)
    RTM_F_PREFIX   = 0x800  # Prefix Address

    flag_to_string = {
        RTM_F_NOTIFY   : 'RTM_F_NOTIFY',
        RTM_F_CLONED   : 'RTM_F_CLONED',
        RTM_F_EQUALIZE : 'RTM_F_EQUALIZE',
        RTM_F_PREFIX   : 'RTM_F_PREFIX'
    }

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = '=8BI'  # or is it 8Bi ?
        self.LEN = calcsize(self.PACK)

    def get_prefix_string(self):
        dst = self.get_attribute_value(self.RTA_DST)

        if dst:
            return "%s/%d" % (dst, self.src_len)
        else:
            if self.family == AF_INET:
                return "0.0.0.0/0"
            elif self.family == AF_INET6:
                return "::/0"

    def get_protocol_string(self, index=None):
        if index is None:
            index = self.protocol
        return self.get_string(self.prot_to_string, index)

    def get_rt_type_string(self, index=None):
        if index is None:
            index = self.route_type
        return self.get_string(self.rt_type_to_string, index)

    def get_scope_string(self, index=None):
        if index is None:
            index = self.scope
        return self.get_string(self.scope_to_string, index)

    def get_table_id_string(self, index=None):
        if index is None:
            index = self.table_id
        return self.get_string(self.table_to_string, index)

    def _get_ifname_from_index(self, ifindex, ifname_by_index):
        if ifindex:
            ifname = ifname_by_index.get(ifindex)

            if ifname is None:
                ifname = str(ifindex)
        else:
            ifname = None

        return ifname

    def get_nexthops(self, ifname_by_index={}):
        nexthop = self.get_attribute_value(self.RTA_GATEWAY)
        multipath = self.get_attribute_value(self.RTA_MULTIPATH)
        nexthops = []

        if nexthop:
            rta_oif = self.get_attribute_value(self.RTA_OIF)
            ifname = self._get_ifname_from_index(rta_oif, ifname_by_index)
            nexthops.append((nexthop, ifname))

        elif multipath:
            for (nexthop, rtnh_ifindex, rtnh_flags, rtnh_hops) in multipath:
                ifname = self._get_ifname_from_index(rtnh_ifindex, ifname_by_index)
                nexthops.append((nexthop, ifname))

        return nexthops

    def get_nexthops_string(self, ifname_by_index={}):
        output = []

        for (nexthop, ifname) in self.get_nexthops(ifname_by_index):
            output.append(" via %s on %s" % (nexthop, ifname))

        return ",".join(output)

    def decode_service_header(self):

        # Nothing to do if the message did not contain a service header
        if self.length == self.header_LEN:
            return

        (self.family, self.src_len, self.dst_len, self.tos,
         self.table_id, self.protocol, self.scope, self.route_type,
         self.flags) = \
            unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN/4):
                if self.line_number == 5:
                    extra = "Family %s (%d), Source Length %s (%d), Destination Length %s (%d), TOS %s (%d)" % \
                            (zfilled_hex(self.family, 2), self.family,
                             zfilled_hex(self.src_len, 2), self.src_len,
                             zfilled_hex(self.dst_len, 2), self.dst_len,
                             zfilled_hex(self.tos, 2), self.tos)
                elif self.line_number == 6:
                    extra = "Table ID %s (%d - %s), Protocol %s (%d - %s), Scope %s (%d - %s), Type %s (%d - %s)" % \
                            (zfilled_hex(self.table_id, 2), self.table_id, self.get_table_id_string(),
                             zfilled_hex(self.protocol, 2), self.protocol, self.get_protocol_string(),
                             zfilled_hex(self.scope, 2), self.scope, self.get_scope_string(),
                             zfilled_hex(self.route_type, 2), self.route_type, self.get_rt_type_string())
                elif self.line_number == 7:
                    extra = "Flags %s" % zfilled_hex(self.flags, 8)
                else:
                    extra = "Unexpected line number %d" % self.line_number

                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1

class Done(NetlinkPacket):
    """
    NLMSG_DONE

    Service Header
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             TBD                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, msgtype, debug=False, logger=None, use_color=True):
        NetlinkPacket.__init__(self, msgtype, debug, logger, use_color)
        self.PACK = 'i'
        self.LEN = calcsize(self.PACK)

    def decode_service_header(self):
        foo = unpack(self.PACK, self.msg_data[:self.LEN])

        if self.debug:
            color = yellow if self.use_color else None
            color_start = "\033[%dm" % color if color else ""
            color_end = "\033[0m" if color else ""
            self.dump_buffer.append("  %sService Header%s" % (color_start, color_end))

            for x in range(0, self.LEN/4):
                extra = ''
                start = x * 4
                end = start + 4
                self.dump_buffer.append(data_to_color_text(self.line_number, color, self.msg_data[start:end], extra))
                self.line_number += 1
