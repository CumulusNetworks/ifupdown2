# Copyright (C) 2019, 2020 Cumulus Networks, Inc. all rights reserved
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

import ipaddress


class IPNetwork:

    __INIT_WITH_PREFIXLEN = 0b01

    def __init__(self, ip, prefixlen=None, scope=0):
        self.__scope = scope
        self.__flags = 0

        if isinstance(ip, int):
            self._ip = ipaddress.ip_address(ip)
            ip = str(self._ip)
        elif isinstance(ip, IPNetwork):
            self._ip = ip._ip
            self.__prefixlen = ip.prefixlen
        else:
            if not prefixlen:
                try:
                    ip, prefixlen = ip.split("/")
                except ValueError:
                    prefixlen = None

            self._ip = ipaddress.ip_address(ip)

        if not prefixlen:
            self.__prefixlen = 32 if self.ip.version == 4 else 128
        else:
            try:
                self.__prefixlen = int(prefixlen)
            except ValueError:
                if isinstance(prefixlen, str) and "." in prefixlen:
                    self.__prefixlen = ipaddress.ip_network("{}/{}".format(ip, prefixlen), strict=False).prefixlen
                else:
                    raise

            self.__flags |= self.__INIT_WITH_PREFIXLEN

    def __hash__(self):
        return int(self._ip) ^ self.__prefixlen ^ self.version

    def __eq__(self, other) -> bool:
        return other \
               and self.version == other.version \
               and self._ip == other.ip \
               and self.__prefixlen == other.prefixlen

    def __repr__(self):
        return "{}/{}".format(self._ip, self.__prefixlen)

    @property
    def ip(self):
        return self._ip

    @property
    def packed(self):
        return self._ip.packed

    @property
    def is_multicast(self):
        return self._ip.is_multicast

    @property
    def prefixlen(self) -> int:
        return self.__prefixlen

    @property
    def version(self) -> int:
        return self._ip.version

    @property
    def scope(self) -> int:
        return self.__scope

    @property
    def initialized_with_prefixlen(self) -> int:
        return self.__flags & self.__INIT_WITH_PREFIXLEN

    def ignore_prefixlen(self):
        self.__prefixlen = 32 if self.ip.version == 4 else 128


class IPv4Network(IPNetwork):
    def __init__(self, *args, **kwargs):
        super(IPv4Network, self).__init__(*args, **kwargs)

        if self.version != 4:
            self._ip = ipaddress.IPv4Address(self._ip)


class IPv6Network(IPNetwork):
    def __init__(self, *args, **kwargs):
        super(IPv6Network, self).__init__(*args, **kwargs)

        if self.version != 6:
            self._ip = ipaddress.IPv6Address(self._ip)


class IPAddress(IPNetwork):
    def __init__(self, ip, prefixlen=None, *args, **kwargs):

        if isinstance(ip, int):
            raise NotImplementedError

        if prefixlen is not None:
            self.__raise_exception("{}/{}".format(ip, prefixlen))
        elif "/" in ip:
            self.__raise_exception(ip)

        super(IPAddress, self).__init__(ip, prefixlen, *args, **kwargs)
        self.ignore_prefixlen()

    def __repr__(self):
        return self._ip

    def __raise_exception(self, ip):
        raise ValueError(
            "'%s' does not appear to be an IPv4 or IPv6 address"
            % ip
        )


class IPv4Address(IPv4Network):
    def __init__(self, *args, **kwargs):
        super(IPv4Address, self).__init__(*args, **kwargs)
        self.ignore_prefixlen()

    def __repr__(self):
        return str(self._ip)

