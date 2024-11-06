#!/usr/bin/env python3
#
# Copyright (C) 2017, 2018 Cumulus Networks, Inc. all rights reserved
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
# Netlink cache --
#

import os
import socket
import struct
import signal
import inspect
import logging
import ipaddress
import threading
import traceback

from logging import DEBUG, WARNING
from collections import OrderedDict

try:
    from ifupdown2.lib.sysfs import Sysfs
    from ifupdown2.lib.base_objects import BaseObject
    from ifupdown2.lib.exceptions import RetryCMD

    from ifupdown2.nlmanager.nlpacket import \
        Address, \
        Netconf, \
        Link, \
        Route, \
        AF_MPLS, \
        NetlinkPacket, \
        NLM_F_REQUEST, \
        RTM_NEWLINK, \
        RTM_SETLINK, \
        RTM_DELLINK, \
        RTM_NEWADDR, \
        RTM_DELADDR, \
        RTMGRP_ALL, \
        NLMSG_DONE, \
        NLM_F_REQUEST, \
        NLM_F_CREATE, \
        NLM_F_ACK, \
        RT_SCOPES, \
        INFINITY_LIFE_TIME

    import ifupdown2.nlmanager.ipnetwork as ipnetwork
    import ifupdown2.nlmanager.nlpacket as nlpacket
    import ifupdown2.nlmanager.nllistener as nllistener
    import ifupdown2.nlmanager.nlmanager as nlmanager
    import ifupdown2.ifupdown.statemanager as statemanager
except ImportError:
    from lib.sysfs import Sysfs
    from lib.base_objects import BaseObject
    from lib.exceptions import RetryCMD

    from nlmanager.nlpacket import \
        Address, \
        Netconf, \
        Link, \
        Route, \
        AF_MPLS, \
        NetlinkPacket, \
        NLM_F_REQUEST, \
        RTM_NEWLINK, \
        RTM_SETLINK, \
        RTM_DELLINK, \
        RTM_NEWADDR, \
        RTM_DELADDR, \
        RTMGRP_ALL, \
        NLMSG_DONE, \
        NLM_F_REQUEST, \
        NLM_F_CREATE, \
        NLM_F_ACK, \
        RT_SCOPES, \
        INFINITY_LIFE_TIME

    import nlmanager.ipnetwork as ipnetwork
    import nlmanager.nlpacket as nlpacket
    import nlmanager.nllistener as nllistener
    import nlmanager.nlmanager as nlmanager
    import ifupdown.statemanager as statemanager


log = logging.getLogger()


class NetlinkListenerWithCacheErrorNotInitialized(Exception):
    """
    If NetlinkListenerWithCache fails on __init__() or / start()
    we need to raise this custom exception.
    """
    pass


class NetlinkError(Exception):
    def __init__(self, exception, prefix=None, ifname=None):
        netlink_exception_message = ['netlink']

        if ifname:
            netlink_exception_message.append(ifname)

        if prefix:
            netlink_exception_message.append(prefix)

        netlink_exception_message.append(str(exception))
        super(NetlinkError, self).__init__(": ".join(netlink_exception_message))


class NetlinkCacheError(Exception):
    pass


class NetlinkCacheIfnameNotFoundError(NetlinkCacheError):
    pass


class NetlinkCacheIfindexNotFoundError(NetlinkCacheError):
    pass


class _NetlinkCache:
    """ Netlink Cache Class """

    # we need to store these attributes in a static list to be able to iterate
    # through it when comparing Address objects in add_address()
    # we ignore IFA_CACHEINFO and IFA_FLAGS
    _ifa_attributes = (
        Address.IFA_ADDRESS,
        Address.IFA_LOCAL,
        Address.IFA_LABEL,
        Address.IFA_BROADCAST,
        Address.IFA_ANYCAST,
        # Address.IFA_CACHEINFO,
        Address.IFA_MULTICAST,
        # Address.IFA_FLAGS
    )

    def __init__(self):
        # sysfs API
        self.__sysfs = Sysfs
        self.__sysfs.cache = self

        self._link_cache = {}
        self._addr_cache = {}
        self._bridge_vlan_cache = {}
        self._bridge_vlan_vni_cache = {}

        # helper dictionaries
        # ifindex: ifname
        # ifname: ifindex
        self._ifname_by_ifindex  = {}
        self._ifindex_by_ifname  = {}

        self._ifname_by_ifindex_sysfs = {}
        self._ifindex_by_ifname_sysfs = {}

        # master/slave(s) dictionary
        # master_ifname: [slave_ifname, slave_ifname]
        self._masters_and_slaves = {}

        # slave/master dictionary
        # slave_ifname: master_ifname
        self._slaves_master = {}

        # netconf cache data-structure schema:
        # {
        #     family: {
        #         ifindex: obj
        #     }
        # }
        self._netconf_cache = {
            socket.AF_INET: {},
            socket.AF_INET6: {},
            AF_MPLS: {}
        }
        # custom lock mechanism for netconf cache
        self._netconf_cache_lock = threading.Lock()

        # RLock is needed because we don't want to have separate handling in
        # get_ifname, get_ifindex and all the API function
        self._cache_lock = threading.RLock()

        # After sending a RTM_DELLINK request (ip link del DEV) we don't
        # automatically receive an RTM_DELLINK notification but instead we
        # have 3 to 5 RTM_NEWLINK notifications (first the device goes
        # admin-down then, goes through other steps that send notifications...
        # Because of this behavior the cache is out of sync and may cause
        # issues. To work-around this behavior we can ignore RTM_NEWLINK for a
        # given ifname until we receive the RTM_DELLINK. That way our cache is
        # not stale. When deleting a link, ifupdown2 uses:
        #   - NetlinkListenerWithCache:link_del(ifname)
        # Before sending the RTM_DELLINK netlink packet we:
        #   - register the ifname in the _ignore_rtm_newlinkq
        #   - force purge the cache because we are not notified right away
        #   - for every RTM_NEWLINK notification we check _ignore_rtm_newlinkq
        # to see if we need to ignore that packet
        #   - for every RTM_DELLINK notification we check if we have a
        # corresponding entry in _ignore_rtm_newlinkq and remove it
        self._ignore_rtm_newlinkq = list()
        self._ignore_rtm_newlinkq_lock = threading.Lock()

        # After sending a no master request (IFLA_MASTER=0) the kernels send
        # 2 or 3 notifications (with IFLA_MASTER) before sending the final
        # notification where IFLA_MASTER is removed. For performance purposes
        # we don't wait for those notifications, we simply update the cache
        # to reflect the change (if we got an ACK on the nomaster request).
        # Those extra notification re-add the former slave to it's master
        # (in our internal data-structures at least). ifupdown2 relies on
        # the cache to get accurate information, this puts the cache in an
        # unreliable state. We can detected this bad state and avoid it. Afer
        # a nomaster request we "register" the device as "nomaster", meaning
        # that we will manually remove the IFLA_MASTER attribute from any
        # subsequent packet, until the final packet arrives - then unregister
        # the device from the nomasterq.
        # We need an extra data-structure and lock mechanism for this:
        self._rtm_newlink_nomasterq = list()
        self._rtm_newlink_nomasterq_lock = threading.Lock()

        # In the scenario of NetlinkListenerWithCache, the listener thread
        # decode netlink packets and perform caching operation based on their
        # respective msgtype add_link for RTM_NEWLINK, remove_link for DELLINK
        # In some cases the main thread is creating a new device with:
        #   NetlinkListenerWithCache.link_add()
        # the request is sent and the cache won't have any knowledge of this
        # new link until we receive a NEWLINK notification on the listener
        # socket meanwhile the main thread keeps going. The main thread may
        # query the cache for the newly created device but the cache might not
        # know about it yet thus creating unexpected situation in the main
        # thread operations. We need to provide a mechanism to block the main
        # thread until the desired notification is processed. The main thread
        # can call:
        #   register_wait_event(ifname, netlink_msgtype)
        # to register an event for device name 'ifname' and netlink msgtype.
        # The main thread should then call wait_event to sleep until the
        # notification is received the NetlinkListenerWithCache provides the
        # following API:
        #   tx_nlpacket_get_response_with_error_and_wait_for_cache(ifname, nl_packet)
        # to handle both packet transmission, error handling and cache event
        self._wait_event = None
        self._wait_event_alarm = threading.Event()

    def __handle_type_error(self, func_name, data, exception, return_value):
        """
        TypeError shouldn't happen but if it does, we are prepared to log and recover
        """
        log.debug('nlcache: %s: %s: TypeError: %s' % (func_name, data, str(exception)))
        return return_value

    def __unslave_nolock(self, slave, master=None):
        """
        WARNING: LOCK SHOULD BE ACQUIRED BEFORE CALLING THIS FUNCTION

        When unslaving a device we need to manually clear and update our internal
        data structures to avoid keeping stale information before receiving a proper
        netlink notification.

        Dictionaries:
        - master_and_slaves
        - slaves_master
        - bridge_vlan_cache

        :param master:
        :param slave:
        :return:
        """
        try:
            del self._link_cache[slave].attributes[Link.IFLA_MASTER]
        except Exception:
            pass

        try:
            if not master:
                master = self._slaves_master[slave]

            self._masters_and_slaves[master].remove(slave)
        except (KeyError, ValueError):
            for master, slaves_list in self._masters_and_slaves.items():
                if slave in slaves_list:
                    slaves_list.remove(slave)
                    break

        try:
            del self._slaves_master[slave]
        except KeyError:
            pass

        try:
            del self._bridge_vlan_cache[slave]
        except KeyError:
            pass

        try:
            del self._bridge_vlan_vni_cache[slave]
        except KeyError:
            pass

    def append_to_ignore_rtm_newlinkq(self, ifname):
        """
        Register device 'ifname' to the ignore_rtm_newlinkq list pending
        RTM_DELLINK (see comments above _ignore_rtm_newlinkq declaration)
        """
        with self._ignore_rtm_newlinkq_lock:
            self._ignore_rtm_newlinkq.append(ifname)

    def remove_from_ignore_rtm_newlinkq(self, ifname):
        """ Unregister ifname from ignore_newlinkq list """
        try:
            with self._ignore_rtm_newlinkq_lock:
                self._ignore_rtm_newlinkq.remove(ifname)
        except ValueError:
            pass

    def append_to_rtm_newlink_nomasterq(self, ifname):
        """ Register device 'ifname' to the _ignore_rtm_newlink_nomasterq """
        with self._rtm_newlink_nomasterq_lock:
            self._rtm_newlink_nomasterq.append(ifname)

    def remove_from_rtm_newlink_nomasterq(self, ifname):
        """ Unregister ifname from _ignore_rtm_newlink_nomasterq list """
        try:
            with self._rtm_newlink_nomasterq_lock:
                self._rtm_newlink_nomasterq.remove(ifname)
        except ValueError:
            pass

    def register_wait_event(self, ifname, msgtype):
        """
        Register a cache "wait event" for device named 'ifname' and packet
        type msgtype

        We only one wait_event to be registered. Currently we don't support
        multi-threaded application so we need to had a strict check. In the
        future we could have a wait_event queue for multiple thread could
        register wait event.
        :param ifname: target device
        :param msgtype: netlink message type (RTM_NEWLINK, RTM_DELLINK etc.)
        :return: boolean: did we successfully register a wait_event?
        """
        with self._cache_lock:
            if self._wait_event:
                return False
            self._wait_event = (ifname, msgtype)
        return True

    def wait_event(self):
        """
        Sleep until cache event happened in netlinkq thread or timeout expired
        :return: None

        We set an arbitrary timeout at 1sec in case the kernel doesn't send
        out a notification for the event we want to wait for.
        """
        if not self._wait_event_alarm.wait(1):
            log.debug('nlcache: wait event alarm timeout expired for device "%s" and netlink packet type: %s'
                      % (self._wait_event[0], NetlinkPacket.type_to_string.get(self._wait_event[1], str(self._wait_event[1]))))
        with self._cache_lock:
            self._wait_event = None
            self._wait_event_alarm.clear()

    def unregister_wait_event(self):
        """
        Clear current wait event (cache can only handle one at once)
        :return:
        """
        with self._cache_lock:
            self._wait_event = None
            self._wait_event_alarm.clear()

    def override_link_flag(self, ifname, flags):
        # TODO: dont override all the flags just turn on/off IFF_UP
        try:
            with self._cache_lock:
                self._link_cache[ifname].flags = flags
        except Exception:
            pass

    def override_link_mtu(self, ifname, mtu):
        """
        Manually override link mtu and ignore any failures
        :param ifname:
        :param mtu:
        :return:
        """
        try:
            with self._cache_lock:
                self._link_cache[ifname].attributes[Link.IFLA_MTU].value = mtu
        except Exception:
            pass

    def override_cache_unslave_link(self, slave, master):
        """
        Manually update the cache unslaving SLAVE from MASTER

        When calling link_set_nomaster, we don't want to wait for the RTM_GETLINK
        notification - if the operation return with NL_SUCCESS we can manually
        update our cache and move on.

        :param master:
        :param slave:
        :return:
        """
        with self._cache_lock:
            self.__unslave_nolock(slave, master)

    def DEBUG_IFNAME(self, ifname, with_addresses=False):
        """
        A very useful function to use while debugging, it dumps the netlink
        packet with debug and color output.
        """
        import logging
        root = logging.getLogger()

        level = root.level

        try:
            root.setLevel(DEBUG)
            for handler in root.handlers:
                handler.setLevel(DEBUG)

            nllistener.log.setLevel(DEBUG)
            nlpacket.log.setLevel(DEBUG)
            nlmanager.log.setLevel(DEBUG)
            with self._cache_lock:
                obj = self._link_cache[ifname]
                save_debug = obj.debug
                obj.debug = True
                obj.dump()
                obj.debug = save_debug

                #if with_addresses:
                #    addrs = self._addr_cache.get(ifname, [])
                #    log.error('ADDRESSES=%s' % addrs)
                #    for addr in addrs:
                #        save_debug = addr.debug
                #        addr.debug = True
                #        addr.dump()
                #        addr.debug = save_debug
                #        log.error('-----------')
                #        log.error('-----------')
                #        log.error('-----------')
        except Exception:
            traceback.print_exc()
        # TODO: save log_level at entry and re-apply it after the dump
        nllistener.log.setLevel(WARNING)
        nlpacket.log.setLevel(WARNING)
        nlmanager.log.setLevel(WARNING)

        root.setLevel(level)
        for handler in root.handlers:
            handler.setLevel(level)

    def DEBUG_MSG(self, msg):
        import logging
        root = logging.getLogger()
        level = root.level

        try:
            root.setLevel(DEBUG)
            for handler in root.handlers:
                handler.setLevel(DEBUG)

            nllistener.log.setLevel(DEBUG)
            nlpacket.log.setLevel(DEBUG)
            nlmanager.log.setLevel(DEBUG)

            save_debug = msg.debug
            msg.debug = True
            msg.dump()
            msg.debug = save_debug
        except Exception:
            traceback.print_exc()
        # TODO: save log_level at entry and re-apply it after the dump
        nllistener.log.setLevel(WARNING)
        nlpacket.log.setLevel(WARNING)
        nlmanager.log.setLevel(WARNING)

        root.setLevel(level)
        for handler in root.handlers:
            handler.setLevel(level)

    def _populate_sysfs_ifname_ifindex_dicts(self):
        ifname_by_ifindex_dict = {}
        ifindex_by_ifname_dict = {}
        try:
            for dir_name in os.listdir('/sys/class/net/'):
                try:
                    with open('/sys/class/net/%s/ifindex' % dir_name) as f:
                        ifindex = int(f.readline())
                        ifname_by_ifindex_dict[ifindex] = dir_name
                        ifindex_by_ifname_dict[dir_name] = ifindex
                except (IOError, ValueError):
                    pass
        except OSError:
            pass
        with self._cache_lock:
            self._ifname_by_ifindex_sysfs = ifname_by_ifindex_dict
            self._ifindex_by_ifname_sysfs = ifindex_by_ifname_dict

    def get_ifindex(self, ifname):
        """
        Return device index or raise NetlinkCacheIfnameNotFoundError
        :param ifname:
        :return: int
        :raise: NetlinkCacheIfnameNotFoundError(NetlinkCacheError)
        """
        try:
            with self._cache_lock:
                return self._ifindex_by_ifname[ifname]
        except KeyError:
            # We assume that if the user requested a valid device ifindex but
            # for some reason we don't find any trace of it in our cache, we
            # then use sysfs to make sure that this device exists and fill our
            # internal help dictionaries.
            with self._cache_lock:
                ifindex = self._ifindex_by_ifname_sysfs.get(ifname)

            if ifindex:
                return ifindex
            self._populate_sysfs_ifname_ifindex_dicts()
            try:
                return self._ifindex_by_ifname_sysfs[ifname]
            except KeyError:
                # if we still haven't found any trace of the requested device
                # we raise a custom exception
                raise NetlinkCacheIfnameNotFoundError('ifname %s not present in cache' % ifname)

    def get_ifname(self, ifindex):
        """
        Return device name or raise NetlinkCacheIfindexNotFoundError
        :param ifindex:
        :return: str
        :raise: NetlinkCacheIfindexNotFoundError (NetlinkCacheError)
        """
        try:
            with self._cache_lock:
                return self._ifname_by_ifindex[ifindex]
        except KeyError:
            # We assume that if the user requested a valid device ifname but
            # for some reason we don't find any trace of it in our cache, we
            # then use sysfs to make sure that this device exists and fill our
            # internal help dictionaries.
            with self._cache_lock:
                ifname = self._ifname_by_ifindex_sysfs.get(ifindex)

            if ifname:
                return ifname
            self._populate_sysfs_ifname_ifindex_dicts()
            try:
                return self._ifname_by_ifindex_sysfs[ifindex]
            except KeyError:
                # if we still haven't found any trace of the requested device
                # we raise a custom exception
                raise NetlinkCacheIfindexNotFoundError('ifindex %s not present in cache' % ifindex)

    def link_exists(self, ifname):
        """
        Check if we have a cache entry for device 'ifname'
        :param ifname: device name
        :return: boolean
        """
        with self._cache_lock:
            return ifname in self._link_cache

    def link_is_up(self, ifname):
        """
        Check if device 'ifname' has IFF_UP flag
        :param ifname:
        :return: boolean
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].flags & Link.IFF_UP
        except (KeyError, TypeError):
            # ifname is not present in the cache
            return False
        except Exception as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=False)

    def link_is_loopback(self, ifname):
        """
        Check if device has IFF_LOOPBACK flag
        :param ifname:
        :return: boolean
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].flags & Link.IFF_LOOPBACK
                # IFF_LOOPBACK should be enough, otherwise we can also check for
                # link.device_type & Link.ARPHRD_LOOPBACK
        except (KeyError, AttributeError):
            return False
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=False)

    def link_exists_and_up(self, ifname):
        """
        Check if device exists and has IFF_UP flag set
        :param ifname:
        :return: tuple (boolean, boolean) -> (link_exists, link_is_up)
        """
        try:
            with self._cache_lock:
                return True, self._link_cache[ifname].flags & Link.IFF_UP
        except KeyError:
            # ifname is not present in the cache
            return False, False
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=(False, False))

    def link_is_bridge(self, ifname):
        return self.get_link_kind(ifname) == 'bridge'

    def get_link_kind(self, ifname):
        """
        Return link IFLA_INFO_KIND
        :param ifname:
        :return: string
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_KIND]
        except (KeyError, AttributeError):
            return None
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=None)

    def get_link_mtu(self, ifname):
        """
        Return link IFLA_MTU
        :param ifname:
        :return: int
        """
        return self.get_link_attribute(ifname, Link.IFLA_MTU, default=0)

    def get_link_mtu_str(self, ifname):
        """
        Return link IFLA_MTU as string
        :param ifname:
        :return: str
        """
        return str(self.get_link_mtu(ifname))

    def get_link_address(self, ifname):
        """
        Return link IFLA_ADDRESS
        :param ifname:
        :return: str
        """
        packet = None
        default_value = ""
        try:
            with self._cache_lock:
                packet = self._link_cache[ifname]
                return packet.attributes[Link.IFLA_ADDRESS].value.lower()
        except (KeyError, AttributeError):
            # KeyError will be raised if:
            #   - ifname is missing from the cache (but link_exists should be called prior this call)
            #   - IFLA_ADDRESS is missing
            # AttributeError can also be raised if attributes[IFLA_ADDRESS] returns None
            # If the packet is tagged as a REQUEST packet (priv_flags) we should query sysfs
            # otherwise default_value is returned.
            if packet and packet.priv_flags & NLM_F_REQUEST:
                return self.__sysfs.get_link_address(ifname)
            else:
                return default_value
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), default_value)

    def get_link_address_raw(self, ifname):
        """
        Return link IFLA_ADDRESS as integer
        :param ifname:
        :return: int
        """
        return self.get_link_attribute_raw(ifname, Link.IFLA_ADDRESS, default=0)

    def get_link_alias(self, ifname):
        """
        Return link IFLA_IFALIAS
        :param ifname:
        :return: str
        """
        return self.get_link_attribute(ifname, Link.IFLA_IFALIAS)

    def get_link_protodown(self, ifname):
        """
        Return link IFLA_PROTO_DOWN
        :param ifname:
        :return: int
        """
        return self.get_link_attribute(ifname, Link.IFLA_PROTO_DOWN)

    def get_link_attribute(self, ifname, attr, default=None):
        """
        Return link attribute 'attr'.value
        :param ifname:
        :param attr:
        :param default:
        :return:
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[attr].value
        except (KeyError, AttributeError):
            return default
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=default)

    def get_link_attribute_raw(self, ifname, attr, default=None):
        """
        Return link attribute 'attr'.raw
        :param ifname:
        :param attr:
        :param default:
        :return:
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[attr].raw
        except (KeyError, AttributeError):
            return default
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=default)

    def get_link_slave_kind(self, ifname):
        """
        Return device slave kind
        :param ifname:
        :return: str
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_SLAVE_KIND]
        except (KeyError, AttributeError):
            return None
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=None)

    def get_link_info_data_attribute(self, ifname, info_data_attribute, default=None):
        """
        Return device linkinfo:info_data attribute or default value
        :param ifname:
        :param info_data_attribute:
        :param default:
        :return:
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][info_data_attribute]
        except (KeyError, AttributeError):
            return default
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=default)

    def get_link_info_data(self, ifname):
        """
        Return device linkinfo:info_data attribute or default value
        :param ifname:
        :param info_data_attribute:
        :param default:
        :return:
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA]
        except (KeyError, AttributeError):
            return {}
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value={})

    def get_link_info_slave_data_attribute(self, ifname, info_slave_data_attribute, default=None):
        """
        Return device linkinfo:info_slave_data attribute or default value
        :param ifname:
        :param info_data_attribute:
        :param default:
        :return:
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_SLAVE_DATA][info_slave_data_attribute]
        except (KeyError, AttributeError):
            return default
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=default)

    ################
    # MASTER & SLAVE
    ################
    def get_master(self, ifname):
        """
        Return device master's ifname
        :param ifname:
        :return: str
        """
        try:
            with self._cache_lock:
                return self._slaves_master[ifname]
        except (KeyError, AttributeError):
            return None
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=None)

    def get_slaves(self, master):
        """
        Return all devices ifname enslaved to master device
        :param master:
        :return: list of string
        """
        try:
            with self._cache_lock:
                return list(self._masters_and_slaves[master])
        except KeyError:
            return []

    def is_link_enslaved_to(self, slave, master):
        """
        Return bool if SLAVE is enslaved to MASTER
        :param slave:
        :param master:
        :return:
        """
        try:
            with self._cache_lock:
                return self._slaves_master[slave] == master
        except KeyError:
            return False

    def get_lower_device_ifname(self, ifname):
        """
        Return the lower-device (IFLA_LINK) name or raise KeyError
        :param ifname:
        :return: string
        """
        try:
            with self._cache_lock:
                return self.get_ifname(self._link_cache[ifname].attributes[Link.IFLA_LINK].value)
        except (NetlinkCacheIfnameNotFoundError, AttributeError, KeyError):
            return None
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=None)

    ##########################################################################
    # VRF ####################################################################
    ##########################################################################

    def get_vrf_table_map(self):
        vrf_table_map = {}
        try:
            with self._cache_lock:
                for ifname, obj in self._link_cache.items():
                    linkinfo = obj.attributes.get(Link.IFLA_LINKINFO)

                    if linkinfo and linkinfo.value.get(Link.IFLA_INFO_KIND) == "vrf":
                        vrf_table_map[linkinfo.value[Link.IFLA_INFO_DATA][Link.IFLA_VRF_TABLE]] = ifname
        except Exception as e:
            log.debug("get_vrf_table_map: %s" % str(e))
        return vrf_table_map

    def get_vrf_table(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][Link.IFLA_VRF_TABLE]
        except (KeyError, AttributeError):
            return 0

    ##########################################################################
    # BOND ###################################################################
    ##########################################################################

    def bond_exists(self, ifname):
        """
        Check if bond 'ifname' exists
        :param ifname: bond name
        :return: boolean
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[nlpacket.Link.IFLA_LINKINFO].value[nlpacket.Link.IFLA_INFO_KIND] == 'bond'
        except (KeyError, AttributeError):
            return False
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=False)

    ##########################################################################
    # BRIDGE PORT ############################################################
    ##########################################################################

    def get_bridge_port_multicast_router(self, ifname):
        """
        Get bridge port multicast_router value - defaults to 1

        :param ifname:
        :return:
        """
        default_value = 1
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_SLAVE_DATA][Link.IFLA_BRPORT_MULTICAST_ROUTER]
        except (KeyError, AttributeError):
            # KeyError will be raised if:
            #   - ifname is missing from the cache (but link_exists should be called prior this call)
            #   - IFLA_BRPORT_MULTICAST_ROUTER is missing
            # AttributeError can also be raised if IFLA_LINKINFO is missing (None.value)
            # default_value is returned.
            return default_value
        except TypeError as e:
            return self.__handle_type_error(
                inspect.currentframe().f_code.co_name,
                ifname,
                str(e),
                return_value=default_value
            )

    ##########################################################################
    # BRIDGE #################################################################
    ##########################################################################

    def get_bridge_multicast_snooping(self, ifname):
        """
        Get bridge multicast_snooping value - defaults to 1

        :param ifname:
        :return:
        """
        default_value = 1
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][Link.IFLA_BR_MCAST_SNOOPING]
        except (KeyError, AttributeError):
            # KeyError will be raised if:
            #   - ifname is missing from the cache (but link_exists should be called prior this call)
            #   - IFLA_BR_MCAST_SNOOPING is missing
            # AttributeError can also be raised if IFLA_LINKINFO is missing (None.value)
            # default_value is returned.
            return default_value
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=default_value)

    def get_bridge_stp(self, ifname):
        """
        WARNING: ifname should be a bridge
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][Link.IFLA_BR_STP_STATE]
        except (KeyError, AttributeError):
            return 0
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=0)

    def get_brport_cost(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][Link.IFLA_BRPORT_COST]
        except (KeyError, AttributeError):
            return None
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=None)

    def get_brport_priority(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][Link.IFLA_BRPORT_PRIORITY]
        except (KeyError, AttributeError):
            return None
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=None)

    def get_brport_unicast_flood(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][Link.IFLA_BRPORT_UNICAST_FLOOD]
        except (KeyError, AttributeError):
            return 0
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=0)

    def get_brport_multicast_flood(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][Link.IFLA_BRPORT_MCAST_FLOOD]
        except (KeyError, AttributeError):
            return 0
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=0)

    def get_brport_broadcast_flood(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][Link.IFLA_BRPORT_BCAST_FLOOD]
        except (KeyError, AttributeError):
            return 0
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=0)

    def get_brport_neigh_suppress(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][Link.IFLA_BRPORT_NEIGH_SUPPRESS]
        except (KeyError, AttributeError):
            return 0
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=0)

    def get_brport_learning(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_SLAVE_DATA][Link.IFLA_BRPORT_LEARNING]
        except (KeyError, AttributeError):
            return 0

    def get_vlan_vni(self, ifname):
        with self._cache_lock:
            return self._bridge_vlan_vni_cache.get(ifname)

    def get_pvid_and_vids(self, ifname):
        """
        vlan-identifiers are stored in:

        self._bridge_vlan_cache = {
            ifname: [(vlan, flag), (vlan, flag), ...]
        }

        Those vlans are stored in compressed format (RTEXT_FILTER_BRVLAN_COMPRESSED)
        We only uncompress the vlan when the user request it.

        :param ifname:
        :return tuple: pvid, vids = int, [int, ]
        """
        pvid = None
        vlans = []
        try:
            range_begin_vlan_id = None
            range_flag = 0

            with self._cache_lock:
                bridge_vlans_tuples = self._bridge_vlan_cache.get(ifname)

                if bridge_vlans_tuples:
                    for (vlan_id, vlan_flag) in sorted(bridge_vlans_tuples):

                        if vlan_flag & Link.BRIDGE_VLAN_INFO_PVID:
                            pvid = vlan_id

                        if vlan_flag & Link.BRIDGE_VLAN_INFO_RANGE_BEGIN:
                            range_begin_vlan_id = vlan_id
                            range_flag = vlan_flag

                        elif vlan_flag & Link.BRIDGE_VLAN_INFO_RANGE_END:
                            range_flag |= vlan_flag

                            if not range_begin_vlan_id:
                                log.warning("BRIDGE_VLAN_INFO_RANGE_END is %d but we never "
                                            "saw a BRIDGE_VLAN_INFO_RANGE_BEGIN" % vlan_id)
                                range_begin_vlan_id = vlan_id

                            for x in range(range_begin_vlan_id, vlan_id + 1):
                                vlans.append(x)

                            range_begin_vlan_id = None
                            range_flag = 0

                        else:
                            vlans.append(vlan_id)
        except Exception:
            log.exception("get_bridge_vids")
        return pvid, vlans

    def get_pvid(self, ifname):
        """
        Get Port VLAN ID for device 'ifname'

        :param ifname:
        :return:
        """
        pvid = None
        try:
            with self._cache_lock:
                bridge_vlans_tuples = self._bridge_vlan_cache.get(ifname)

                if bridge_vlans_tuples:

                    for (vlan_id, vlan_flag) in sorted(bridge_vlans_tuples):

                        if vlan_flag & Link.BRIDGE_VLAN_INFO_PVID:
                            return vlan_id
        except Exception:
            log.exception("get_pvid")
        return pvid

    def bridge_exists(self, ifname):
        """
        Check if cached device is a bridge
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_KIND] == "bridge"
        except (KeyError, AttributeError):
            return False
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=False)

    def bridge_is_vlan_aware(self, ifname):
        """
        Return IFLA_BR_VLAN_FILTERING value
        :param ifname:
        :return: boolean
        """
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA][Link.IFLA_BR_VLAN_FILTERING]
        except (KeyError, AttributeError):
            return False
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=False)

    def link_is_bridge_port(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_SLAVE_KIND] == "bridge"
        except (KeyError, AttributeError):
            return False
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=False)

    def bridge_port_exists(self, bridge_name, brport_name):
        try:
            with self._cache_lock:
                # we are assuming that bridge_name is a valid bridge?
                return self._slaves_master[brport_name] == bridge_name
        except (KeyError, AttributeError):
            return False
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, bridge_name, str(e), return_value=False)

    def get_bridge_name_from_port(self, bridge_port_name):
        bridge_name = self.get_master(bridge_port_name)
        # now that we have the master's name we just need to double check
        # if the master is really a bridge
        return bridge_name if self.link_is_bridge(bridge_name) else None

    #def is_link_slave_kind(self, ifname, _type):
    #    try:
    #      with self._cache_lock:
    #            return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_SLAVE_KIND] == _type
    #    except (KeyError, AttributeError):
    #        return False

    ########################################

    def get_link_ipv6_addrgen_mode(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_AF_SPEC].value[socket.AF_INET6][Link.IFLA_INET6_ADDR_GEN_MODE]
        except (KeyError, AttributeError):
            # default to 0 (eui64)
            return 0
        except TypeError as e:
            return self.__handle_type_error(inspect.currentframe().f_code.co_name, ifname, str(e), return_value=0)

    #####################################################
    #####################################################
    #####################################################
    #####################################################
    #####################################################

    def add_link(self, link):
        """
        Cache RTM_NEWLINK packet
        :param link:
        :return:
        """
        ifindex = link.ifindex

        try:
            ifname = link.get_attribute_value(Link.IFLA_IFNAME).decode()
        except AttributeError:
            # ifname is already a string we don't need to decode it
            ifname = link.get_attribute_value(Link.IFLA_IFNAME)

        # check if this device is registered in the ignore list
        with self._ignore_rtm_newlinkq_lock:
            if ifname in self._ignore_rtm_newlinkq:
                return
        # check if this device is registered in the nomaster list:
        # if so we need to remove IFLA_MASTER attribute (if it fails
        # it means we've received the final notification and we should
        # unregister the device from our list.
        with self._rtm_newlink_nomasterq_lock:
            if ifname in self._rtm_newlink_nomasterq:
                try:
                    del link.attributes[Link.IFLA_MASTER]
                except Exception:
                    self._rtm_newlink_nomasterq.remove(ifname)

        # we need to check if the device was previously enslaved
        # so we can update the _masters_and_slaves and _slaves_master
        # dictionaries if the master has changed or was un-enslaved.
        old_ifla_master = None

        with self._cache_lock:

            # do we have a wait event registered for RTM_NEWLINK this ifname
            if self._wait_event and self._wait_event == (ifname, RTM_NEWLINK):
                self._wait_event_alarm.set()

            try:
                ifla_master_attr = self._link_cache[ifname].attributes.get(Link.IFLA_MASTER)

                if ifla_master_attr:
                    old_ifla_master = ifla_master_attr.get_pretty_value()
            except KeyError:
                # link is not present in the cache
                pass
            except AttributeError:
                # if this code is ever reached, this is very concerning and
                # should never happen as _link_cache should always contains
                # nlpacket.NetlinkPacket... maybe have some extra handling
                # here just in case?
                pass

            self._link_cache[ifname] = link

            ######################################################
            # update helper dictionaries and handle link renamed #
            ######################################################
            if ifindex:
                # ifindex can be None for packet added on ACK, it means
                # that we are caching the request packet and not the
                # notification coming from the kernel. We can leave
                # those data-strctures empty and rely on our try/excepts
                # in get_ifname/get_ifindex/get_master to do the work.

                self._ifindex_by_ifname[ifname] = ifindex

                rename_detected                 = False
                old_ifname_entry_for_ifindex    = self._ifname_by_ifindex.get(ifindex)

                if old_ifname_entry_for_ifindex and old_ifname_entry_for_ifindex != ifname:
                    # The ifindex was reused for a new interface before we got the
                    # RTM_DELLINK notification or the device using that ifindex was
                    # renamed. We need to update the cache accordingly.
                    rename_detected = True

                self._ifname_by_ifindex[ifindex] = ifname

                if rename_detected:
                    # in this case we detected a rename... It should'nt happen has we should get a RTM_DELLINK before that.
                    # if we still detect a rename the opti is to get rid of the stale value directly
                    try:
                        del self._ifindex_by_ifname[old_ifname_entry_for_ifindex]
                    except KeyError:
                        log.debug('update_helper_dicts: del _ifindex_by_ifname[%s]: KeyError ifname: %s'
                                  % (old_ifname_entry_for_ifindex, old_ifname_entry_for_ifindex))
                    try:
                        del self._link_cache[old_ifname_entry_for_ifindex]
                    except KeyError:
                        log.debug('update_helper_dicts: del _link_cache[%s]: KeyError ifname: %s'
                                  % (old_ifname_entry_for_ifindex, old_ifname_entry_for_ifindex))
            ######################################################
            ######################################################

            link_ifla_master_attr = link.attributes.get(Link.IFLA_MASTER)
            if link_ifla_master_attr:
                link_ifla_master = link_ifla_master_attr.get_pretty_value()
            else:
                link_ifla_master = None

            # if the link has a master we need to store it in an helper dictionary, where
            # the key is the master ifla_ifname and the value is a list of slaves, example:
            # _masters_slaves_dict = {
            #       'bond0': ['swp21', 'swp42']
            # }
            # this will be useful in the case we need to iterate on all slaves of a specific link

            if old_ifla_master:
                if old_ifla_master != link_ifla_master:
                    # the link was previously enslaved but master is now unset on this device
                    # we need to reflect that on the _masters_and_slaves and _slaves_master dictionaries
                    try:
                        self.__unslave_nolock(slave=ifname)
                    except NetlinkCacheIfindexNotFoundError:
                        pass
                else:
                    # the master status didn't change we can assume that our internal
                    # masters_slaves dictionary is up to date and return here
                    return

            if not link_ifla_master:
                return

            master_ifname = self._ifname_by_ifindex.get(link_ifla_master)

            if not master_ifname:
                # in this case we have a link object with IFLA_MASTER set to a ifindex
                # but this ifindex is not in our _ifname_by_ifindex dictionary thus it's
                # not in the _link_cache yet. This situation may happen when getting the
                # very first link dump. The kernel dumps device in the "ifindex" order.
                #
                # So let's say you have a box with 4 ports (lo, eth0, swp1, swp2), then
                # manually create a bond (bond0) and enslave swp1 and swp2, bond0 will
                # have ifindex 5 but when getting the link dump swp1 will be handled first
                # so at this point the cache has no idea if ifindex 5 is valid or not.
                # But since we've made it this far we can assume that this is probably a
                # valid device and will use sysfs to confirm.
                master_device_path = '/sys/class/net/%s/master' % ifname

                if os.path.exists(master_device_path):
                    # this check is necessary because realpath doesn't return None on error
                    # it returns it's input argument...
                    # >>> os.path.realpath('/sys/class/net/device_not_found')
                    # '/sys/class/net/device_not_found'
                    # >>>
                    master_ifname = os.path.basename(os.path.realpath(master_device_path))

            if master_ifname in self._masters_and_slaves:
                slave_list = self._masters_and_slaves[master_ifname]
                if ifname not in slave_list:
                    slave_list.append(ifname)
            else:
                self._masters_and_slaves[master_ifname] = [ifname]

            self._slaves_master[ifname] = master_ifname

    def update_link_info_data(self, ifname, ifla_info_data):
        """
        Update specific IFLA_INFO_DATA attributes of an existing cached device
        ignore all errors
        """
        try:
            with self._cache_lock:
                self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_DATA].update(ifla_info_data)
        except Exception:
            pass

    def update_link_ifla_address(self, ifname, ifla_address_str, ifla_address_int):
        try:
            with self._cache_lock:
                self._link_cache[ifname].attributes[Link.IFLA_ADDRESS].value = ifla_address_str
                self._link_cache[ifname].attributes[Link.IFLA_ADDRESS].raw = ifla_address_int
        except Exception:
            pass

    def add_bridge_vlan(self, msg):
        """
        Process AF_BRIDGE family packets (AF_BRIDGE family should be check
        before calling this function).

        Extract VLAN_INFO (vlan id and flag) and store it in cache.

        :param link:
        :return:
        """
        vlans_list = []

        # Todo: acquire the lock only when really needed
        with self._cache_lock:
            ifla_af_spec = msg.get_attribute_value(Link.IFLA_AF_SPEC)
            ifname = msg.get_attribute_value(Link.IFLA_IFNAME)

            if not ifla_af_spec:
                return

            try:
                # We need to check if this object is still in cache, after a bridge
                # is removed we still receive AF_BRIDGE notifications for it's slave
                # those notifications should be ignored.
                ifla_master = msg.get_attribute_value(Link.IFLA_MASTER)

                if not ifla_master or ifla_master not in self._ifname_by_ifindex:
                    return
            except Exception:
                pass

            # Example IFLA_AF_SPEC
            #  20: 0x1c001a00  ....  Length 0x001c (28), Type 0x001a (26) IFLA_AF_SPEC
            #  21: 0x08000200  ....  Nested Attribute - Length 0x0008 (8),  Type 0x0002 (2) IFLA_BRIDGE_VLAN_INFO
            #  22: 0x00000a00  ....
            #  23: 0x08000200  ....  Nested Attribute - Length 0x0008 (8),  Type 0x0002 (2) IFLA_BRIDGE_VLAN_INFO
            #  24: 0x00001000  ....
            #  25: 0x08000200  ....  Nested Attribute - Length 0x0008 (8),  Type 0x0002 (2) IFLA_BRIDGE_VLAN_INFO
            #  26: 0x00001400  ....
            for x_type, x_value in ifla_af_spec.items():
                if x_type == Link.IFLA_BRIDGE_VLAN_INFO:
                    for vlan_flag, vlan_id in x_value:
                        # We store these in the tuple as (vlan, flag) instead
                        # (flag, vlan) so that we can sort the list of tuples
                        vlans_list.append((vlan_id, vlan_flag))

                elif x_type == Link.IFLA_BRIDGE_VLAN_TUNNEL_INFO:
                    self._bridge_vlan_vni_cache.update({ifname: x_value})

            self._bridge_vlan_cache.update({ifname: vlans_list})

    def force_add_slave(self, master, slave):
        """
        When calling link_set_master, we don't want to wait for the RTM_GETLINK
        notification - if the operation return with NL_SUCCESS we can manually
        update our cache and move on
        :param master:
        :param slave:
        :return:
        """
        try:
            with self._cache_lock:
                master_slaves = self._masters_and_slaves.get(master)

                if not master_slaves:
                    self._masters_and_slaves[master] = [slave]
                else:
                    if slave not in master_slaves:
                        master_slaves.append(slave)

                # if the slave is already enslaved to another device we should
                # make sure to remove it from the _masters_and_slaves data
                # structure as well.
                old_master = self._slaves_master.get(slave)

                if old_master and old_master != master:
                    try:
                        self._masters_and_slaves.get(old_master, []).remove(slave)
                    except Exception:
                        pass

                self._slaves_master[slave] = master
        except Exception:
            # since this is an optimization function we can ignore all error
            pass

    def force_add_slave_list(self, master, slave_list):
        """
        When calling link_set_master, we don't want to wait for the RTM_GETLINK
        notification - if the operation return with NL_SUCCESS we can manually
        update our cache and move on
        :param master:
        :param slave:
        :return:
        """
        try:
            with self._cache_lock:
                master_slaves = self._masters_and_slaves.get(master)

                if not master_slaves:
                    self._masters_and_slaves[master] = slave_list
                else:
                    for slave_ifname in slave_list:
                        if slave_ifname not in master_slaves:
                            master_slaves.append(slave_ifname)

                for slave in slave_list:
                    self._slaves_master[slave] = master
        except Exception:
            # since this is an optimization function we can ignore all error
            pass

    def force_remove_link(self, ifname):
        """
        When calling link_del (RTM_DELLINK) we need to manually remove the
        associated cache entry - the RTM_DELLINK notification isn't received
        instantaneously - we don't want to keep stale value in our cache
        :param ifname:
        :return:
        """
        try:
            ifindex = self.get_ifindex(ifname)
        except (KeyError, NetlinkCacheIfnameNotFoundError):
            ifindex = None
        self.remove_link(None, link_ifname=ifname, link_ifindex=ifindex)

    def remove_link(self, link, link_ifname=None, link_ifindex=None):
        """ Process RTM_DELLINK packet and purge the cache accordingly """
        if link:
            ifindex = link.ifindex
            ifname = link.get_attribute_value(Link.IFLA_IFNAME)
            try:
                # RTM_DELLINK received - we can now remove ifname from the
                # ignore_rtm_newlinkq list. We don't bother checkin if the
                # if name is present in the list (because it's likely in)
                with self._ignore_rtm_newlinkq_lock:
                    self._ignore_rtm_newlinkq.remove(ifname)
            except ValueError:
                pass
        else:
            ifname = link_ifname
            ifindex = link_ifindex

        link_ifla_master = None
        # when an enslaved device is removed we receive the RTM_DELLINK
        # notification without the IFLA_MASTER attribute, we need to
        # get the previous cached value in order to correctly update the
        # _masters_and_slaves dictionary

        with self._cache_lock:
            try:
                try:
                    ifla_master_attr = self._link_cache[ifname].attributes.get(Link.IFLA_MASTER)
                    if ifla_master_attr:
                        link_ifla_master = ifla_master_attr.get_pretty_value()
                except KeyError:
                    # link is not present in the cache
                    pass
                except AttributeError:
                    # if this code is ever reached this is very concerning and
                    # should never happen as _link_cache should always contains
                    # nlpacket.NetlinkPacket maybe have some extra handling here
                    # just in case?
                    pass
                finally:
                    del self._link_cache[ifname]
            except KeyError:
                # KeyError means that the link doesn't exists in the cache
                log.debug('del _link_cache: KeyError ifname: %s' % ifname)

            try:
                # like in __unslave_nolock() we need to make sure that all deleted link
                # have their bridge-vlans and _slaves_master entries cleared.
                for slave in list(self._masters_and_slaves[ifname]):
                    self.__unslave_nolock(slave, master=ifname)
            except Exception:
                pass

            try:
                del self._bridge_vlan_cache[ifname]
            except Exception:
                pass

            try:
                del self._bridge_vlan_vni_cache[ifname]
            except Exception:
                pass

            try:
                del self._ifname_by_ifindex[ifindex]
            except KeyError:
                log.debug('del _ifname_by_ifindex: KeyError ifindex: %s' % ifindex)

            try:
                del self._ifindex_by_ifname[ifname]
            except KeyError:
                log.debug('del _ifindex_by_ifname: KeyError ifname: %s' % ifname)

            try:
                del self._addr_cache[ifname]
            except KeyError:
                log.debug('del _addr_cache: KeyError ifname: %s' % ifname)

            try:
                del self._masters_and_slaves[ifname]
            except KeyError:
                log.debug('del _masters_and_slaves: KeyError ifname: %s' % ifname)

            # if the device was enslaved to another device we need to remove
            # it's entry from our _masters_and_slaves dictionary
            if link_ifla_master and link_ifla_master > 0:
                try:
                    self.__unslave_nolock(slave=ifname)
                except NetlinkCacheIfindexNotFoundError as e:
                    log.debug('cache: remove_link: %s: %s' % (ifname, str(e)))
                except KeyError:
                    log.debug('_masters_and_slaves[if%s].remove(%s): KeyError' % (link_ifla_master, ifname))

    def _address_get_ifname_and_ifindex(self, addr):
        ifindex = addr.ifindex
        label = addr.get_attribute_value(Address.IFA_LABEL)

        if not label:
            try:
                label = self.get_ifname(ifindex)
            except NetlinkCacheIfindexNotFoundError:
                pass

        if isinstance(label, bytes):
            label = label.decode()

        return label, ifindex

    @staticmethod
    def __check_and_replace_address(address_list, new_addr):
        """
        Check if new_addr is in address_list, if found we replace the occurrence
        with the new and update object "new_addr"

        address_list should be a valid list (check before calling to improve perf)
        :param address_list:
        :param new_addr:
        :return:
        """
        ip_with_prefix = new_addr.get_attribute_value(Address.IFA_ADDRESS)

        for index, addr in enumerate(address_list):
            if addr.get_attribute_value(Address.IFA_ADDRESS) == ip_with_prefix:
                address_list[index] = new_addr
                return True

        return False

    def add_address(self, addr):
        ifname, ifindex = self._address_get_ifname_and_ifindex(addr)

        if not ifname:
            log.debug('nlcache: add_address: cannot cache addr for ifindex %s' % ifindex)
            return

        ip_version = addr.get_attribute_value(Address.IFA_ADDRESS).version

        with self._cache_lock:

            if ifname in self._addr_cache:
                address_list = self._addr_cache[ifname][ip_version]
                # First check if the address is already cached, if so
                # we need to update it's entry with the new obj
                if not address_list or not self.__check_and_replace_address(address_list, addr):
                    address_list.append(addr)
            else:
                self._addr_cache[ifname] = {
                    4: [],
                    6: [],
                    ip_version: [addr]
                }

    def force_address_flush_family(self, ifname, family):
        try:
            with self._cache_lock:
                self._addr_cache[ifname][family] = []
        except Exception:
            pass

    def address_flush_link(self, ifname):
        """
        Flush address cache for link 'ifname'
        :param ifname:
        :return:
        """
        try:
            with self._cache_lock:
                self._addr_cache[ifname] = {4: [], 6: []}
        except Exception:
            pass

    def force_remove_addr(self, ifname, addr):
        """
        When calling addr_del (RTM_DELADDR) we need to manually remove the
        associated cache entry - the RTM_DELADDR notification isn't received
        instantaneously - we don't want to keep stale value in our cache
        :param ifname:
        :param addr:
        """
        try:
            with self._cache_lock:
                # iterate through the interface addresses
                # to find which one to remove from the cache
                obj_to_remove = None

                for cache_addr in self._addr_cache[ifname][addr.version]:
                    try:
                        if cache_addr.attributes[Address.IFA_ADDRESS].value == addr:
                            obj_to_remove = cache_addr
                    except Exception:
                        try:
                            if cache_addr.attributes[Address.IFA_LOCAL].value == addr:
                                obj_to_remove = cache_addr
                        except Exception:
                            return
                if obj_to_remove:
                    self._addr_cache[ifname][addr.version].remove(obj_to_remove)
        except Exception:
            pass

    def remove_address(self, addr_to_remove):
        ifname, _ = self._address_get_ifname_and_ifindex(addr_to_remove)

        with self._cache_lock:
            # iterate through the interface addresses
            # to find which one to remove from the cache
            try:
                ip_version = addr_to_remove.get_attribute_value(Address.IFA_ADDRESS).version
            except Exception:
                try:
                    ip_version = addr_to_remove.get_attribute_value(Address.IFA_LOCAL).version
                except Exception:
                    # print debug error
                    return

            addrs_for_interface = self._addr_cache.get(ifname, {}).get(ip_version)

            if not addrs_for_interface:
                return

            list_addr_to_remove = []

            for addr in addrs_for_interface:
                # compare each object attribute to see if they match
                addr_match = False

                for ifa_attr in self._ifa_attributes:
                    if addr.get_attribute_value(ifa_attr) != addr_to_remove.get_attribute_value(ifa_attr):
                        addr_match = False
                        break
                    addr_match = True
                    # if the address attribute matches we need to remove this one

                if addr_match:
                    list_addr_to_remove.append(addr)

            for addr in list_addr_to_remove:
                try:
                    addrs_for_interface.remove(addr)
                except ValueError as e:
                    log.debug('nlcache: remove_address: exception: %s' % e)

    def get_ip_addresses(self, ifname: str) -> list:
        addresses = []
        try:
            with self._cache_lock:
                intf_addresses = self._addr_cache[ifname]

                for addr in intf_addresses.get(4, []):
                    addresses.append(addr.attributes[Address.IFA_ADDRESS].value)

                for addr in intf_addresses.get(6, []):
                    addresses.append(addr.attributes[Address.IFA_ADDRESS].value)

                return addresses
        except (KeyError, AttributeError):
            return addresses

    def link_has_ip(self, ifname):
        try:
            with self._cache_lock:
                intf_addresses = self._addr_cache[ifname]
                return bool(intf_addresses.get(4, None) or intf_addresses.get(6, None))
        except Exception:
            return False

    ############################################################################
    ############################################################################
    ############################################################################

    def add_netconf(self, msg):
        """
        cache RTM_NEWNETCONF objects
        {
            family: {
                ifindex: RTM_NEWNETCONF
            }
        }
        we currently only support AF_INET, AF_INET6 and AF_MPLS family.
        """
        try:
            with self._netconf_cache_lock:
                self._netconf_cache[msg.family][msg.get_attribute_value(msg.NETCONFA_IFINDEX)] = msg
        except Exception:
            pass

    def remove_netconf(self, msg):
        """
        Process RTM_DELNETCONF, remove associated entry in our _netconf_cache
        """
        try:
            with self._netconf_cache_lock:
                del self._netconf_cache[msg.family][msg.get_attribute_value(msg.NETCONFA_IFINDEX)]
        except Exception:
            pass

    def get_netconf_forwarding(self, family, ifname):
        """
        Return netconf device forwarding value
        """
        try:
            with self._netconf_cache_lock:
                return self._netconf_cache[family][self.get_ifindex(ifname)].get_attribute_value(Netconf.NETCONFA_FORWARDING)
        except Exception:
            # if KeyError and family == AF_INET6: ipv6 is probably disabled on this device
            return None

    def get_netconf_mpls_input(self, ifname):
        """
        Return netconf device MPLS input value
        """
        try:
            with self._netconf_cache_lock:
                return self._netconf_cache[AF_MPLS][self.get_ifindex(ifname)].get_attribute_value(Netconf.NETCONFA_INPUT)
        except Exception:
            return None

    ############################################################################
    ############################################################################
    ############################################################################

    @staticmethod
    def get_user_configured_addresses(ifaceobj_list: list, with_address_virtual=False) -> list:
        ip4 = []
        ip6 = []

        for ifaceobj in ifaceobj_list:
            addresses = ifaceobj.get_attr_value("address")

            if addresses:
                for addr_index, addr in enumerate(addresses):
                    if "/" in addr:
                        ip_network_obj = ipnetwork.IPNetwork(addr)
                    else:
                        # if netmask is specified under the stanza we need to use to
                        # create the IPNetwork objects, otherwise let IPNetwork figure
                        # out the correct netmask for ip4 & ip6
                        ip_network_obj = ipnetwork.IPNetwork(addr, ifaceobj.get_attr_value_n("netmask", addr_index))

                    if ip_network_obj.version == 6:
                        ip6.append(ip_network_obj)
                    else:
                        ip4.append(ip_network_obj)

            if not with_address_virtual:
                continue
            #
            # address-virtual and vrrp ips also needs to be accounted for
            #
            addresses_virtual = ifaceobj.get_attr_value("address-virtual")
            vrrp              = ifaceobj.get_attr_value("vrrp")

            for attr_config in (addresses_virtual, vrrp):
                for addr_virtual_entry in attr_config or []:
                    for addr in addr_virtual_entry.split():
                        try:
                            ip_network_obj = ipnetwork.IPNetwork(addr)

                            if ip_network_obj.version == 6:
                                ip6.append(ip_network_obj)
                            else:
                                ip4.append(ip_network_obj)
                        except Exception:
                            continue

        # always return ip4 first, followed by ip6
        return ip4 + ip6

    def get_managed_ip_addresses(self, ifname: str, ifaceobj_list: list, with_address_virtual: bool = False):
        """
        Get all ip addresses managed by ifupdown2. As a network manager we need
        to be able to detect manually added ip addresses (with iproute2 for
        example).
        We only addressed added by the kernel (scope: link).

        Args:
            ifname: str
            ifaceobj_list: list of ifaceobj
            with_address_virtual: boolean (to include vrrp and address-virtual)

        Returns: List of ipnetwork.IPNetwork objects
        """
        config_addrs = set(
            self.get_user_configured_addresses(
                ifaceobj_list,
                with_address_virtual=with_address_virtual,
            )
        )

        previous_state_ifaceobjs = statemanager.statemanager_api.get_ifaceobjs(ifname)

        if previous_state_ifaceobjs:
            for previous_state_addr in self.get_user_configured_addresses(
                previous_state_ifaceobjs,
                with_address_virtual=with_address_virtual,
            ):
                config_addrs.add(previous_state_addr)

        managed_addresses = []

        for addr in self.get_ip_addresses(ifname):
            if addr in config_addrs:
                managed_addresses.append(addr)

            elif not addr.scope & Route.RT_SCOPE_LINK:
                managed_addresses.append(addr)

        return managed_addresses

    ############################################################################
    ############################################################################
    ############################################################################

    def addr_is_cached(self, ifname, addr):
        """
        return True if addr is in cache

        We might need to check if metric/peer and other attribute are also correctly cached.
        We might also need to add a "force" attribute to skip the cache check
        :param ifname:
        :param ifindex:
        :return:
        """
        try:
            with self._cache_lock:
                for cache_addr in self._addr_cache[ifname][addr.version]:
                    try:
                        ifa_address = cache_addr.attributes[Address.IFA_ADDRESS].value
                        if ifa_address.ip == addr.ip and ifa_address.prefixlen == addr.prefixlen:
                            return True
                    except Exception:
                        try:
                            ifa_local = cache_addr.attributes[Address.IFA_LOCAL].value
                            return ifa_local.ip == addr.ip and ifa_local.prefixlen == addr.prefixlen
                        except Exception:
                            pass
        except (KeyError, AttributeError):
            pass
        return False

    # old

    def get_link_obj(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname]
        except KeyError:
            return None

    def get_link_info_slave_data(self, ifname):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_SLAVE_DATA]
        except (KeyError, AttributeError):
            return {}

    def is_link_kind(self, ifname, _type):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_KIND] == _type
        except (KeyError, AttributeError):
            return False

    def is_link_slave_kind(self, ifname, _type):
        try:
            with self._cache_lock:
                return self._link_cache[ifname].attributes[Link.IFLA_LINKINFO].value[Link.IFLA_INFO_SLAVE_KIND] == _type
        except (KeyError, AttributeError):
            return False


class NetlinkListenerWithCache(nllistener.NetlinkManagerWithListener, BaseObject):

    __instance = None
    VXLAN_UDP_PORT = 4789

    @staticmethod
    def init(log_level):
        """
        Create the singleton via this init function
        Following calls should use get_instance()
        :param log_level:
        :return:
        """
        if not NetlinkListenerWithCache.__instance:
            try:
                NetlinkListenerWithCache.__instance = NetlinkListenerWithCache(log_level=log_level)
            except Exception as e:
                log.error('NetlinkListenerWithCache: init: %s' % e)
                traceback.print_exc()

    @staticmethod
    def get_instance():
        """
        Use this function to retrieve the active reference to the
        NetlinkListenerWithCache, make sure you called .init() first
        :return:
        """
        if not NetlinkListenerWithCache.__instance:
            raise NetlinkListenerWithCacheErrorNotInitialized("NetlinkListenerWithCache not initialized")
        return NetlinkListenerWithCache.__instance

    @staticmethod
    def is_init():
        return bool(NetlinkListenerWithCache.__instance)

    def __init__(self, log_level):
        """

        :param log_level:
        """
        if NetlinkListenerWithCache.__instance:
            raise RuntimeError("NetlinkListenerWithCache: invalid access. Please use NetlinkListenerWithCache.getInstance()")
        else:
            NetlinkListenerWithCache.__instance = self

        nllistener.NetlinkManagerWithListener.__init__(
            self,
            groups=(
                nlpacket.RTMGRP_LINK
                | nlpacket.RTMGRP_IPV4_IFADDR
                | nlpacket.RTMGRP_IPV6_IFADDR
                | nlpacket.RTNLGRP_IPV4_NETCONF
                | nlpacket.RTNLGRP_IPV6_NETCONF
                | nlpacket.RTNLGRP_MPLS_NETCONF
            ),
            start_listener=False,
            error_notification=True
        )

        BaseObject.__init__(self)

        signal.signal(signal.SIGTERM, self.signal_term_handler)
        #signal.signal(signal.SIGINT, self.signal_int_handler)

        self.cache = _NetlinkCache()

        # set specific log level to lower-level API
        nllistener.log.setLevel(log_level)
        nlpacket.log.setLevel(log_level)
        nlmanager.log.setLevel(log_level)

        self.IPNetwork_version_to_family = {4: socket.AF_INET, 6: socket.AF_INET6}

        nlpacket.mac_int_to_str = lambda mac_int: ':'.join(('%012x' % mac_int)[i:i + 2] for i in range(0, 12, 2))
        # Override the nlmanager's mac_int_to_str function
        # Return an integer in MAC string format: xx:xx:xx:xx:xx:xx instead of xxxx.xxxx.xxxx

        self.workq_handler = {
            self.WORKQ_SERVICE_NETLINK_QUEUE: self.service_netlinkq,
        }

        # NetlinkListenerWithCache first dumps links and addresses then start
        # a worker thread before returning. The worker thread processes the
        # workq mainly to service (process) the netlinkq which contains our
        # netlink packet (notification coming from the Kernel).
        # When the main thread is making netlin requests (i.e. bridge add etc
        # ...) the main thread will sleep (thread.event.wait) until we notify
        # it when receiving an ack associated with the request. The request
        # may fail and the kernel won't return an ACK but instead return a
        # NLMSG_ERROR packet. We need to store those packet separatly because:
        #   - we could have several NLMSG_ERROR for different requests from
        #     different threads (in a multi-threaded ifupdown2 case)
        #   - we want to decode the packet and tell the user/log or even raise
        #     an exception with the appropriate message.
        #     User must check the return value of it's netlink requests and
        #     catch any exceptions, for that purpose please use API:
        #        - tx_nlpacket_get_response_with_error
        self.errorq = list()
        self.errorq_lock = threading.Lock()
        self.errorq_enabled = True

        # when ifupdown2 starts, we need to fill the netlink cache
        # GET_LINK/ADDR request are asynchronous, we need to block
        # and wait for the cache to be filled. We are using this one
        # time netlinkq_notify_event to wait for the cache completion event
        self.netlinkq_notify_event = None

        # another threading event to make sure that the netlinkq worker thread is ready
        self.is_ready = threading.Event()

        self.worker = None

    def __str__(self):
        return "NetlinkListenerWithCache"

    def start(self):
        """
        Start NetlinkListener -
        cache all links, bridges, addresses and netconfs
        :return:
        """
        self.restart_listener()

        # set ifupdown2 specific supported and ignore messages
        self.listener.supported_messages = (
            nlpacket.RTM_NEWLINK,
            nlpacket.RTM_DELLINK,
            nlpacket.RTM_NEWADDR,
            nlpacket.RTM_DELADDR,
            nlpacket.RTM_NEWNETCONF,
            nlpacket.RTM_DELNETCONF
        )
        self.listener.ignore_messages = (
            nlpacket.RTM_GETLINK,
            nlpacket.RTM_GETADDR,
            nlpacket.RTM_GETNEIGH,
            nlpacket.RTM_GETROUTE,
            nlpacket.RTM_GETQDISC,
            nlpacket.RTM_NEWNEIGH,
            nlpacket.RTM_DELNEIGH,
            nlpacket.RTM_NEWROUTE,
            nlpacket.RTM_DELROUTE,
            nlpacket.RTM_DELNETCONF,
            nlpacket.RTM_NEWQDISC,
            nlpacket.RTM_DELQDISC,
            nlpacket.RTM_GETQDISC,
            nlpacket.NLMSG_ERROR,  # should be in supported_messages ?
            nlpacket.NLMSG_DONE  # should be in supported_messages ?
        )

        # get all links and wait for the cache to be filled
        self.get_all_links_wait_netlinkq()

        # get all addresses and wait for cache to be filled
        self.get_all_addresses_wait_netlinkq()

        # get a netconf dump and wait for the cached to be filled
        self.get_all_netconf_wait_netlinkq()

        # TODO: on ifquery we shoudn't start any thread (including listener in NetlinkListener)
        # only for standalone code.
        #import sys
        #for arg in sys.argv:
        #    if 'ifquery' in arg:
        #        self.worker = None
        #        return

        # start the netlinkq worker thread
        self.worker = threading.Thread(target=self.main, name='NetlinkListenerWithCache')
        self.worker.start()
        self.is_ready.wait()

    def cleanup(self):
        if not self.__instance:
            return

        # passing 0, 0 to the handler so it doesn't log.info
        self.signal_term_handler(0, 0)

        if self.worker:
            self.worker.join()

    def main(self):
        self.is_ready.set()

        # This loop has two jobs:
        # - process items on our workq
        # - process netlink messages on our netlinkq, messages are placed there via our NetlinkListener
        try:
            while True:
                # Sleep until our alarm goes off...NetlinkListener will set the alarm once it
                # has placed a NetlinkPacket object on our netlinkq. If someone places an item on
                # our workq they should also set our alarm...if they don't it is not the end of
                # the world as we will wake up in 1s anyway to check to see if our shutdown_event
                # has been set.
                self.alarm.wait(0.1)
                # when ifupdown2 is not running we could change the timeout to 1 sec or more (daemon mode)
                # the daemon can also put a hook (pyinotify) on /etc/network/interfaces
                # if we detect changes to that file it probably means that ifupdown2 will be called very soon
                # then we can scale up our ops (or maybe unpause some of them)
                # lets study the use cases
                self.alarm.clear()
                if self.shutdown_event.is_set():
                    break

                while not self.workq.empty():
                    (event, options) = self.workq.get()

                    if event == self.WORKQ_SERVICE_NETLINK_QUEUE:
                        self.service_netlinkq(self.netlinkq_notify_event)
                    elif event == self.WORKQ_SERVICE_ERROR:
                        self.logger.error('NetlinkListenerWithCache: WORKQ_SERVICE_ERROR')
                    else:
                        raise NetlinkCacheError("Unsupported workq event %s" % event)
        finally:
            # il faut surement mettre un try/except autour de la boucle au dessus
            # car s'il y a une exception on ne quitte pas le listener thread
            self.listener.shutdown_event.set()
            self.listener.join()

    def reset_errorq(self):
        with self.errorq_lock:
            self.logger.debug("nlcache: reset errorq")
            self.errorq = []

    def rx_rtm_newaddr(self, rxed_addr_packet):
        super(NetlinkListenerWithCache, self).rx_rtm_newaddr(rxed_addr_packet)
        self.cache.add_address(rxed_addr_packet)

    def rx_rtm_dellink(self, link):
        # cache only supports AF_UNSPEC for now
        if link.family != socket.AF_UNSPEC:
            return
        super(NetlinkListenerWithCache, self).rx_rtm_dellink(link)
        self.cache.remove_link(link)

    def rx_rtm_deladdr(self, addr):
        super(NetlinkListenerWithCache, self).rx_rtm_deladdr(addr)
        self.cache.remove_address(addr)

    def rx_rtm_newlink(self, rxed_link_packet):
        # cache only supports AF_UNSPEC for now
        # we can modify the cache to support more family:
        # cache {
        #    intf_name: {
        #       AF_UNSPEC: NetlinkObj,
        #       AF_BRIDGE: NetlinkObj
        #    },
        # }
        if rxed_link_packet.family != socket.AF_UNSPEC:
            # special handling for AF_BRIDGE packets
            if rxed_link_packet.family == socket.AF_BRIDGE:
                self.cache.add_bridge_vlan(rxed_link_packet)
            return

        super(NetlinkListenerWithCache, self).rx_rtm_newlink(rxed_link_packet)
        self.cache.add_link(rxed_link_packet)

    def rx_rtm_newnetconf(self, msg):
        super(NetlinkListenerWithCache, self).rx_rtm_newnetconf(msg)
        self.cache.add_netconf(msg)

    def rx_rtm_delnetconf(self, msg):
        super(NetlinkListenerWithCache, self).rx_rtm_delnetconf(msg)
        self.cache.remove_netconf(msg)

    def tx_nlpacket_get_response_with_error(self, nl_packet):
        """
            After getting an ACK we need to check if this ACK was in fact an
            error (NLMSG_ERROR). This function go through the .errorq list to
            find the error packet associated with our request.
            If found, we process it and raise an exception with the appropriate
            information/message.

        :param nl_packet:
        :return:
        """
        self.tx_nlpacket_get_response(nl_packet)

        error_packet = None
        index = 0

        with self.errorq_lock:
            for error in self.errorq:
                if error.seq == nl_packet.seq and error.pid == nl_packet.pid:
                    error_packet = error
                    break
                index += 1

            if error_packet:
                del self.errorq[index]

        if not error_packet:
            return True

        error_code = abs(error_packet.negative_errno)

        if error_packet.msgtype == NLMSG_DONE or not error_code:
            # code NLE_SUCCESS...this is an ACK
            return True

        if self.debug:
            error_packet.dump()

        try:
            # os.strerror might raise ValueError
            strerror = os.strerror(error_code)

            if strerror:
                error_str = "operation failed with '%s' (%s)" % (strerror, error_code)
            else:
                error_str = "operation failed with code %s" % error_code

        except ValueError:
            error_str = "operation failed with code %s" % error_code

        raise NetlinkCacheError(error_str)

    def tx_nlpacket_get_response_with_error_and_cache_on_ack(self, packet, ifname=None):
        """
            TX packet and manually cache the object
        """
        self.tx_nlpacket_get_response_with_error(packet)
        # When creating a new link via netlink, we don't always wait for the kernel
        # NEWLINK notification to be cached to continue. If our request is ACKed by
        # the OS we assume that the link was successfully created. Since we aren't
        # waiting for the kernel notification to continue we need to manually fill
        # our cache with the packet we just TX'ed. Once the NEWLINK notification
        # is received it will simply override the previous entry.
        # We need to keep track of those manually cached packets. We set a private
        # flag on the objects via the attribute priv_flags
        packet.priv_flags |= NLM_F_REQUEST
        try:
            # we need to decode the service header so all the attribute are properly
            # filled in the packet object that we are about to store in cache.
            # i.e.: packet.flags shouldn't contain NLM_F_* values but IFF_* (in case of Link object)
            # otherwise call to cache.link_is_up() will probably return True
            packet.decode_service_header()
        except Exception:
            # we can ignore all errors
            pass

        try:
            # We might be pre-caching an updated object that is "incomplete".
            # i.e. say you have an existing bond in the cache, on ifreload only
            # one attribute is updated. Our object 'packet' here will only have
            # a couple attributes (but overriding a 'full' object in the cache).
            # We need to somehow 'merge' some of the attributes that are not
            # updated, otherwise later calls to the cache might return None for
            # the missing attributes. MTU is a prime example.
            if ifname:
                # To minimize the changes each parent function can decide to
                # trigger this 'merge' code by provided the optional 'ifname' arg

                # MERGING MTU:
                # First check if we are not already setting MTU in this packet
                try:
                    packet_mtu = packet.attributes[Link.IFLA_MTU].value
                except Exception:
                    packet_mtu = None
                # Then update 'packet' before caching
                if not packet_mtu:
                    old_packet_mtu = self.cache.get_link_attribute(ifname, Link.IFLA_MTU)
                    if old_packet_mtu:
                        packet.add_attribute(Link.IFLA_MTU, old_packet_mtu)
        except Exception:
            # we can ignore all errors
            pass

        # Then we can use our normal "add_link" API call to cache the packet
        # and fill up our additional internal data structures.
        self.cache.add_link(packet)

    def tx_nlpacket_get_response_with_error_and_wait_for_cache(self, ifname, nl_packet):
        """
        The netlink request are asynchronus, but sometimes the main thread/user
         would like to wait until the result of the request is cached. To do so
         a cache event for ifname and nl_packet.msgtype is registered. Then the
         netlink packet is TXed, errors are checked then we sleep until the
         cache event is set (or we reach the timeout). This allows us to reliably
         make sure is up to date with newly created/removed devices or addresses.
        :param nl_packet:
        :return:
        """
        wait_event_registered = self.cache.register_wait_event(ifname, nl_packet.msgtype)

        try:
            result = self.tx_nlpacket_get_response_with_error(nl_packet)
        except Exception:
            # an error was caught, we need to unregister the event and raise again
            self.cache.unregister_wait_event()
            raise

        if wait_event_registered:
            self.cache.wait_event()

        return result

    def get_all_links_wait_netlinkq(self):
        self.logger.info("requesting link dump")
        # create netlinkq notify event so we can wait until the links are cached
        self.netlinkq_notify_event = threading.Event()
        self.get_all_links()
        # we also need a dump of all existing bridge vlans
        self.get_all_br_links(compress_vlans=True)
        # block until the netlinkq was serviced and cached
        self.service_netlinkq(self.netlinkq_notify_event)
        self.netlinkq_notify_event.wait()
        self.netlinkq_notify_event.clear()

    def get_all_addresses_wait_netlinkq(self):
        self.logger.info("requesting address dump")
        self.netlinkq_notify_event = threading.Event()
        self.get_all_addresses()
        # block until the netlinkq was serviced and cached
        self.service_netlinkq(self.netlinkq_notify_event)
        self.netlinkq_notify_event.wait()
        self.netlinkq_notify_event.clear()
        self.netlinkq_notify_event = False

    def get_all_netconf_wait_netlinkq(self):
        self.logger.info("requesting netconf dump")
        self.netlinkq_notify_event = threading.Event()
        self.netconf_dump()
        # block until the netlinkq was serviced and cached
        self.service_netlinkq(self.netlinkq_notify_event)
        self.netlinkq_notify_event.wait()
        self.netlinkq_notify_event.clear()
        self.netlinkq_notify_event = False

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
        link.body = struct.pack('Bxxxiii', socket.AF_BRIDGE, ifindex, 0, 0)

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
        return self.tx_nlpacket_get_response_with_error(link)

    def vlan_set_bridge_binding(self, ifname, bridge_binding=True):
        """
        Set VLAN_FLAG_BRIDGE_BINDING on vlan interface
        :param ifname: the vlan interface
        :param bridge_binding: True to set the flag, False to unset
        """
        self.logger.info("%s: netlink: ip link set dev %s type vlan bridge_binding %s" % (ifname, ifname, "on" if bridge_binding else "off"))

        debug = RTM_NEWLINK in self.debug

        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = struct.pack('=BxxxiLL', socket.AF_UNSPEC, 0, 0, 0)

        link.add_attribute(Link.IFLA_IFNAME, ifname)
        info_data = {Link.IFLA_VLAN_FLAGS: {Link.VLAN_FLAG_BRIDGE_BINDING: bridge_binding}}
        link.add_attribute(Link.IFLA_LINKINFO, {
            Link.IFLA_INFO_KIND: "vlan",
            Link.IFLA_INFO_DATA: info_data
        })

        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response_with_error(link)

    #############################################################################################################
    # Netlink API ###############################################################################################
    #############################################################################################################

    def link_add(self, ifname, kind):
        self.link_add_with_attributes(ifname, kind, {})

    def link_add_with_attributes(self, ifname, kind, ifla):
        """
        Build and TX a RTM_NEWLINK message to add the desired interface
        """
        if ifla:
            self.logger.info("%s: netlink: ip link add dev %s type %s (with attributes)" % (ifname, ifname, kind))
            self.logger.debug("attributes: %s" % ifla)
        else:
            self.logger.info("%s: netlink: ip link add dev %s type %s" % (ifname, ifname, kind))
        try:
            debug = RTM_NEWLINK in self.debug

            link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
            link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
            link.body = struct.pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)

            for nl_attr, value in list(ifla.items()):
                link.add_attribute(nl_attr, value)

            link.add_attribute(Link.IFLA_IFNAME, ifname)
            link.add_attribute(Link.IFLA_LINKINFO, {
                Link.IFLA_INFO_KIND: kind
            })
            link.build_message(next(self.sequence), self.pid)
            return self.tx_nlpacket_get_response_with_error_and_cache_on_ack(link)
        except Exception:
            raise NetlinkCacheError("%s: cannot create link %s type %s" % (ifname, ifname, kind))

    def link_add_with_attributes_dry_run(self, ifname, kind, ifla):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link add dev %s type %s" % (ifname, kind))
        self.logger.debug("attributes: %s" % ifla)

    ###

    def __link_set_flag(self, ifname, flags):
        """
        Bring interface 'ifname' up (raises on error)
        :param ifname:
        :return:
        """
        try:
            link = Link(RTM_NEWLINK, RTM_NEWLINK in self.debug, use_color=self.use_color)
            link.flags = NLM_F_REQUEST | NLM_F_ACK
            link.body = struct.pack("=BxxxiLL", socket.AF_UNSPEC, 0, flags, Link.IFF_UP)
            link.add_attribute(Link.IFLA_IFNAME, ifname)
            link.build_message(next(self.sequence), self.pid)
            result = self.tx_nlpacket_get_response_with_error(link)
            # if we reach this code it means the operation went through
            # without exception we can update the cache value this is
            # needed for the following case (and probably others):
            #
            # ifdown bond0 ; ip link set dev bond_slave down
            # ifup bond0
            #       at the beginning the slaves are admin down
            #       ifupdownmain:run_up link up the slave
            #       the bond addon check if the slave is up or down
            #           and admin down the slave before enslavement
            #           but the cache didn't process the UP notification yet
            #           so the cache has a stale value and we try to enslave
            #           a port, that is admin up, to a bond resulting
            #           in an unexpected failure
            self.cache.override_link_flag(ifname, flags)
            return result
        except Exception as e:
            raise NetlinkError(e, "ip link set dev %s %s" % (ifname, "up" if flags == Link.IFF_UP else "down"), ifname=ifname)

    def link_up(self, ifname):
        if not self.cache.link_is_up(ifname):
            self.logger.info("%s: netlink: ip link set dev %s up" % (ifname, ifname))
            self.__link_set_flag(ifname, flags=Link.IFF_UP)

    def link_up_force(self, ifname):
        self.logger.info("%s: netlink: ip link set dev %s up" % (ifname, ifname))
        self.__link_set_flag(ifname, flags=Link.IFF_UP)

    def link_down(self, ifname):
        if self.cache.link_is_up(ifname):
            self.logger.info("%s: netlink: ip link set dev %s down" % (ifname, ifname))
            self.__link_set_flag(ifname, flags=0)

    def link_down_force(self, ifname):
        self.logger.info("%s: netlink: ip link set dev %s down" % (ifname, ifname))
        self.__link_set_flag(ifname, flags=0)

    def link_up_dry_run(self, ifname):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link set dev %s up" % ifname)

    def link_down_dry_run(self, ifname):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link set dev %s down" % ifname)

    def link_down_force_dry_run(self, ifname):
        self.link_down_dry_run(ifname)

    ###

    def __link_set_protodown(self, ifname, state):
        debug = RTM_NEWLINK in self.debug
        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = struct.pack("=BxxxiLL", socket.AF_UNSPEC, 0, 0, 0)
        link.add_attribute(Link.IFLA_IFNAME, ifname)
        link.add_attribute(Link.IFLA_PROTO_DOWN, state)
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response_with_error(link)

    def link_set_protodown_on(self, ifname):
        """
        Bring ifname up by setting IFLA_PROTO_DOWN on
        """
        if self.cache.get_link_protodown(ifname) == 1:
            return True

        self.logger.info("%s: netlink: set link %s protodown on" % (ifname, ifname))
        try:
            self.__link_set_protodown(ifname, 1)
        except Exception as e:
            raise NetlinkError(e, "cannot set link %s protodown on" % ifname, ifname=ifname)

    def link_set_protodown_off(self, ifname):
        """
        Take ifname down by setting IFLA_PROTO_DOWN off
        """
        if self.cache.get_link_protodown(ifname) == 0:
            return True

        self.logger.info("%s: netlink: set link %s protodown off" % (ifname, ifname))
        try:
            self.__link_set_protodown(ifname, 0)
        except Exception as e:
            raise NetlinkError(e, "cannot set link %s protodown off" % ifname, ifname=ifname)

    def link_set_protodown_on_dry_run(self, ifname):
        self.log_info_ifname_dry_run(ifname, "netlink: set link %s protodown on" % ifname)

    def link_set_protodown_off_dry_run(self, ifname):
        self.log_info_ifname_dry_run(ifname, "netlink: set link %s protodown off" % ifname)

    ###

    def link_del(self, ifname):
        """
        Send RTM_DELLINK request
        :param ifname:
        :return:
        """
        try:
            try:
                ifindex = self.cache.get_ifindex(ifname)
            except NetlinkCacheIfnameNotFoundError:
                # link doesn't exists on the system
                return True

            self.logger.info("%s: netlink: ip link del %s" % (ifname, ifname))

            debug = RTM_DELLINK in self.debug

            link = Link(RTM_DELLINK, debug, use_color=self.use_color)
            link.flags = NLM_F_REQUEST | NLM_F_ACK
            link.body = struct.pack("Bxxxiii", socket.AF_UNSPEC, ifindex, 0, 0)
            link.build_message(next(self.sequence), self.pid)

            try:
                # We need to register this ifname so the cache can ignore and discard
                # any further RTM_NEWLINK packet until we receive the associated
                # RTM_DELLINK notification
                self.cache.append_to_ignore_rtm_newlinkq(ifname)

                result = self.tx_nlpacket_get_response_with_error(link)

                # Manually purge the cache entry for ifname to make sure we don't have
                # any stale value in our cache
                self.cache.force_remove_link(ifname)
                return result
            except Exception:
                # Something went wrong while sending the RTM_DELLINK request
                # we need to clear ifname from the ignore_rtm_newlinkq list
                self.cache.remove_from_ignore_rtm_newlinkq(ifname)
                raise
        except Exception as e:
            raise NetlinkError(e, "cannot delete link %s" % ifname, ifname=ifname)

    def link_del_dry_run(self, ifname):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link del %s" % ifname)

    ###

    def __link_set_master(self, ifname, master_ifindex, master_ifname=None):
        debug = RTM_NEWLINK in self.debug
        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_REQUEST | NLM_F_ACK
        link.body = struct.pack("=BxxxiLL", socket.AF_UNSPEC, 0, 0, 0)
        link.add_attribute(Link.IFLA_IFNAME, ifname)
        link.add_attribute(Link.IFLA_MASTER, master_ifindex)
        link.build_message(next(self.sequence), self.pid)
        result = self.tx_nlpacket_get_response_with_error(link)
        # opti:
        # if we reach this code it means the slave/unslave opreation went through
        # we can manually update our cache to reflect the change without having
        # to wait for the netlink notification
        if master_ifindex:
            self.cache.force_add_slave(master_ifname, ifname)
        else:
            self.cache.override_cache_unslave_link(slave=ifname, master=master_ifname)
        return result

    def link_set_master(self, ifname, master_ifname):
        self.logger.info("%s: netlink: ip link set dev %s master %s" % (ifname, ifname, master_ifname))
        try:
            self.__link_set_master(ifname, self.cache.get_ifindex(master_ifname), master_ifname=master_ifname)
        except Exception as e:
            raise NetlinkError(e, "cannot enslave link %s to %s" % (ifname, master_ifname), ifname=ifname)

    def link_set_nomaster(self, ifname):
        self.logger.info("%s: netlink: ip link set dev %s nomaster" % (ifname, ifname))
        try:
            self.cache.append_to_rtm_newlink_nomasterq(ifname)
            self.__link_set_master(ifname, 0)
        except Exception as e:
            self.cache.remove_from_rtm_newlink_nomasterq(ifname)
            raise NetlinkError(e, "cannot un-enslave link %s" % ifname, ifname=ifname)

    def link_set_master_dry_run(self, ifname, master_dev):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link set dev %s master %s" % (ifname, master_dev))

    def link_set_nomaster_dry_run(self, ifname):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link set dev %s nomaster" % ifname)

    ###

    def link_set_address_dry_run(self, ifname, hw_address, hw_address_int):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link set dev %s address %s" % (ifname, hw_address))

    def link_set_address(self, ifname, hw_address, hw_address_int, keep_link_down=False):
        is_link_up = self.cache.link_is_up(ifname)
        # check if the link is already up or not if the link is
        # up we need to down it then make sure we up it again
        try:
            if is_link_up:
                self.link_down_force(ifname)

            self.logger.info("%s: netlink: ip link set dev %s address %s" % (ifname, ifname, hw_address))
            debug = RTM_NEWLINK in self.debug
            link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
            link.flags = NLM_F_REQUEST | NLM_F_ACK
            link.body = struct.pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)

            link.add_attribute(Link.IFLA_IFNAME, ifname)
            link.add_attribute(Link.IFLA_ADDRESS, hw_address)

            link.build_message(next(self.sequence), self.pid)
            result = self.tx_nlpacket_get_response_with_error(link)

            # if we reach that code it means we got an ACK from the kernel, we can pro-actively
            # update our local cache to reflect the change until the notificate arrives
            self.cache.update_link_ifla_address(ifname, hw_address, hw_address_int)

            return result
        except Exception as e:
            raise NetlinkError(e, "cannot set dev %s address %s" % (ifname, hw_address), ifname=ifname)
        finally:
            if is_link_up and not keep_link_down:
                self.link_up_force(ifname)
            else:
                self.logger.info(f"{ifname}: keeping link down")

    ###

    __macvlan_mode = {
        "private": Link.MACVLAN_MODE_PRIVATE,
        "vepa": Link.MACVLAN_MODE_VEPA,
        "bridge": Link.MACVLAN_MODE_BRIDGE,
        "passthru": Link.MACVLAN_MODE_PASSTHRU,
        "source": Link.MACVLAN_MODE_SOURCE
    }

    def link_add_macvlan(self, ifname, macvlan_ifname, macvlan_mode=None):
        self.logger.info(
            "%s: netlink: ip link add link %s name %s type macvlan mode %s"
            % (ifname, ifname, macvlan_ifname, macvlan_mode if macvlan_mode else "private")
        )
        try:
            ifindex = self.cache.get_ifindex(ifname)
            debug = RTM_NEWLINK in self.debug

            link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
            link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
            link.body = struct.pack("Bxxxiii", socket.AF_UNSPEC, 0, 0, 0)

            link.add_attribute(Link.IFLA_IFNAME, ifname)

            if ifindex:
                link.add_attribute(Link.IFLA_LINK, ifindex)

            link.add_attribute(Link.IFLA_LINKINFO, {
                Link.IFLA_INFO_KIND: "macvlan",
                Link.IFLA_INFO_DATA: {
                    Link.IFLA_MACVLAN_MODE: self.__macvlan_mode.get(
                        macvlan_mode,
                        Link.MACVLAN_MODE_PRIVATE
                    )
                }
            })
            link.build_message(next(self.sequence), self.pid)
            return self.tx_nlpacket_get_response_with_error_and_cache_on_ack(link)

        except Exception as e:
            raise NetlinkCacheError(
                "netlink: %s: cannot create macvlan %s: %s"
                % (ifname, macvlan_ifname, str(e))
            )

    def link_add_macvlan_dry_run(self, ifname, macvlan_ifame, macvlan_mode=None):
        self.log_info_ifname_dry_run(
            ifname,
            "netlink: ip link add link %s name %s type macvlan mode %s"
            % (ifname, macvlan_ifame, macvlan_mode if macvlan_mode else "private")
        )
        return True

    ###

    def link_add_vrf(self, ifname, vrf_table):
        self.logger.info("%s: netlink: ip link add dev %s type vrf table %s" % (ifname, ifname, vrf_table))

        debug = RTM_NEWLINK in self.debug

        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
        link.body = struct.pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
        link.add_attribute(Link.IFLA_IFNAME, ifname)
        link.add_attribute(Link.IFLA_LINKINFO, {
            Link.IFLA_INFO_KIND: "vrf",
            Link.IFLA_INFO_DATA: {
                Link.IFLA_VRF_TABLE: int(vrf_table)
            }
        })
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response_with_error_and_cache_on_ack(link)

    def link_add_vrf_dry_run(self, ifname, vrf_table):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link add dev %s type vrf table %s" % (ifname, vrf_table))
        return True

    ###

    def link_add_bridge(self, ifname, mtu=None):
        self.logger.info("%s: netlink: ip link add dev %s type bridge" % (ifname, ifname))

        debug = RTM_NEWLINK in self.debug

        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
        link.body = struct.pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
        link.add_attribute(Link.IFLA_IFNAME, ifname)

        if mtu:
            self.logger.info("%s: netlink: set bridge mtu %s" % (ifname, mtu))
            link.add_attribute(Link.IFLA_MTU, mtu)

        link.add_attribute(Link.IFLA_LINKINFO, {
            Link.IFLA_INFO_KIND: "bridge",
        })
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response_with_error_and_cache_on_ack(link)

    def link_add_bridge_dry_run(self, ifname, mtu=None):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link add dev %s type bridge" % ifname)
        return True

    def link_set_bridge_info_data(self, ifname, ifla_info_data):
        self.logger.info(
            "%s: netlink: ip link set dev %s type bridge (with attributes)"
            % (ifname, ifname)
        )
        self.logger.debug("attributes: %s" % ifla_info_data)

        try:
            debug = RTM_NEWLINK in self.debug
            link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
            link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
            link.body = struct.pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
            link.add_attribute(Link.IFLA_IFNAME, ifname)
            link.add_attribute(Link.IFLA_LINKINFO, {
                Link.IFLA_INFO_KIND: "bridge",
                Link.IFLA_INFO_DATA: ifla_info_data
            })
            link.build_message(next(self.sequence), self.pid)
            result = self.tx_nlpacket_get_response_with_error(link)

            self.cache.update_link_info_data(ifname, ifla_info_data)

            return result
        except Exception as e:
            raise NetlinkCacheError("%s: netlink: cannot create bridge or set attributes: %s" % (ifname, str(e)))

    def link_set_bridge_info_data_dry_run(self, ifname, ifla_info_data):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link add dev %s type bridge (with attributes)" % ifname)
        self.logger.debug("attributes: %s" % ifla_info_data)

    ###

    def link_add_bridge_vlan(self, ifname, vlan_id):
        """
        Add VLAN(s) to a bridge interface
        """
        self.logger.info("%s: netlink: bridge vlan add vid %s dev %s" % (ifname, vlan_id, ifname))
        try:
            ifindex = self.cache.get_ifindex(ifname)
            self.vlan_modify(RTM_SETLINK, ifindex, vlan_id, bridge_self=True)
            # TODO: we should probably fill our internal cache when when the ACK is received.
        except Exception as e:
            raise NetlinkError(e, "cannot add bridge vlan %s" % vlan_id, ifname=ifname)

    def link_del_bridge_vlan(self, ifname, vlan_id):
        """
        Delete VLAN(s) from a bridge interface
        """
        self.logger.info("%s: netlink: bridge vlan del vid %s dev %s" % (ifname, vlan_id, ifname))
        try:
            ifindex = self.cache.get_ifindex(ifname)
            self.vlan_modify(RTM_DELLINK, ifindex, vlan_id, bridge_self=True)
        except Exception as e:
            raise NetlinkError(e, "cannot remove bridge vlan %s" % vlan_id, ifname=ifname)

    def link_add_bridge_vlan_dry_run(self, ifname, vlan_id):
        self.log_info_ifname_dry_run(ifname, "netlink: bridge vlan add vid %s dev %s" % (vlan_id, ifname))

    def link_del_bridge_vlan_dry_run(self, ifname, vlan_id):
        self.log_info_ifname_dry_run(ifname, "netlink: bridge vlan del vid %s dev %s" % (vlan_id, ifname))

    ###

    def link_add_vlan(self, vlan_raw_device, ifname, vlan_id, vlan_protocol=None, bridge_binding=None):
        """
        ifindex is the index of the parent interface that this sub-interface
        is being added to

        If you name an interface swp2.17 but assign it to vlan 12, the kernel
        will return a very misleading NLE_MSG_OVERFLOW error.  It only does
        this check if the ifname uses dot notation.

        Do this check here so we can provide a more intuitive error
        """
        vlan_iproute2_cmd = ["ip link add link %s name %s type vlan id %s" % (vlan_raw_device, ifname, vlan_id)]
        try:
            ifla_info_data = {Link.IFLA_VLAN_ID: vlan_id}

            if vlan_protocol:
                vlan_iproute2_cmd.append("protocol %s" % vlan_protocol)
                ifla_info_data[Link.IFLA_VLAN_PROTOCOL] = vlan_protocol

            bridge_binding_str = ""

            if bridge_binding is not None:
                bridge_binding_str = "bridge_binding %s" % ("on" if bridge_binding else "off")
                ifla_info_data[Link.IFLA_VLAN_FLAGS] = {Link.VLAN_FLAG_BRIDGE_BINDING: bridge_binding}

            self.logger.info("%s: netlink: %s %s" % (ifname, " ".join(vlan_iproute2_cmd), bridge_binding_str))

            if "." in ifname:
                ifname_vlanid = int(ifname.split(".")[-1])

                if ifname_vlanid != vlan_id:
                    raise NetlinkCacheError(
                        "Interface %s must belong to VLAN %d (VLAN %d was requested)"
                        % (ifname, ifname_vlanid, vlan_id)
                    )

            ifindex = self.cache.get_ifindex(vlan_raw_device)

            debug = RTM_NEWLINK in self.debug

            link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
            link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
            link.body = struct.pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)

            link.add_attribute(Link.IFLA_IFNAME, ifname)
            link.add_attribute(Link.IFLA_LINK, ifindex)
            link.add_attribute(Link.IFLA_LINKINFO, {
                Link.IFLA_INFO_KIND: "vlan",
                Link.IFLA_INFO_DATA: ifla_info_data
            })
            link.build_message(next(self.sequence), self.pid)
            return self.tx_nlpacket_get_response_with_error_and_cache_on_ack(link, ifname)
        except Exception as e:
            if "Invalid argument" in str(e) and bridge_binding is not None:
                raise RetryCMD(cmd=" ".join(vlan_iproute2_cmd))
            else:
                raise NetlinkError(e, "cannot create vlan %s %s" % (ifname, vlan_id), ifname=ifname)

    def link_add_vlan_dry_run(self, vlan_raw_device, ifname, vlan_id, vlan_protocol=None, bridge_binding=None):
        """
        ifindex is the index of the parent interface that this sub-interface
        is being added to

        If you name an interface swp2.17 but assign it to vlan 12, the kernel
        will return a very misleading NLE_MSG_OVERFLOW error.  It only does
        this check if the ifname uses dot notation.

        Do this check here so we can provide a more intuitive error
        """
        if vlan_protocol:
            self.log_info_ifname_dry_run(
                ifname,
                "netlink: ip link add link %s name %s type vlan id %s protocol %s"
                % (vlan_raw_device, ifname, vlan_id, vlan_protocol)
            )

        else:
            self.log_info_ifname_dry_run(
                ifname,
                "netlink: ip link add link %s name %s type vlan id %s"
                % (vlan_raw_device, ifname, vlan_id)
            )

    ###

    def link_add_vxlan_with_info_data(self, ifname, info_data):
        """
                cmd = ["ip link add %s type vxlan id %s" % (ifname, id)]

                if port:
                    cmd.append("dstport %s" % port)
                    info_data[nlpacket.Link.IFLA_VXLAN_PORT] = int(port)

                if local:
                    cmd.append("local %s" % local)
                    info_data[nlpacket.Link.IFLA_VXLAN_LOCAL] = local

                if ageing:
                    cmd.append("ageing %s" % ageing)
                    info_data[nlpacket.Link.IFLA_VXLAN_AGEING] = int(ageing)

                if group:
                    if group.ip.is_multicast:
                        cmd.append("group %s" % group)
                    else:
                        cmd.append("remote %s" % group)
                    info_data[nlpacket.Link.IFLA_VXLAN_GROUP] = group
                else:
                    cmd.append("noremote")

                if not learning:
                    cmd.append("nolearning")
                info_data[nlpacket.Link.IFLA_VXLAN_LEARNING] = int(learning)

                if not udp_csum:
                    cmd.append("noudpcsum")
                info_data[nlpacket.Link.IFLA_VXLAN_UDP_CSUM] = int(udp_csum)

                if physdev:
                    cmd.append("dev %s" % physdev)
                    info_data[nlpacket.Link.IFLA_VXLAN_LINK] = self.cache.get_ifindex(physdev)

                if ttl:
                    cmd.append("ttl %s" % ttl)
                    info_data[nlpacket.Link.IFLA_VXLAN_TTL] = ttl

                self.logger.info('%s: netlink: %s' % (ifname, " ".join(cmd)))

        :param ifname:
        :param info_data:
        :return:
        """
        self.logger.info(
            "%s: netlink: ip link add dev %s type vxlan id %s (with attributes)"
            % (ifname, ifname, info_data.get(Link.IFLA_VXLAN_ID))
        )
        self.logger.debug("attributes: %s" % info_data)

        debug = RTM_NEWLINK in self.debug
        link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
        link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
        link.body = struct.pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
        link.add_attribute(Link.IFLA_IFNAME, ifname)
        link.add_attribute(Link.IFLA_LINKINFO, {
            Link.IFLA_INFO_KIND: "vxlan",
            Link.IFLA_INFO_DATA: info_data
        })
        link.build_message(next(self.sequence), self.pid)
        return self.tx_nlpacket_get_response_with_error_and_cache_on_ack(link, ifname)

    def link_add_vxlan_with_info_data_dry_run(self, ifname, info_data):
        self.log_info_ifname_dry_run(
            ifname,
            "netlink: ip link add dev %s type vxlan id %s (with attributes)"
            % (ifname, info_data.get(Link.IFLA_VXLAN_ID))
        )
        self.logger.debug("attributes: %s" % info_data)
        return True

    ###

    def link_add_bond_with_info_data(self, ifname, ifla_master, ifla_info_data):
        self.logger.info(
            "%s: netlink: ip link add dev %s type bond (with attributes)"
            % (ifname, ifname)
        )
        self.logger.debug("attributes: %s" % ifla_info_data)

        try:
            debug = RTM_NEWLINK in self.debug
            link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
            link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
            link.body = struct.pack('Bxxxiii', socket.AF_UNSPEC, 0, 0, 0)
            link.add_attribute(Link.IFLA_IFNAME, ifname)

            if ifla_master:
                link.add_attribute(Link.IFLA_MASTER, ifla_master)

            link.add_attribute(Link.IFLA_LINKINFO, {
                Link.IFLA_INFO_KIND: "bond",
                Link.IFLA_INFO_DATA: ifla_info_data
            })
            link.build_message(next(self.sequence), self.pid)
            return self.tx_nlpacket_get_response_with_error_and_cache_on_ack(link, ifname=ifname)
        except Exception as e:
            raise NetlinkCacheError("%s: netlink: cannot create bond with attributes: %s" % (ifname, str(e)))

    def link_add_bond_with_info_data_dry_run(self, ifname, ifla_master, ifla_info_data):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link add dev %s type bond (with attributes)" % ifname)
        self.logger.debug("attributes: %s" % ifla_info_data)

    ###

    def link_set_brport_with_info_slave_data(self, ifname, kind, ifla_info_data, ifla_info_slave_data):
        """
        Build and TX a RTM_NEWLINK message to add the desired interface
        """
        self.logger.info("%s: netlink: ip link set dev %s: bridge port attributes" % (ifname, ifname))
        self.logger.debug("attributes: %s" % ifla_info_slave_data)

        try:
            debug = RTM_NEWLINK in self.debug

            link = Link(RTM_NEWLINK, debug, use_color=self.use_color)
            link.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
            link.body = struct.pack("Bxxxiii", socket.AF_UNSPEC, 0, 0, 0)

            if ifname:
                link.add_attribute(Link.IFLA_IFNAME, ifname)

            linkinfo = dict()

            if kind:
                linkinfo[Link.IFLA_INFO_KIND] = kind
                linkinfo[Link.IFLA_INFO_DATA] = ifla_info_data

            linkinfo[Link.IFLA_INFO_SLAVE_KIND] = "bridge"
            linkinfo[Link.IFLA_INFO_SLAVE_DATA] = ifla_info_slave_data

            link.add_attribute(Link.IFLA_LINKINFO, linkinfo)
            link.build_message(next(self.sequence), self.pid)

            # the brport already exists and is cached - after this operation we most
            # likely don't need to do anything about the brport so we don't need to
            # wait for the new notification to be cached.
            return self.tx_nlpacket_get_response_with_error(link)
        except Exception as e:
            raise NetlinkCacheError("netlink: %s: cannot set %s (bridge slave) with options: %s" % (kind, ifname, str(e)))

    def link_set_brport_with_info_slave_data_dry_run(self, ifname, kind, ifla_info_data, ifla_info_slave_data):
        self.log_info_ifname_dry_run(ifname, "netlink: ip link set dev %s: bridge port attributes" % ifname)
        self.logger.debug("attributes: %s" % ifla_info_slave_data)

    ############################################################################
    # ADDRESS
    ############################################################################

    def addr_add_dry_run(self, ifname, addr, broadcast=None, peer=None, scope=None, preferred_lifetime=None, metric=None, nodad=False):
        log_msg = ["netlink: ip addr add %s dev %s" % (addr, ifname)]

        if scope:
            log_msg.append("scope %s" % scope)

        if broadcast:
            log_msg.append("broadcast %s" % broadcast)

        if preferred_lifetime:
            log_msg.append("preferred_lft %s" % preferred_lifetime)

        if peer:
            log_msg.append("peer %s" % peer)

        if metric:
            log_msg.append("metric %s" % metric)

        self.log_info_ifname_dry_run(ifname, " ".join(log_msg))

    def addr_add(self, ifname, addr, broadcast=None, peer=None, scope=None, preferred_lifetime=None, metric=None, nodad=False):
        log_msg = ["%s: netlink: ip addr add %s dev %s" % (ifname, addr, ifname)]
        log_msg_displayed = False
        try:
            # We might need to check if metric/peer and other attribute are also
            # correctly cached.
            # We might also need to add a "force" attribute to skip the cache check
            if self.cache.addr_is_cached(ifname, addr):
                return

            if scope:
                log_msg.append("scope %s" % scope)
                scope_value = RT_SCOPES.get(scope, 0)
            else:
                scope_value = 0

            debug = RTM_NEWADDR in self.debug

            packet = Address(RTM_NEWADDR, debug, use_color=self.use_color)
            packet.flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK
            packet.family = self.IPNetwork_version_to_family.get(addr.version)

            packet.add_attribute(Address.IFA_ADDRESS, addr)
            packet.add_attribute(Address.IFA_LOCAL, addr)

            if nodad:
                log_msg.append("nodad")
                packet.add_attribute(Address.IFA_FLAGS, Address.IFA_F_NODAD)

            if broadcast:
                log_msg.append("broadcast %s" % broadcast)
                packet.add_attribute(Address.IFA_BROADCAST, ipnetwork.IPAddress(broadcast))

            if preferred_lifetime:
                # struct ifa_cacheinfo {
                #    __u32	ifa_prefered;
                #    __u32	ifa_valid;
                #    __u32	cstamp; /* created timestamp, hundredths of seconds */
                #    __u32	tstamp; /* updated timestamp, hundredths of seconds */
                # };
                log_msg.append("preferred_lft %s" % preferred_lifetime)

                if preferred_lifetime.lower() == "forever":
                    preferred_lifetime = INFINITY_LIFE_TIME

                packet.add_attribute(Address.IFA_CACHEINFO, (int(preferred_lifetime), INFINITY_LIFE_TIME, 0, 0))

            if metric:
                log_msg.append("metric %s" % metric)
                packet.add_attribute(Address.IFA_RT_PRIORITY, int(metric))

            if peer:
                log_msg.append("peer %s" % peer)

                # peer is already in nlmanager.ipnetwork.IPNetwork format
                packet.add_attribute(Address.IFA_ADDRESS, peer)
                packet_prefixlen = peer.prefixlen
            else:
                packet_prefixlen = addr.prefixlen

            self.logger.info(" ".join(log_msg))
            log_msg_displayed = True

            packet.body = struct.pack("=4Bi", packet.family, packet_prefixlen, 0, scope_value, self.cache.get_ifindex(ifname))
            packet.build_message(next(self.sequence), self.pid)
            return self.tx_nlpacket_get_response_with_error(packet)
        except Exception as e:
            if not log_msg_displayed:
                # just in case we get an exception before we reach the log.info
                # we should display it before we raise the exception
                log.info(" ".join(log_msg))
            raise NetlinkError(e, "cannot add address %s dev %s" % (addr, ifname), ifname=ifname)

    ###

    def addr_del_dry_run(self, ifname, addr):
        self.log_info_ifname_dry_run(ifname, "netlink: ip addr del %s dev %s" % (addr, ifname))

    def addr_del(self, ifname, addr):
        if not self.cache.addr_is_cached(ifname, addr):
            return
        self.logger.info("%s: netlink: ip addr del %s dev %s" % (ifname, addr, ifname))
        try:
            debug = RTM_DELADDR in self.debug

            packet = Address(RTM_DELADDR, debug, use_color=self.use_color)
            packet.flags = NLM_F_REQUEST | NLM_F_ACK
            packet.family = self.IPNetwork_version_to_family.get(addr.version)
            packet.body = struct.pack("=4Bi", packet.family, addr.prefixlen, 0, 0, self.cache.get_ifindex(ifname))

            packet.add_attribute(Address.IFA_LOCAL, addr)

            packet.build_message(next(self.sequence), self.pid)
            result = self.tx_nlpacket_get_response_with_error(packet)

            # RTM_DELADDR successful, we need to update our cache
            # to make sure we don't have any stale ip addr cached
            self.cache.force_remove_addr(ifname, addr)

            return result
        except Exception as e:
            raise NetlinkError(e, "cannot delete address %s dev %s" % (addr, ifname), ifname=ifname)

    def addr_flush(self, ifname):
        """
        From iproute2/ip/ipaddress.c
            /*
             * Note that the kernel may delete multiple addresses for one
             * delete request (e.g. if ipv4 address promotion is disabled).
             * Since a flush operation is really a series of delete requests
             * its possible that we may request an address delete that has
             * already been done by the kernel. Therefore, ignore EADDRNOTAVAIL
             * errors returned from a flush request
             */
        """
        for addr in self.cache.get_ip_addresses(ifname):
            try:
                self.addr_del(ifname, addr)
            except Exception:
                pass

    ########################
    # TEMPORARY DEBUG CODE #
    ########################

    def DEBUG_ON(self):
        self.debug_link(True)
        self.debug_address(True)
        nllistener.log.setLevel(DEBUG)
        nlpacket.log.setLevel(DEBUG)
        nlmanager.log.setLevel(DEBUG)

    def DEBUG_OFF(self):
        self.debug_address(False)
        self.debug_link(False)
        nllistener.log.setLevel(WARNING)
        nlpacket.log.setLevel(WARNING)
        nlmanager.log.setLevel(WARNING)
