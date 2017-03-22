#!/usr/bin/python
#
# Copyright 2016-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Julien Fortin, julien@cumulusnetworks.com
#

try:
    import sys
    import socket
    import logging

    from collections import OrderedDict

    import nlmanager.nlpacket

    from nlmanager.nlmanager import Link, Address, Route, NetlinkPacket

    from ifupdownaddons.cache import *
    from ifupdownaddons.utilsbase import utilsBase
    from ifupdownaddons.systemutils import systemUtils

    import ifupdown.ifupdownflags as ifupdownflags
except ImportError, e:
    raise ImportError('%s - required module not found' % str(e))


class Netlink(utilsBase):
    VXLAN_UDP_PORT = 4789

    def __init__(self, *args, **kargs):
        utilsBase.__init__(self, *args, **kargs)
        try:
            sys.path.insert(0, '/usr/share/ifupdown2/')
            from nlmanager.nlmanager import NetlinkManager
            # this should force the use of the local nlmanager
            self._nlmanager_api = NetlinkManager(log_level=logging.WARNING)

            # Override the nlmanager's mac_int_to_str function to print the MACs
            # like xx:xx:xx:xx:xx:xx instead of xxxx.xxxx.xxxx
            nlmanager.nlpacket.mac_int_to_str = self.mac_int_to_str

            self.ipcmd = None
            self.vxrd_running = None

            self.link_kind_handlers = {
                'vlan': self._link_dump_info_data_vlan,
                'vrf': self._link_dump_info_data_vrf,
                'vxlan': self._link_dump_info_data_vxlan
            }

        except Exception as e:
            self.logger.error('cannot initialize ifupdown2\'s '
                              'netlink manager: %s' % str(e))
            raise

    @staticmethod
    def IN_MULTICAST(a):
        """
            /include/uapi/linux/in.h

            #define IN_CLASSD(a)            ((((long int) (a)) & 0xf0000000) == 0xe0000000)
            #define IN_MULTICAST(a)         IN_CLASSD(a)
        """
        return (int(a) & 0xf0000000) == 0xe0000000

    @staticmethod
    def mac_int_to_str(mac_int):
        """
        Return an integer in MAC string format: xx:xx:xx:xx:xx:xx
        """
        return ':'.join(("%012x" % mac_int)[i:i + 2] for i in range(0, 12, 2))

    def get_iface_index(self, ifacename):
        if ifupdownflags.flags.DRYRUN: return
        try:
            return self._nlmanager_api.get_iface_index(ifacename)
        except Exception as e:
            raise Exception('%s: netlink: %s: cannot get ifindex: %s'
                            % (ifacename, ifacename, str(e)))

    def get_iface_name(self, ifindex):
        if ifupdownflags.flags.DRYRUN: return
        try:
            return self._nlmanager_api.get_iface_name(ifindex)
        except Exception as e:
            raise Exception('netlink: cannot get ifname for index %s: %s' % (ifindex, str(e)))

    def link_add_vlan(self, vlanrawdevice, ifacename, vlanid):
        self.logger.info('%s: netlink: ip link add link %s name %s type vlan id %s'
                         % (ifacename, vlanrawdevice, ifacename, vlanid))
        if ifupdownflags.flags.DRYRUN: return
        ifindex = self.get_iface_index(vlanrawdevice)
        try:
            return self._nlmanager_api.link_add_vlan(ifindex, ifacename, vlanid)
        except Exception as e:
            raise Exception('netlink: %s: cannot create vlan %s: %s'
                            % (vlanrawdevice, vlanid, str(e)))

    def link_add_macvlan(self, ifacename, macvlan_ifacename):
        self.logger.info('%s: netlink: ip link add link %s name %s type macvlan mode private'
                         % (ifacename, ifacename, macvlan_ifacename))
        if ifupdownflags.flags.DRYRUN: return
        ifindex = self.get_iface_index(ifacename)
        try:
            return self._nlmanager_api.link_add_macvlan(ifindex, macvlan_ifacename)
        except Exception as e:
            raise Exception('netlink: %s: cannot create macvlan %s: %s'
                            % (ifacename, macvlan_ifacename, str(e)))

    def link_set_updown(self, ifacename, state):
        self.logger.info('%s: netlink: ip link set dev %s %s'
                         % (ifacename, ifacename, state))
        if ifupdownflags.flags.DRYRUN: return
        try:
            return self._nlmanager_api.link_set_updown(ifacename, state)
        except Exception as e:
            raise Exception('netlink: cannot set link %s %s: %s'
                            % (ifacename, state, str(e)))

    def link_set_protodown(self, ifacename, state):
        self.logger.info('%s: netlink: set link %s protodown %s'
                         % (ifacename, ifacename, state))
        if ifupdownflags.flags.DRYRUN: return
        try:
            return self._nlmanager_api.link_set_protodown(ifacename, state)
        except Exception as e:
            raise Exception('netlink: cannot set link %s protodown %s: %s'
                            % (ifacename, state, str(e)))

    def link_add_bridge_vlan(self, ifacename, vlanid):
        self.logger.info('%s: netlink: bridge vlan add vid %s dev %s'
                         % (ifacename, vlanid, ifacename))
        if ifupdownflags.flags.DRYRUN: return
        ifindex = self.get_iface_index(ifacename)
        try:
            return self._nlmanager_api.link_add_bridge_vlan(ifindex, vlanid)
        except Exception as e:
            raise Exception('netlink: %s: cannot create bridge vlan %s: %s'
                            % (ifacename, vlanid, str(e)))

    def link_del_bridge_vlan(self, ifacename, vlanid):
        self.logger.info('%s: netlink: bridge vlan del vid %s dev %s'
                         % (ifacename, vlanid, ifacename))
        if ifupdownflags.flags.DRYRUN: return
        ifindex = self.get_iface_index(ifacename)
        try:
            return self._nlmanager_api.link_del_bridge_vlan(ifindex, vlanid)
        except Exception as e:
            raise Exception('netlink: %s: cannot remove bridge vlan %s: %s'
                            % (ifacename, vlanid, str(e)))

    def link_add_vxlan(self, ifacename, vxlanid, local=None, dstport=VXLAN_UDP_PORT,
                       group=None, learning='on', ageing=None):
        cmd = 'ip link add %s type vxlan id %s dstport %s' % (ifacename,
                                                              vxlanid,
                                                              dstport)
        cmd += ' local %s' % local if local else ''
        cmd += ' ageing %s' % ageing if ageing else ''
        cmd += ' remote %s' % group if group else ' noremote'
        cmd += ' nolearning' if learning == 'off' else ''
        self.logger.info('%s: netlink: %s' % (ifacename, cmd))
        if ifupdownflags.flags.DRYRUN: return
        try:
            return self._nlmanager_api.link_add_vxlan(ifacename,
                                                      vxlanid,
                                                      dstport=dstport,
                                                      local=local,
                                                      group=group,
                                                      learning=learning,
                                                      ageing=ageing)
        except Exception as e:
            raise Exception('netlink: %s: cannot create vxlan %s: %s'
                            % (ifacename, vxlanid, str(e)))

    @staticmethod
    def _link_dump_attr(link, ifla_attributes, dump):
        for obj in ifla_attributes:

            attr = obj['attr']

            if attr in link.attributes:
                func = obj['func'] if 'func' in obj else None
                dump[obj['name']] = link.attributes[attr].get_pretty_value(obj=func)

    @staticmethod
    def _link_dump_linkdata_attr(linkdata, ifla_linkdata_attr, dump):
        for obj in ifla_linkdata_attr:

            attr = obj['attr']

            if attr in linkdata:
                func = obj['func'] if 'func' in obj else None

                if func:
                    value = func(linkdata[attr])
                else:
                    value = linkdata[attr]

                if value or obj['accept_none']:
                    dump[obj['name']] = value

    ifla_attributes = [
        {
            'attr': Link.IFLA_LINK,
            'name': 'link',
            'func': lambda x: netlink.get_iface_name(x)
        },
        {
            'attr': Link.IFLA_IFNAME,
            'name': 'ifname',
            'func': str,
        },
        {
            'attr': Link.IFLA_MTU,
            'name': 'mtu',
            'func': str
        },
        {
            'attr': Link.IFLA_OPERSTATE,
            'name': 'state',
            'func': lambda x: '0%x' % int(x) if x > len(Link.oper_to_string) else Link.oper_to_string[x][8:]
        }
    ]

    ifla_address = {'attr': Link.IFLA_ADDRESS, 'name': 'hwaddress', 'func': str}

    ifla_vxlan_attributes = [
        {
            'attr': Link.IFLA_VXLAN_LOCAL,
            'name': 'local',
            'func': str,
            'accept_none': True
        },
        {
            'attr': Link.IFLA_VXLAN_LOCAL6,
            'name': 'local',
            'func': str,
            'accept_none': True
        },
        {
            'attr': Link.IFLA_VXLAN_GROUP,
            'name': 'svcnode',
            'func': lambda x: x if not Netlink.IN_MULTICAST(x) else None,
            'accept_none': False
        },
        {
            'attr': Link.IFLA_VXLAN_GROUP6,
            'name': 'svcnode',
            'func': lambda x: x if not Netlink.IN_MULTICAST(x) else None,
            'accept_none': False
        },
        {
            'attr': Link.IFLA_VXLAN_LEARNING,
            'name': 'learning',
            'func': lambda x: 'on' if x else 'off',
            'accept_none': True
        }
    ]

    def _link_dump_info_data_vlan(self, ifname, linkdata):
        return {'vlanid': str(linkdata[Link.IFLA_VLAN_ID])}

    def _link_dump_info_data_vrf(self, ifname, linkdata):
        vrf_info = {'table': str(linkdata[Link.IFLA_VRF_TABLE])}

        # to remove later when moved to a true netlink cache
        linkCache.vrfs[ifname] = vrf_info
        return vrf_info

    def _link_dump_info_data_vxlan(self, ifname, linkdata):
        vattrs = {
            'learning': 'on',
            'remote': [],
            'svcnode': None,
            'vxlanid': str(linkdata[Link.IFLA_VXLAN_ID]),
            'ageing': str(linkdata[Link.IFLA_VXLAN_AGEING])
        }

        self._link_dump_linkdata_attr(linkdata, self.ifla_vxlan_attributes, vattrs)

        # if none, vxrd is undefined and needs to be set to True/False
        if self.vxrd_running == None:
            self.vxrd_running = systemUtils.is_service_running(None, '/var/run/vxrd.pid')

        if self.vxrd_running:
            if not self.ipcmd:
                from ifupdownaddons.iproute2 import iproute2
                self.ipcmd = iproute2()
            peers = self.ipcmd.get_vxlan_peers(ifname, vattrs['svcnode'])
            if peers:
                vattrs['remote'] = peers

        return vattrs

    def _link_dump_linkinfo(self, link, dump):
        linkinfo = link.attributes[Link.IFLA_LINKINFO].get_pretty_value(dict)

        if linkinfo:
            kind = linkinfo[Link.IFLA_INFO_KIND]
            dump['kind'] = kind

            if link.IFLA_INFO_DATA in linkinfo:
                linkdata = linkinfo[Link.IFLA_INFO_DATA]

                if linkdata:
                    if kind in self.link_kind_handlers:
                        dump['linkinfo'] = self.link_kind_handlers[kind](dump['ifname'], linkdata)

    def link_dump(self, ifname=None):
        if ifname:
            self.logger.info('netlink: ip link show dev %s' % ifname)
        else:
            self.logger.info('netlink: ip link show')

        if ifupdownflags.flags.DRYRUN: return {}

        self.vxrd_running = None
        links = dict()

        try:
            links_dump = self._nlmanager_api.link_dump(ifname)
        except Exception as e:
            raise Exception('netlink: link dump failed: %s' % str(e))

        for link in links_dump:
            try:
                dump = dict()

                flags = []
                for flag, string in Link.flag_to_string.items():
                    if link.flags & flag:
                        flags.append(string[4:])

                dump['flags'] = flags
                dump['iiflags'] = 'UP' if 'UP' in flags else 'DOWN'
                dump['ifindex'] = str(link.ifindex)

                if link.device_type == Link.ARPHRD_ETHER:
                    self._link_dump_attr(link, [self.ifla_address], dump)

                self._link_dump_attr(link, self.ifla_attributes, dump)

                if Link.IFLA_LINKINFO in link.attributes:
                    self._link_dump_linkinfo(link, dump)

                links[dump['ifname']] = dump
            except Exception as e:
                self.logger.warning('netlink: ip link show: %s' % str(e))
        return links

    def _addr_dump_extract_ifname(self, addr_packet):
        addr_ifname_attr = addr_packet.attributes.get(Address.IFA_LABEL)

        if addr_ifname_attr:
            return addr_ifname_attr.get_pretty_value(str)
        else:
            return self.get_iface_name(addr_packet.ifindex)

    @staticmethod
    def _addr_filter(addr_ifname, addr, scope):
        default_addrs = ['127.0.0.1/8', '::1/128', '0.0.0.0']

        if addr_ifname == 'lo' and addr in default_addrs:
            return True

        if scope == Route.RT_SCOPE_LINK:
            return True

        return False

    def _addr_dump_entry(self, ifaces, addr_packet, addr_ifname, ifa_attr):
        attribute = addr_packet.attributes.get(ifa_attr)

        if attribute:
            address = attribute.get_pretty_value(str)

            if hasattr(addr_packet, 'prefixlen'):
                address = '%s/%d' % (address, addr_packet.prefixlen)

            if self._addr_filter(addr_ifname, address, addr_packet.scope):
                return

            addr_family = NetlinkPacket.af_family_to_string.get(addr_packet.family)
            if not addr_family:
                return

            addr_scope = Route.rtnl_rtscope_tab.get(addr_packet.scope)
            if not addr_scope:
                return

            ifaces[addr_ifname]['addrs'][address] = {
                'type': addr_family,
                'scope': addr_scope
            }

    ifa_attributes = [
        Address.IFA_ADDRESS,
        Address.IFA_LOCAL,
        Address.IFA_BROADCAST,
        Address.IFA_ANYCAST,
        Address.IFA_MULTICAST
    ]

    def addr_dump(self, ifname=None):
        if ifname:
            self.logger.info('netlink: ip addr show dev %s' % ifname)
        else:
            self.logger.info('netlink: ip addr show')

        ifaces = dict()
        addr_dump = self._nlmanager_api.addr_dump()

        for addr_packet in addr_dump:
            addr_ifname = self._addr_dump_extract_ifname(addr_packet)

            if addr_packet.family not in [socket.AF_INET, socket.AF_INET6]:
                continue

            if ifname and ifname != addr_ifname:
                continue

            if addr_ifname not in ifaces:
                ifaces[addr_ifname] = {'addrs': OrderedDict({})}

            for ifa_attr in self.ifa_attributes:
                self._addr_dump_entry(ifaces, addr_packet, addr_ifname, ifa_attr)

        if ifname:
            return {ifname: ifaces.get(ifname, {})}

        return ifaces


netlink = Netlink()
