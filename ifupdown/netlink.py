#!/usr/bin/python
#
# Copyright 2016 Cumulus Networks, Inc. All rights reserved.
# Author: Julien Fortin, julien@cumulusnetworks.com
#

try:
    from ifupdownaddons.utilsbase import utilsBase
    from nlmanager.nlmanager import NetlinkManager
    import ifupdown.ifupdownflags as ifupdownflags
except ImportError, e:
    raise ImportError(str(e) + "- required module not found")


class Netlink(utilsBase):
    VXLAN_UDP_PORT = 4789

    def __init__(self, *args, **kargs):
        utilsBase.__init__(self, *args, **kargs)
        self._nlmanager_api = NetlinkManager()

    def get_iface_index(self, ifacename):
        if ifupdownflags.flags.DRYRUN: return
        try:
            return self._nlmanager_api.get_iface_index(ifacename)
        except Exception as e:
            raise Exception('%s: netlink: %s: cannot get ifindex: %s'
                            % (ifacename, ifacename, str(e)))

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
                       group=None, learning='on', ageing=None, physdev=None):
        cmd = 'ip link add %s type vxlan id %s dstport %s' % (ifacename,
                                                              vxlanid,
                                                              dstport)


        cmd += ' local %s' % local if local else ''
        cmd += ' ageing %s' % ageing if ageing else ''
        cmd += ' remote %s' % group if group else ' noremote'
        cmd += ' nolearning' if learning == 'off' else ''
        cmd += ' dev %s' % physdev if physdev else ''
        self.logger.info('%s: netlink: %s' % (ifacename, cmd))
        if ifupdownflags.flags.DRYRUN: return
        try:
            if physdev:
                physdev = self.get_iface_index (physdev)
            return self._nlmanager_api.link_add_vxlan(ifacename,
                                                      vxlanid,
                                                      dstport=dstport,
                                                      local=local,
                                                      group=group,
                                                      learning=learning,
                                                      ageing=ageing,
                                                      physdev=physdev)
        except Exception as e:
            raise Exception('netlink: %s: cannot create vxlan %s: %s'
                            % (ifacename, vxlanid, str(e)))

netlink = Netlink()
