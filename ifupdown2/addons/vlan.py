#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import subprocess
import re

try:
    from ifupdown2.lib.addon import Addon, AddonException
    from ifupdown2.lib.iproute2 import IPRoute2
    from ifupdown2.ifupdown.iface import ifaceType, ifaceLinkKind, ifaceStatus
    from ifupdown2.ifupdown.statemanager import statemanager_api as statemanager
    from ifupdown2.nlmanager.nlmanager import Link
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.lib.exceptions import RetryCMD
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownconfig as ifupdownconfig
except ImportError:
    from lib.addon import Addon, AddonException
    from lib.iproute2 import IPRoute2
    from ifupdown.iface import ifaceType, ifaceLinkKind, ifaceStatus
    from ifupdown.statemanager import statemanager_api as statemanager
    from nlmanager.nlmanager import Link
    from ifupdownaddons.modulebase import moduleBase
    from ifupdown.utils import utils
    from lib.exceptions import RetryCMD
    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownconfig as ifupdownconfig


class vlan(Addon, moduleBase):
    """  ifupdown2 addon module to configure vlans """

    _modinfo = {
        "mhelp": "vlan module configures vlan interfaces. "
                 "This module understands vlan interfaces with dot "
                 "notations. eg swp1.100. Vlan interfaces with any "
                 "other names need to have raw device and vlan id attributes",
        "attrs": {
            "vlan-raw-device": {
                "help": "vlan raw device",
                "validvals": ["<interface>"]
            },
            "vlan-id": {
                "help": "vlan id",
                "validrange": ["0", "4096"]
            },
            "vlan-protocol": {
                "help": "vlan protocol",
                "default": "802.1q",
                "validvals": ["802.1q", "802.1ad"],
                "example": ["vlan-protocol 802.1q"]
            },
            "vlan-bridge-binding": {
                "help": "The link state of the vlan device may need to track only the state of the subset of ports "
                        "that are also members of the corresponding vlan, rather than that of all ports. Add a flag to "
                        "specify a vlan bridge binding mode, by which the link state is no longer automatically "
                        "transferred from the lower device, but is instead determined by the bridge ports that are "
                        "members of the vlan.",
                "default": "off",
                "validvals": ["on", "off"],
                "example": ["vlan-bridge-binding on"]
            }
        }
    }

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)
        self.iproute2 = IPRoute2()

    def _is_vlan_device(self, ifaceobj):
        vlan_raw_device = ifaceobj.get_attr_value_first('vlan-raw-device')
        if vlan_raw_device:
            return True
        elif '.' in ifaceobj.name:
            try:
                if self._get_vlan_id(ifaceobj) != -1:
                    return True
            except Exception:
                pass
        return False

    @staticmethod
    def _is_vlan_by_name(ifacename):
        return '.' in ifacename

    @staticmethod
    def _get_vlan_raw_device_from_ifacename(ifacename):
        """ Returns vlan raw device from ifname
        Example:
            Returns eth0 for ifname eth0.100
            Returns eth0.100 for ifname eth0.100.200
            Returns None if vlan raw device name cannot
            be determined
        """
        vlist = ifacename.split('.', 2)
        if len(vlist) == 2:
            return vlist[0]
        elif len(vlist) == 3:
            return vlist[0] + "." + vlist[1]
        return None

    def _get_vlan_raw_device(self, ifaceobj):
        vlan_raw_device = ifaceobj.get_attr_value_first('vlan-raw-device')
        if vlan_raw_device:
            return vlan_raw_device
        return self._get_vlan_raw_device_from_ifacename(ifaceobj.name)

    def get_dependent_ifacenames(self, ifaceobj, ifaceobjs_all=None, old_ifaceobjs=False):
        if not self._is_vlan_device(ifaceobj):
            return None
        ifaceobj.link_kind |= ifaceLinkKind.VLAN
        return [self._get_vlan_raw_device(ifaceobj)]

    def _bridge_vid_add_del(self, bridgename, vlanid, add=True):
        """ If the lower device is a vlan aware bridge, add/del the vlanid
        to the bridge """
        if self.cache.bridge_is_vlan_aware(bridgename):
            if add:
                self.netlink.link_add_bridge_vlan(bridgename, vlanid)
            else:
                self.netlink.link_del_bridge_vlan(bridgename, vlanid)

    def _bridge_vid_check(self, ifaceobjcurr, bridgename, vlanid):
        """ If the lower device is a vlan aware bridge, check if the vlanid
        is configured on the bridge """
        if not self.cache.bridge_is_vlan_aware(bridgename):
            return
        _, vids = self.cache.get_pvid_and_vids(bridgename)
        if not vids or vlanid not in vids:
            ifaceobjcurr.status = ifaceStatus.ERROR
            ifaceobjcurr.status_str = 'bridge vid error'

    def _is_peerlink(self, ifaceobj):
        return ifaceobj.get_attr_value_first('clagd-backup-ip')

    def vxlan_hopping_filter_bypass(self, ifaceobj, vlanrawdevice, vid, ifaceobj_getfunc):
        vlan_is_peerlink = self._is_peerlink(ifaceobj)
        old_ifaceobjs = statemanager.get_ifaceobjs(ifaceobj.name) or []
        vlan_was_peerlink = any(map(self._is_peerlink, old_ifaceobjs))

        if not vlan_is_peerlink and not vlan_was_peerlink:
            return

        bridge_ifaceobjs = ifaceobj_getfunc(vlanrawdevice)
        if any(map(lambda b: b.link_kind == ifaceLinkKind.BRIDGE, bridge_ifaceobjs)):
            bridge_ports = [ port for b in bridge_ifaceobjs for ports in (self._get_bridge_port_list(b) or []) for port in (ifaceobj_getfunc(ports) or []) ]
            bridge_is_vxlan = any(map(lambda p: p.link_kind == ifaceLinkKind.VXLAN, bridge_ports))
        else:
            bridge_is_vxlan = False

        vxlan_port = self.netlink.VXLAN_UDP_PORT
        if bridge_is_vxlan:
            vxlan_dev = next(p for p in bridge_ports if p.link_kind == ifaceLinkKind.VXLAN)
            vxlan_port_str = vxlan_dev.get_attr_value_first("vxlan-port")
            if vxlan_port_str:
                vxlan_port = vxlan_port_str

        if vlan_is_peerlink:
            desired_filters = [(vxlan_port, vid, 'pass')]
        else:
            desired_filters = []
        filters_to_add, filters_to_delete = self.iproute2.check_tc_filters(bridge_ifaceobjs[0].name, desired_filters)

        try:
            self.iproute2.batch_start()

            for (vxlan_port, vlan_id, _) in filters_to_delete:
                if vlan_id == vid:
                    self.iproute2.del_vxlan_hopping_tc_filter_bypass(bridge_ifaceobjs[0].name, vlan_id, vxlan_port)

            for (vxlan_port, vid, _) in filters_to_add:
                self.iproute2.add_vxlan_hopping_tc_filter_bypass(bridge_ifaceobjs[0].name, vid, vxlan_port)

            self.iproute2.batch_commit()
        except Exception as e:
            if "Unterminated quoted string" not in str(e):
                raise
            self.logger.debug(f"tc quote failure: {str(e)}")

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        vlanid = self._get_vlan_id(ifaceobj)
        if vlanid == -1:
            raise AddonException('could not determine vlanid')
        vlanrawdevice = self._get_vlan_raw_device(ifaceobj)
        if not vlanrawdevice:
            raise AddonException('could not determine vlan raw device')

        ifname = ifaceobj.name

        if ifupdownflags.flags.PERFMODE:
            cached_vlan_ifla_info_data = {}
        else:
            cached_vlan_ifla_info_data = self.cache.get_link_info_data(ifname)

        vlan_bridge_binding = ifaceobj.get_attr_value_first("vlan-bridge-binding")

        if not vlan_bridge_binding:
            vlan_bridge_binding = policymanager.policymanager_api.get_attr_default(
                self.__class__.__name__,
                "vlan-bridge-binding"
            ) or self.get_attr_default_value("vlan-bridge-binding")

        bool_vlan_bridge_binding = utils.get_boolean_from_string(vlan_bridge_binding)

        vlan_protocol = ifaceobj.get_attr_value_first('vlan-protocol')
        cached_vlan_protocol = cached_vlan_ifla_info_data.get(Link.IFLA_VLAN_PROTOCOL)

        if not vlan_protocol:
            vlan_protocol = self.get_attr_default_value('vlan-protocol')

        if cached_vlan_protocol and vlan_protocol.lower() != cached_vlan_protocol.lower():
            raise AddonException('%s: cannot change vlan-protocol to %s: operation not supported. '
                            'Please delete the device with \'ifdown %s\' and recreate it to '
                            'apply the change.'
                            % (ifaceobj.name, vlan_protocol, ifaceobj.name))

        cached_vlan_id = cached_vlan_ifla_info_data.get(Link.IFLA_VLAN_ID)
        if cached_vlan_id is not None and vlanid != cached_vlan_id:
            raise AddonException('%s: cannot change vlan-id to %s: operation not supported. '
                            'Please delete the device with \'ifdown %s\' and recreate it to '
                            'apply the change.'
                            % (ifaceobj.name, vlanid, ifaceobj.name))

        if not ifupdownflags.flags.PERFMODE:

            vlan_exists = self.cache.link_exists(ifaceobj.name)

            if vlan_exists:
                user_vlan_raw_device = ifaceobj.get_attr_value_first('vlan-raw-device')
                cached_vlan_raw_device = self.cache.get_lower_device_ifname(ifname)

                if cached_vlan_raw_device and user_vlan_raw_device and cached_vlan_raw_device != user_vlan_raw_device:
                    raise AddonException('%s: cannot change vlan-raw-device from %s to %s: operation not supported. '
                                    'Please delete the device with \'ifdown %s\' and recreate it to apply the change.'
                                    % (ifaceobj.name, cached_vlan_raw_device, user_vlan_raw_device, ifaceobj.name))

            if not self.cache.link_exists(vlanrawdevice):
                if ifupdownflags.flags.DRYRUN:
                    return
                else:
                    raise AddonException('rawdevice %s not present' % vlanrawdevice)
            if vlan_exists:

                # vlan-bridge-binding has changed we need to update it
                if vlan_bridge_binding is not None and bool_vlan_bridge_binding != cached_vlan_ifla_info_data.get(Link.IFLA_VLAN_FLAGS, {}).get(Link.VLAN_FLAG_BRIDGE_BINDING, False):
                    self.logger.info("%s: mismatch detected: resetting: vlan-bridge-binding %s" % (ifname, vlan_bridge_binding))
                    self.netlink.link_add_vlan(vlanrawdevice, ifaceobj.name, vlanid, vlan_protocol, bool_vlan_bridge_binding)

                self._bridge_vid_add_del(vlanrawdevice, vlanid)
                self.vxlan_hopping_filter_bypass(ifaceobj, vlanrawdevice, vlanid, ifaceobj_getfunc)
                return

        try:
            self.netlink.link_add_vlan(vlanrawdevice, ifaceobj.name, vlanid, vlan_protocol, bool_vlan_bridge_binding if vlan_bridge_binding is not None else None)
            self.vxlan_hopping_filter_bypass(ifaceobj, vlanrawdevice, vlanid, ifaceobj_getfunc)
        except RetryCMD as e:
            self.logger.info("%s: attempting to create vlan without bridge_binding (capability not detected on the system)" % ifaceobj.name)
            utils.exec_command(e.cmd)
        self._bridge_vid_add_del(vlanrawdevice, vlanid)

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        vlanid = self._get_vlan_id(ifaceobj)
        if vlanid == -1:
            raise AddonException('could not determine vlanid')
        vlanrawdevice = self._get_vlan_raw_device(ifaceobj)
        if not vlanrawdevice:
            raise AddonException('could not determine vlan raw device')
        if not ifupdownflags.flags.PERFMODE and not self.cache.link_exists(ifaceobj.name):
            return
        try:
            self.netlink.link_del(ifaceobj.name)
            self._bridge_vid_add_del(vlanrawdevice, vlanid, add=False)
        except Exception as e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        if not self.cache.link_exists(ifaceobj.name):
            return

        ifname = ifaceobj.name
        cached_vlan_info_data = self.cache.get_link_info_data(ifname)

        if '.' not in ifaceobj.name:
            # if vlan name is not in the dot format, check its running state

            cached_vlan_raw_device = self.cache.get_lower_device_ifname(ifname)

            #
            # vlan-raw-device
            #
            ifaceobjcurr.update_config_with_status(
                'vlan-raw-device',
                cached_vlan_raw_device,
                cached_vlan_raw_device != ifaceobj.get_attr_value_first('vlan-raw-device')
            )

            #
            # vlan-id
            #
            vlanid_config = ifaceobj.get_attr_value_first('vlan-id')
            if not vlanid_config:
                vlanid_config = str(self._get_vlan_id(ifaceobj))

            cached_vlan_id = cached_vlan_info_data.get(Link.IFLA_VLAN_ID)
            cached_vlan_id_str = str(cached_vlan_id)
            ifaceobjcurr.update_config_with_status('vlan-id', cached_vlan_id_str, vlanid_config != cached_vlan_id_str)

        #
        # vlan-protocol (dot or not dot format)
        #
        protocol_config = ifaceobj.get_attr_value_first('vlan-protocol')
        if protocol_config:

            cached_vlan_protocol = cached_vlan_info_data.get(Link.IFLA_VLAN_PROTOCOL)

            if protocol_config.upper() != cached_vlan_protocol.upper():
                ifaceobjcurr.update_config_with_status(
                    'vlan-protocol',
                    cached_vlan_protocol,
                    1
                )
            else:
                ifaceobjcurr.update_config_with_status(
                    'vlan-protocol',
                    protocol_config,
                    0
                 )

        if '.' not in ifaceobj.name:
            #
            # vlan-bridge-binding
            #
            vlan_bridge_binding = ifaceobj.get_attr_value_first("vlan-bridge-binding")
            if vlan_bridge_binding:
                cached_vlan_bridge_binding = cached_vlan_info_data.get(Link.IFLA_VLAN_FLAGS, {}).get(
                    Link.VLAN_FLAG_BRIDGE_BINDING, False)

                ifaceobjcurr.update_config_with_status(
                    "vlan-bridge-binding",
                    "on" if cached_vlan_bridge_binding else "off",
                    cached_vlan_bridge_binding != utils.get_boolean_from_string(vlan_bridge_binding)
                )

            self._bridge_vid_check(ifaceobjcurr, cached_vlan_raw_device, cached_vlan_id)

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        ifname = ifaceobjrunning.name

        if not self.cache.link_exists(ifname):
            return

        if self.cache.get_link_kind(ifname) != 'vlan':
            return

        # If vlan name is not in the dot format, get the
        # vlan dev and vlan id
        if '.' in ifname:
            return

        cached_vlan_info_data = self.cache.get_link_info_data(ifname)

        for attr_name, nl_attr in (
                ('vlan-id', Link.IFLA_VLAN_ID),
                ('vlan-protocol', Link.IFLA_VLAN_PROTOCOL)
        ):
            ifaceobjrunning.update_config(attr_name, str(cached_vlan_info_data.get(nl_attr)))

        ifaceobjrunning.update_config('vlan-raw-device', self.cache.get_lower_device_ifname(ifname))

        if cached_vlan_info_data.get(Link.IFLA_VLAN_FLAGS, {}).get(Link.VLAN_FLAG_BRIDGE_BINDING, False):
            ifaceobjrunning.update_config("vlan-bridge-binding", "on")

    _run_ops = {
        "pre-up": _up,
        "post-down": _down,
        "query-checkcurr": _query_check,
        "query-running": _query_running
    }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return list(self._run_ops.keys())

    def run(self, ifaceobj, operation, query_ifaceobj=None, ifaceobj_getfunc=None):
        """ run vlan configuration on the interface object passed as argument

        Args:
            **ifaceobj** (object): iface object

            **operation** (str): any of 'pre-up', 'post-down', 'query-checkcurr',
                                 'query-running'
        Kwargs:
            **query_ifaceobj** (object): query check ifaceobject. This is only
                valid when op is 'query-checkcurr'. It is an object same as
                ifaceobj, but contains running attribute values and its config
                status. The modules can use it to return queried running state
                of interfaces. status is success if the running state is same
                as user required state in ifaceobj. error otherwise.
        """
        if ifaceobj.type == ifaceType.BRIDGE_VLAN:
            return
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        if (operation != 'query-running' and
                not self._is_vlan_device(ifaceobj)):
            return
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
        else:
            op_handler(self, ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
