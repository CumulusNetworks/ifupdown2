#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

try:
    from ifupdown2.lib.addon import Addon

    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.netlink import netlink

    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    from lib.addon import Addon

    import ifupdown.ifupdownflags as ifupdownflags

    from ifupdown.iface import *
    from ifupdown.netlink import netlink

    from nlmanager.nlmanager import Link

    from ifupdownaddons.modulebase import moduleBase



class vlan(Addon, moduleBase):
    """  ifupdown2 addon module to configure vlans """

    _modinfo = {'mhelp' : 'vlan module configures vlan interfaces.' +
                        'This module understands vlan interfaces with dot ' +
                        'notations. eg swp1.100. Vlan interfaces with any ' +
                        'other names need to have raw device and vlan id ' +
                        'attributes',
                'attrs' : {
                        'vlan-raw-device' :
                            {'help' : 'vlan raw device',
                             'validvals': ['<interface>']},
                        'vlan-id' :
                            {'help' : 'vlan id',
                             'validrange' : ['0', '4096']},
                        'vlan-protocol' :
                            {'help' : 'vlan protocol',
                             'default' : '802.1q',
                             'validvals': ['802.1q', '802.1ad'],
                             'example' : ['vlan-protocol 802.1q']},
               }}


    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)

    def _is_vlan_device(self, ifaceobj):
        vlan_raw_device = ifaceobj.get_attr_value_first('vlan-raw-device')
        if vlan_raw_device:
            return True
        elif '.' in ifaceobj.name:
            return True
        return False

    def _is_vlan_by_name(self, ifacename):
        return '.' in ifacename

    def _get_vlan_raw_device_from_ifacename(self, ifacename):
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

    def get_dependent_ifacenames(self, ifaceobj, ifaceobjs_all=None):
        if not self._is_vlan_device(ifaceobj):
            return None
        ifaceobj.link_kind |= ifaceLinkKind.VLAN
        return [self._get_vlan_raw_device(ifaceobj)]

    def _bridge_vid_add_del(self, ifaceobj, bridgename, vlanid,
                            add=True):
        """ If the lower device is a vlan aware bridge, add/del the vlanid
        to the bridge """
        if self.cache.bridge_is_vlan_aware(bridgename):
           if add:
               netlink.link_add_bridge_vlan(bridgename, vlanid)
           else:
               netlink.link_del_bridge_vlan(bridgename, vlanid)

    def _bridge_vid_check(self, ifaceobj, ifaceobjcurr, bridgename, vlanid):
        """ If the lower device is a vlan aware bridge, check if the vlanid
        is configured on the bridge """
        if not self.cache.bridge_is_vlan_aware(bridgename):
            return
        _, vids = self.cache.get_pvid_and_vids(bridgename)
        if not vids or vlanid not in vids:
            ifaceobjcurr.status = ifaceStatus.ERROR
            ifaceobjcurr.status_str = 'bridge vid error'

    def _up(self, ifaceobj):
        vlanid = self._get_vlan_id(ifaceobj)
        if vlanid == -1:
            raise Exception('could not determine vlanid')
        vlanrawdevice = self._get_vlan_raw_device(ifaceobj)
        if not vlanrawdevice:
            raise Exception('could not determine vlan raw device')

        ifname = ifaceobj.name

        if ifupdownflags.flags.PERFMODE:
            cached_vlan_ifla_info_data = {}
        else:
            cached_vlan_ifla_info_data = self.cache.get_link_info_data(ifname)

        vlan_protocol           = ifaceobj.get_attr_value_first('vlan-protocol')
        cached_vlan_protocol    = cached_vlan_ifla_info_data.get(Link.IFLA_VLAN_PROTOCOL)

        if not vlan_protocol:
            vlan_protocol = self.get_attr_default_value('vlan-protocol')

        if cached_vlan_protocol and vlan_protocol.lower() != cached_vlan_protocol.lower():
            raise Exception('%s: cannot change vlan-protocol to %s: operation not supported. '
                            'Please delete the device with \'ifdown %s\' and recreate it to '
                            'apply the change.'
                            % (ifaceobj.name, vlan_protocol, ifaceobj.name))

        if not ifupdownflags.flags.PERFMODE:

            vlan_exists = self.cache.link_exists(ifaceobj.name)

            if vlan_exists:
                user_vlan_raw_device = ifaceobj.get_attr_value_first('vlan-raw-device')
                cached_vlan_raw_device = self.cache.get_lower_device_ifname(ifname)

                if cached_vlan_raw_device and user_vlan_raw_device and cached_vlan_raw_device != user_vlan_raw_device:
                    raise Exception('%s: cannot change vlan-raw-device from %s to %s: operation not supported. '
                                    'Please delete the device with \'ifdown %s\' and recreate it to apply the change.'
                                    % (ifaceobj.name, cached_vlan_raw_device, user_vlan_raw_device, ifaceobj.name))

            if not self.cache.link_exists(vlanrawdevice):
                if ifupdownflags.flags.DRYRUN:
                    return
                else:
                    raise Exception('rawdevice %s not present' %vlanrawdevice)
            if vlan_exists:
                self._bridge_vid_add_del(ifaceobj, vlanrawdevice, vlanid)
                return

        netlink.link_add_vlan(vlanrawdevice, ifaceobj.name, vlanid, vlan_protocol)
        self._bridge_vid_add_del(ifaceobj, vlanrawdevice, vlanid)

    def _down(self, ifaceobj):
        vlanid = self._get_vlan_id(ifaceobj)
        if vlanid == -1:
            raise Exception('could not determine vlanid')
        vlanrawdevice = self._get_vlan_raw_device(ifaceobj)
        if not vlanrawdevice:
            raise Exception('could not determine vlan raw device')
        if (not ifupdownflags.flags.PERFMODE and
            not self.cache.link_exists(ifaceobj.name)):
           return
        try:
            self.netlink.link_del(ifaceobj.name)
            self._bridge_vid_add_del(ifaceobj, vlanrawdevice, vlanid, add=False)
        except Exception, e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if not self.cache.link_exists(ifaceobj.name):
           return
        if not '.' in ifaceobj.name:
            # if vlan name is not in the dot format, check its running state

            ifname = ifaceobj.name
            cached_vlan_raw_device = self.cache.get_lower_device_ifname(ifname)

            #
            # vlan-raw-device
            #
            ifaceobjcurr.update_config_with_status(
                'vlan-raw-device',
                cached_vlan_raw_device,
                cached_vlan_raw_device != ifaceobj.get_attr_value_first('vlan-raw-device')
            )

            cached_vlan_info_data = self.cache.get_link_info_data(ifname)

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
            # vlan-protocol
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

            self._bridge_vid_check(ifaceobj, ifaceobjcurr, cached_vlan_raw_device, cached_vlan_id)

    def _query_running(self, ifaceobjrunning):
        ifname = ifaceobjrunning.name

        if not self.cache.link_exists(ifname):
            return

        if not self.cache.get_link_kind(ifname) == 'vlan':
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

    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
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
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
