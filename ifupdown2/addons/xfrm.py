#!/usr/bin/python3
#
# Copyright 2019 Voleatech GmbH. All rights reserved.
# Author: Sven Auhagen, sven.auhagen@voleatech.de
#

import os
import glob
import socket

try:
    from ifupdown2.lib.addon import Addon

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.nlmanager.nlpacket import Link

    from ifupdown2.ifupdownaddons.modulebase import moduleBase

    import ifupdown2.ifupdown.statemanager as statemanager
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.ifupdownconfig as ifupdownconfig
except (ImportError, ModuleNotFoundError):
    from lib.addon import Addon

    from ifupdown.iface import *
    from ifupdown.utils import utils

    from nlmanager.nlpacket import Link

    from ifupdownaddons.modulebase import moduleBase

    import ifupdown.statemanager as statemanager
    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.ifupdownconfig as ifupdownconfig


class xfrm(Addon, moduleBase):
    """
    ifupdown2 addon module to create a xfrm interface
    """
    _modinfo = {
        'mhelp': 'xfrm module creates a xfrm interface for',
        'attrs': {
            'xfrm-id': {
                'help': 'xfrm id',
                'validrange': ['1', '65535'],
                'example': ['xfrm-id 1']
            },
            'xfrm-physdev': {
                'help': 'xfrm physical device',
                'example': ['xfrm-physdev lo']
            },
        },
    }

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None, old_ifaceobjs=False):

        parent_int = self._get_parent_ifacename(ifaceobj)
        if parent_int:
            return [parent_int]

        return None

    def _get_parent_ifacename(self, ifaceobj):
        if ifaceobj.get_attr_value('xfrm-physdev'):
            av_attr = ifaceobj.get_attr_value_first('xfrm-physdev')
            return av_attr

        return None

    def _get_xfrmid(self, ifaceobj):
        if ifaceobj.get_attr_value('xfrm-id'):
            av_attr = ifaceobj.get_attr_value_first('xfrm-id')
            return av_attr

        return None

    def _get_xfrm_name(self, ifaceobj):
        return ifaceobj.name

    @staticmethod
    def _is_my_interface(ifaceobj):
        return ifaceobj.get_attr_value_first('xfrm-id')

    def _up(self, ifaceobj):
        """
        Up the XFRM Interface
        """
        # Create a xfrm device on this device and set the virtual
        # router mac and ip on it
        xfrm_ifacename = self._get_xfrm_name(ifaceobj)
        physdev = self._get_parent_ifacename(ifaceobj)
        xfrmid = self._get_xfrmid(ifaceobj)
        if not self.cache.link_exists(xfrm_ifacename):
            self.iproute2.link_add_xfrm(physdev, xfrm_ifacename, xfrmid)
        else:
            xfrmid_cur = str(
                self.cache.get_link_info_data_attribute(
                    xfrm_ifacename,
                    Link.IFLA_XFRM_IF_ID,
                    0
                )
            )
            physdev_cur = self.cache.get_ifname(
                self.cache.get_link_info_data_attribute(
                    xfrm_ifacename,
                    Link.IFLA_XFRM_LINK,
                    0
                )
            )

            # Check XFRM Values
            if xfrmid != xfrmid_cur or physdev != physdev_cur:
                # Delete and recreate
                self.netlink.link_del(xfrm_ifacename)
                self.iproute2.link_add_xfrm(physdev, xfrm_ifacename, xfrmid)

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        """
        Down the XFRM Interface
        """
        try:
            xfrm_ifacename = self._get_xfrm_name(ifaceobj)
            self.netlink.link_del(xfrm_ifacename)
        except Exception as e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if not self.cache.link_exists(ifaceobj.name):
            return

        ifaceobjcurr.status = ifaceStatus.SUCCESS

    def _query_running(self, ifaceobjrunning):
        if not self.cache.link_exists(ifaceobjrunning.name):
            return

    # Operations supported by this addon (yet).
    _run_ops = {
        'pre-up': _up,
        'post-down': _down,
        'query-checkcurr': _query_check,
        'query-running': _query_running,
    }

    def get_ops(self):
        return self._run_ops.keys()

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        op_handler = self._run_ops.get(operation)

        if not op_handler:
            return

        if operation != 'query-running' and not self._is_my_interface(ifaceobj):
            return

        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
