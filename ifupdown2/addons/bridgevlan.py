#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

try:
    from ifupdown2.lib.addon import Addon

    from ifupdown2.ifupdown.iface import ifaceType, ifaceLinkKind, ifaceStatus

    from ifupdown2.ifupdownaddons.modulebase import moduleBase

    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
except ImportError:
    from lib.addon import Addon

    from ifupdown.iface import ifaceType, ifaceLinkKind, ifaceStatus

    from ifupdownaddons.modulebase import moduleBase

    import ifupdown.ifupdownflags as ifupdownflags


class bridgevlan(Addon, moduleBase):
    """  ifupdown2 addon module to configure vlan attributes on a vlan
         aware bridge """

    _modinfo = {
        "mhelp": "bridgevlan module configures vlan attributes on a vlan aware "
                 "bridge. This module only understands vlan interface name "
                 "with dot notations. eg br0.100. where br0 is the vlan aware "
                 "bridge this config is for",
        "attrs": {
            "bridge-igmp-querier-src": {
                "help": "bridge igmp querier src. Must be specified under "
                        "the vlan interface",
                "validvals": ["<ipv4>"],
                "example": ["bridge-igmp-querier-src 172.16.101.1"]
            }
        }
    }

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)

    @staticmethod
    def _is_bridge_vlan_device(ifaceobj):
        return ifaceobj.type == ifaceType.BRIDGE_VLAN

    @staticmethod
    def _get_bridge_n_vlan(ifaceobj):
        vlist = ifaceobj.name.split('.', 1)
        if len(vlist) == 2:
            return vlist[0], vlist[1]
        return None

    @staticmethod
    def _get_bridgename(ifaceobj):
        vlist = ifaceobj.name.split('.', 1)
        if len(vlist) == 2:
            return vlist[0]
        return None

    def get_dependent_ifacenames(self, ifaceobj, ifaceobjs_all=None, old_ifaceobjs=False):
        if not self._is_bridge_vlan_device(ifaceobj):
            return None
        return [self._get_bridgename(ifaceobj)]

    def _up(self, ifaceobj):
        try:
            (bridgename, vlan) = self._get_bridge_n_vlan(ifaceobj)
            vlanid = int(vlan, 10)
        except Exception:
            self.log_error("%s: bridge vlan interface name does not correspond "
                           "to format (eg. br0.100)" % ifaceobj.name, ifaceobj)
            raise

        if not self.cache.link_exists(bridgename):
            #self.logger.warning('%s: bridge %s does not exist' %(ifaceobj.name,
            #                 bridgename))
            return

        running_mcqv4src = {}
        if not ifupdownflags.flags.PERFMODE:
            running_mcqv4src = self.sysfs.bridge_get_mcqv4src(bridgename)
        if running_mcqv4src:
            r_mcqv4src = running_mcqv4src.get(vlan)
        else:
            r_mcqv4src = None
        mcqv4src = ifaceobj.get_attr_value_first('bridge-igmp-querier-src')
        if not mcqv4src:
            if r_mcqv4src:
                self.iproute2.bridge_del_mcqv4src(bridgename, vlanid)
            return

        if r_mcqv4src and r_mcqv4src != mcqv4src:
            self.iproute2.bridge_del_mcqv4src(bridgename, vlanid)
            self.iproute2.bridge_set_mcqv4src(bridgename, vlanid, mcqv4src)
        else:
            self.iproute2.bridge_set_mcqv4src(bridgename, vlanid, mcqv4src)

    def _down(self, ifaceobj):
        try:
            (bridgename, vlan) = self._get_bridge_n_vlan(ifaceobj)
            vlanid = int(vlan, 10)
        except Exception:
            self.logger.warning("%s: bridge vlan interface name does not "
                             "correspond to format (eg. br0.100)" % ifaceobj.name)
            raise

        if not self.cache.link_exists(bridgename):
            #self.logger.warning('%s: bridge %s does not exist' %(ifaceobj.name,
            #                 bridgename))
            return
        mcqv4src = ifaceobj.get_attr_value_first('bridge-igmp-querier-src')
        if mcqv4src:
            self.iproute2.bridge_del_mcqv4src(bridgename, vlanid)

    def _query_running_bridge_igmp_querier_src(self, ifaceobj):
        (bridgename, vlanid) = ifaceobj.name.split('.')
        running_mcqv4src = self.sysfs.bridge_get_mcqv4src(bridgename)
        if running_mcqv4src:
            return running_mcqv4src.get(vlanid)
        return None

    def _query_check(self, ifaceobj, ifaceobjcurr):
        attrval = ifaceobj.get_attr_value_first('bridge-igmp-querier-src')
        if attrval:
            running_mcq = self._query_running_bridge_igmp_querier_src(ifaceobj)
            if not running_mcq or running_mcq != attrval:
                ifaceobjcurr.update_config_with_status(
                        'bridge-igmp-querier-src', running_mcq, 1)
            else:
                ifaceobjcurr.update_config_with_status(
                        'bridge-igmp-querier-src', attrval, 0)
                ifaceobjcurr.status = ifaceStatus.SUCCESS

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        ret = True
        bvlan_intf = self._is_bridge_vlan_device(ifaceobj)
        if (ifaceobj.get_attr_value_first('bridge-igmp-querier-src') and not bvlan_intf):
            self.logger.error('%s: bridge-igmp-querier-src only allowed under vlan stanza' % ifaceobj.name)
            ret = False
        return ret

    _run_ops = {
        "pre-up": _up,
        "post-down": _down,
        "query-checkcurr": _query_check,
    }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return list(self._run_ops.keys())

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
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        if (operation != 'query-running' and not self._is_bridge_vlan_device(ifaceobj)):
            # most common problem is people specify BRIDGE_VLAN
            # attribute on a bridge or a vlan device, which
            # is incorrect. So, catch them here and warn before
            # giving up processing the interface
            if (ifaceobj.link_kind & ifaceLinkKind.BRIDGE or ifaceobj.link_kind & ifaceLinkKind.VLAN) \
                    and not self.syntax_check(ifaceobj, None):
                ifaceobj.status = ifaceStatus.ERROR
            return
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
