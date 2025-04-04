#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# This should be pretty simple and might not really even need to exist.
# The key is that we need to call link_create with a type of "dummy"
# since that will translate to 'ip link add loopbackX type dummy'
# The config file should probably just indicate that the type is
# loopback or dummy.

try:
    from ifupdown2.lib.addon import Addon
    from ifupdown2.ifupdown.iface import ifaceLinkKind, ifaceLinkPrivFlags, ifaceStatus
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.modulebase import moduleBase

    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.policymanager as policymanager
except ImportError:
    from lib.addon import Addon
    from ifupdown.iface import ifaceLinkKind, ifaceLinkPrivFlags, ifaceStatus
    from ifupdown.utils import utils

    from ifupdownaddons.modulebase import moduleBase

    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.policymanager as policymanager


class link(Addon, moduleBase):
    _modinfo = {
        "mhelp": "create/configure link types. similar to ip-link",
        "attrs": {
            "link-type": {
                "help": "type of link as in 'ip link' command.",
                "validvals": ["dummy", "veth"],
                "example": ["link-type <dummy|veth>"]
            },
            "link-down": {
                "help": "keep link down",
                "example": ["link-down yes/no"],
                "default": "no",
                "validvals": ["yes", "no"]
            },
            "veth-peer-name": {
                "help": "Name of the veth peer interface.",
                "validvals": "<interface>",
                "example": ["veth-peer-name veth_ext2int"]
            }
        }
    }

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)

        self.check_physical_port_existance = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                self.__class__.__name__,
                'warn_on_physdev_not_present'
            )
        )

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        if self.check_physical_port_existance and not ifaceobj.link_kind and not self.cache.link_exists(ifaceobj.name):
            self.logger.warning('%s: interface does not exist' % ifaceobj.name)
            return False
        return True

    @staticmethod
    def _is_my_interface(ifaceobj):
        return ifaceobj.get_attr_value_first('link-type') or ifaceobj.get_attr_value_first('link-down')

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None, old_ifaceobjs=False):
        if ifaceobj.get_attr_value_first('link-down') == 'yes':
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.KEEP_LINK_DOWN
        if ifaceobj.get_attr_value_first('link-type'):
            ifaceobj.link_kind = ifaceLinkKind.OTHER

        link_type = ifaceobj.get_attr_value_first("link-type")
        # If this interface is one side of a veth link pair and a name for
        # the peer interface if given, pass it to the link_create call.
        if link_type == "veth" and ifaceobj.get_attr_value_first("veth-peer-name"):
            return [ifaceobj.get_attr_value_first("veth-peer-name")]

        return None

    def _up(self, ifaceobj):
        link_type = ifaceobj.get_attr_value_first("link-type")

        # If this interface is one side of a veth link pair and a name for
        # the peer interface if given, pass it to the link_create call.
        if link_type == "veth":
            peer_name = ifaceobj.get_attr_value_first("veth-peer-name")

            if peer_name and not self.cache.link_exists(ifaceobj.name):
                self.iproute2.link_add_veth(ifaceobj.name, peer_name)

        elif link_type:
            self.netlink.link_add(ifname=ifaceobj.name, kind=link_type)

    def _down(self, ifaceobj):
        if not ifaceobj.get_attr_value_first('link-type'):
            return
        if not ifupdownflags.flags.PERFMODE and not self.cache.link_exists(ifaceobj.name):
            return
        try:
            self.netlink.link_del(ifaceobj.name)
        except Exception as e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if ifaceobj.get_attr_value('link-type'):
            if not self.cache.link_exists(ifaceobj.name):
                ifaceobjcurr.update_config_with_status('link-type', 'None', 1)
            else:
                link_type = ifaceobj.get_attr_value_first('link-type')
                if self.cache.get_link_kind(ifaceobj.name) == link_type:
                    ifaceobjcurr.update_config_with_status('link-type', link_type, 0)
                else:
                    ifaceobjcurr.update_config_with_status('link-type', link_type, 1)

        self._query_check_link_down(ifaceobj, ifaceobjcurr)

    def _query_check_link_down(self, ifaceobj, ifaceobjcurr):
        link_down = ifaceobj.get_attr_value_first('link-down')

        if link_down:
            link_should_be_down = utils.get_boolean_from_string(link_down)
        else:
            link_should_be_down = False

        link_up = self.cache.link_is_up(ifaceobj.name)

        if not link_up and not link_should_be_down and not link_down:
            ifaceobjcurr.status_str = 'link is down'
            ifaceobjcurr.status = ifaceStatus.ERROR
        elif link_down:
            if link_should_be_down and link_up:
                status = 1
                link_down = 'no'
            elif link_should_be_down and not link_up:
                status = 0
            elif not link_should_be_down and link_up:
                status = 0
            else:
                status = 1

            ifaceobjcurr.update_config_with_status('link-down', link_down, status)

    _run_ops = {
        "pre-up": _up,
        "post-down": _down,
        "query-checkcurr": _query_check
    }

    def get_ops(self):
        return list(self._run_ops.keys())

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        if (operation != 'query-running' and operation != 'query-checkcurr' and
                not self._is_my_interface(ifaceobj)):
            return
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
