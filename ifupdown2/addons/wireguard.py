#!/usr/bin/env python3
#
# Marcel Straub <marcel@straubs.eu>
#  --  Sun 15 Jan 2023 10:53:13 PM CEST
#
try:
    from ifupdown2.lib.addon import Addon
    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdown.iface import *

    from ifupdown2.ifupdownaddons.modulebase import moduleBase
    from ifupdown2.ifupdown.exceptions import moduleNotSupported
    from ifupdown2.ifupdown.utils import utils

    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.nlmanager.ipnetwork as ipnetwork
except (ImportError, ModuleNotFoundError):
    from lib.addon import Addon
    from nlmanager.nlmanager import Link

    from ifupdown.iface import *

    from ifupdownaddons.modulebase import moduleBase
    from ifupdown.exceptions import moduleNotSupported
    from ifupdown.utils import utils

    import ifupdown.ifupdownflags as ifupdownflags
    import nlmanager.ipnetwork as ipnetwork

import os

class wireguard(Addon, moduleBase):
    """
    ifupdown2 addon module to configure tunnels
    """
    _modinfo = {
        'mhelp': 'create/configure Wireguard interfaces',
        'attrs': {
            'wireguard-config-path': {
                'help': 'Path to wireguard configuration',
                'validvals': ['<text>'],
                'required': True,
            },
            'wireguard-dev': {
                'help': 'Physical underlay device to use for VPN packets',
                'validvals': ['<interface>'],
                'required': False,
                'example': 'wireguard-dev eth0',
                'aliases': ['wireguard-physdev']
            }
        }
    }

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)
        self.logger.info("Initialized wireguard addon")
        if not os.path.exists(utils.wireguard_cmd):
            raise moduleNotSupported('module init failed: no %s found' % (utils.wireguard_cmd, ))

    @staticmethod
    def _is_my_interface(ifaceobj):
        return ifaceobj.get_attr_value_first("wireguard-config-path")

    @staticmethod
    def _has_config_changed(attrs_present, attrs_configured):
        for key, value in attrs_configured.items():
            if attrs_present.get(key) != value:
                return True
        return False

    def __get_info_data(self, info_data):
        tunnel_link_ifindex = info_data.get(Link.IFLA_GRE_LINK)

        return {
            "tunnel-endpoint": info_data.get(Link.IFLA_GRE_REMOTE),
            "tunnel-local": info_data.get(Link.IFLA_GRE_LOCAL),
            "tunnel-ttl": str(info_data.get(Link.IFLA_GRE_TTL)),
            "tunnel-tos": str(info_data.get(Link.IFLA_GRE_TOS)),
            "tunnel-dev": self.cache.get_ifname(tunnel_link_ifindex) if tunnel_link_ifindex else ""
        }

    def _up(self, ifaceobj):
        ifname = ifaceobj.name

        wireguard_config_file_path = ifaceobj.get_attr_value_first('wireguard-config-path')
        self.logger.info("Using configuration file '%s'" % (wireguard_config_file_path, ))

        link_exists = self.cache.link_exists(ifname)

        # Create the tunnel if it doesn't exist yet...
        if not link_exists:
            self.logger.info("wireguard[%s]: creating new interface" % (ifname, ))
            self.iproute2.wireguard_create(ifname, wireguard_config_file_path)
        else:
            self.logger.info("wireguard[%s]: changing existing interface" % (ifname, ))
            self.iproute2.wireguard_update(ifname, wireguard_config_file_path)

        self.logger.info("wireguard[%s]: finished setting up wireguard interface" % (ifname, ))

    def _down(self, ifaceobj):
        ifname = ifaceobj.name
        self.logger.info("wireguard[%s]: shutting down interface" % (ifname, ))
        if not ifupdownflags.flags.PERFMODE and not self.cache.link_exists(ifaceobj.name):
            return
        try:
            self.logger.info("wireguard[%s]: executing interface deletion" % (ifname, ))
            self.netlink.link_del(ifaceobj.name)
        except Exception as e:
            self.log_warn(str(e))

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None, old_ifaceobjs=False):
        if not self._is_my_interface(ifaceobj):
            return None

        device = ifaceobj.get_attr_value_first('wireguard-dev')
        if device:
            return [device]

        return None

    @staticmethod
    def _query_check_n_update(ifaceobjcurr, attrname, attrval, running_attrval):
        if running_attrval and attrval == running_attrval:
            ifaceobjcurr.update_config_with_status(attrname, attrval, 0)
        else:
            ifaceobjcurr.update_config_with_status(attrname, running_attrval, 1)

    def _query_check(self, ifaceobj, ifaceobjcurr):
        ifname = ifaceobj.name
        self.logger.info("wireguard[%s]: Entering _query_check" % (ifname, ))

        if not self.cache.link_exists(ifname):
            return

        link_kind = self.cache.get_link_kind(ifname)
        tunattrs = self.get_linkinfo_attrs(ifaceobj.name, link_kind)

        self.logger.info("wireguard[%s]: Finished _query_check" % (ifname, ))
        # if not tunattrs:
        #     ifaceobjcurr.check_n_update_config_with_status_many(ifaceobj, self.get_mod_attrs(), -1)
        #     return

        # tunattrs["tunnel-mode"] = link_kind

        # user_config_mode = ifaceobj.get_attr_value_first("tunnel-mode")
        # if user_config_mode in ('ipip6', 'ip6ip6'):
        #     ifaceobj.replace_config("tunnel-mode", "ip6tnl")

        # for attr, netlink_func in (
        #     ("tunnel-mode", None),
        #     ("tunnel-local", ipnetwork.IPNetwork),
        #     ("tunnel-endpoint", ipnetwork.IPNetwork),
        #     ("tunnel-ttl", self._get_tunnel_ttl),
        #     ("tunnel-tos", self._get_tunnel_tos),
        #     ("tunnel-dev", None),
        # ):
        #     attr_value = ifaceobj.get_attr_value_first(attr)

        #     if not attr_value:
        #         continue

        #     if callable(netlink_func):
        #         attr_value = netlink_func(attr_value)

        #     # Validate all interface attributes set in the config.
        #     # Remote any leading 'tunnel-' prefix in front of the attr name
        #     # when accessing tunattrs parsed from 'ip -d link'.
        #     self._query_check_n_update(ifaceobjcurr, attr, attr_value, tunattrs.get(attr))

    # Operations supported by this addon (yet).
    _run_ops = {
        'pre-up': _up,
        'post-down': _down,
        'query-checkcurr': _query_check
    }

    def get_ops(self):
        return list(self._run_ops.keys())

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        ifname = ifaceobj.name
        self.logger.info("wireguard[%s]: Entering run" % (ifname, ))
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            self.logger.info("wireguard[%s]: Leaving, no op_handler" % (ifname, ))
            return

        if operation != 'query-running' and not self._is_my_interface(ifaceobj):
            self.logger.info("wireguard[%s]: Leaving no query-running and not my interface" % (ifname, ))
            return

        if operation == 'query-checkcurr':
            self.logger.info("wireguard[%s]: query-checkcurr" % (ifname, ))
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            self.logger.info("wireguard[%s]: Executing '%s'" % (ifname, operation, ))
            op_handler(self, ifaceobj)
