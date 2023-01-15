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
import hashlib

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

    def _get_wg_config_on_disk(self, ifaceobj):
        file_path = ifaceobj.get_attr_value_first("wireguard-config-path")
        file_hash = hashlib.sha256()
        BLOCK_SIZE = 65536

        with open(file_path, 'rb') as f:
            fb = f.read(BLOCK_SIZE)
            while len(fb) > 0:
                file_hash.update(fb)
                fb = f.read(BLOCK_SIZE)
        
        return file_hash.hexdigest()

    def _get_wg_config_running(self, ifaceobj):
        ifname = ifaceobj.name
        x = utils.exec_command("wg showconf %s" % (ifname, ))
        self.logger.info("Output wg showconf: " + x)

    def _query_check(self, ifaceobj, ifaceobjcurr):
        """Check between desired and current state and report current state back

        Args:
            ifaceobj (_type_): _description_
            ifaceobjcurr (_type_): _description_
        """
        ifname = ifaceobj.name
        self.logger.info("wireguard[%s]: Entering _query_check" % (ifname, ))

        if not self.cache.link_exists(ifname):
            return

        # config path
        attr = "wireguard-config-path"
        attr_value = ifaceobj.get_attr_value_first(attr)
        self._query_check_n_update(ifaceobjcurr, attr, attr_value, attr_value)
        self.logger.info("wireguard[%s]: attr%s, value=%s" % (ifname, attr, attr_value))

        on_disk_wg_config_hash = self._get_wg_config_on_disk(ifaceobj)
        self.logger.info("wireguard[%s]: on_disk_wg_config_hash=" % (ifname, on_disk_wg_config_hash))
        self._get_wg_config_running(ifaceobj)

        # master dev, it's hard to check if is, it's just a hint for bringing up the devs in order
        attr = "wireguard-dev"
        attr_value = ifaceobj.get_attr_value_first(attr)
        self._query_check_n_update(ifaceobjcurr, attr, attr_value, attr_value)
        self.logger.info("wireguard[%s]: attr%s, value=%s" % (ifname, attr, attr_value))
        self.logger.info("wireguard[%s]: Finished _query_check" % (ifname, ))

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
