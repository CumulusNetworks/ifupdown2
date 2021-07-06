#!/usr/bin/python3

import os
import hashlib

try:
    from ifupdown2.lib.addon import Addon
    import ifupdown2.ifupdown.statemanager as statemanager

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.modulebase import moduleBase

    from ifupdown2.ifupdown.exceptions import moduleNotSupported
except (ImportError, ModuleNotFoundError):
    from lib.addon import Addon
    import ifupdown.statemanager as statemanager

    from ifupdown.iface import *
    from ifupdown.utils import utils

    from ifupdownaddons.modulebase import moduleBase

    from ifupdown.exceptions import moduleNotSupported


class ppp(Addon, moduleBase):
    """
    ifupdown2 addon module to configure ppp
    """
    _modinfo = {
        'mhelp': 'create/configure ppp interfaces',
        'attrs': {
            'provider': {
                'help': 'Provider file in ppp',
                'validvals': ['<text>'],
                'required': True,
                'example': ['dsl-provider']
            },
            'ppp-physdev': {
                'help': 'Physical underlay device to use for ppp if any',
                'validvals': ['<interface>'],
                'required': False,
                'example': ['ppp-physdev eth1']
            },
        }
    }

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)
        if not os.path.exists('/usr/bin/pon'):
            raise moduleNotSupported('module init failed: no /usr/bin/pon found')

    @staticmethod
    def _is_my_interface(ifaceobj):
        return ifaceobj.addr_method == "ppp" and ifaceobj.get_attr_value_first('provider')

    def _up(self, ifaceobj):
        """
        Up the PPP connection
        """
        provider = ifaceobj.get_attr_value_first('provider')
        old_config = None
        old_provider = None

        try:
            ppp_file = os.path.join('/etc/ppp/peers', provider)
            if not os.path.isfile(ppp_file):
                self.log_warn('Invalid ppp provider file does not exist')
                return

            # Load state data
            saved_ifaceobjs = statemanager.statemanager_api.get_ifaceobjs(ifaceobj.name)
            if saved_ifaceobjs:
                old_provider = saved_ifaceobjs[0].get_attr_value_first('provider')
                old_config = saved_ifaceobjs[0].get_attr_value_first('provider_file')

            config = hashlib.sha256(open(ppp_file, 'rb').read()).hexdigest()
            # Always save the current config files hash
            ifaceobj.update_config('provider_file', config)

            if not self.cache.link_exists(ifaceobj.name):
                try:
                    # This fails if not running
                    utils.exec_user_command('/bin/ps ax | /bin/grep pppd | /bin/grep -v grep | /bin/grep ' + provider)
                except Exception:
                    utils.exec_commandl(['/usr/bin/pon', provider], stdout=None, stderr=None)

            if old_config and old_config != config:
                # Restart on config change
                utils.exec_commandl(['/usr/bin/poff', provider], stdout=None, stderr=None)
                utils.exec_commandl(['/usr/bin/pon', provider], stdout=None, stderr=None)
            elif old_provider and old_provider != provider:
                # Restart on provider change
                utils.exec_commandl(['/usr/bin/poff', old_provider], stdout=None, stderr=None)
                utils.exec_commandl(['/usr/bin/pon', provider], stdout=None, stderr=None)

        except Exception as e:
            self.log_warn(str(e))

    def _down(self, ifaceobj):
        """
        Down the PPP connection
        """
        try:
            provider = ifaceobj.get_attr_value_first('provider')
            # This fails if not running
            utils.exec_user_command('/bin/ps ax | /bin/grep pppd | /bin/grep -v grep | /bin/grep ' + provider)
            utils.exec_commandl(['/usr/bin/poff', provider], stdout=None, stderr=None)
        except Exception as e:
            self.log_warn(str(e))

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None, old_ifaceobjs=False):
        if not self._is_my_interface(ifaceobj):
            return None

        device = ifaceobj.get_attr_value_first('ppp-physdev')

        if device:
            return [device]

        return None

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
        'down': _down,
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
