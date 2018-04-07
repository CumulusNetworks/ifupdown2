#!/usr/bin/python
import os
import hashlib

from ifupdown.iface import *
from ifupdown.utils import utils
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.iproute2 import iproute2
from ifupdown.netlink import netlink
import ifupdown.statemanager as statemanager
import ifupdown.ifupdownflags as ifupdownflags
import logging

class ppp (moduleBase):
    _modinfo = { 'mhelp' : 'create/configure ppp interfaces',
                 'attrs' : {
                   'provider' :
                        { 'help' : 'Provider file in ppp',
                          'validvals' : ['<text>'],
                          'required' : True,
                          'example' : ['dsl-provider']},
                   'ppp-physdev' :
                        { 'help' : 'Physical underlay device to use for ppp if any',
                          'validvals' : ['<interface>'],
                          'required' : False,
                          'example' : ['ppp-physdev eth1']},
                 }
               }


    def __init__ (self, *args, **kargs):
        moduleBase.__init__ (self, *args, **kargs)
        if not os.path.exists('/usr/bin/pon'):
            raise moduleNotSupported('module init failed: no /usr/bin/pon found')
        self.ipcmd = None

    def _is_my_interface (self, ifaceobj):
        if ifaceobj.addr_method == "ppp" and ifaceobj.get_attr_value_first ('provider'):
            return True
        return False

    def _up (self, ifaceobj):
        '''
        Up the PPP connection
        '''
        provider = ifaceobj.get_attr_value_first ('provider')
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
                old_provider = saved_ifaceobjs[0].get_attr_value_first ('provider')
                old_config = saved_ifaceobjs[0].get_attr_value_first ('provider_file')

            config = hashlib.sha256(open(ppp_file, 'rb').read()).hexdigest()
            # Always save the current config files hash
            ifaceobj.update_config('provider_file', config)

            if not self.ipcmd.link_exists(ifaceobj.name):
                utils.exec_commandl(['/usr/bin/pon', provider], stdout=None, stderr=None)
            elif old_config and old_config != config:
                # Restart on config change
                utils.exec_commandl(['/usr/bin/poff', provider], stdout=None, stderr=None)
                utils.exec_commandl(['/usr/bin/pon', provider], stdout=None, stderr=None)
            elif old_provider and old_provider != provider:
                # Restart on provider change
                utils.exec_commandl(['/usr/bin/poff', old_provider], stdout=None, stderr=None)
                utils.exec_commandl(['/usr/bin/pon', provider], stdout=None, stderr=None)

        except Exception, e:
            self.log_warn (str (e))

    def _down (self, ifaceobj):
        if not ifupdownflags.flags.PERFMODE and not self.ipcmd.link_exists (ifaceobj.name):
           return
        try:
            provider = ifaceobj.get_attr_value_first ('provider')
            utils.exec_commandl(['/usr/bin/poff', provider], stdout=None, stderr=None)
        except Exception, e:
            self.log_warn (str (e))

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        if not self._is_my_interface(ifaceobj):
            return None
        
        device = ifaceobj.get_attr_value_first ('ppp-physdev')
        if device:
            return device

        return None

    def _query_check (self, ifaceobj, ifaceobjcurr):
        if not self.ipcmd.link_exists(ifaceobj.name):
           return

        ifaceobjcurr.status = ifaceStatus.SUCCESS

    def _query_running(self, ifaceobjrunning):
        if not self.ipcmd.link_exists(ifaceobjrunning.name):
            return

    # Operations supported by this addon (yet).
    _run_ops = {
        'pre-up' : _up,
        'post-down' : _down,
        'query-checkcurr' : _query_check,
        'query-running' : _query_running,
    }

    def get_ops (self):
        return self._run_ops.keys()

    def _init_command_handlers (self):
        if not self.ipcmd:
            self.ipcmd = iproute2 ()

    def run (self, ifaceobj, operation, query_ifaceobj = None, **extra_args):
        op_handler = self._run_ops.get (operation)
        if not op_handler:
            return

        if operation != 'query-running' and not self._is_my_interface (ifaceobj):
            return

        self._init_command_handlers ()
        if operation == 'query-checkcurr':
            op_handler (self, ifaceobj, query_ifaceobj)
        else:
            op_handler (self, ifaceobj)
