#!/usr/bin/python
#
# Joerg Dorchain <joerg@dorchain.net>
#  13 Jul 2017

import os
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.iproute2 import iproute2
from ifupdownaddons.pppd import pppd

from ifupdown.utils import utils
import ifupdown.ifupdownflags as ifupdownflags

class ppp(moduleBase):
    """  ifupdown2 addon module to configure ppp interfaces """

    _modinfo = {'mhelp' : 'create/configure ppp interfaces',
                'attrs' : {
                   'provider' :
                        {'help' : 'Use name as the provider (from /etc/ppp/peers)',
                         'required' : True},
                   'unit' :
                        {'help' : 'Use number as the ppp unit number.',
                         'validvals' : ['<number>']},
                   'options' :
                        {'help' : 'Pass string as additional options to pon.'},
			}
		}
    def __init__ (self, *args, **kargs):
    	moduleBase.__init__(self, *args, **kargs)
	self.pppcmd = pppd(**kargs)
	self.ipcmd = None;

    def _is_my_interface (self, ifaceobj):
    	if ifaceobj.addr_method == "ppp" and ifaceobj.get_attr_value_first ('provider'):
		return True
	return False

    def _up (self, ifaceobj):
    	self.pppcmd.start(ifaceobj)

    def _down (self, ifaceobj):
    	self.pppcmd.stop(ifaceobj)

    def _query_check (self, ifaceobj, ifaceobjcurr):
	status = ifaceStatus.SUCCESS
	pppd_running = False

	if self.pppcmd.is_running(ifaceobjcurr.name):
		pppd_running = True
	ifaceobjcurr.addr_method = 'ppp'
	ifaceobjcurr.addr_family = ifaceobj.addr_family
	if not pppd_running:
		ifaceobjcurr.addr_family = []
		status = ifaceStatus.ERROR
	ifaceobjcurr.status = status

    _run_ops = {
    	'up' : _up,
	'down' : _down,
	'pre-down' : _down,
	'query-checkcurr' : _query_check
    }
    def get_ops (self):
    	return self._run_ops.keys()

    def run (self, ifaceobj, operation, query_ifaceobj = None, **extra_args):
    	op_handler = self._run_ops.get(operation)
	if not op_handler:
		return
	if operation != 'query-running' and not self._is_my_interface (ifaceobj):
		return
	if not self.ipcmd:
		self.ipcmd = iproute2 ()
	if operation == 'query-checkcurr':
		op_handler (self, ifaceobj, query_ifaceobj)
	else:
		op_handler (self, ifaceobj)
