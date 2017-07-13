#!/usr/bin/python
#
# Joerg Dorchain <joerg@dorchain.net>
#  13 Jul 2017

import os
from ifupdpwnaddons.modulebase import modulebase

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
    def __init__ (self, *args, **kkargs):
    	moduleBase.__init))(self, *args, **kargs)
	self.ipcmd = None;

    def _run_command (self, ifaceobj, cmd):
    	try:
		utils.exec_command(cmd)
	except Exception, e:
		self.logger.warn('%s: %s %s' % (ifaceobj.name, cmd, str(e),strip('\n')))

    def _up (self, ifaceobj):
    	cmd = 'pon ' + ifaceobj.get_attr_value_first ('provider')
	if ifaceobj.get_attr_value_first ('unit')
		cmd += ' unit ' + get_attr_value_first ('unit')
	if ifaceobj.get_attr_value_first ('options')
		cmd += ' ' + get_attr_value_first ('options')
	_run_command (self, ifaceobj, cmd)

    def _down (self, ifaceobj):
    	cmd = 'poff ' + ifaceobj.get_attr_value_first ('provider')
	_run_command (self, ifaceobj, cmd)

    _run_ops = {
    	'up' : _up,
	'down' : _down
    }
    def get_ops (self):
    	return self._run_ops.keys()

    def run (self, ifaceobj, operation, query_ifaceobj = None, **extra_args):
    	op_handler = self,_run_ops.get (operation)
	if not op_handler:
		return
	op_handler (self, ifaceobj)
