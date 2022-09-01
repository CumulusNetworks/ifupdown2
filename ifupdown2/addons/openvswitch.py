#!/usr/bin/env python3
#
# Copyright 2020 Alexandre Derumier <aderumier@odiso.com>
# Author: Alexandre Derumier, aderumier@odiso.com
#

try:
    from ifupdown2.lib.addon import Addon

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
    from ifupdown2.ifupdown.exceptions import moduleNotSupported
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

except Exception:
    from lib.addon import Addon

    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdownaddons.modulebase import moduleBase
    from ifupdown.exceptions import moduleNotSupported
    import ifupdown.ifupdownflags as ifupdownflags

import logging
import re
import subprocess
import os

class openvswitch(Addon, moduleBase):
    """  ifupdown2 addon module to configure Openvswitch bridge """

    _modinfo = {
        'mhelp': 'openvswitch module configure openvswitch bridges',
        'attrs': {
            'ovs-ports': {
                'help': 'Interfaces to be part of this ovs bridge.',
                'validvals': ['<interface-list>'],
                'required': False,
                "multivalue": True,
                "example": [
                    "ovs-ports swp1.100 swp2.100 swp3.100",
                    "ovs-ports glob swp1-3.100",
                    "ovs-ports regex (swp[1|2|3].100)"
                ]
            },
            'ovs-type': {
                'help': 'ovs interface type',
                'validvals': ['OVSBridge'],
                'required': True,
            },
            'ovs-mtu': {
                'help': 'Interface MTU (maximum transmission unit)',
                'validrange': ['552', '9216'],
                'example': ['ovs-mtu 1600'],
                'default': '1500'
            },
            'ovs-options': {
                'help': 'This option lets you add extra arguments to a ovs-vsctl command',
                'required': False,
            },
            'ovs-extra': {
                'help': 'This option lets you run additional ovs-vsctl commands,'  +
                        'separated by "--" (double dash). Variables can be part of the "ovs_extra"' +
                        'option. You can provide all the standard environmental variables' + 
                        'described in the interfaces(5) man page. You can also pass shell' +
                        'commands.extra args',
                'required': False,
                'example': ['ovs_extra set bridge ${IFACE} other-config:hwaddr=00:59:cf:9c:84:3a -- br-set-external-id ${IFACE} bridge-id ${IFACE}']

            },
            'ovs-ports-condone-regex': {
                    "help": "ovs ports to ignore/condone when reloading config / removing interfaces",
                    "required": False,
                    "example": ["ovs-ports-condone-regex ^[a-zA-Z0-9]+_v[0-9]{1,4}$"]
            },
            'ovs-bridge': {
                'help': 'Optional parent bridge for fake bridges',
                'required': False,
            },
        }
    }

    def __init__ (self, *args, **kargs):
        moduleBase.__init__ (self, *args, **kargs)
        Addon.__init__(self)
        if not os.path.exists('/usr/bin/ovs-vsctl'):
            raise moduleNotSupported('module init failed: no /usr/bin/ovs-vsctl found')

    def _is_ovs_bridge (self, ifaceobj):
        ovstype = ifaceobj.get_attr_value_first('ovs-type')
        if ovstype:
            if ovstype == 'OVSBridge':
                return True
            else:
                return False
        return False

    def _get_ovs_ports (self, ifaceobj):
        ovs_ports = []

        for port in ifaceobj.get_attr_value('ovs-ports') or []:
            ovs_ports.extend(port.split())

        if ovs_ports:
            return self.parse_port_list(ifaceobj.name, ' '.join(ovs_ports))
        else:
            return None

    def _get_running_ovs_ports (self, iface):
        output = utils.exec_command("/usr/bin/ovs-vsctl list-ports %s" %iface)
        if output:
            ovs_ports = sorted(output.splitlines())
            return ovs_ports
        return None

    def _get_ovs_port_condone_regex(self, ifaceobj, get_string = False):
        ovs_port_condone_regex = ifaceobj.get_attr_value_first('ovs-ports-condone-regex')
        if ovs_port_condone_regex:
            if get_string:
                return ovs_port_condone_regex
            return re.compile (r"%s" % ovs_port_condone_regex)
        return None

    def _ovs_vsctl(self, ifaceobj, cmdlist):

        if cmdlist:

            os.environ['IFACE'] = ifaceobj.name if ifaceobj.name else ''
            os.environ['LOGICAL'] = ifaceobj.name if ifaceobj.name else ''
            os.environ['METHOD'] = ifaceobj.addr_method if ifaceobj.addr_method else ''
            os.environ['ADDRFAM'] = ','.join(ifaceobj.addr_family) if ifaceobj.addr_family else ''

            finalcmd = "/usr/bin/ovs-vsctl"

            for cmd in cmdlist:
                finalcmd = finalcmd + " -- " + cmd

            try:
                self.logger.debug ("Running %s" % (finalcmd))
                utils.exec_user_command(finalcmd)
            except subprocess.CalledProcessError as c:
                raise Exception ("Command \"%s failed: %s" % (finalcmd, c.output))
            except Exception as e:
                raise Exception ("%s" % e)

    def _addbridge (self, ifaceobj):

        iface = ifaceobj.name
        ovsoptions = ifaceobj.get_attr_value_first ('ovs-options')
        ovsextra = ifaceobj.get_attr_value('ovs-extra')
        ovsmtu = ifaceobj.get_attr_value_first ('ovs-mtu')
        ovsportscondoneregex = self._get_ovs_port_condone_regex(ifaceobj)
        ovsparent = ifaceobj.get_attr_value_first ('ovs-bridge')

        cmd_list = []

        cmd = "--may-exist add-br %s"%(iface)
        if ovsparent is not None and ovsoptions:
            cmd = cmd + " %s" %(ovsoptions)

        cmd_list.append(cmd)

        if ovsparent is None and ovsoptions:
            cmd = "set bridge %s %s" %(iface, ovsoptions)
            cmd_list.append(cmd)

        #update
        if self.cache.link_exists (iface):
            # on update, delete active ports not in the new port list
            ovs_ports = self._get_ovs_ports(ifaceobj)
            running_ovs_ports = self._get_running_ovs_ports(iface)

            missingports = []
            if running_ovs_ports is not None and ovs_ports is not None:
                missingports = list(set(running_ovs_ports) - set(ovs_ports))

            if missingports is not None:
                for port in missingports:
                    if ovsportscondoneregex and ovsportscondoneregex.match(port):
                        self.logger.info("%s: port %s will stay enslaved as it matches with ovs-ports-condone-regex" % (ifaceobj.name, port))
                        continue
                    cmd = "--if-exists del-port %s %s"%(iface, port)
                    cmd_list.append(cmd)

            #clear old bridge options
            cmd = "--if-exists clear bridge %s auto_attach controller external-ids fail_mode flood_vlans ipfix mirrors netflow other_config protocols sflow"%(iface)

            cmd_list.append(cmd)

            #clear old interface options
            cmd = "--if-exists clear interface %s mtu_request external-ids other_config options"%(iface)
            cmd_list.append(cmd)

        if ovsextra is not None:
            cmd_list.extend(ovsextra)

        if ovsmtu is not None:
            cmd = "set Interface %s mtu_request=%s"%(iface, ovsmtu)
            cmd_list.append(cmd)

        self._ovs_vsctl(ifaceobj, cmd_list)
        if not self.cache.link_exists(ifaceobj.name):
            self.iproute2.link_add_openvswitch(ifaceobj.name, "openvswitch")

    def _delbridge (self, ifaceobj):

        cmd = "del-br %s"%(ifaceobj.name)
        self._ovs_vsctl(ifaceobj, [cmd])

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None, old_ifaceobjs=False):
        if not self._is_ovs_bridge(ifaceobj):
            return None
        ifaceobj.link_privflags |= ifaceLinkPrivFlags.OPENVSWITCH
        return None

    def _up (self, ifaceobj):
        self._addbridge (ifaceobj)

    def _down (self, ifaceobj):
        if not ifupdownflags.flags.PERFMODE and not self.cache.link_exists (ifaceobj.name):
           return

        self._delbridge (ifaceobj)

    def _query_check (self, ifaceobj, ifaceobjcurr):
        if not self.cache.link_exists (ifaceobj.name):
            return
        return

    _run_ops = {
        'pre-up': _up,
        'post-down': _down,
        'query-checkcurr': _query_check
    }

    def get_ops (self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys ()

    def run (self, ifaceobj, operation, query_ifaceobj = None, **extra_args):
        """ run openvswitch configuration on the interface object passed as argument

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
        op_handler = self._run_ops.get (operation)
        if not op_handler:
            return

        if (operation != 'query-running' and not self._is_ovs_bridge (ifaceobj)):
            return

        if operation == 'query-checkcurr':
            op_handler (self, ifaceobj, query_ifaceobj)
        else:
            op_handler (self, ifaceobj)
