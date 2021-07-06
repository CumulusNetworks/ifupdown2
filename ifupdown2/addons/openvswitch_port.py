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

class openvswitch_port(Addon, moduleBase):
    """  ifupdown2 addon module to configure openvswitch ports """

    _modinfo = {
        'mhelp': 'openvswitch module configure openvswitch ports',
        'attrs': {
            'ovs-bridge': {
                'help': 'Interfaces to be part of this ovs bridge',
                'required': True,
            },
            'ovs-type': {
                'help': 'ovs interface type',
                'validvals': ['OVSPort', 'OVSIntPort', 'OVSBond', 'OVSTunnel', 'OVSPatchPort'],
                'required': True,
                'example': ['ovs-type OVSPort'],
            },
            'ovs-options': {
                'help': 'This option lets you add extra arguments to a ovs-vsctl command',
                'required': False,
                'example': ['ovs_options bond_mode=balance-tcp lacp=active tag=100']
            },
            'ovs-extra': {
                'help': 'This option lets you run additional ovs-vsctl commands,'  +
                        'separated by "--" (double dash). Variables can be part of the "ovs_extra"' +
                        'option. You can provide all the standard environmental variables' + 
                        'described in the interfaces(5) man page. You can also pass shell' +
                        'commands.extra args',
                'required': False,
                'example': ['ovs_extra set interface ${IFACE} external-ids:iface-id=$(hostname -s)']
            },
            'ovs-bonds': {
                'help': 'Interfaces to be part of this ovs bond',
                'validvals': ['<interface-list>'],
                'required': False,
            },
            'ovs-tunnel-type': {
                'help': 'For "OVSTunnel" interfaces, the type of the tunnel',
                'required': False,
                'example': ['ovs-tunnel-type gre'],
            },
            'ovs-tunnel-options': {
                'help': 'For "OVSTunnel" interfaces, this field should be ' +
                        'used to specify the tunnel options like remote_ip, key, etc.',
                'required': False,
                'example': ['ovs-tunnel-options options:remote_ip=182.168.1.2 options:key=1'],
            },
            'ovs-patch-peer': {
                'help': 'ovs patch peer',
                'required': False,
                'example': ['ovs-patch-peer patch0'],
            },
            'ovs-mtu': {
                'help': 'mtu of the ovs interface',
                'required': False,
                'example': ['ovs-mtu 9000'],
            },
        }
    }

    def __init__ (self, *args, **kargs):
        moduleBase.__init__ (self, *args, **kargs)
        Addon.__init__(self)
        if not os.path.exists('/usr/bin/ovs-vsctl'):
            raise moduleNotSupported('module init failed: no /usr/bin/ovs-vsctl found')

    def _is_ovs_port (self, ifaceobj):
        ovstype = ifaceobj.get_attr_value_first ('ovs-type')
        ovsbridge = ifaceobj.get_attr_value_first ('ovs-bridge')
        if ovstype and ovsbridge:
            return True
        return False

    def _get_bond_ifaces (self, ifaceobj):
        ovs_bonds = ifaceobj.get_attr_value_first ('ovs-bonds')
        if ovs_bonds:
            return sorted (ovs_bonds.split ())
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

    def _addport (self, ifaceobj):
        iface = ifaceobj.name
        ovsbridge = ifaceobj.get_attr_value_first ('ovs-bridge')
        ovsoptions = ifaceobj.get_attr_value_first ('ovs-options')
        ovstype = ifaceobj.get_attr_value_first ('ovs-type')
        ovsbonds = ifaceobj.get_attr_value_first ('ovs-bonds')
        ovsextra = ifaceobj.get_attr_value('ovs-extra')

        cmd_list = []

        if ovstype == 'OVSBond':
           if ovsbonds is None:
               raise Exception ("missing ovs-bonds option")
           cmd = "--may-exist --fake-iface add-bond %s %s %s"%(ovsbridge, iface, ovsbonds)
           cmd_list.append(cmd)
        else:
           cmd = "--may-exist add-port %s %s"%(ovsbridge, iface)
           cmd_list.append(cmd)


        #clear old ports options
        cmd = "--if-exists clear port %s bond_active_slave bond_mode cvlans external_ids lacp mac other_config qos tag trunks vlan_mode"%(iface)
        cmd_list.append(cmd)

        #clear old interface options
        cmd = "--if-exists clear interface %s mtu_request external-ids other_config options"%(iface)
        cmd_list.append(cmd)

        if ovsoptions:
            cmd = "set Port %s %s" %(iface, ovsoptions)
            cmd_list.append(cmd)


        if ovstype == 'OVSIntPort':
            cmd = "set Interface %s type=internal"%(iface)
            cmd_list.append(cmd)

        if ovstype == 'OVSTunnel':
            ovstunneltype = ifaceobj.get_attr_value_first ('ovs-tunnel-type')
            if ovstunneltype is None:
                raise Exception ("missing ovs-tunnel-type option")
            ovstunneloptions = ifaceobj.get_attr_value_first('ovs-tunnel-options')
            if ovstunneloptions is None:
                raise Exception ("missing ovs-tunnel-options option")
            cmd = "set Interface %s type=%s %s"%(iface, ovstunneltype, ovstunneloptions)
            cmd_list.append(cmd)

        if ovstype == 'OVSPatchPort':
            ovspatchpeer = ifaceobj.get_attr_value_first ('ovs-patch-peer')
            if ovspatchpeer is None:
                raise Exception ("missing ovs-patch-peer")
            cmd = "set Interface %s type=patch options:peer=%s"%(iface, ovspatchpeer)
            cmd_list.append(cmd)

        #mtu
        ovsmtu = ifaceobj.get_attr_value_first ('ovs-mtu')
        ovsbonds_list = self._get_bond_ifaces(ifaceobj)
        if ovsmtu is not None:
            #we can't set mtu on bond fake interface, we apply it on slaves interfaces
            if ovstype == 'OVSBond' and ovsbonds_list is not None:
                for slave in ovsbonds_list: 
                    cmd = "set Interface %s mtu_request=%s"%(slave,ovsmtu)
                    cmd_list.append(cmd)

            else:
                cmd = "set Interface %s mtu_request=%s"%(iface,ovsmtu)
                cmd_list.append(cmd)

        #extra
        if ovsextra is not None:
            cmd_list.extend(ovsextra)

        self._ovs_vsctl(ifaceobj, cmd_list)

        if ovstype != 'OVSTunnel' and ovstype != 'OVSPatchPort':
            if not self.cache.link_exists(ifaceobj.name):
                self.iproute2.link_add_openvswitch(ifaceobj.name, "openvswitch")

    def _delport (self, ifaceobj):
        iface = ifaceobj.name
        ovsbridge = ifaceobj.get_attr_value_first ('ovs-bridge')
        cmd = "--if-exists del-port %s %s"%(ovsbridge, iface)

        self._ovs_vsctl(ifaceobj, [cmd])

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None, old_ifaceobjs=False):

        if not self._is_ovs_port (ifaceobj):
            return None

        ifaceobj.link_privflags |= ifaceLinkPrivFlags.OPENVSWITCH

        ovsbridge = ifaceobj.get_attr_value_first ('ovs-bridge')
        return [ovsbridge]

    def _up (self, ifaceobj):

        self._addport (ifaceobj)

    def _down (self, ifaceobj):
        if not ifupdownflags.flags.PERFMODE and not self.cache.link_exists (ifaceobj.name):
           return

        self._delport (ifaceobj)

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
        """ run Openvswitch port configuration on the interface object passed as argument

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

        if (operation != 'query-running' and not self._is_ovs_port (ifaceobj)):
            return

        if operation == 'query-checkcurr':
            op_handler (self, ifaceobj, query_ifaceobj)
        else:
            op_handler (self, ifaceobj)
