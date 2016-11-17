#!/usr/bin/python
#
# Copyright 2016 Maximilian Wilhelm <max@rfc2324.org>
# Author: Maximilian Wilhelm, max@rfc2324.org
#

from ifupdown.iface import *
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.iproute2 import iproute2
from ifupdown.netlink import netlink
import ifupdown.ifupdownflags as ifupdownflags
import logging
import re
import subprocess


class batman_adv (moduleBase):
    """  ifupdown2 addon module to configure B.A.T.M.A.N. advanced interfaces """

    _modinfo = {'mhelp' : 'batman_adv module configures B.A.T.M.A.N. advanced interfaces.' +
                        'Every B.A.T.M.A.N. advanced interface needs at least on ethernet ' +
                        'interface to be creatable. You can specify a space separated list' +
                        'of interfaces by using the "batma-ifaces" paramater. If this parameter' +
                        'is set for an interfaces this module will do the magic.',
                'attrs' : {
                        'batman-ifaces' :
                            {'help' : 'Interfaces to be part of this B.A.T.M.A.N. advanced instance'},
                        'batman-ifaces-ignore-regex' :
                            {'help' : 'Interfaces to ignore when verifying configuration (regexp)'},
                        'batman-hop-penalty' :
                            {'help' : 'B.A.T.M.A.N. hop penalty'}}}


    def __init__ (self, *args, **kargs):
        moduleBase.__init__ (self, *args, **kargs)
        self.ipcmd = None


    def _is_batman_device (self, ifaceobj):
        if ifaceobj.get_attr_value_first ('batman-ifaces'):
            return True
        return False


    def _get_batman_ifaces (self, ifaceobj ):
        batman_ifaces = ifaceobj.get_attr_value_first ('batman-ifaces')
        if batman_ifaces:
            return sorted (batman_ifaces.split ())
        return None


    def _get_batman_ifaces_ignore_regex (self, ifaceobj):
        ifaces_ignore_regex = ifaceobj.get_attr_value_first ('batman-ifaces-ignore-regex')
        if ifaces_ignore_regex:
            return re.compile (r"%s" % ifaces_ignore_regex)
        return None


    def _get_batman_hop_penalty (self, ifaceobj):
        # XXX config option for default value?
        hop_penalty = ifaceobj.get_attr_value_first ('batman-hop-penalty')
        if hop_penalty:
            return int (hop_penalty)
        return 15

    def _read_current_hop_penalty (self, ifaceobj):
        hop_penalty_file_path = "/sys/class/net/%s/mesh/hop_penalty" % ifaceobj.name
        try:
            with open (hop_penalty_file_path, "r") as fh:
                 return int (fh.readline ().strip ())
        except IOError as i:
             raise Exception ("_read_current_hop_penalty: %s" % i)
        except ValueError:
             raise Exception ("Hop penalty not an integer value!")


    def _set_hop_penalty (self, ifaceobj, hop_penalty):
        hop_penalty_file_path = "/sys/class/net/%s/mesh/hop_penalty" % ifaceobj.name
        try:
            with open (hop_penalty_file_path, "w") as fh:
                 fh.write ("%d\n" % int (hop_penalty))
        except IOError as i:
             raise Exception ("_set_hop_penalty: %s" % i)
        except ValueError:
             raise Exception ("Hop penalty not an integer value!")


    def _batctl_if (self, bat_iface, mesh_iface, op):
        if op not in [ 'add', 'del' ]:
            raise Exception ("_batctl_if() called with invalid \"op\" value: %s" % op)

        try:
            self.logger.debug ("Running batctl -m %s if %s %s" % (bat_iface, op, mesh_iface))
            batctl_output = subprocess.check_output (["/usr/sbin/batctl", "-m", bat_iface, "if", op, mesh_iface], stderr = subprocess.STDOUT)
        except subprocess.CalledProcessError as c:
            raise Exception ("Command \"batctl -m %s if %s %s\" failed: %s" % (bat_iface, op, mesh_iface, c.output))
        except Exception as e:
            raise Exception ("_batctl_if: %s" % e)


    def _find_member_ifaces (self, ifaceobj, ignore = True):
        members = []
        iface_ignore_re = self._get_batman_ifaces_ignore_regex (ifaceobj)
        batctl_fh = subprocess.Popen (["/usr/sbin/batctl", "-m", ifaceobj.name, "if"], bufsize = 4194304, stdout = subprocess.PIPE).stdout
        for line in batctl_fh.readlines ():
            iface = line.split (':')[0]
            if iface_ignore_re and iface_ignore_re.match (iface) and ignore:
                 continue

            members.append (iface)

        return sorted (members)


    def get_dependent_ifacenames (self, ifaceobj, ifaceobjs_all=None):
        if not self._is_batman_device (ifaceobj):
            return None

        ifaceobj.link_kind |= ifaceLinkKind.BATMAN_ADV
        batman_ifaces = self._get_batman_ifaces (ifaceobj)
        if batman_ifaces:
            return batman_ifaces

        return [None]


    def _up (self, ifaceobj):
        batman_ifaces = self._get_batman_ifaces (ifaceobj)
        if batman_ifaces == None:
            raise Exception ('could not determine batman interfacaes')

        # Verify existance of batman interfaces (should be present already)
        for iface in batman_ifaces:
            if not self.ipcmd.link_exists (iface):
                raise Exception ('batman iface %s not present' % iface)

        if_ignore_re = self._get_batman_ifaces_ignore_regex (ifaceobj)
        # Is the batman main interface already present?
        if self.ipcmd.link_exists (ifaceobj.name):
            # Verify which member interfaces are present
            members = self._find_member_ifaces (ifaceobj)
            for iface in members:
                if iface not in batman_ifaces:
                    self._batctl_if (ifaceobj.name, iface, 'del')
            for iface in batman_ifaces:
                if iface not in members:
                    self._batctl_if (ifaceobj.name, iface, 'add')

        # Batman interfaces no present, add member interfaces to create it
        else:
            for iface in batman_ifaces:
                self._batctl_if (ifaceobj.name, iface, 'add')

        # Check/set Hop Penalty
        hop_penalty_cfg = self._get_batman_hop_penalty (ifaceobj)
        if hop_penalty_cfg != self._read_current_hop_penalty (ifaceobj):
            self._set_hop_penalty (ifaceobj, hop_penalty_cfg)

        if ifaceobj.addr_method == 'manual':
            netlink.link_set_updown(ifaceobj.name, "up")



    def _down (self, ifaceobj):
        if not ifupdownflags.flags.PERFMODE and not self.ipcmd.link_exists (ifaceobj.name):
           return

        members = self._find_member_ifaces (ifaceobj)
        for iface in members:
            self._batctl_if (ifaceobj.name, iface, 'del')

        # The main interface will automagically vanish after the last member
        # interface has been deleted.


    def _query_check (self, ifaceobj, ifaceobjcurr):
        if not self.ipcmd.link_exists (ifaceobj.name):
            return

        hop_penalty = self._get_batman_hop_penalty (ifaceobj)
        hop_penalty_curr = self._read_current_hop_penalty (ifaceobj)
        batman_ifaces_cfg = self._get_batman_ifaces (ifaceobj)
        batman_ifaces_real = self._find_member_ifaces (ifaceobj, False)
        # Produce list of all current interfaces, tag interfaces ignore by
        # regex with () around the iface name.
        batman_ifaces_real_tagged = []
        iface_ignore_re_str = ifaceobj.get_attr_value_first ('batman-ifaces-ignore-regex')
        iface_ignore_re = self._get_batman_ifaces_ignore_regex (ifaceobj)

        # Assume everything's fine and wait for reality to prove us otherwise
        ifaces_ok = 0
        # Interfaces configured but not active?
        for iface in batman_ifaces_cfg:
            if iface not in batman_ifaces_real:
                 ifaces_ok = 1

        # Interfaces active but not configured (or ignored)?
        for iface in batman_ifaces_real:
            if iface not in batman_ifaces_cfg:
                 if iface_ignore_re and iface_ignore_re.match (iface):
                     batman_ifaces_real_tagged.append ("(%s)" % iface)
                     continue
                 ifaces_ok = 1
            else:
                batman_ifaces_real_tagged.append (iface)

        # Produce sorted list of active and ignored interfaces
        ifaces_str = " ".join (batman_ifaces_real_tagged)
        ifaceobjcurr.update_config_with_status ('batman-ifaces', ifaces_str, ifaces_ok)
        ifaceobjcurr.update_config_with_status ('batman-ifaces-ignore-regex', iface_ignore_re_str, 0)

        # Check Hop Penalty
        hop_penalty_ok = 0
        if hop_penalty != hop_penalty_curr:
             hop_penalty_ok = 1
        ifaceobjcurr.update_config_with_status ('batman-hop-penalty', hop_penalty_curr, hop_penalty_ok)


    def _query_running (self, ifaceobjrunning):
        if not self.ipcmd.link_exists (ifaceobjrunning.name):
            return

        # XXX Now what?


    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check}
# XXX              'query-running' : _query_running}


    def get_ops (self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys ()


    def _init_command_handlers (self):
        if not self.ipcmd:
            self.ipcmd = iproute2()


    def run (self, ifaceobj, operation, query_ifaceobj = None, **extra_args):
        """ run B.A.T.M.A.N. configuration on the interface object passed as argument

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

        if (operation != 'query-running' and not self._is_batman_device (ifaceobj)):
            return

        self._init_command_handlers ()

        if operation == 'query-checkcurr':
            op_handler (self, ifaceobj, query_ifaceobj)
        else:
            op_handler (self, ifaceobj)
