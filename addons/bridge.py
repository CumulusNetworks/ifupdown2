#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from sets import Set
from ifupdown.iface import *
import ifupdown.policymanager as policymanager
from ifupdown.utils import utils
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.bridgeutils import brctl
from ifupdownaddons.iproute2 import iproute2
from collections import Counter
from ifupdown.netlink import netlink
import ifupdown.ifupdownflags as ifupdownflags
import itertools
import re
import time

class bridgeFlags:
    PORT_PROCESSED = 0x1
    PORT_PROCESSED_OVERRIDE = 0x2

class bridge(moduleBase):
    """  ifupdown2 addon module to configure linux bridges """

    _modinfo = { 'mhelp' : 'Bridge configuration module. Supports both ' +
                    'vlan aware and non vlan aware bridges. For the vlan ' +
                    'aware bridge, the port specific attributes must be ' +
                    'specified under the port. And for vlan unaware bridge ' +
                    'port specific attributes must be specified under the ' +
                    'bridge.',
                 'attrs' : {
                   'bridge-vlan-aware' :
                        {'help' : 'vlan aware bridge. Setting this ' +
                                  'attribute to yes enables vlan filtering' +
                                  ' on the bridge',
                         'validvals' : ['yes', 'no'],
                         'example' : ['bridge-vlan-aware yes/no']},
                   'bridge-ports' :
                        {'help' : 'bridge ports',
                         'multivalue' : True,
                         'required' : True,
                         'validvals': ['<interface-list>'],
                         'example' : ['bridge-ports swp1.100 swp2.100 swp3.100',
                                      'bridge-ports glob swp1-3.100',
                                      'bridge-ports regex (swp[1|2|3].100)']},
                   'bridge-ports-condone-regex' :
                        {'help' : 'bridge ports to ignore/condone when reloading config / removing interfaces',
                         'required' : False,
                         'example' : [ 'bridge-ports-condone-regex ^[a-zA-Z0-9]+_v[0-9]{1,4}$']},
                   'bridge-stp' :
                        {'help': 'bridge-stp yes/no',
                         'example' : ['bridge-stp no'],
                         'validvals' : ['yes', 'on', 'off', 'no'],
                         'default' : 'no'},
                   'bridge-bridgeprio' :
                        {'help': 'bridge priority',
                         'validrange' : ['0', '65535'],
                         'example' : ['bridge-bridgeprio 32768'],
                         'default' : '32768'},
                   'bridge-ageing' :
                       {'help': 'bridge ageing',
                         'validrange' : ['0', '65535'],
                         'example' : ['bridge-ageing 300'],
                         'default' : '300'},
                   'bridge-fd' :
                        { 'help' : 'bridge forward delay',
                          'validrange' : ['0', '255'],
                          'example' : ['bridge-fd 15'],
                          'default' : '15'},
                   'bridge-gcint' :
                        # XXX: recheck values
                        { 'help' : 'bridge garbage collection interval in secs',
                          'validrange' : ['0', '255'],
                          'example' : ['bridge-gcint 4'],
                          'default' : '4',
                          'compat' : True,
                          'deprecated': True},
                   'bridge-hello' :
                        { 'help' : 'bridge set hello time',
                          'validrange' : ['0', '255'],
                          'example' : ['bridge-hello 2'],
                          'default' : '2'},
                   'bridge-maxage' :
                        { 'help' : 'bridge set maxage',
                          'validrange' : ['0', '255'],
                          'example' : ['bridge-maxage 20'],
                          'default' : '20'},
                   'bridge-pathcosts' :
                        { 'help' : 'bridge set port path costs',
                          'validvals': ['<interface-range-list>'],
                          'validrange' : ['0', '65535'],
                          'example' : ['under the bridge: bridge-pathcosts swp1=100 swp2=100',
                                       'under the port (recommended): bridge-pathcosts 100'],
                          'default' : '100'},
                   'bridge-portprios' :
                        { 'help' : 'bridge port prios',
                          'validvals': ['<interface-range-list>'],
                          'validrange' : ['0', '65535'],
                          'example' : ['under the bridge: bridge-portprios swp1=32 swp2=32',
                                       'under the port (recommended): bridge-portprios 32'],
                          'default' : '32'},
                   'bridge-mclmc' :
                        { 'help' : 'set multicast last member count',
                          'validrange' : ['0', '255'],
                          'example' : ['bridge-mclmc 2'],
                          'default' : '2'},
                    'bridge-mcrouter' :
                        { 'help' : 'set multicast router',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'yes',
                          'example' : ['bridge-mcrouter yes']},
                    'bridge-mcsnoop' :
                        { 'help' : 'set multicast snooping',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'yes',
                          'example' : ['bridge-mcsnoop yes']},
                    'bridge-mcsqc' :
                        { 'help' : 'set multicast startup query count',
                          'validrange' : ['0', '255'],
                          'default' : '2',
                          'example' : ['bridge-mcsqc 2']},
                    'bridge-mcqifaddr' :
                        { 'help' : 'set multicast query to use ifaddr',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'no',
                          'example' : ['bridge-mcqifaddr no']},
                    'bridge-mcquerier' :
                        { 'help' : 'set multicast querier',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'no',
                          'example' : ['bridge-mcquerier no']},
                    'bridge-hashel' :
                        { 'help' : 'set hash elasticity',
                          'validrange' : ['0', '4096'],
                          'default' : '4096',
                          'example' : ['bridge-hashel 4096']},
                    'bridge-hashmax' :
                        { 'help' : 'set hash max',
                          'validrange' : ['0', '4096'],
                          'default' : '4096',
                          'example' : ['bridge-hashmax 4096']},
                    'bridge-mclmi' :
                        { 'help' : 'set multicast last member interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '1',
                          'example' : ['bridge-mclmi 1']},
                    'bridge-mcmi' :
                        { 'help' : 'set multicast membership interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '260',
                          'example' : ['bridge-mcmi 260']},
                    'bridge-mcqpi' :
                        { 'help' : 'set multicast querier interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '255',
                          'example' : ['bridge-mcqpi 255']},
                    'bridge-mcqi' :
                        { 'help' : 'set multicast query interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '125',
                          'example' : ['bridge-mcqi 125']},
                    'bridge-mcqri' :
                        { 'help' : 'set multicast query response interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '10',
                          'example' : ['bridge-mcqri 10']},
                    'bridge-mcsqi' :
                        { 'help' : 'set multicast startup query interval (in secs)',
                          'validrange' : ['0', '255'],
                          'default' : '31',
                          'example' : ['bridge-mcsqi 31']},
                    'bridge-mcqv4src' :
                        { 'help' : 'set per VLAN v4 multicast querier source address',
                          'validvals' : ['<number-ipv4-list>', ],
                          'multivalue' : True,
                          'compat' : True,
                          'example' : ['bridge-mcqv4src 100=172.16.100.1 101=172.16.101.1']},
                    'bridge-portmcrouter' :
                        { 'help' : 'set port multicast routers',
                          'validvals' : ['<interface-yes-no-0-1-list>'],
                          'default' : 'yes',
                          'example' : ['under the bridge: bridge-portmcrouter swp1=yes swp2=yes',
                                       'under the port (recommended): bridge-portmcrouter yes']},
                    'bridge-portmcfl' :
                        { 'help' : 'port multicast fast leave.',
                          'validvals': ['<interface-range-list>'],
                          'validrange' : ['0', '65535'],
                          'default' : '0',
                          'example' : ['under the bridge: bridge-portmcfl swp1=0 swp2=0',
                                       'under the port (recommended): bridge-portmcfl 0']},
                    'bridge-waitport' :
                        { 'help' : 'wait for a max of time secs for the' +
                                ' specified ports to become available,' +
                                'if no ports are specified then those' +
                                ' specified on bridge-ports will be' +
                                ' used here. Specifying no ports here ' +
                                'should not be used if we are using ' +
                                'regex or \"all\" on bridge_ports,' +
                                'as it wouldnt work.',
                          'default' : '0',
                          'validvals': ['<number-interface-list>'],
                          'example' : ['bridge-waitport 4 swp1 swp2']},
                    'bridge-maxwait' :
                        { 'help' : 'forces to time seconds the maximum time ' +
                                'that the Debian bridge setup scripts will ' +
                                'wait for the bridge ports to get to the ' +
                                'forwarding status, doesn\'t allow factional ' +
                                'part. If it is equal to 0 then no waiting' +
                                ' is done',
                          'validrange' : ['0', '255'],
                          'default' : '0',
                          'example' : ['bridge-maxwait 3']},
                    'bridge-vids' :
                        { 'help' : 'bridge port vids. Can be specified ' +
                                   'under the bridge or under the port. ' +
                                   'If specified under the bridge the ports ' +
                                   'inherit it unless overridden by a ' +
                                   'bridge-vids attribute under the port',
                          'validvals': ['<number-range-list>'],
                          'example' : ['bridge-vids 4000',
                                       'bridge-vids 2000 2200-3000']},
                    'bridge-pvid' :
                        { 'help' : 'bridge port pvid. Must be specified under' +
                                   ' the bridge port',
                          'validrange' : ['0', '4096'],
                          'example' : ['bridge-pvid 1']},
                    'bridge-access' :
                        { 'help' : 'bridge port access vlan. Must be ' +
                                   'specified under the bridge port',
                          'validrange' : ['0', '4096'],
                          'example' : ['bridge-access 300']},
                    'bridge-allow-untagged' :
                        { 'help' : 'indicate if the bridge port accepts ' +
                                   'untagged packets or not.  Must be ' +
                                   'specified under the bridge port. ' +
                                   'Default is \'yes\'',
                          'validvals' : ['yes', 'no'],
                          'example' : ['bridge-allow-untagged yes'],
                          'default' : 'yes'},
                    'bridge-port-vids' :
                        { 'help' : 'bridge vlans',
                          'compat': True,
                          'example' : ['bridge-port-vids bond0=1-1000,1010-1020']},
                    'bridge-port-pvids' :
                        { 'help' : 'bridge port vlans',
                          'compat': True,
                          'example' : ['bridge-port-pvids bond0=100 bond1=200']},
                     }}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self.name = self.__class__.__name__
        self.brctlcmd = None
        self._running_vidinfo = {}
        self._running_vidinfo_valid = False
        self._resv_vlan_range =  self._get_reserved_vlan_range()
        self.logger.debug('%s: using reserved vlan range %s'
                  %(self.__class__.__name__, str(self._resv_vlan_range)))
        default_stp_attr = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__, attr='bridge-stp')
        if (default_stp_attr and (default_stp_attr == 'on' or default_stp_attr == 'yes')):
            self.default_stp_on = True
        else:
            self.default_stp_on = False

        should_warn = policymanager.policymanager_api.\
            get_module_globals(module_name=self.__class__.__name__,
                               attr='warn_on_untagged_bridge_absence')
        self.warn_on_untagged_bridge_absence = should_warn == 'yes'

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        return self.check_bridge_vlan_aware_port(ifaceobj, ifaceobj_getfunc)

    def check_bridge_vlan_aware_port(self, ifaceobj, ifaceobj_getfunc):
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE:
            ports = self._get_bridge_port_list(ifaceobj)
            if not ports:
                return False
            result = True
            for port_name in ports:
                port_obj_l = ifaceobj_getfunc(port_name)
                if port_obj_l and port_obj_l[0].link_kind & ifaceLinkKind.VLAN:
                    self.logger.error('%s: %s: vlan sub-interface is not '
                                      'supported in a vlan-aware bridge'
                                      % (ifaceobj.name, port_name))
                    result = False
            return result
        return True


    def _is_bridge(self, ifaceobj):
        if ifaceobj.get_attr_value_first('bridge-ports'):
            return True
        return False

    def _get_ifaceobj_bridge_ports(self, ifaceobj):
        ports = ifaceobj.get_attr_value('bridge-ports')
        if ports and len(ports) > 1:
            self.log_warn('%s: ignoring duplicate bridge-ports lines: %s'
                          %(ifaceobj.name, ports[1:]))
        if ports:
            if 'none' in ports[0]:
                return []

            return ports[0]

        return None

    def _is_bridge_port(self, ifaceobj):
        if self.brctlcmd.is_bridge_port(ifaceobj.name):
            return True
        return False

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        if not self._is_bridge(ifaceobj):
            return None
        if ifaceobj.link_type != ifaceLinkType.LINK_NA:
           ifaceobj.link_type = ifaceLinkType.LINK_MASTER
        ifaceobj.link_kind |= ifaceLinkKind.BRIDGE
        # for special vlan aware bridges, we need to add another bit
        if ifaceobj.get_attr_value_first('bridge-vlan-aware') == 'yes':
            ifaceobj.link_kind |= ifaceLinkKind.BRIDGE
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE
        ifaceobj.role |= ifaceRole.MASTER
        ifaceobj.dependency_type = ifaceDependencyType.MASTER_SLAVE
        return self.parse_port_list(ifaceobj.name,
                                    self._get_ifaceobj_bridge_ports(ifaceobj),
                                    ifacenames_all)

    def get_dependent_ifacenames_running(self, ifaceobj):
        self._init_command_handlers()
        if not self.brctlcmd.bridge_exists(ifaceobj.name):
            return None
        return self.brctlcmd.get_bridge_ports(ifaceobj.name)

    def _get_bridge_port_list(self, ifaceobj):

        # port list is also available in the previously
        # parsed dependent list. Use that if available, instead
        # of parsing port expr again
        port_list = ifaceobj.lowerifaces
        if port_list:
            return port_list
        ports = self._get_ifaceobj_bridge_ports(ifaceobj)
        if ports:
            return self.parse_port_list(ifaceobj.name, ports)
        else:
            return None

    def _get_bridge_port_condone_regex(self, ifaceobj, get_string = False):
        bridge_port_condone_regex = ifaceobj.get_attr_value_first('bridge-ports-condone-regex')
        # If bridge-ports-ignore-regex is configured, do NOT use the parse_port_list()
        # function to gather a list of ports matching the regex here and now but set
        # up a compiled regex to be used in a match later. This way we try to avoid
        # a race condition where an (possibly VM) interface is created after this
        # function has been called but before the bridgeports are validated.
        if bridge_port_condone_regex:
            if get_string:
                return bridge_port_condone_regex
            return re.compile (r"%s" % bridge_port_condone_regex)
        return None

    def _process_bridge_waitport(self, ifaceobj, portlist):
        waitport_value = ifaceobj.get_attr_value_first('bridge-waitport')
        if not waitport_value: return
        try:
            waitportvals = re.split(r'[\s\t]\s*', waitport_value, 1)
            if not waitportvals: return
            try:
                waitporttime = int(waitportvals[0])
            except:
                self.log_warn('%s: invalid waitport value \'%s\''
                        %(ifaceobj.name, waitporttime))
                return
            if waitporttime <= 0: return
            try:
                waitportlist = self.parse_port_list(ifaceobj.name,
                                                    waitportvals[1])
            except IndexError, e:
                # ignore error and use all bridge ports
                waitportlist = portlist
                pass
            if not waitportlist: return
            self.logger.info('%s: waiting for ports %s to exist ...'
                    %(ifaceobj.name, str(waitportlist)))
            starttime = time.time()
            while ((time.time() - starttime) < waitporttime):
                if all([False for p in waitportlist
                        if not self.ipcmd.link_exists(p)]):
                    break;
                time.sleep(1)
        except Exception, e:
            self.log_warn('%s: unable to process waitport: %s'
                    %(ifaceobj.name, str(e)))

    def _enable_disable_ipv6(self, port, enable='1'):
        try:
            self.write_file('/proc/sys/net/ipv6/conf/%s/disable_ipv6' % port, enable)
        except Exception, e:
            self.logger.info(str(e))

    def handle_ipv6(self, ports, state, ifaceobj=None):
        if ifaceobj and (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VXLAN):
            self._enable_disable_ipv6(ifaceobj.name, state)
        for p in ports:
            self._enable_disable_ipv6(p, state)

    def _pretty_print_add_ports_error(self, errstr, bridgeifaceobj, bridgeports):
        """ pretty print bridge port add errors.
            since the commands are batched and the kernel only returns error
            codes, this function tries to interpret some error codes
            and prints clearer errors """

        if re.search('RTNETLINK answers: Invalid argument', errstr):
            # Cumulus Linux specific error checks
            try:
                if self.sysctl_get('net.bridge.bridge-allow-multiple-vlans') == '0':
                    vlanid = None
                    for bport in bridgeports:
                        ifattrs = bport.split('.')
                        if vlanid:
                            if (len(ifattrs) == 1 or ifattrs[1] != vlanid):
                                self.log_error('%s: ' %bridgeifaceobj.name +
                                               'net.bridge.bridge-allow-multiple-vlans not set, multiple vlans not allowed', bridgeifaceobj)
                                break
                        if len(ifattrs) == 2:
                            vlanid = ifattrs[1]
            except:
                pass
        self.log_error(bridgeifaceobj.name + ': ' + errstr, bridgeifaceobj)

    def _add_ports(self, ifaceobj):
        bridgeports = self._get_bridge_port_list(ifaceobj)
        bridgeportscondoneregex = self._get_bridge_port_condone_regex(ifaceobj)
        runningbridgeports = []
        removedbridgeports = []

        self.ipcmd.batch_start()
        self._process_bridge_waitport(ifaceobj, bridgeports)
        self.ipcmd.batch_start()
        # Delete active ports not in the new port list
        if not ifupdownflags.flags.PERFMODE:
            runningbridgeports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
            if runningbridgeports:
                for bport in runningbridgeports:
                    if not bridgeports or bport not in bridgeports:
                        if bridgeportscondoneregex and bridgeportscondoneregex.match(bport):
                            continue
                        self.ipcmd.link_set(bport, 'nomaster')
                        removedbridgeports.append(bport)
            else:
                runningbridgeports = []
        if not bridgeports:
            self.ipcmd.batch_commit()
            return
        err = 0
        ports = 0
        newbridgeports = Set(bridgeports).difference(Set(runningbridgeports))
        for bridgeport in newbridgeports:
            try:
                if (not ifupdownflags.flags.DRYRUN and
                    not self.ipcmd.link_exists(bridgeport)):
                    self.log_error('%s: bridge port %s does not exist'
                                   %(ifaceobj.name, bridgeport), ifaceobj)
                    err += 1
                    continue
                hwaddress = self.ipcmd.link_get_hwaddress(bridgeport)
                if not self._valid_ethaddr(hwaddress):
                    self.log_warn('%s: skipping port %s, ' %(ifaceobj.name,
                                  bridgeport) + 'invalid ether addr %s'
                                  %hwaddress)
                    continue
                self.ipcmd.link_set(bridgeport, 'master', ifaceobj.name)
                self.ipcmd.addr_flush(bridgeport)
                ports += 1
                if ports == 250:
                    ports = 0
                    self.ipcmd.batch_commit()
                    self.ipcmd.batch_start()
            except Exception, e:
                self.logger.error(str(e))
                pass
        try:
            self.ipcmd.batch_commit()
        except Exception, e:
            self._pretty_print_add_ports_error(str(e), ifaceobj,
                                               bridgeports)
            pass

        # enable ipv6 for ports that were removed
        self.handle_ipv6(removedbridgeports, '0')
        if err:
            self.log_error('bridge configuration failed (missing ports)')


    def _process_bridge_maxwait(self, ifaceobj, portlist):
        maxwait = ifaceobj.get_attr_value_first('bridge-maxwait')
        if not maxwait: return
        try:
            maxwait = int(maxwait)
        except:
            self.log_warn('%s: invalid maxwait value \'%s\'' %(ifaceobj.name,
                    maxwait))
            return
        if not maxwait: return
        self.logger.info('%s: waiting for ports to go to fowarding state ..'
                %ifaceobj.name)
        try:
            starttime = time.time()
            while ((time.time() - starttime) < maxwait):
                if all([False for p in portlist
                    if self.read_file_oneline(
                            '/sys/class/net/%s/brif/%s/state'
                            %(ifaceobj.name, p)) != '3']):
                    break;
                time.sleep(1)
        except Exception, e:
            self.log_warn('%s: unable to process maxwait: %s'
                    %(ifaceobj.name, str(e)))

    def _ints_to_ranges(self, ints):
        for a, b in itertools.groupby(enumerate(ints), lambda (x, y): y - x):
            b = list(b)
            yield b[0][1], b[-1][1]

    def _ranges_to_ints(self, rangelist):
        """ returns expanded list of integers given set of string ranges
        example: ['1', '2-4', '6'] returns [1, 2, 3, 4, 6]
        """
        result = []
        try:
            for part in rangelist:
                if '-' in part:
                    a, b = part.split('-')
                    a, b = int(a), int(b)
                    result.extend(range(a, b + 1))
                else:
                    a = int(part)
                    result.append(a)
        except:
            self.logger.warn('unable to parse vids \'%s\''
                             %''.join(rangelist))
            pass
        return result

    def _compress_into_ranges(self, vids_ints):
        return ['%d' %start if start == end else '%d-%d' %(start, end)
                       for start, end in self._ints_to_ranges(vids_ints)]

    def _diff_vids(self, vids1_ints, vids2_ints):
        vids_to_add = Set(vids1_ints).difference(vids2_ints)
        vids_to_del = Set(vids2_ints).difference(vids1_ints)

        return (vids_to_del, vids_to_add)

    def _compare_vids(self, vids1, vids2, pvid=None):
        """ Returns true if the vids are same else return false """

        vids1_ints = self._ranges_to_ints(vids1)
        vids2_ints = self._ranges_to_ints(vids2)
        set_diff = Set(vids1_ints).symmetric_difference(vids2_ints)
        if pvid and int(pvid) in set_diff:
            set_diff.remove(int(pvid))
        if set_diff:
            return False
        else:
            return True

    def _set_bridge_mcqv4src_compat(self, ifaceobj):
        #
        # Sets old style igmp querier
        #
        attrval = ifaceobj.get_attr_value_first('bridge-mcqv4src')
        if attrval:
            running_mcqv4src = {}
            if not ifupdownflags.flags.PERFMODE:
                running_mcqv4src = self.brctlcmd.get_mcqv4src(ifaceobj.name)
            mcqs = {}
            srclist = attrval.split()
            for s in srclist:
                k, v = s.split('=')
                mcqs[k] = v

            k_to_del = Set(running_mcqv4src.keys()).difference(mcqs.keys())
            for v in k_to_del:
                self.brctlcmd.del_mcqv4src(ifaceobj.name, v)
            for v in mcqs.keys():
                self.brctlcmd.set_mcqv4src(ifaceobj.name, v, mcqs[v])

    def _get_running_vidinfo(self):
        if self._running_vidinfo_valid:
            return self._running_vidinfo
        self._running_vidinfo = {}

        # CM-8161.  Removed check for PERFMODE.  Need the get in all cases
        # including reboot, so that we can configure the pvid correctly.
        self._running_vidinfo = self.ipcmd.bridge_port_vids_get_all_json()
        self._running_vidinfo_valid = True
        return self._running_vidinfo

    def _flush_running_vidinfo(self):
        self._running_vidinfo = {}
        self._running_vidinfo_valid = False

    def _set_bridge_vidinfo_compat(self, ifaceobj):
        #
        # Supports old style vlan vid info format
        # for compatibility
        #
        bridge_port_pvids = ifaceobj.get_attr_value_first('bridge-port-pvids')
        bridge_port_vids = ifaceobj.get_attr_value_first('bridge-port-vids')
        if not bridge_port_pvids and not bridge_port_vids:
            return

        # Handle bridge vlan attrs
        # Install pvids
        if bridge_port_pvids:
            portlist = self.parse_port_list(ifaceobj.name, bridge_port_pvids)
            if not portlist:
                self.log_warn('%s: could not parse \'%s %s\''
                              %(ifaceobj.name, 'bridge-port-pvids',
                                bridge_port_pvids))
                return
            for p in portlist:
                try:
                    (port, pvid) = p.split('=')
                    pvid = int(pvid)
                    running_pvid = self._get_running_pvid(port)
                    if running_pvid:
                        if running_pvid == pvid:
                            continue
                        else:
                            self.ipcmd.bridge_port_pvid_del(port, running_pvid)
                    self.ipcmd.bridge_port_pvid_add(port, pvid)
                except Exception, e:
                    self.log_warn('%s: failed to set pvid `%s` (%s)'
                            %(ifaceobj.name, p, str(e)))

        # install port vids
        if bridge_port_vids:
            portlist = self.parse_port_list(ifaceobj.name, bridge_port_vids)
            if not portlist:
                self.log_warn('%s: could not parse \'%s %s\'' %(ifaceobj.name,
                              'bridge-port-vids', bridge_port_vids))
                return
            for p in portlist:
                try:
                    (port, val) = p.split('=')
                    vids = val.split(',')
                    vids_int =  self._ranges_to_ints(vids)
                    running_vids = self._get_running_vids(port)
                    if running_vids:
                        (vids_to_del, vids_to_add) = \
                                self._diff_vids(vids_int, running_vids)
                        if vids_to_del:
                            self.ipcmd.bridge_port_vids_del(port,
                                    self._compress_into_ranges(vids_to_del))
                        if vids_to_add:
                            self.ipcmd.bridge_port_vids_add(port,
                                    self._compress_into_ranges(vids_to_add))
                    else:
                        self.ipcmd.bridge_port_vids_add(port, vids_int)
                except Exception, e:
                    self.log_warn('%s: failed to set vid `%s` (%s)'
                        %(ifaceobj.name, p, str(e)))

    def _is_running_stp_state_on(self, bridgename):
        """ Returns True if running stp state is on, else False """

        stp_state_file = '/sys/class/net/%s/bridge/stp_state' %bridgename
        if not stp_state_file:
            return False
        running_stp_state = self.read_file_oneline(stp_state_file)
        if running_stp_state and running_stp_state != '0':
            return True
        return False

    def _is_config_stp_state_on(self, ifaceobj):
        """ Returns true if user specified stp state is on, else False """

        stp_attr = ifaceobj.get_attr_value_first('bridge-stp')
        if not stp_attr:
            return self.default_stp_on
        if (stp_attr and (stp_attr == 'on' or stp_attr == 'yes')):
            return True
        return False

    def _apply_bridge_settings(self, ifaceobj):
        try:
            if self._is_config_stp_state_on(ifaceobj):
                if not self._is_running_stp_state_on(ifaceobj.name):
                    self.brctlcmd.set_stp(ifaceobj.name, "on")
                    self.logger.info('%s: stp state reset, reapplying port '
                                     'settings' %ifaceobj.name)
                    ifaceobj.module_flags[ifaceobj.name] = \
                        ifaceobj.module_flags.setdefault(self.name,0) | \
                        bridgeFlags.PORT_PROCESSED_OVERRIDE
            else:
                # If stp not specified and running stp state on, set it to off
                if self._is_running_stp_state_on(ifaceobj.name):
                   self.brctlcmd.set_stp(ifaceobj.name, 'no')

            # Use the brctlcmd bulk set method: first build a dictionary
            # and then call set
            bridgeattrs = { k:v for k,v in
                             {'ageing' :
                                ifaceobj.get_attr_value_first('bridge-ageing'),
                              'bridgeprio' :
                                ifaceobj.get_attr_value_first(
                                                        'bridge-bridgeprio'),
                              'fd' :
                                ifaceobj.get_attr_value_first('bridge-fd'),
                              'hello' :
                                ifaceobj.get_attr_value_first('bridge-hello'),
                              'maxage' :
                                ifaceobj.get_attr_value_first('bridge-maxage'),
                              'mclmc' :
                                ifaceobj.get_attr_value_first('bridge-mclmc'),
                              'mcrouter' :
                                ifaceobj.get_attr_value_first(
                                                            'bridge-mcrouter'),
                              'mcsnoop' :
                                ifaceobj.get_attr_value_first('bridge-mcsnoop'),
                              'mcsqc' :
                                ifaceobj.get_attr_value_first('bridge-mcsqc'),
                              'mcqifaddr' :
                                ifaceobj.get_attr_value_first(
                                                            'bridge-mcqifaddr'),
                              'mcquerier' :
                                ifaceobj.get_attr_value_first(
                                                            'bridge-mcquerier'),
                              'hashel' :
                                ifaceobj.get_attr_value_first('bridge-hashel'),
                              'hashmax' :
                                ifaceobj.get_attr_value_first('bridge-hashmax'),
                              'mclmi' :
                                ifaceobj.get_attr_value_first('bridge-mclmi'),
                              'mcmi' :
                                ifaceobj.get_attr_value_first('bridge-mcmi'),
                              'mcqpi' :
                                ifaceobj.get_attr_value_first('bridge-mcqpi'),
                              'mcqi' :
                                ifaceobj.get_attr_value_first('bridge-mcqi'),
                              'mcqri' :
                                ifaceobj.get_attr_value_first('bridge-mcqri'),
                              'mcsqi' :
                                ifaceobj.get_attr_value_first('bridge-mcsqi')
                               }.items()
                            if v }
            if bridgeattrs:
                utils.support_yesno_attrs(bridgeattrs, ['mcqifaddr',
                                                        'mcquerier',
                                                        'mcrouter',
                                                        'mcsnoop'])
                self.brctlcmd.set_bridge_attrs(ifaceobj.name, bridgeattrs)
            portattrs = {}
            for attrname, dstattrname in {'bridge-pathcosts' : 'pathcost',
                                'bridge-portprios' : 'portprio',
                                'bridge-portmcrouter' : 'portmcrouter',
                                'bridge-portmcfl' : 'portmcfl'}.items():
                attrval = ifaceobj.get_attr_value_first(attrname)
                if not attrval:
                    continue
                portlist = self.parse_port_list(ifaceobj.name, attrval)
                if not portlist:
                    self.log_error('%s: could not parse \'%s %s\''
                         %(ifaceobj.name, attrname, attrval), ifaceobj,
                           raise_error=False)
                    continue
                for p in portlist:
                    try:
                        (port, val) = p.split('=')
                        if not portattrs.get(port):
                            portattrs[port] = {}
                        if attrname == 'bridge-portmcrouter':
                            portattrs[port].update({dstattrname: utils.boolean_support_binary(val)})
                        else:
                            portattrs[port].update({dstattrname : val})
                    except Exception, e:
                        self.log_error('%s: could not parse %s (%s)'
                                       %(ifaceobj.name, attrname, str(e)),
                                         ifaceobj, raise_error=False)
            for port, attrdict in portattrs.iteritems():
                try:
                    self.brctlcmd.set_bridgeport_attrs(ifaceobj.name, port,
                                                       attrdict)
                except Exception, e:
                    self.log_error('%s: %s' %(ifaceobj.name, str(e)), ifaceobj,
                                   raise_error=False)
                    pass
            self._set_bridge_vidinfo_compat(ifaceobj)
            self._set_bridge_mcqv4src_compat(ifaceobj)
            self._process_bridge_maxwait(ifaceobj,
                    self._get_bridge_port_list(ifaceobj))
        except Exception, e:
            self.log_error(str(e), ifaceobj)

    def _check_vids(self, ifaceobj, vids):
        ret = True
        for v in vids:
            try:
                if '-' in v:
                    va, vb = v.split('-')
                    va, vb = int(va), int(vb)
                    if (self._handle_reserved_vlan(va, ifaceobj.name) or
                        self._handle_reserved_vlan(vb, ifaceobj.name)):
                        ret = False
                else:
                    va = int(v)
                    if self._handle_reserved_vlan(va, ifaceobj.name):
                        ret = False
            except Exception:
                self.logger.warn('%s: unable to parse vid \'%s\''
                                 %(ifaceobj.name, v))
        return ret
         
    def _apply_bridge_port_pvids(self, bportifaceobj, pvid, running_pvid):
        # Install pvids
        try:
            if running_pvid:
                if running_pvid != pvid:
                    self.ipcmd.bridge_port_pvid_del(bportifaceobj.name,
                                                    running_pvid)
                self.ipcmd.bridge_port_pvid_add(bportifaceobj.name, pvid)
            else:
                self.ipcmd.bridge_port_pvid_add(bportifaceobj.name, pvid)
        except Exception, e:
            self.log_error('%s: failed to set pvid `%s` (%s)'
                           %(bportifaceobj.name, pvid, str(e)), bportifaceobj)

    def _get_running_pvid(self, ifacename):
        pvid = 0

        running_vidinfo = self._get_running_vidinfo()
        for vinfo in running_vidinfo.get(ifacename, {}):
            v = vinfo.get('vlan')
            pvid = v if 'PVID' in vinfo.get('flags', []) else 0
            if pvid:
                return pvid
        return pvid

    def _get_running_vids(self, ifacename):
        vids = []

        running_vidinfo = self._get_running_vidinfo()
        for vinfo in running_vidinfo.get(ifacename, {}):
            v = vinfo.get('vlan')
            ispvid = True if 'PVID' in vinfo.get('flags', []) else False
            if ispvid:
                pvid = v if 'PVID' in vinfo.get('flags', []) else 0
                if pvid == 1:
                    continue
            vEnd = vinfo.get('vlanEnd')
            if vEnd:
               vids.extend(range(v, vEnd + 1))
            else:
               vids.append(v)
        return vids

    def _get_running_vids_n_pvid(self, ifacename):
        vids = []
        pvid = 0

        running_vidinfo = self._get_running_vidinfo()
        for vinfo in running_vidinfo.get(ifacename, {}):
            v = vinfo.get('vlan')
            ispvid = True if 'PVID' in vinfo.get('flags', []) else False
            if ispvid:
                pvid = v if 'PVID' in vinfo.get('flags', []) else 0
            vEnd = vinfo.get('vlanEnd')
            if vEnd:
               vids.extend(range(v, vEnd + 1))
            else:
               vids.append(v)
        return (vids, pvid)

    def _get_running_vids_n_pvid_str(self, ifacename):
        vids = []
        pvid = None

        (vids, pvid) = self._get_running_vids_n_pvid(ifacename)

        if vids:
            ret_vids = self._compress_into_ranges(vids)
        else:
            ret_vids = None

        if pvid:
            ret_pvid = '%s' %pvid
        else:
            ret_pvid = None
        return (ret_vids, ret_pvid)

    def _get_running_vids_n_pvid_str2(self, ifacename):
        vids = []
        pvid = None


        running_vidinfo = self._get_running_vidinfo()
        for vinfo in running_vidinfo.get(ifacename, {}):
            v = vinfo.get('vlan')
            if not pvid:
                pvid = '%s' %v if 'PVID' in vinfo.get('flags', []) else None
            vEnd = vinfo.get('vlanEnd')
            if vEnd:
               vids.append('%s-%s' %(v, vEnd))
            else:
               vids.append('%s' %v)
        return (vids, pvid)

    def _apply_bridge_vids_and_pvid(self, bportifaceobj, vids, pvid,
                                    isbridge):
        """ This method is a combination of methods _apply_bridge_vids and
            _apply_bridge_port_pvids above. A combined function is
            found necessary to do the deletes first and the adds later
            because kernel does honor vid info flags during deletes.

        """

        vids_int =  self._ranges_to_ints(vids)
        try:
            pvid_int = int(pvid) if pvid else 0
        except Exception:
            self.logger.warn('%s: unable to parse pvid \'%s\''
                             %(bportifaceobj.name, pvid))
            pvid_int = 0
            pass

        vids_to_del = []
        vids_to_add = vids_int
        pvid_to_del = None
        pvid_to_add = pvid_int

        try:
            if not self._check_vids(bportifaceobj, vids):
               return

            (running_vids, running_pvid) = self._get_running_vids_n_pvid(
                                                        bportifaceobj.name)

            if not running_vids and not running_pvid:
                # There cannot be a no running pvid.
                # It might just not be in our cache:
                # this can happen if at the time we were
                # creating the bridge vlan cache, the port
                # was not part of the bridge. And we need
                # to make sure both vids and pvid is not in
                # the cache, to declare that our cache may
                # be stale.
                running_pvid = 1
                running_vids = [1]

            if running_vids:
                (vids_to_del, vids_to_add) = \
                    self._diff_vids(vids_to_add, running_vids)

            if running_pvid:
                if running_pvid != pvid_int and running_pvid != 0:
                    pvid_to_del = running_pvid

            if (pvid_to_del and (pvid_to_del in vids_int) and
                (pvid_to_del not in vids_to_add)):
                # kernel deletes dont take into account
                # bridge vid flags and its possible that
                # the pvid deletes we do end up deleting
                # the vids. Be proactive and add the pvid
                # to the vid add list if it is in the vids
                # and not already part of vids_to_add.
                # This helps with a small corner case:
                #   - running
                #       pvid 100
                #       vid 101 102
                #   - new change is going to move the state to
                #       pvid 101
                #       vid 100 102
                vids_to_add.add(pvid_to_del)
        except Exception, e:
            self.log_error('%s: failed to process vids/pvids'
                           %bportifaceobj.name + ' vids = %s' %str(vids) +
                           'pvid = %s ' %pvid + '(%s)' %str(e),
                           bportifaceobj, raise_error=False)
        try:
            if vids_to_del:
               if pvid_to_add in vids_to_del:
                   vids_to_del.remove(pvid_to_add)
               self.ipcmd.bridge_vids_del(bportifaceobj.name,
                                          self._compress_into_ranges(
                                          vids_to_del), isbridge)
        except Exception, e:
                self.log_warn('%s: failed to del vid `%s` (%s)'
                        %(bportifaceobj.name, str(vids_to_del), str(e)))

        try:
            if pvid_to_del:
               self.ipcmd.bridge_port_pvid_del(bportifaceobj.name,
                                               pvid_to_del)
        except Exception, e:
                self.log_warn('%s: failed to del pvid `%s` (%s)'
                        %(bportifaceobj.name, pvid_to_del, str(e)))

        try:
            if vids_to_add:
               self.ipcmd.bridge_vids_add(bportifaceobj.name,
                                          self._compress_into_ranges(
                                          vids_to_add), isbridge)
        except Exception, e:
                self.log_error('%s: failed to set vid `%s` (%s)'
                               %(bportifaceobj.name, str(vids_to_add),
                                 str(e)), bportifaceobj, raise_error=False)

        try:
            if pvid_to_add and pvid_to_add != running_pvid:
                self.ipcmd.bridge_port_pvid_add(bportifaceobj.name,
                                                pvid_to_add)
        except Exception, e:
                self.log_error('%s: failed to set pvid `%s` (%s)'
                               %(bportifaceobj.name, pvid_to_add, str(e)),
                               bportifaceobj)

    def _apply_bridge_vlan_aware_port_settings_all(self, bportifaceobj,
                                                   bridge_vids=None,
                                                   bridge_pvid=None):
        vids = None
        pvids = None
        vids_final = []
        pvid_final = None
        bport_access = bportifaceobj.get_attr_value_first('bridge-access')
        if bport_access:
            vids = re.split(r'[\s\t]\s*', bport_access)
            pvids = vids
            allow_untagged = 'yes'
        else:
            allow_untagged = bportifaceobj.get_attr_value_first('bridge-allow-untagged') or 'yes'

            bport_vids = bportifaceobj.get_attr_value_first('bridge-vids')
            if bport_vids:
                vids = re.split(r'[\s\t,]\s*', bport_vids)

            bport_pvids = bportifaceobj.get_attr_value_first('bridge-pvid')
            if bport_pvids:
                pvids = re.split(r'[\s\t]\s*', bport_pvids)

        if vids:
            vids_final =  vids
        elif bridge_vids:
            vids_final = bridge_vids

        if allow_untagged == 'yes':
            if pvids:
                pvid_final = pvids[0]
            elif bridge_pvid:
                pvid_final = bridge_pvid
            else:
                pvid_final = '1'
        else:
            pvid_final = None

        self._apply_bridge_vids_and_pvid(bportifaceobj, vids_final,
                                         pvid_final, False)

    def _apply_bridge_port_settings(self, bportifaceobj, bridgename=None,
                                    bridgeifaceobj=None):
        if not bridgename and bridgeifaceobj:
            bridgename = bridgeifaceobj.name
        # Set other stp and igmp attributes
        portattrs = {}
        for attrname, dstattrname in {
            'bridge-pathcosts' : 'pathcost',
            'bridge-portprios' : 'portprio',
            'bridge-portmcrouter' : 'portmcrouter',
            'bridge-portmcfl' : 'portmcfl'}.items():
            attrval = bportifaceobj.get_attr_value_first(attrname)
            if not attrval:
                # Check if bridge has that attribute
                #if bridgeifaceobj:
                #    attrval = bridgeifaceobj.get_attr_value_first(attrname)
                #    if not attrval:
                #        continue
                #else:
                continue
            portattrs[dstattrname] = attrval
        try:
            self.brctlcmd.set_bridgeport_attrs(bridgename,
                            bportifaceobj.name, portattrs)
        except Exception, e:
            self.log_error(str(e), bportifaceobj)

    def _apply_bridge_port_settings_all(self, ifaceobj,
                                        ifaceobj_getfunc=None,
                                        bridge_vlan_aware=False):
        err = False

        if (ifaceobj.get_attr_value_first('bridge-port-vids') and
                ifaceobj.get_attr_value_first('bridge-port-pvids')):
            # Old style bridge port vid info
            # skip new style setting on ports
            return
        self.logger.info('%s: applying bridge configuration '
                         %ifaceobj.name + 'specific to ports')

        bridge_vids = ifaceobj.get_attr_value_first('bridge-vids')
        if bridge_vids:
           bridge_vids = re.split(r'[\s\t,]\s*', bridge_vids)
        else:
           bridge_vids = None

        bridge_pvid = ifaceobj.get_attr_value_first('bridge-pvid')
        if bridge_pvid:
           bridge_pvid = re.split(r'[\s\t]\s*', bridge_pvid)[0]
        else:
           bridge_pvid = None

        if (ifaceobj.module_flags.get(self.name, 0x0) &
                bridgeFlags.PORT_PROCESSED_OVERRIDE):
            port_processed_override = True
        else:
            port_processed_override = False

        bridgeports = self._get_bridge_port_list(ifaceobj)
        if not bridgeports:
           self.logger.debug('%s: cannot find bridgeports' %ifaceobj.name)
           return
        self.ipcmd.batch_start()
        for bport in bridgeports:
            # Use the brctlcmd bulk set method: first build a dictionary
            # and then call set
            if not self.ipcmd.bridge_port_exists(ifaceobj.name, bport):
                self.logger.info('%s: skipping bridge config' %ifaceobj.name +
                        ' for port %s (missing port)' %bport)
                continue
            self.logger.info('%s: processing bridge config for port %s'
                             %(ifaceobj.name, bport))
            bportifaceobjlist = ifaceobj_getfunc(bport)
            if not bportifaceobjlist:
               continue
            for bportifaceobj in bportifaceobjlist:
                # Dont process bridge port if it already has been processed
                # and there is no override on port_processed
                if (not port_processed_override and
                    (bportifaceobj.module_flags.get(self.name,0x0) & 
                     bridgeFlags.PORT_PROCESSED)):
                    continue
                try:
                    # Add attributes specific to the vlan aware bridge
                    if bridge_vlan_aware:
                        self._apply_bridge_vlan_aware_port_settings_all(
                                bportifaceobj, bridge_vids, bridge_pvid)
                        self._apply_bridge_port_settings(bportifaceobj,
                                                 bridgeifaceobj=ifaceobj)
                    elif self.warn_on_untagged_bridge_absence:
                        self._check_untagged_bridge(ifaceobj.name, bportifaceobj, ifaceobj_getfunc)
                except Exception, e:
                    err = True
                    self.logger.warn('%s: %s' %(ifaceobj.name, str(e)))
                    pass
        self.ipcmd.bridge_batch_commit()
        if err:
           raise Exception('%s: errors applying port settings' %ifaceobj.name)

    def _check_untagged_bridge(self, bridgename, bridgeportifaceobj, ifaceobj_getfunc):
        if bridgeportifaceobj.link_kind & ifaceLinkKind.VLAN:
            lower_ifaceobj_list = ifaceobj_getfunc(bridgeportifaceobj.lowerifaces[0])
            if lower_ifaceobj_list and lower_ifaceobj_list[0] and \
                    not lower_ifaceobj_list[0].link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT:
                self.logger.warn('%s: untagged bridge not found. Please configure a bridge with untagged bridge ports to avoid Spanning Tree Interoperability issue.' % bridgename)
                self.warn_on_untagged_bridge_absence = False

    def _get_bridgename(self, ifaceobj):
        for u in ifaceobj.upperifaces:
            if self.ipcmd.is_bridge(u):
                return u
        return None

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        # Check if bridge port and see if we need to add it to the bridge
        add_port = False
        bridgename = self.ipcmd.bridge_port_get_bridge_name(ifaceobj.name)
        if (not bridgename and
            (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT)):
            # get bridgename and add port to bridge
            bridgename = self._get_bridgename(ifaceobj)
            add_port = True
        if bridgename:
            if self.ipcmd.bridge_is_vlan_aware(bridgename):
                if add_port:
                    # add ifaceobj to bridge
                    self.ipcmd.link_set(ifaceobj.name, 'master', bridgename)
                bridge_vids = self._get_bridge_vids(bridgename,
                                                    ifaceobj_getfunc)
                bridge_pvid = self._get_bridge_pvid(bridgename,
                                                    ifaceobj_getfunc)
                self._apply_bridge_vlan_aware_port_settings_all(ifaceobj,
                                                                bridge_vids,
                                                                bridge_pvid)
            self._apply_bridge_port_settings(ifaceobj, bridgename=bridgename)
            ifaceobj.module_flags[self.name] = ifaceobj.module_flags.setdefault(self.name,0) | \
                                              bridgeFlags.PORT_PROCESSED
            return
        if not self._is_bridge(ifaceobj):
            return
        err = False
        errstr = ''
        running_ports = ''
        bridge_just_created = False
        try:
            if not ifupdownflags.flags.PERFMODE:
                if not self.ipcmd.link_exists(ifaceobj.name):
                   self.ipcmd.link_create(ifaceobj.name, 'bridge')
                   bridge_just_created = True
            else:
                self.ipcmd.link_create(ifaceobj.name, 'bridge')
                bridge_just_created = True
        except Exception, e:
            raise Exception(str(e))

        try:
            bridge_vlan_aware = False
            if ifaceobj.get_attr_value_first('bridge-vlan-aware') == 'yes':
                if not self.check_bridge_vlan_aware_port(ifaceobj, ifaceobj_getfunc):
                    return
                bridge_vlan_aware = True
                if (bridge_just_created or
                        not self.ipcmd.bridge_is_vlan_aware(ifaceobj.name)):
                    self.ipcmd.link_set(ifaceobj.name, 'vlan_filtering', '1',
                                        False, "bridge")
                    if not bridge_just_created:
                        ifaceobj.module_flags[self.name] = ifaceobj.module_flags.setdefault(self.name,0) | bridgeFlags.PORT_PROCESSED_OVERRIDE
            elif (not bridge_just_created and
                  ifaceobj.get_attr_value_first('bridge-vlan-aware') == 'no'
                  and self.ipcmd.bridge_is_vlan_aware(ifaceobj.name)):
                  self.ipcmd.link_set(ifaceobj.name, 'vlan_filtering', '0',
                                      False, "bridge")
                  bridge_vlan_aware = False
        except Exception, e:
            raise Exception(str(e))

        try:
            self._add_ports(ifaceobj)
        except Exception, e:
            err = True
            errstr = str(e)
            pass

        try:
            self._apply_bridge_settings(ifaceobj)
        except Exception, e:
            err = True
            errstr = str(e)
            pass

        try:
            running_ports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
            if not running_ports:
               return
            # disable ipv6 for ports that were added to bridge
            self.handle_ipv6(running_ports, '1', ifaceobj=ifaceobj)
            self._apply_bridge_port_settings_all(ifaceobj,
                            ifaceobj_getfunc=ifaceobj_getfunc,
                            bridge_vlan_aware=bridge_vlan_aware)
        except Exception, e:
            err = True
            errstr = str(e)
            pass
        finally:
            if ifaceobj.link_type != ifaceLinkType.LINK_NA:
                for p in running_ports:
                    try:
                        netlink.link_set_updown(p, "up")
                    except Exception, e:
                        self.logger.debug('%s: %s: link set up (%s)'
                                          %(ifaceobj.name, p, str(e)))
                        pass

            if ifaceobj.addr_method == 'manual':
                try:
                    netlink.link_set_updown(ifaceobj.name, "up")
                except Exception as e:
                    self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj)
        if err:
            raise Exception(errstr)

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        try:
            if self._get_ifaceobj_bridge_ports(ifaceobj):
                ports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
                self.brctlcmd.delete_bridge(ifaceobj.name)
                if ports:
                    self.handle_ipv6(ports, '0')
                    if ifaceobj.link_type != ifaceLinkType.LINK_NA:
                        map(lambda p: netlink.link_set_updown(p, "down"),
                            ports)
        except Exception, e:
            self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj)

    def _query_running_vidinfo_compat(self, ifaceobjrunning, ports):
        running_attrs = {}
        if ports:
            running_bridge_port_vids = ''
            for p in ports:
                try:
                    running_vids = self._get_runing_vids(p)
                    if running_vids:
                        running_bridge_port_vids += ' %s=%s' %(p,
                                                      ','.join(running_vids))
                except Exception:
                    pass
            running_attrs['bridge-port-vids'] = running_bridge_port_vids

            running_bridge_port_pvid = ''
            for p in ports:
                try:
                    running_pvid = self._get_runing_pvid(p)
                    if running_pvid:
                        running_bridge_port_pvid += ' %s=%s' %(p,
                                                        running_pvid)
                except Exception:
                    pass
            running_attrs['bridge-port-pvids'] = running_bridge_port_pvid

        running_bridge_vids = self._get_running_vids(ifaceobjrunning.name)
        if running_bridge_vids:
            running_attrs['bridge-vids'] = ','.join(self._compress_into_ranges(running_bridge_vids))
        return running_attrs

    def _query_running_vidinfo(self, ifaceobjrunning, ifaceobj_getfunc,
                               bridgeports=None):
        running_attrs = {}

        # 'bridge-vids' under the bridge is all about 'vids' on the port.
        # so query the ports
        running_bridgeport_vids = []
        running_bridgeport_pvids = []
        for bport in bridgeports:
            (vids, pvid) = self._get_running_vids_n_pvid_str(bport)
            if vids:
                running_bridgeport_vids.append(' '.join(vids))
            if pvid:
                running_bridgeport_pvids.append(pvid)

        bridge_vids = None
        if running_bridgeport_vids: 
           (vidval, freq) = Counter(running_bridgeport_vids).most_common()[0]
           if freq == len(bridgeports):
              running_attrs['bridge-vids'] = vidval
              bridge_vids = vidval.split()

        bridge_pvid = None
        if running_bridgeport_pvids:
           (vidval, freq) = Counter(running_bridgeport_pvids).most_common()[0]
           if freq == len(bridgeports) and vidval != '1':
              running_attrs['bridge-pvid'] = vidval
              bridge_pvid = vidval.split()[0]

        # Go through all bridge ports and find their vids
        for bport in bridgeports:
            bportifaceobj = ifaceobj_getfunc(bport)
            if not bportifaceobj:
               continue
            bport_vids = []
            bport_pvid = None
            (vids, pvid) = self._get_running_vids_n_pvid_str(bport)
            if vids and vids != bridge_vids:
               bport_vids = vids
            if pvid and pvid != bridge_pvid:
               bport_pvid = pvid
            if bport_vids and bport_pvid in bport_vids:
                bport_vids.remove(bport_pvid)
            if (not bport_vids and bport_pvid and bport_pvid != '1'):
               bportifaceobj[0].replace_config('bridge-access', bport_pvid)
               bportifaceobj[0].delete_config('bridge-pvid')
               bportifaceobj[0].delete_config('bridge-vids')
            else:
               if bport_pvid and bport_pvid != '1':
                  bportifaceobj[0].replace_config('bridge-pvid', bport_pvid)
               else:
                  # delete any stale bridge-vids under ports
                  bportifaceobj[0].delete_config('bridge-pvid')
               if bport_vids:
                  bportifaceobj[0].replace_config('bridge-vids',
                                                  ' '.join(bport_vids))
               else:
                  # delete any stale bridge-vids under ports
                  bportifaceobj[0].delete_config('bridge-vids')
        return running_attrs

    def _query_running_mcqv4src(self, ifaceobjrunning):
        running_mcqv4src = self.brctlcmd.get_mcqv4src(ifaceobjrunning.name)
        mcqs = ['%s=%s' %(v, i) for v, i in running_mcqv4src.items()]
        mcqs.sort()
        mcq = ' '.join(mcqs)
        return mcq

    def _query_running_attrs(self, ifaceobjrunning, ifaceobj_getfunc,
                             bridge_vlan_aware=False):
        bridgeattrdict = {}
        userspace_stp = 0
        ports = None
        skip_kernel_stp_attrs = 0

        if self.systcl_get_net_bridge_stp_user_space() == '1':
            userspace_stp = 1

        tmpbridgeattrdict = self.brctlcmd.get_bridge_attrs(ifaceobjrunning.name)
        if not tmpbridgeattrdict:
            self.logger.warn('%s: unable to get bridge attrs'
                    %ifaceobjrunning.name)
            return bridgeattrdict

        # Fill bridge_ports and bridge stp attributes first
        ports = tmpbridgeattrdict.get('ports')
        if ports:
            bridgeattrdict['bridge-ports'] = [' '.join(ports.keys())]
        stp = tmpbridgeattrdict.get('stp', 'no')
        if stp != self.get_mod_subattr('bridge-stp', 'default'):
            bridgeattrdict['bridge-stp'] = [stp]

        if  stp == 'yes' and userspace_stp:
            skip_kernel_stp_attrs = 1

        bool2str = {'0': 'no', '1': 'yes'}
        # pick all other attributes
        for k,v in tmpbridgeattrdict.items():
            if not v:
                continue
            if k == 'ports' or k == 'stp':
                continue

            if skip_kernel_stp_attrs and k[:2] != 'mc':
                # only include igmp attributes if kernel stp is off
                continue
            attrname = 'bridge-' + k
            mod_default = self.get_mod_subattr(attrname, 'default')
            if v != mod_default:
                # convert '0|1' running values to 'no|yes'
                if v in bool2str.keys() and bool2str[v] == mod_default:
                    continue
                bridgeattrdict[attrname] = [v]

        if bridge_vlan_aware:
            bridgevidinfo = self._query_running_vidinfo(ifaceobjrunning,
                                                        ifaceobj_getfunc,
                                                        ports.keys())
        else:
            bridgevidinfo = self._query_running_vidinfo_compat(ifaceobjrunning,
                                                               ports)
        if bridgevidinfo:
           bridgeattrdict.update({k : [v] for k, v in bridgevidinfo.items()
                                  if v})

        mcq = self._query_running_mcqv4src(ifaceobjrunning)
        if mcq:
            bridgeattrdict['bridge-mcqv4src'] = [mcq]

        if skip_kernel_stp_attrs:
            return bridgeattrdict

        # Do this only for vlan-UNAWARE-bridge
        if ports and not bridge_vlan_aware:
            portconfig = {'bridge-pathcosts' : '',
                          'bridge-portprios' : ''}
            for p, v in ports.items():
                v = self.brctlcmd.get_pathcost(ifaceobjrunning.name, p)
                if v and v != self.get_mod_subattr('bridge-pathcosts',
                                                   'default'):
                    portconfig['bridge-pathcosts'] += ' %s=%s' %(p, v)

                v = self.brctlcmd.get_portprio(ifaceobjrunning.name, p)
                if v and v != self.get_mod_subattr('bridge-portprios',
                                                   'default'):
                    portconfig['bridge-portprios'] += ' %s=%s' %(p, v)

            bridgeattrdict.update({k : [v] for k, v in portconfig.items()
                                    if v})

        return bridgeattrdict

    def _query_check_mcqv4src(self, ifaceobj, ifaceobjcurr):
        running_mcqs = self._query_running_mcqv4src(ifaceobj)
        attrval = ifaceobj.get_attr_value_first('bridge-mcqv4src')
        if attrval:
            mcqs = attrval.split()
            mcqs.sort()
            mcqsout = ' '.join(mcqs)
            ifaceobjcurr.update_config_with_status('bridge-mcqv4src',
                         running_mcqs, 1 if running_mcqs != mcqsout else 0)

    def _query_check_bridge_vidinfo(self, ifaceobj, ifaceobjcurr):
        err = 0
        attrval = ifaceobj.get_attr_value_first('bridge-port-vids')
        if attrval:
            running_bridge_port_vids = ''
            portlist = self.parse_port_list(ifaceobj.name, attrval)
            if not portlist:
                self.log_warn('%s: could not parse \'bridge-port-vids %s\''
                          %(ifaceobj.name, attrval))
                return
            err = 0
            for p in portlist:
                try:
                    (port, val) = p.split('=')
                    vids = val.split(',')
                    running_vids = self._get_running_vids(port)
                    if running_vids:
                        if not self._compare_vids(vids, running_vids):
                            err += 1
                            running_bridge_port_vids += ' %s=%s' %(port,
                                                      ','.join(running_vids))
                        else:
                            running_bridge_port_vids += ' %s' %p
                    else:
                        err += 1
                except Exception, e:
                    self.log_warn('%s: failure checking vid %s (%s)'
                        %(ifaceobj.name, p, str(e)))
            if err:
                ifaceobjcurr.update_config_with_status('bridge-port-vids',
                                                 running_bridge_port_vids, 1)
            else:
                ifaceobjcurr.update_config_with_status('bridge-port-vids',
                                                 attrval, 0)

        attrval = ifaceobj.get_attr_value_first('bridge-port-pvids')
        if attrval:
            portlist = self.parse_port_list(ifaceobj.name, attrval)
            if not portlist:
                self.log_warn('%s: could not parse \'bridge-port-pvids %s\''
                              %(ifaceobj.name, attrval))
                return
            running_bridge_port_pvids = ''
            err = 0
            for p in portlist:
                try:
                    (port, pvid) = p.split('=')
                    running_pvid = self._get_running_vids(port)
                    if running_pvid and running_pvid == pvid:
                        running_bridge_port_pvids += ' %s' %p
                    else:
                        err += 1
                        running_bridge_port_pvids += ' %s=%s' %(port,
                                                            running_pvid)
                except Exception, e:
                    self.log_warn('%s: failure checking pvid %s (%s)'
                            %(ifaceobj.name, pvid, str(e)))
            if err:
                ifaceobjcurr.update_config_with_status('bridge-port-pvids',
                                                 running_bridge_port_pvids, 1)
            else:
                ifaceobjcurr.update_config_with_status('bridge-port-pvids',
                                                 running_bridge_port_pvids, 0)

        attrval = ifaceobj.get_attr_value_first('bridge-vids')
        if attrval:
            ifaceobjcurr.update_config_with_status('bridge-vids', attrval, -1)

    def _query_check_bridge(self, ifaceobj, ifaceobjcurr,
                            ifaceobj_getfunc=None):
        if not self._is_bridge(ifaceobj):
            return
        if not self.brctlcmd.bridge_exists(ifaceobj.name):
            self.logger.info('%s: bridge: does not exist' %(ifaceobj.name))
            return

        ifaceattrs = self.dict_key_subset(ifaceobj.config,
                                          self.get_mod_attrs())
        #Add default attributes if --with-defaults is set
        if ifupdownflags.flags.WITHDEFAULTS and 'bridge-stp' not in ifaceattrs:
            ifaceattrs.append('bridge-stp')
        if not ifaceattrs:
            return
        try:
            runningattrs = self.brctlcmd.get_bridge_attrs(ifaceobj.name)
            if not runningattrs:
               self.logger.debug('%s: bridge: unable to get bridge attrs'
                                 %ifaceobj.name)
               runningattrs = {}
        except Exception, e:
            self.logger.warn(str(e))
            runningattrs = {}

        self._query_check_support_yesno_attrs(runningattrs, ifaceobj)

        filterattrs = ['bridge-vids', 'bridge-port-vids',
                       'bridge-port-pvids']
        bridge_port_condone_regex = self._get_bridge_port_condone_regex(ifaceobj)
        for k in Set(ifaceattrs).difference(filterattrs):
            # get the corresponding ifaceobj attr
            v = ifaceobj.get_attr_value_first(k)
            if not v:
                if ifupdownflags.flags.WITHDEFAULTS and k == 'bridge-stp':
                    v = 'on' if self.default_stp_on else 'off'
                else:
                    continue
            rv = runningattrs.get(k[7:])
            if k == 'bridge-mcqv4src':
               continue
            if k == 'bridge-maxwait' or k == 'bridge-waitport':
                ifaceobjcurr.update_config_with_status(k, v, 0)
                continue
            if k == 'bridge-vlan-aware':
                rv = self.ipcmd.bridge_is_vlan_aware(ifaceobj.name)
                if (rv and v == 'yes') or (not rv and v == 'no'):
                    ifaceobjcurr.update_config_with_status('bridge-vlan-aware',
                               v, 0)
                else:
                    ifaceobjcurr.update_config_with_status('bridge-vlan-aware',
                               v, 1)
            elif k == 'bridge-stp':
               # special case stp compare because it may
               # contain more than one valid values
               stp_on_vals = ['on', 'yes']
               stp_off_vals = ['off', 'no']
               if ((v in stp_on_vals and rv in stp_on_vals) or
                   (v in stp_off_vals and rv in stp_off_vals)):
                    ifaceobjcurr.update_config_with_status('bridge-stp',
                               rv, 0)
               else:
                    ifaceobjcurr.update_config_with_status('bridge-stp',
                               rv, 1)
            elif k == 'bridge-ports-condone-regex':
               bridge_port_condone_regex_str = self._get_bridge_port_condone_regex(ifaceobj, True)
               ifaceobjcurr.update_config_with_status(k, bridge_port_condone_regex_str, 0)
            elif k == 'bridge-ports':
               # special case ports because it can contain regex or glob
               running_port_list = rv.keys() if rv else []
               bridge_port_list = self._get_bridge_port_list(ifaceobj)
               if not running_port_list and not bridge_port_list:
                  continue
               portliststatus = 1
               if running_port_list and bridge_port_list:
                  difference = set(running_port_list
                                 ).symmetric_difference(bridge_port_list)
                  running_port_list_pretty = running_port_list
                  if bridge_port_condone_regex:
                      # Drop any condoned port from the difference set
                      difference = [port for port in difference if not bridge_port_condone_regex.match (port)]
                      # Tag all condoned ports in brackets in output
                      running_port_list_pretty = ["(%s)" % port if port not in bridge_port_list and bridge_port_condone_regex.match (port) else port for port in running_port_list]
                  if not difference:
                      portliststatus = 0
                  ifaceobjcurr.update_config_with_status('bridge-ports',
                              ' '.join(running_port_list_pretty)
                              if running_port_list else '', portliststatus)
            elif (k == 'bridge-pathcosts' or
                  k == 'bridge-portprios' or k == 'bridge-portmcrouter'
                  or k == 'bridge-portmcfl'):
               brctlcmdattrname = k[7:].rstrip('s')
               # for port attributes, the attributes are in a list
               # <portname>=<portattrvalue>
               status = 0
               currstr = ''
               vlist = self.parse_port_list(ifaceobj.name, v)
               if not vlist:
                  continue
               for vlistitem in vlist:
                   try:
                      (p, v) = vlistitem.split('=')
                      currv = self.brctlcmd.get_bridgeport_attr(
                                         ifaceobj.name, p,
                                         brctlcmdattrname)
                      if currv:
                          currstr += ' %s=%s' %(p, currv)
                      else:
                          currstr += ' %s=%s' %(p, 'None')
                      if currv != v:
                          status = 1
                   except Exception, e:
                      self.log_warn(str(e))
                   pass
               ifaceobjcurr.update_config_with_status(k, currstr, status)
            elif not rv:
               if k == 'bridge-pvid' or k == 'bridge-vids' or k == 'bridge-allow-untagged':
                   # bridge-pvid and bridge-vids on a bridge does
                   # not correspond directly to a running config
                   # on the bridge. They correspond to default
                   # values for the bridge ports. And they are
                   # already checked against running config of the
                   # bridge port and reported against a bridge port.
                   # So, ignore these attributes under the bridge.
                   # Use '2' for ignore today. XXX: '2' will be
                   # mapped to a defined value in subsequent patches.
                   ifaceobjcurr.update_config_with_status(k, v, 2)
               else:
                   ifaceobjcurr.update_config_with_status(k, 'notfound', 1)
               continue
            elif v != rv:
               ifaceobjcurr.update_config_with_status(k, rv, 1)
            else:
               ifaceobjcurr.update_config_with_status(k, rv, 0)

        self._query_check_bridge_vidinfo(ifaceobj, ifaceobjcurr)

        self._query_check_mcqv4src(ifaceobj, ifaceobjcurr)

    def _get_bridge_vids(self, bridgename, ifaceobj_getfunc):
        ifaceobjs = ifaceobj_getfunc(bridgename)
        for ifaceobj in ifaceobjs:
            vids = ifaceobj.get_attr_value_first('bridge-vids')
            if vids: return re.split(r'[\s\t,]\s*', vids)
        return None

    def _get_bridge_pvid(self, bridgename, ifaceobj_getfunc):
        ifaceobjs = ifaceobj_getfunc(bridgename)
        pvid = None
        for ifaceobj in ifaceobjs:
            pvid = ifaceobj.get_attr_value_first('bridge-pvid')
            if pvid:
                break
        return pvid

    def _get_bridge_name(self, ifaceobj):
        return self.ipcmd.bridge_port_get_bridge_name(ifaceobj.name)

    def _query_check_bridge_port_vidinfo(self, ifaceobj, ifaceobjcurr,
                                         ifaceobj_getfunc, bridgename):
        attr_name = 'bridge-access'
        vid = ifaceobj.get_attr_value_first(attr_name)
        if vid:
            (running_vids, running_pvid) = self._get_running_vids_n_pvid_str(
                                                        ifaceobj.name)
            if (not running_pvid or running_pvid != vid or
                (running_vids and running_vids[0] != vid)):
               ifaceobjcurr.update_config_with_status(attr_name,
                                running_pvid, 1)
            else:
               ifaceobjcurr.update_config_with_status(attr_name, vid, 0)
            return

        (running_vids, running_pvid) = self._get_running_vids_n_pvid_str(
                                                        ifaceobj.name)
        attr_name = 'bridge-pvid'
        pvid = ifaceobj.get_attr_value_first('bridge-pvid')
        if pvid:
            if running_pvid and running_pvid == pvid:
                ifaceobjcurr.update_config_with_status(attr_name,
                                                       running_pvid, 0)
            else:
                ifaceobjcurr.update_config_with_status(attr_name,
                                                       running_pvid, 1)
        elif (not (ifaceobj.flags & iface.HAS_SIBLINGS) or
              ((ifaceobj.flags & iface.HAS_SIBLINGS) and
               (ifaceobj.flags & iface.OLDEST_SIBLING))):
            # if the interface has multiple iface sections,
            # we check the below only for the oldest sibling
            # or the last iface section
            pvid = self._get_bridge_pvid(bridgename, ifaceobj_getfunc)
            if pvid:
                if not running_pvid or running_pvid != pvid:
                    ifaceobjcurr.status = ifaceStatus.ERROR
                    ifaceobjcurr.status_str = 'bridge pvid error'
            elif not running_pvid or running_pvid != '1':
                ifaceobjcurr.status = ifaceStatus.ERROR
                ifaceobjcurr.status_str = 'bridge pvid error'

        attr_name = 'bridge-vids'
        vids = ifaceobj.get_attr_value_first(attr_name)
        if vids:
           vids = re.split(r'[\s\t]\s*', vids)
           if not running_vids or not self._compare_vids(vids, running_vids,
                                                         running_pvid):
               ifaceobjcurr.update_config_with_status(attr_name,
                                            ' '.join(running_vids), 1)
           else:
               ifaceobjcurr.update_config_with_status(attr_name,
                                            ' '.join(vids), 0)
        elif (not (ifaceobj.flags & iface.HAS_SIBLINGS) or
              ((ifaceobj.flags & iface.HAS_SIBLINGS) and
               (ifaceobj.flags & iface.OLDEST_SIBLING))):
           # if the interface has multiple iface sections,
           # we check the below only for the oldest sibling
           # or the last iface section

           # check if it matches the bridge vids
           bridge_vids = self._get_bridge_vids(bridgename, ifaceobj_getfunc)
           if (bridge_vids and (not running_vids  or
                   not self._compare_vids(bridge_vids, running_vids, running_pvid))):
              ifaceobjcurr.status = ifaceStatus.ERROR
              ifaceobjcurr.status_str = 'bridge vid error'

    def _query_check_bridge_port(self, ifaceobj, ifaceobjcurr,
                                 ifaceobj_getfunc):
        if not self._is_bridge_port(ifaceobj):
            # Mark all bridge attributes as failed
            ifaceobjcurr.check_n_update_config_with_status_many(ifaceobj,
                    ['bridge-vids', 'bridge-pvid', 'bridge-access',
                     'bridge-pathcosts', 'bridge-portprios',
                     'bridge-portmcrouter',
                     'bridge-portmcfl'], 1)
            return
        bridgename = self._get_bridge_name(ifaceobj)
        if not bridgename:
            self.logger.warn('%s: unable to determine bridge name'
                             %ifaceobj.name)
            return

        if self.ipcmd.bridge_is_vlan_aware(bridgename):
            self._query_check_bridge_port_vidinfo(ifaceobj, ifaceobjcurr,
                                                  ifaceobj_getfunc,
                                                  bridgename)
        for attr, dstattr in {'bridge-pathcosts' : 'pathcost',
                              'bridge-portprios' : 'portprio',
                              'bridge-portmcrouter' : 'portmcrouter',
                              'bridge-portmcfl' : 'portmcfl' }.items():
            attrval = ifaceobj.get_attr_value_first(attr)
            if not attrval:
                continue

            try:
                running_attrval = self.brctlcmd.get_bridgeport_attr(
                                       bridgename, ifaceobj.name, dstattr)

                if dstattr == 'portmcrouter':
                    if not utils.is_binary_bool(attrval) and running_attrval:
                        running_attrval = utils.get_yesno_boolean(
                            utils.get_boolean_from_string(running_attrval))

                if running_attrval != attrval:
                    ifaceobjcurr.update_config_with_status(attr,
                                            running_attrval, 1)
                else:
                    ifaceobjcurr.update_config_with_status(attr,
                                            running_attrval, 0)
            except Exception, e:
                self.log_warn('%s: %s' %(ifaceobj.name, str(e)))

    def _query_check(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        if self._is_bridge(ifaceobj):
            self._query_check_bridge(ifaceobj, ifaceobjcurr)
        else:
            self._query_check_bridge_port(ifaceobj, ifaceobjcurr,
                                          ifaceobj_getfunc)

    def _query_running_bridge(self, ifaceobjrunning, ifaceobj_getfunc):
        if self.ipcmd.bridge_is_vlan_aware(ifaceobjrunning.name):
            ifaceobjrunning.update_config('bridge-vlan-aware', 'yes')
            ifaceobjrunning.update_config_dict(self._query_running_attrs(
                                               ifaceobjrunning,
                                               ifaceobj_getfunc,
                                               bridge_vlan_aware=True))
        else: 
            ifaceobjrunning.update_config_dict(self._query_running_attrs(
                                               ifaceobjrunning, None))

    def _query_running_bridge_port_attrs(self, ifaceobjrunning, bridgename):
        if self.systcl_get_net_bridge_stp_user_space() == '1':
            return

        v = self.brctlcmd.get_pathcost(bridgename, ifaceobjrunning.name)
        if v and v != self.get_mod_subattr('bridge-pathcosts', 'default'):
            ifaceobjrunning.update_config('bridge-pathcosts', v)

        v = self.brctlcmd.get_pathcost(bridgename, ifaceobjrunning.name)
        if v and v != self.get_mod_subattr('bridge-portprios', 'default'):
            ifaceobjrunning.update_config('bridge-portprios', v)

    def _query_running_bridge_port(self, ifaceobjrunning,
                                   ifaceobj_getfunc=None):

        bridgename = self.ipcmd.bridge_port_get_bridge_name(
                                                ifaceobjrunning.name)
        bridge_vids = None
        bridge_pvid = None
        if not bridgename:
            self.logger.warn('%s: unable to find bridgename'
                             %ifaceobjrunning.name)
            return
        if not self.ipcmd.bridge_is_vlan_aware(bridgename):
            return

        (bridge_port_vids, bridge_port_pvid) = self._get_running_vids_n_pvid_str(
                                                           ifaceobjrunning.name)
        if bridge_port_vids and bridge_port_pvid in bridge_port_vids:
                bridge_port_vids.remove(bridge_port_pvid)

        bridgeifaceobjlist = ifaceobj_getfunc(bridgename)
        if bridgeifaceobjlist:
           bridge_vids = bridgeifaceobjlist[0].get_attr_value('bridge-vids')
           bridge_pvid = bridgeifaceobjlist[0].get_attr_value_first('bridge-pvid')

        if not bridge_port_vids and bridge_port_pvid:
            # must be an access port
            if bridge_port_pvid != '1':
               ifaceobjrunning.update_config('bridge-access',
                                          bridge_port_pvid)
        else:
            if bridge_port_vids:
                if (not bridge_vids or bridge_port_vids != bridge_vids):
                   ifaceobjrunning.update_config('bridge-vids',
                                        ' '.join(bridge_port_vids))
            if bridge_port_pvid and bridge_port_pvid != '1':
                if (not bridge_pvid or (bridge_port_pvid != bridge_pvid)):
                    ifaceobjrunning.update_config('bridge-pvid',
                                        bridge_port_pvid)
        self._query_running_bridge_port_attrs(ifaceobjrunning, bridgename)

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        if self.brctlcmd.bridge_exists(ifaceobjrunning.name):
            self._query_running_bridge(ifaceobjrunning, ifaceobj_getfunc)
        elif self.brctlcmd.is_bridge_port(ifaceobjrunning.name):
            self._query_running_bridge_port(ifaceobjrunning, ifaceobj_getfunc)

    def _query(self, ifaceobj, **kwargs):
        """ add default policy attributes supported by the module """
        if (not (ifaceobj.link_kind & ifaceLinkKind.BRIDGE) or
            ifaceobj.get_attr_value_first('bridge-stp')):
            return
        if self.default_stp_on:
            ifaceobj.update_config('bridge-stp', 'yes')

    def _query_check_support_yesno_attrs(self, runningattrs, ifaceobj):
        for attrl in [['mcqifaddr', 'bridge-mcqifaddr'],
                     ['mcquerier', 'bridge-mcquerier'],
                     ['mcrouter', 'bridge-mcrouter'],
                     ['mcsnoop', 'bridge-mcsnoop']]:
            value = ifaceobj.get_attr_value_first(attrl[1])
            if value and not utils.is_binary_bool(value):
                if attrl[0] in runningattrs:
                    bool = utils.get_boolean_from_string(runningattrs[attrl[0]])
                    runningattrs[attrl[0]] = utils.get_yesno_boolean(bool)
        attrval = ifaceobj.get_attr_value_first('bridge-portmcrouter')
        if attrval:
            portlist = self.parse_port_list(ifaceobj.name, attrval)
            if portlist:
                to_convert = []
                for p in portlist:
                    (port, val) = p.split('=')
                    if not utils.is_binary_bool(val):
                        to_convert.append(port)
                for port in to_convert:
                    runningattrs['ports'][port]['portmcrouter'] = utils.get_yesno_boolean(
                        utils.get_boolean_from_string(runningattrs['ports'][port]['portmcrouter']))

    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running,
               'query' : _query}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = iproute2()
        if not self.brctlcmd:
            self.brctlcmd = brctl()

    def run(self, ifaceobj, operation, query_ifaceobj=None,
            ifaceobj_getfunc=None):
        """ run bridge configuration on the interface object passed as
            argument. Can create bridge interfaces if they dont exist already

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
        op_handler = self._run_ops.get(operation)
        if not op_handler:
           return
        self._init_command_handlers()
        #self._flush_running_vidinfo()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
        else:
            op_handler(self, ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
