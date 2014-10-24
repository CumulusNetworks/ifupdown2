#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from sets import Set
from ifupdown.iface import *
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.bridgeutils import brctl
from ifupdownaddons.iproute2 import iproute2
import itertools
import re
import time

class bridge(moduleBase):
    """  ifupdown2 addon module to configure linux bridges """

    _modinfo = { 'mhelp' : 'bridge configuration module',
                 'attrs' : {
                   'bridge-vlan-aware' :
                        {'help' : 'bridge vlan aware',
                         'example' : ['bridge-vlan-aware yes/no']},
                   'bridge-ports' :
                        {'help' : 'bridge ports',
                         'required' : True,
                         'example' : ['bridge-ports swp1.100 swp2.100 swp3.100',
                                      'bridge-ports glob swp1-3.100',
                                      'bridge-ports regex (swp[1|2|3].100)']},
                   'bridge-stp' :
                        {'help': 'bridge-stp yes/no',
                         'example' : ['bridge-stp no'],
                         'validvals' : ['yes', 'on', 'off', 'no'],
                         'default' : 'no'},
                   'bridge-bridgeprio' :
                        {'help': 'bridge priority',
                         'example' : ['bridge-bridgeprio 32768'],
                         'default' : '32768'},
                   'bridge-ageing' :
                       {'help': 'bridge ageing',
                         'example' : ['bridge-ageing 300'],
                         'default' : '300'},
                   'bridge-fd' :
                        { 'help' : 'bridge forward delay',
                          'example' : ['bridge-fd 15'],
                          'default' : '15'},
                   'bridge-gcint' :
                        # XXX: recheck values
                        { 'help' : 'bridge garbage collection interval in secs',
                          'example' : ['bridge-gcint 4'],
                          'default' : '4'},
                   'bridge-hello' :
                        { 'help' : 'bridge set hello time',
                          'example' : ['bridge-hello 2'],
                          'default' : '2'},
                   'bridge-maxage' :
                        { 'help' : 'bridge set maxage',
                          'example' : ['bridge-maxage 20'],
                          'default' : '20'},
                   'bridge-pathcosts' :
                        { 'help' : 'bridge set port path costs',
                          'example' : ['bridge-pathcosts swp1=100 swp2=100'],
                          'default' : '100'},
                   'bridge-portprios' :
                        { 'help' : 'bridge port prios',
                          'example' : ['bridge-portprios swp1=32 swp2=32'],
                          'default' : '32'},
                   'bridge-mclmc' :
                        { 'help' : 'set multicast last member count',
                          'example' : ['bridge-mclmc 2'],
                          'default' : '2'},
                    'bridge-mcrouter' :
                        { 'help' : 'set multicast router',
                          'default' : '1',
                          'example' : ['bridge-mcrouter 1']},
                    'bridge-mcsnoop' :
                        { 'help' : 'set multicast snooping',
                          'default' : '1',
                          'example' : ['bridge-mcsnoop 1']},
                    'bridge-mcsqc' :
                        { 'help' : 'set multicast startup query count',
                          'default' : '2',
                          'example' : ['bridge-mcsqc 2']},
                    'bridge-mcqifaddr' :
                        { 'help' : 'set multicast query to use ifaddr',
                          'default' : '0',
                          'example' : ['bridge-mcqifaddr 0']},
                    'bridge-mcquerier' :
                        { 'help' : 'set multicast querier',
                          'default' : '0',
                          'example' : ['bridge-mcquerier 0']},
                    'bridge-hashel' :
                        { 'help' : 'set hash elasticity',
                          'default' : '4096',
                          'example' : ['bridge-hashel 4096']},
                    'bridge-hashmax' :
                        { 'help' : 'set hash max',
                          'default' : '4096',
                          'example' : ['bridge-hashmax 4096']},
                    'bridge-mclmi' :
                        { 'help' : 'set multicast last member interval (in secs)',
                          'default' : '1',
                          'example' : ['bridge-mclmi 1']},
                    'bridge-mcmi' :
                        { 'help' : 'set multicast membership interval (in secs)',
                          'default' : '260',
                          'example' : ['bridge-mcmi 260']},
                    'bridge-mcqpi' :
                        { 'help' : 'set multicast querier interval (in secs)',
                          'default' : '255',
                          'example' : ['bridge-mcqpi 255']},
                    'bridge-mcqi' :
                        { 'help' : 'set multicast query interval (in secs)',
                          'default' : '125',
                          'example' : ['bridge-mcqi 125']},
                    'bridge-mcqri' :
                        { 'help' : 'set multicast query response interval (in secs)',
                          'default' : '10',
                          'example' : ['bridge-mcqri 10']},
                    'bridge-mcsqi' :
                        { 'help' : 'set multicast startup query interval (in secs)',
                          'default' : '31',
                          'example' : ['bridge-mcsqi 31']},
                    'bridge-mcqv4src' :
                        { 'help' : 'set per VLAN v4 multicast querier source address',
                          'example' : ['bridge-mcqv4src 100=172.16.100.1 101=172.16.101.1']},
                    'bridge-portmcrouter' :
                        { 'help' : 'set port multicast routers',
                          'default' : '1',
                          'example' : ['bridge-portmcrouter swp1=1 swp2=1']},
                    'bridge-portmcfl' :
                        { 'help' : 'port multicast fast leave',
                          'default' : '0',
                          'example' : ['bridge-portmcfl swp1=0 swp2=0']},
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
                          'example' : ['bridge-waitport 4 swp1 swp2']},
                    'bridge-maxwait' :
                        { 'help' : 'forces to time seconds the maximum time ' +
                                'that the Debian bridge setup  scripts will ' +
                                'wait for the bridge ports to get to the ' +
                                'forwarding status, doesn\'t allow factional ' +
                                'part. If it is equal to 0 then no waiting' +
                                ' is done',
                          'default' : '0',
                          'example' : ['bridge-maxwait 3']},
                    'bridge-vids' :
                        { 'help' : 'bridge vlans',
                          'example' : ['bridge-vids 4000']},
                    'bridge-pvid' :
                        { 'help' : 'bridge vlans',
                          'example' : ['bridge-pvid 1']},
                    'bridge-access' :
                        { 'help' : 'bridge access vlans',
                          'example' : ['bridge-access 300']},
                    'bridge-port-vids' :
                        { 'help' : 'bridge vlans',
                          'example' : ['bridge-port-vids bond0=1-1000,1010-1020']},
                    'bridge-port-pvids' :
                        { 'help' : 'bridge port vlans',
                          'example' : ['bridge-port-pvids bond0=100 bond1=200']},
                    'bridge-pathcost' :
                        { 'help' : 'bridge port path cost',
                          'example' : ['bridge-pathcost 10']},
                    'bridge-priority' :
                        { 'help' : 'bridge port priority',
                          'example' : ['bridge-priority 10']},
                    'bridge-multicast-router' :
                        { 'help' : 'bridge multicast router',
                          'example' : ['bridge-multicast-router 1']},
                    'bridge-multicast-fast-leave' :
                        { 'help' : 'bridge multicast fast leave',
                          'example' : ['bridge-multicast-fast-leave 1']},
                    'bridge-igmp-querier-src' :
                        { 'help' : 'bridge igmp querier src',
                          'example' : ['bridge-igmp-querier-src 172.16.101.1']},
                        }}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self.brctlcmd = None
        self._running_vidinfo = {}
        self._running_vidinfo_valid = False

    def _is_bridge(self, ifaceobj):
        if ifaceobj.get_attr_value_first('bridge-ports'):
            return True
        return False

    def _is_bridge_port(self, ifaceobj):
        if self.brctlcmd.is_bridge_port(ifaceobj.name):
            return True
        return False

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        if not self._is_bridge(ifaceobj):
            return None
        return self.parse_port_list(ifaceobj.get_attr_value_first(
                                    'bridge-ports'), ifacenames_all)

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
        ports = ifaceobj.get_attr_value_first('bridge-ports')
        if ports:
            return self.parse_port_list(ports)
        else:
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
                waitportlist = self.parse_port_list(waitportvals[1])
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

    def _add_ports(self, ifaceobj):
        bridgeports = self._get_bridge_port_list(ifaceobj)
        runningbridgeports = []

        self._process_bridge_waitport(ifaceobj, bridgeports)
        # Delete active ports not in the new port list
        if not self.PERFMODE:
            runningbridgeports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
            if runningbridgeports:
                [self.ipcmd.link_set(bport, 'nomaster')
                    for bport in runningbridgeports
                        if not bridgeports or bport not in bridgeports]
            else:
                runningbridgeports = []
        if not bridgeports:
            return
        err = 0
        for bridgeport in Set(bridgeports).difference(Set(runningbridgeports)):
            try:
                if not self.DRYRUN and not self.ipcmd.link_exists(bridgeport):
                    self.log_warn('%s: bridge port %s does not exist'
                                   %(ifaceobj.name, bridgeport))
                    err += 1
                    continue
                self.ipcmd.link_set(bridgeport, 'master', ifaceobj.name)
                self.write_file('/proc/sys/net/ipv6/conf/%s' %bridgeport +
                                '/disable_ipv6', '1')
                self.ipcmd.addr_flush(bridgeport)
            except Exception, e:
                self.log_error(str(e))
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
        for part in rangelist:
            if '-' in part:
                a, b = part.split('-')
                a, b = int(a), int(b)
                result.extend(range(a, b + 1))
            else:
                a = int(part)
                result.append(a)
        return result

    def _diff_vids(self, vids1, vids2):
        vids_to_add = None
        vids_to_del = None

        vids1_ints = self._ranges_to_ints(vids1)
        vids2_ints = self._ranges_to_ints(vids2)
        vids1_diff = Set(vids1_ints).difference(vids2_ints)
        vids2_diff = Set(vids2_ints).difference(vids1_ints)
        if vids1_diff:
            vids_to_add = ['%d' %start if start == end else '%d-%d' %(start, end)
                        for start, end in self._ints_to_ranges(vids1_diff)]
        if vids2_diff:
            vids_to_del = ['%d' %start if start == end else '%d-%d' %(start, end)
                        for start, end in self._ints_to_ranges(vids2_diff)]
        return (vids_to_del, vids_to_add)

    def _compare_vids(self, vids1, vids2):
        """ Returns true if the vids are same else return false """

        vids1_ints = self._ranges_to_ints(vids1)
        vids2_ints = self._ranges_to_ints(vids2)
        if Set(vids1_ints).symmetric_difference(vids2_ints):
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
            if not self.PERFMODE:
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
        if not self.PERFMODE:
            self._running_vidinfo = self.ipcmd.bridge_port_vids_get_all()
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

        # Handle bridge vlan attrs
        running_vidinfo = self._get_running_vidinfo()

        # Install pvids
        attrval = ifaceobj.get_attr_value_first('bridge-port-pvids')
        if attrval:
            portlist = self.parse_port_list(attrval)
            if not portlist:
                self.log_warn('%s: could not parse \'%s %s\''
                              %(ifaceobj.name, attrname, attrval))
                return
            for p in portlist:
                try:
                    (port, pvid) = p.split('=')
                    running_pvid = running_vidinfo.get(port, {}).get('pvid')
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
        attrval = ifaceobj.get_attr_value_first('bridge-port-vids')
        if attrval:
            portlist = self.parse_port_list(attrval)
            if not portlist:
                self.log_warn('%s: could not parse \'%s %s\''
                          %(ifaceobj.name, attrname, attrval))
                return
            for p in portlist:
                try:
                    (port, val) = p.split('=')
                    vids = val.split(',')
                    if running_vidinfo.get(port):
                        (vids_to_del, vids_to_add) = \
                                self._diff_vids(vids,
                                running_vidinfo.get(port).get('vlan'))
                        if vids_to_del:
                            self.ipcmd.bridge_port_vids_del(port, vids_to_del)
                        if vids_to_add:
                            self.ipcmd.bridge_port_vids_add(port, vids_to_add)
                    else:
                        self.ipcmd.bridge_port_vids_add(port, vids)
                except Exception, e:
                    self.log_warn('%s: failed to set vid `%s` (%s)'
                        %(ifaceobj.name, p, str(e)))

        # install vids
        attrval = ifaceobj.get_attr_value_first('bridge-vids')
        if attrval:
            vids = re.split(r'[\s\t]\s*', attrval)
            if running_vidinfo.get(ifaceobj.name):
                (vids_to_del, vids_to_add) = \
                        self._diff_vids(vids,
                            running_vidinfo.get(ifaceobj.name).get('vlan'))
                if vids_to_del:
                    self.ipcmd.bridge_vids_del(ifaceobj.name, vids_to_del)
                if vids_to_add:
                    self.ipcmd.bridge_vids_add(ifaceobj.name, vids_to_add)
            else:
                self.ipcmd.bridge_vids_add(ifaceobj.name, vids)
        else:
            running_vids = running_vidinfo.get(ifaceobj.name)
            if running_vids:
                self.ipcmd.bridge_vids_del(ifaceobj.name, running_vids)

    def _apply_bridge_settings(self, ifaceobj):
        try:
            stp = ifaceobj.get_attr_value_first('bridge-stp')
            if stp:
                self.brctlcmd.set_stp(ifaceobj.name, stp)
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
                              'gcint' :
                                ifaceobj.get_attr_value_first('bridge-gcint'),
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
                self.brctlcmd.set_bridge_attrs(ifaceobj.name, bridgeattrs)
            portattrs = {}
            for attrname, dstattrname in {'bridge-pathcosts' : 'pathcost',
                                'bridge-portprios' : 'portprio',
                                'bridge-portmcrouter' : 'portmcrouter',
                                'bridge-portmcfl' : 'portmcfl'}.items():
                attrval = ifaceobj.get_attr_value_first(attrname)
                if not attrval:
                    continue
                portlist = self.parse_port_list(attrval)
                if not portlist:
                    self.log_warn('%s: could not parse \'%s %s\''
                         %(ifaceobj.name, attrname, attrval))
                    continue
                for p in portlist:
                    try:
                        (port, val) = p.split('=')
                        if not portattrs.get(port):
                            portattrs[port] = {}
                        portattrs[port].update({dstattrname : val})
                    except Exception, e:
                        self.log_warn('%s: could not parse %s (%s)'
                                    %(ifaceobj.name, attrname, str(e)))
            for port, attrdict in portattrs.iteritems():
                self.brctlcmd.set_bridgeport_attrs(ifaceobj.name, port,
                                                   attrdict)
            self._set_bridge_vidinfo_compat(ifaceobj)

            self._set_bridge_mcqv4src_compat(ifaceobj)

            self._process_bridge_maxwait(ifaceobj,
                    self._get_bridge_port_list(ifaceobj))
        except Exception, e:
            self.log_warn(str(e))

    def _apply_bridge_vids(self, bportifaceobj, vids, running_vids, isbridge):
        try:
            if running_vids:
                (vids_to_del, vids_to_add) = \
                    self._diff_vids(vids, running_vids)
                if vids_to_del:
                    self.ipcmd.bridge_vids_del(bportifaceobj.name,
                                               vids_to_del, isbridge)
                if vids_to_add:
                    self.ipcmd.bridge_vids_add(bportifaceobj.name,
                                               vids_to_add, isbridge)
            else:
                self.ipcmd.bridge_vids_add(bportifaceobj.name, vids, isbridge)
        except Exception, e:
                self.log_warn('%s: failed to set vid `%s` (%s)'
                        %(bportifaceobj.name, str(vids), str(e)))

    def _apply_bridge_port_pvids(self, bportifaceobj, pvid, running_pvid):
        # Install pvids
        try:
            if running_pvid:
                if running_pvid != pvid:
                    self.ipcmd.bridge_port_pvid_del(bportifaceobj.name,
                                                    running_pvid)
                    self.ipcmd.bridge_port_pvid_add(bportifaceobj.name, pvid)
        except Exception, e:
            self.log_warn('%s: failed to set pvid `%s` (%s)'
                          %(bportifaceobj.name, pvid, str(e)))

    def _apply_bridge_vlan_aware_port_settings_all(self, bportifaceobj,
                                                   bridge_vids):
        running_vidinfo = self._get_running_vidinfo()
        vids = None
        pvids = None
        bport_access = bportifaceobj.get_attr_value_first('bridge-access')
        if bport_access:
            vids = re.split(r'[\s\t]\s*', bport_access)
            pvids = vids

        bport_vids = bportifaceobj.get_attr_value_first('bridge-vids')
        if bport_vids:
            vids = re.split(r'[\s\t]\s*', bport_vids)

        bport_pvids = bportifaceobj.get_attr_value_first('bridge-pvid')
        if bport_pvids:
            pvids = re.split(r'[\s\t]\s*', bport_pvids)

        if pvids:
            self._apply_bridge_port_pvids(bportifaceobj, pvids[0],
                    running_vidinfo.get(bportifaceobj.name, {}).get('pvid'))
        else:
            self._apply_bridge_port_pvids(bportifaceobj,
                    '1', running_vidinfo.get(bportifaceobj.name,
                    {}).get('pvid'))

        if vids:
            self._apply_bridge_vids(bportifaceobj, vids,
                    running_vidinfo.get(bportifaceobj.name,
                    {}).get('vlan'), False)
        elif bridge_vids:
            self._apply_bridge_vids(bportifaceobj,
                                    bridge_vids, running_vidinfo.get(
                                    bportifaceobj.name, {}).get('vlan'), False)


    def _apply_bridge_port_settings(self, bportifaceobj, bridgename=None,
                                    bridgeifaceobj=None):
        if not bridgename and bridgeifaceobj:
            bridgename = bridgeifaceobj.name
        # Set other stp and igmp attributes
        portattrs = {}
        for attrname, dstattrname in {
            'bridge-pathcost' : 'pathcost',
            'bridge-prio' : 'portprio',
            'bridge-priority' : 'portprio',
            'bridge-mcrouter' : 'portmcrouter',
            'bridge-multicast-router' : 'portmcrouter',
            'bridge-multicast-fast-leave' : 'portmcfl'}.items():
            attrval = bportifaceobj.get_attr_value_first(attrname)
            if not attrval:
                # Check if bridge has that attribute
                if bridgeifaceobj:
                    attrval = bridgeifaceobj.get_attr_value_first(attrname)
                    if not attrval:
                        continue
                else:
                    continue
            portattrs[dstattrname] = attrval
        try:
            self.brctlcmd.set_bridgeport_attrs(bridgename,
                            bportifaceobj.name, portattrs)
        except Exception, e:
            self.log_warn(str(e))

    def _apply_bridge_port_settings_all(self, ifaceobj,
                                        ifaceobj_getfunc=None):
        bridge_vlan_aware = ifaceobj.get_attr_value_first(
                                           'bridge-vlan-aware')
        if bridge_vlan_aware and bridge_vlan_aware == 'yes':
           bridge_vlan_aware = True
        else:
           bridge_vlan_aware = False

        if (ifaceobj.get_attr_value_first('bridge-port-vids') and
                ifaceobj.get_attr_value_first('bridge-port-pvids')):
            # Old style bridge port vid info
            # skip new style setting on ports
            return
        self.logger.info('%s: applying bridge configuration '
                         %ifaceobj.name + 'specific to ports')

        bridge_vids = ifaceobj.get_attr_value_first('bridge-vids')
        if bridge_vids:
           bridge_vids = re.split(r'[\s\t]\s*', bridge_vids)
        else:
           bridge_vids = None

        bridgeports = self._get_bridge_port_list(ifaceobj)
        for bport in bridgeports:
            # Use the brctlcmd bulk set method: first build a dictionary
            # and then call set
            self.logger.info('%s: processing bridge config for port %s'
                             %(ifaceobj.name, bport))
            bportifaceobjlist = ifaceobj_getfunc(bport)
            if not bportifaceobjlist:
               continue
            for bportifaceobj in bportifaceobjlist:
                # Add attributes specific to the vlan aware bridge
                if bridge_vlan_aware:
                   self._apply_bridge_vlan_aware_port_settings_all(
                                bportifaceobj, bridge_vids)
                self._apply_bridge_port_settings(
                                bportifaceobj, bridgeifaceobj=ifaceobj)

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        # Check if bridge port
        if self._is_bridge_port(ifaceobj):
            bridgename = ifaceobj.upperifaces[0]
            if not bridgename:
               self.logger.warn('%s: unable to determine bridge name'
                                %ifaceobj.name)
               return
            self._apply_bridge_port_settings(ifaceobj, bridgename=bridgename)
            return

        if not self._is_bridge(ifaceobj):
            return
        try:
            porterr = False
            porterrstr = ''
            self.ipcmd.batch_start()
            if not self.PERFMODE:
                if not self.ipcmd.link_exists(ifaceobj.name):
                    self.ipcmd.link_create(ifaceobj.name, 'bridge')
            else:
                self.ipcmd.link_create(ifaceobj.name, 'bridge')
            try:
                self._add_ports(ifaceobj)
            except Exception, e:
                porterr = True
                porterrstr = str(e)
                pass
            finally:
                self.ipcmd.batch_commit()
            self._apply_bridge_settings(ifaceobj)
            self._apply_bridge_port_settings_all(ifaceobj,
                            ifaceobj_getfunc=ifaceobj_getfunc)
            self._flush_running_vidinfo()
        except Exception, e:
            self.log_error(str(e))
        if porterr:
            raise Exception(porterrstr)

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        try:
            if ifaceobj.get_attr_value_first('bridge-ports'):
                ports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
                if ports:
                    for p in ports:
                        proc_file = ('/proc/sys/net/ipv6/conf/%s' %p +
                                     '/disable_ipv6')
                        self.write_file(proc_file, '0')
                self.brctlcmd.delete_bridge(ifaceobj.name)
        except Exception, e:
            self.log_error(str(e))

    def _query_running_vidinfo(self, ifaceobjrunning, ports):
        running_attrs = {}
        running_vidinfo = self._get_running_vidinfo()
        if ports:
            running_bridge_port_vids = ''
            for p in ports:
                try:
                    running_vids = running_vidinfo.get(p, {}).get('vlan')
                    if running_vids:
                        running_bridge_port_vids += ' %s=%s' %(p,
                                                      ','.join(running_vids))
                except Exception:
                    pass
            running_attrs['bridge-port-vids'] = running_bridge_port_vids

            running_bridge_port_pvids = ''
            for p in ports:
                try:
                    running_pvids = running_vidinfo.get(p, {}).get('pvid')
                    if running_pvids:
                        running_bridge_port_pvids += ' %s=%s' %(p,
                                                        running_pvids)
                except Exception:
                    pass
            running_attrs['bridge-port-pvids'] = running_bridge_port_pvids

        running_bridge_vids = running_vidinfo.get(ifaceobjrunning.name,
                                                  {}).get('vlan')
        if running_bridge_vids:
            running_attrs['bridge-vids'] = ','.join(running_bridge_vids)
        return running_attrs

    def _query_running_mcqv4src(self, ifaceobjrunning):
        running_mcqv4src = self.brctlcmd.get_mcqv4src(ifaceobjrunning.name)
        mcqs = ['%s=%s' %(v, i) for v, i in running_mcqv4src.items()]
        mcqs.sort()
        mcq = ' '.join(mcqs)
        return mcq

    def _query_running_attrs(self, ifaceobjrunning):
        bridgeattrdict = {}
        userspace_stp = 0
        ports = None
        skip_kernel_stp_attrs = 0

        if self.sysctl_get('net.bridge.bridge-stp-user-space') == '1':
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
            if v != self.get_mod_subattr(attrname, 'default'):
                bridgeattrdict[attrname] = [v]

        bridgevidinfo = self._query_running_vidinfo(ifaceobjrunning, ports)
        if bridgevidinfo:
            bridgeattrdict.update({k : [v] for k, v in bridgevidinfo.items()
                                    if v})

        mcq = self._query_running_mcqv4src(ifaceobjrunning)
        if mcq:
            bridgeattrdict['bridge-mcqv4src'] = [mcq]

        if skip_kernel_stp_attrs:
            return bridgeattrdict

        if ports:
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

    def _query_check_vidinfo(self, ifaceobj, ifaceobjcurr):

        err = 0
        running_vidinfo = self.ipcmd.bridge_port_vids_get_all()
        attrval = ifaceobj.get_attr_value_first('bridge-port-vids')
        if attrval:
            running_bridge_port_vids = ''
            portlist = self.parse_port_list(attrval)
            if not portlist:
                self.log_warn('%s: could not parse \'%s %s\''
                          %(ifaceobj.name, attrname, attrval))
                return
            err = 0
            for p in portlist:
                try:
                    (port, val) = p.split('=')
                    vids = val.split(',')
                    running_vids = running_vidinfo.get(port, {}).get('vlan')
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

        # Install pvids
        attrval = ifaceobj.get_attr_value_first('bridge-port-pvids')
        if attrval:
            portlist = self.parse_port_list(attrval)
            if not portlist:
                self.log_warn('%s: could not parse \'%s %s\''
                              %(ifaceobj.name, attrname, attrval))
                return
            running_bridge_port_pvids = ''
            err = 0
            for p in portlist:
                try:
                    (port, pvid) = p.split('=')
                    running_pvid = running_vidinfo.get(port, {}).get('pvid')
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
            vids = re.split(r'[\s\t]\s*', attrval)
            running_vids = running_vidinfo.get(ifaceobj.name, {}).get('vlan')
            if running_vids:
                if self._compare_vids(vids, running_vids):
                    ifaceobjcurr.update_config_with_status('bridge-vids',
                                                           attrval, 0)
                else:
                    ifaceobjcurr.update_config_with_status('bridge-vids',
                                                ','.join(running_vids), 1)
            else:
                ifaceobjcurr.update_config_with_status('bridge-vids', attrval,
                                                       1)

    def _query_check(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        if not self._is_bridge(ifaceobj):
            return
        if not self.brctlcmd.bridge_exists(ifaceobj.name):
            self.logger.info('%s: bridge: does not exist' %(ifaceobj.name))
            ifaceobjcurr.status = ifaceStatus.NOTFOUND
            return
        ifaceattrs = self.dict_key_subset(ifaceobj.config,
                                          self.get_mod_attrs())
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
        filterattrs = ['bridge-vids', 'bridge-port-vids',
                       'bridge-port-pvids']
        for k in Set(ifaceattrs).difference(filterattrs):
            # get the corresponding ifaceobj attr
            v = ifaceobj.get_attr_value_first(k)
            if not v:
               continue
            rv = runningattrs.get(k[7:])
            if k == 'bridge-mcqv4src':
               continue
            if k == 'bridge-stp':
               # special case stp compare because it may
               # contain more than one valid values
               stp_on_vals = ['on', 'yes']
               stp_off_vals = ['off']
               if ((v in stp_on_vals and rv in stp_on_vals) or
                   (v in stp_off_vals and rv in stp_off_vals)):
                    ifaceobjcurr.update_config_with_status('bridge-stp',
                               v, 0)
               else:
                    ifaceobjcurr.update_config_with_status('bridge-stp',
                                v, 1)
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
                  if not difference:
                     portliststatus = 0
                  ifaceobjcurr.update_config_with_status('bridge-ports',
                              ' '.join(running_port_list)
                              if running_port_list else '', portliststatus)
            elif (k == 'bridge-pathcosts' or
                  k == 'bridge-portprios' or k == 'bridge-portmcrouter'
                  or k == 'bridge-portmcfl'):
               brctlcmdattrname = k[11:].rstrip('s')
               # for port attributes, the attributes are in a list
               # <portname>=<portattrvalue>
               status = 0
               currstr = ''
               vlist = self.parse_port_list(v)
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
               ifaceobjcurr.update_config_with_status(k, 'notfound', 1)
               continue
            elif v != rv:
               ifaceobjcurr.update_config_with_status(k, rv, 1)
            else:
               ifaceobjcurr.update_config_with_status(k, rv, 0)

            self._query_check_vidinfo(ifaceobj, ifaceobjcurr)

            self._query_check_mcqv4src(ifaceobj, ifaceobjcurr)

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        if not self.brctlcmd.bridge_exists(ifaceobjrunning.name):
            return
        ifaceobjrunning.update_config_dict(self._query_running_attrs(
                                           ifaceobjrunning))

    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        flags = self.get_flags()
        if not self.ipcmd:
            self.ipcmd = iproute2(**flags)
        if not self.brctlcmd:
            self.brctlcmd = brctl(**flags)

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
        self._flush_running_vidinfo()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
        else:
            op_handler(self, ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
