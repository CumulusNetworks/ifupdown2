#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
from sets import Set
from ifupdown.iface import *
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.bridgeutils import brctl
from ifupdownaddons.iproute2 import iproute2
from ifupdownaddons.mstpctlutil import mstpctlutil
import traceback

class mstpctlFlags:
    PORT_PROCESSED = 0x1

class mstpctl(moduleBase):
    """  ifupdown2 addon module to configure mstp attributes """

    _modinfo = {'mhelp' : 'mstp configuration module for bridges',
                'attrs' : {
                   'mstpctl-ports' :
                        {'help' : 'mstp ports',
                         'compat' : True},
                   'mstpctl-stp' :
                        {'help': 'bridge stp yes/no',
                         'compat' : True,
                         'default' : 'no'},
                   'mstpctl-treeprio' :
                        {'help': 'tree priority',
                         'default' : '32768',
                         'validrange' : ['0', '65535'],
                         'required' : False,
                         'example' : ['mstpctl-treeprio 32768']},
                   'mstpctl-ageing' :
                        {'help': 'ageing time',
                         'default' : '300',
                         'required' : False,
                         'example' : ['mstpctl-ageing 300']},
                    'mstpctl-maxage' :
                        { 'help' : 'max message age',
                          'default' : '20',
                          'required' : False,
                          'example' : ['mstpctl-maxage 20']},
                    'mstpctl-fdelay' :
                        { 'help' : 'set forwarding delay',
                          'default' : '15',
                          'required' : False,
                          'example' : ['mstpctl-fdelay 15']},
                    'mstpctl-maxhops' :
                        { 'help' : 'bridge max hops',
                          'default' : '15',
                          'required' : False,
                          'example' : ['mstpctl-maxhops 15']},
                    'mstpctl-txholdcount' :
                        { 'help' : 'bridge transmit holdcount',
                          'default' : '6',
                          'required' : False,
                          'example' : ['mstpctl-txholdcount 6']},
                    'mstpctl-forcevers' :
                        { 'help' : 'bridge force stp version',
                          'default' : 'rstp',
                          'required' : False,
                          'example' : ['mstpctl-forcevers rstp']},
                    'mstpctl-portpathcost' :
                        { 'help' : 'bridge port path cost',
                          'default' : '0',
                          'required' : False,
                          'example' : ['mstpctl-portpathcost swp1=0 swp2=1']},
                    'mstpctl-portp2p' :
                        { 'help' : 'bridge port p2p detection mode',
                          'default' : 'auto',
                          'validvals' : ['yes', 'no', 'auto'],
                          'required' : False,
                          'example' : ['mstpctl-portp2p swp1=no swp2=no']},
                    'mstpctl-portrestrrole' :
                        { 'help' :
                          'enable/disable port ability to take root role of the port',
                          'default' : 'no',
                          'validvals' : ['yes', 'no'],
                          'required' : False,
                          'example' : ['mstpctl-portrestrrole swp1=no swp2=no']},
                    'mstpctl-portrestrtcn' :
                        { 'help' :
                          'enable/disable port ability to propagate received topology change notification of the port',
                          'default' : 'no',
                          'validvals' : ['yes', 'no'],
                          'required' : False,
                          'example' : ['mstpctl-portrestrtcn swp1=no swp2=no']},
                    'mstpctl-bpduguard' :
                        { 'help' :
                          'enable/disable bpduguard',
                          'default' : 'no',
                          'validvals' : ['yes', 'no'],
                          'required' : False,
                          'example' : ['mstpctl-bpduguard swp1=no swp2=no']},
                    'mstpctl-treeportprio' : 
                        { 'help' :
                          'port priority for MSTI instance',
                          'default' : '128',
                          'validrange' : ['0', '240'],
                          'required' : False,
                          'example' : ['mstpctl-treeportprio swp1=128 swp2=128']},
                    'mstpctl-hello' :
                        { 'help' : 'set hello time',
                          'default' : '2',
                          'required' : False,
                          'example' : ['mstpctl-hello 2']},
                    'mstpctl-portnetwork' : 
                        { 'help' : 'enable/disable bridge assurance capability for a port',
                          'validvals' : ['yes', 'no'],
                          'default' : 'no',
                          'required' : False,
                          'example' : ['mstpctl-portnetwork swp1=no swp2=no']},
                    'mstpctl-portadminedge' : 
                        { 'help' : 'enable/disable initial edge state of the port',
                          'validvals' : ['yes', 'no'],
                          'default' : 'no',
                          'required' : False,
                          'example' : ['mstpctl-portadminedge swp1=no swp2=no']},
                    'mstpctl-portautoedge' : 
                        { 'help' : 'enable/disable auto transition to/from edge state of the port',
                          'validvals' : ['yes', 'no'],
                          'default' : 'yes',
                          'required' : False,
                          'example' : ['mstpctl-portautoedge swp1=yes swp2=yes']},
                    'mstpctl-treeportcost' : 
                        { 'help' : 'port tree cost',
                          'required' : False},
                    'mstpctl-portbpdufilter' : 
                        { 'help' : 'enable/disable bpdu filter on a port. ' +
                                'syntax varies when defined under a bridge ' +
                                'vs under a port',
                          'validvals' : ['yes', 'no'],
                          'default' : 'no',
                          'required' : False,
                          'example' : ['under a bridge: mstpctl-portbpdufilter swp1=no swp2=no',
                                       'under a port: mstpctl-portbpdufilter yes']},
                        }}

    # Maps mstp bridge attribute names to corresponding mstpctl commands
    # XXX: This can be encoded in the modules dict above
    _attrs_map = OrderedDict([('mstpctl-treeprio' , 'treeprio'),
                  ('mstpctl-ageing' , 'ageing'),
                  ('mstpctl-maxage' , 'maxage'),
                  ('mstpctl-fdelay' , 'fdelay'),
                  ('mstpctl-maxhops' , 'maxhops'),
                  ('mstpctl-txholdcount' , 'txholdcount'),
                  ('mstpctl-forcevers', 'forcevers'),
                  ('mstpctl-hello' , 'hello')])

    # Maps mstp port attribute names to corresponding mstpctl commands
    # XXX: This can be encoded in the modules dict above
    _port_attrs_map = {'mstpctl-portpathcost' : 'portpathcost',
                 'mstpctl-portadminedge' : 'portadminedge',
                 'mstpctl-portautoedge' : 'portautoedge' ,
                 'mstpctl-portp2p' : 'portp2p',
                 'mstpctl-portrestrrole' : 'portrestrrole',
                 'mstpctl-portrestrtcn' : 'portrestrtcn',
                 'mstpctl-bpduguard' : 'bpduguard',
                 'mstpctl-treeportprio' : 'treeportprio',
                 'mstpctl-treeportcost' : 'treeportcost',
                 'mstpctl-portnetwork' : 'portnetwork',
                 'mstpctl-portbpdufilter' : 'portbpdufilter'}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self.name = self.__class__.__name__
        self.brctlcmd = None
        self.mstpctlcmd = None

    def _is_bridge(self, ifaceobj):
        if (ifaceobj.get_attr_value_first('mstpctl-ports') or
                ifaceobj.get_attr_value_first('bridge-ports')):
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
                                    'mstpctl-ports'), ifacenames_all)

    def get_dependent_ifacenames_running(self, ifaceobj):
        self._init_command_handlers()
        if (self.brctlcmd.bridge_exists(ifaceobj.name) and
                not self.mstpctlcmd.mstpbridge_exists(ifaceobj.name)):
            return None
        return self.brctlcmd.get_bridge_ports(ifaceobj.name)

    def _get_bridge_port_list(self, ifaceobj):

        # port list is also available in the previously
        # parsed dependent list. Use that if available, instead
        # of parsing port expr again
        port_list = ifaceobj.lowerifaces
        if port_list:
            return port_list
        ports = ifaceobj.get_attr_value_first('mstpctl-ports')
        if ports:
            return self.parse_port_list(ports)
        else:
            return None

    def _ports_enable_disable_ipv6(self, ports, enable='1'):
        for p in ports:
            try:
                self.write_file('/proc/sys/net/ipv6/conf/%s' %p +
                                '/disable_ipv6', enable)
            except Exception, e:
                self.logger.info(str(e))
                pass

    def _add_ports(self, ifaceobj):
        bridgeports = self._get_bridge_port_list(ifaceobj)

        runningbridgeports = []
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
                self.ipcmd.addr_flush(bridgeport)
            except Exception, e:
                self.log_error(str(e))

        if err:
            self.log_error('error configuring bridge (missing ports)')

    def _apply_bridge_settings(self, ifaceobj):
        check = False if self.PERFMODE else True
        try:
            # set bridge attributes
            for attrname, dstattrname in self._attrs_map.items():
                try:
                    v = ifaceobj.get_attr_value_first(attrname)
                    if not v:
                       continue
                    if attrname == 'mstpctl-treeprio':
                       self.mstpctlcmd.set_bridge_treeprio(ifaceobj.name,
                                v, check)
                    else:
                       self.mstpctlcmd.set_bridge_attr(ifaceobj.name,
                                dstattrname, v, check)
                except Exception, e:
                    self.logger.warn('%s' %str(e))
                    pass

            # set bridge port attributes
            for attrname, dstattrname in self._port_attrs_map.items():
                attrval = ifaceobj.get_attr_value_first(attrname)
                if not attrval:
                    continue
                portlist = self.parse_port_list(attrval)
                if not portlist:
                    self.log_warn('%s: error parsing \'%s %s\''
                         %(ifaceobj.name, attrname, attrval))
                    continue
                for p in portlist:
                    try:
                        (port, val) = p.split('=')
                        # if it is not bridge port, continue
                        if not os.path.exists('/sys/class/net/%s/brport' %port):
                            continue
                        self.mstpctlcmd.set_bridgeport_attr(ifaceobj.name,
                                port, dstattrname, val, check)
                    except Exception, e:
                        self.log_warn('%s: error setting %s (%s)'
                                %(ifaceobj.name, attrname, str(e)))
        except Exception, e:
            self.log_warn(str(e))
            pass

    def _apply_bridge_port_settings(self, ifaceobj, bridgename=None,
                                    bridgeifaceobj=None,
                                    stp_running_on=True,
                                    mstpd_running=True):
        check = False if self.PERFMODE else True
        applied = False
        if not bridgename and bridgeifaceobj:
            bridgename = bridgeifaceobj.name
        # set bridge port attributes
        for attrname, dstattrname in self._port_attrs_map.items():
            attrval = ifaceobj.get_attr_value_first(attrname)
            if not attrval:
               continue
            if not stp_running_on:
               # stp may get turned on at a later point
               self.logger.info('%s: ignoring %s config'
                       %(ifaceobj.name, attrname) +
                       ' (stp on bridge %s is not on yet)' %bridgename)
               continue
            if not mstpd_running:
               continue
            # if its not a bridge port, continue
            if not os.path.exists('/sys/class/net/%s/brport' %ifaceobj.name):
                continue
            try:
               self.mstpctlcmd.set_bridgeport_attr(bridgename,
                           ifaceobj.name, dstattrname, attrval, check)
               applied = True
            except Exception, e:
               self.log_warn('%s: error setting %s (%s)'
                             %(ifaceobj.name, attrname, str(e)))
        return applied

    def _apply_bridge_port_settings_all(self, ifaceobj,
                                        ifaceobj_getfunc=None):
        self.logger.info('%s: applying mstp configuration '
                          %ifaceobj.name + 'specific to ports')
        # Query running bridge ports. and only apply attributes on them
        bridgeports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
        if not bridgeports:
           self.logger.debug('%s: cannot find bridgeports' %ifaceobj.name)
           return
        for bport in bridgeports:
            self.logger.info('%s: processing mstp config for port %s'
                             %(ifaceobj.name, bport))
            if not self.ipcmd.link_exists(bport):
               continue
            if not os.path.exists('/sys/class/net/%s/brport' %bport):
                continue
            bportifaceobjlist = ifaceobj_getfunc(bport)
            if not bportifaceobjlist:
               continue
            for bportifaceobj in bportifaceobjlist:
                # Dont process bridge port if it already has been processed
                if (bportifaceobj.module_flags.get(self.name,0x0) & \
                    mstpctlFlags.PORT_PROCESSED):
                    continue
                try:
                    self._apply_bridge_port_settings(bportifaceobj, 
                                            ifaceobj.name, ifaceobj)
                except Exception, e:
                    self.log_warn(str(e))

    def _is_running_userspace_stp_state_on(self, bridgename):
        stp_state_file = '/sys/class/net/%s/bridge/stp_state' %bridgename
        if not stp_state_file:
            return False
        running_stp_state = self.read_file_oneline(stp_state_file)
        if running_stp_state and running_stp_state == '2':
            return True
        return False

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        # Check if bridge port
        bridgename = self.ipcmd.bridge_port_get_bridge_name(ifaceobj.name)
        if bridgename:
            mstpd_running = (True if self.mstpctlcmd.is_mstpd_running()
                             else False)
            stp_running_on = self._is_running_userspace_stp_state_on(bridgename)
            applied = self._apply_bridge_port_settings(ifaceobj, bridgename,
                                                       None, stp_running_on,
                                                       mstpd_running)
            if applied:
                ifaceobj.module_flags[self.name] = \
                        ifaceobj.module_flags.setdefault(self.name,0) | \
                        mstpctlFlags.PORT_PROCESSED
            return
        if not self._is_bridge(ifaceobj):
            return
        stp = None
        try:
            porterr = False
            porterrstr = ''
            if ifaceobj.get_attr_value_first('mstpctl-ports'):
                # If bridge ports specified with mstpctl attr, create the
                # bridge and also add its ports
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
            running_ports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
            if running_ports:
                # disable ipv6 for ports that were added to bridge
                self._ports_enable_disable_ipv6(running_ports, '1')

            stp = ifaceobj.get_attr_value_first('mstpctl-stp')
            if stp:
               self.set_iface_attr(ifaceobj, 'mstpctl-stp',
                                    self.brctlcmd.set_stp)
            else:
               stp = self.brctlcmd.get_stp(ifaceobj.name)
            if (self.mstpctlcmd.is_mstpd_running() and
                    (stp == 'yes' or stp == 'on')):
                self._apply_bridge_settings(ifaceobj)
                self._apply_bridge_port_settings_all(ifaceobj,
                            ifaceobj_getfunc=ifaceobj_getfunc)
        except Exception, e:
            self.log_error(str(e))
        if porterr:
            raise Exception(porterrstr)

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        if not self._is_bridge(ifaceobj):
            return
        try:
            if ifaceobj.get_attr_value_first('mstpctl-ports'):
                # If bridge ports specified with mstpctl attr, delete the
                # bridge
                ports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
                if ports:
                    self._ports_enable_disable_ipv6(ports, '0')
                self.brctlcmd.delete_bridge(ifaceobj.name)
        except Exception, e:
            self.log_error(str(e))

    def _query_running_attrs(self, ifaceobjrunning):
        bridgeattrdict = {}

        tmpbridgeattrdict = self.mstpctlcmd.get_bridge_attrs(ifaceobjrunning.name)
        if not tmpbridgeattrdict:
            return bridgeattrdict

        for k,v in tmpbridgeattrdict.items():
            if k == 'stp' or not v:
                continue
            if k == 'ports':
                ports = v.keys()
                continue
            attrname = 'mstpctl-' + k
            if v and v != self.get_mod_subattr(attrname, 'default'):
                bridgeattrdict[attrname] = [v]

        ports = self.brctlcmd.get_bridge_ports(ifaceobjrunning.name)
        if ports:
            portconfig = {'mstpctl-portnetwork' : '',
                          'mstpctl-portpathcost' : '',
                          'mstpctl-portadminedge' : '',
                          'mstpctl-portautoedge' : '',
                          'mstpctl-portp2p' : '',
                          'mstpctl-portrestrrole' : '',
                          'mstpctl-portrestrtcn' : '',
                          'mstpctl-bpduguard' : '',
                          'mstpctl-treeportprio' : '',
                          'mstpctl-treeportcost' : ''}

            for p in ports:
                v = self.mstpctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                            p, 'portnetwork')
                if v and v != 'no':
                    portconfig['mstpctl-portnetwork'] += ' %s=%s' %(p, v)

                # XXX: Can we really get path cost of a port ???
                #v = self.mstpctlcmd.get_portpathcost(ifaceobjrunning.name, p)
                #if v and v != self.get_mod_subattr('mstpctl-portpathcost',
                #                                   'default'):
                #    portconfig['mstpctl-portpathcost'] += ' %s=%s' %(p, v)

                v = self.mstpctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                            p, 'portadminedge')
                if v and v != 'no':
                    portconfig['mstpctl-portadminedge'] += ' %s=%s' %(p, v)

                v = self.mstpctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                            p, 'portp2p')
                if v and v != 'no':
                    portconfig['mstpctl-portp2p'] += ' %s=%s' %(p, v)

                v = self.mstpctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                            p, 'portrestrrole')
                if v and v != 'no':
                    portconfig['mstpctl-portrestrrole'] += ' %s=%s' %(p, v)

                v = self.mstpctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                            p, 'portrestrtcn')
                if v and v != 'no':
                    portconfig['mstpctl-portrestrtcn'] += ' %s=%s' %(p, v)

                v = self.mstpctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                            p, 'bpduguard')
                if v and v != 'no':
                    portconfig['mstpctl-bpduguard'] += ' %s=%s' %(p, v)

                # XXX: Can we really get path cost of a port ???
                #v = self.mstpctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                #            p, 'treeprio')
                #if v and v != self.get_mod_subattr('mstpctl-treeportprio',
                #                                   'default'):
                #    portconfig['mstpctl-treeportprio'] += ' %s=%s' %(p, v)

                #v = self.mstpctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
                #            p, 'treecost')
                #if v and v != self.get_mod_subattr('mstpctl-treeportcost',
                #                                   'default'):
                #    portconfig['mstpctl-treeportcost'] += ' %s=%s' %(p, v)

            bridgeattrdict.update({k : [v] for k, v in portconfig.items()
                                    if v})
        return bridgeattrdict

    def _query_check_bridge(self, ifaceobj, ifaceobjcurr):
        # list of attributes that are not supported currently
        blacklistedattrs = ['mstpctl-portpathcost',
                'mstpctl-treeportprio', 'mstpctl-treeportcost']
        if not self.brctlcmd.bridge_exists(ifaceobj.name):
            self.logger.debug('bridge %s does not exist' %ifaceobj.name)
            return
        ifaceattrs = self.dict_key_subset(ifaceobj.config,
                                          self.get_mod_attrs())
        if not ifaceattrs:
            return
        runningattrs = self.mstpctlcmd.get_bridge_attrs(ifaceobj.name)
        if not runningattrs:
            runningattrs = {}
        for k in ifaceattrs:
            # for all mstpctl options
            if k in blacklistedattrs:
                continue
            # get the corresponding ifaceobj attr
            v = ifaceobj.get_attr_value_first(k)
            if not v:
                continue

            # Get the running attribute
            rv = runningattrs.get(k[8:])
            if k == 'mstpctl-stp':
                # special case stp compare because it may
                # contain more than one valid values
                stp_on_vals = ['on', 'yes']
                stp_off_vals = ['off']
                rv = self.brctlcmd.get_stp(ifaceobj.name)
                if ((v in stp_on_vals and rv in stp_on_vals) or
                    (v in stp_off_vals and rv in stp_off_vals)):
                    ifaceobjcurr.update_config_with_status('mstpctl-stp', v, 0)
                else:
                    ifaceobjcurr.update_config_with_status('mstpctl-stp', v, 1)
                continue

            if k == 'mstpctl-ports':
                # special case ports because it can contain regex or glob
                # XXX: We get all info from mstputils, which means if
                # mstpd is down, we will not be returning any bridge bridgeports
                running_port_list = self.brctlcmd.get_bridge_ports(ifaceobj.name)
                bridge_port_list = self._get_bridge_port_list(ifaceobj)
                if not running_port_list and not bridge_port_list:
                    continue
                portliststatus = 1
                if running_port_list and bridge_port_list:
                    difference = Set(running_port_list).symmetric_difference(
                                                        Set(bridge_port_list))
                    if not difference:
                        portliststatus = 0
                ifaceobjcurr.update_config_with_status('mstpctl-ports',
                    ' '.join(running_port_list)
                    if running_port_list else '', portliststatus)
            elif k[:12] == 'mstpctl-port' or k == 'mstpctl-bpduguard':
                # Now, look at port attributes
                # derive the mstpctlcmd attr name
                #mstpctlcmdattrname = k[12:] if k[:12] == 'mstpctl-port' else k[8:]
                mstpctlcmdattrname = k[8:]

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
                        currv = self.mstpctlcmd.get_bridgeport_attr(
                                        ifaceobj.name, p, mstpctlcmdattrname)
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
                ifaceobjcurr.update_config_with_status(k, '', 1)
            elif v != rv:
                ifaceobjcurr.update_config_with_status(k, rv, 1)
            else:
                ifaceobjcurr.update_config_with_status(k, rv, 0)

    def _query_check_bridge_port(self, ifaceobj, ifaceobjcurr):
        if not self.ipcmd.link_exists(ifaceobj.name):
            #self.logger.debug('bridge port %s does not exist' %ifaceobj.name)
            ifaceobjcurr.status = ifaceStatus.NOTFOUND
            return
        # Check if this is a bridge port
        if not self._is_bridge_port(ifaceobj):
            # mark all the bridge attributes as error
            ifaceobjcurr.check_n_update_config_with_status_many(ifaceobj,
                            self._port_attrs_map.keys(), 0)
            return
        bridgename = self.ipcmd.bridge_port_get_bridge_name(ifaceobj.name)
        # list of attributes that are not supported currently
        blacklistedattrs = ['mstpctl-portpathcost',
                'mstpctl-treeportprio', 'mstpctl-treeportcost']
        ifaceattrs = self.dict_key_subset(ifaceobj.config,
                                          self._port_attrs_map.keys())
        if not ifaceattrs:
            return
        runningattrs = self.mstpctlcmd.get_bridge_attrs(ifaceobj.name)
        if not runningattrs:
            runningattrs = {}
        for k in ifaceattrs:
            # for all mstpctl options
            # get the corresponding ifaceobj attr
            v = ifaceobj.get_attr_value_first(k)
            if not v or k in blacklistedattrs:
                ifaceobjcurr.update_config_with_status(k, v, -1)
                continue
            currv = self.mstpctlcmd.get_bridgeport_attr(bridgename,
                             ifaceobj.name, self._port_attrs_map.get(k))
            if currv:
                if currv != v:
                    ifaceobjcurr.update_config_with_status(k, currv, 1)
                else:
                    ifaceobjcurr.update_config_with_status(k, currv, 0)
            else:
                ifaceobjcurr.update_config_with_status(k, None, 1)

    def _query_check(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        if self._is_bridge(ifaceobj):
            self._query_check_bridge(ifaceobj, ifaceobjcurr)
        else:
            self._query_check_bridge_port(ifaceobj, ifaceobjcurr)

    def _query_running_bridge_port(self, ifaceobjrunning):
        bridgename = self.ipcmd.bridge_port_get_bridge_name(
                                ifaceobjrunning.name)
        if not bridgename:
            self.logger.warn('%s: unable to determine bridgename'
                             %ifaceobjrunning.name)
            return
        if self.brctlcmd.get_stp(bridgename) == 'no':
           # This bridge does not run stp, return
           return
        # if userspace stp not set, return
        if self.sysctl_get('net.bridge.bridge-stp-user-space') != '1':
           return
        v = self.mstpctlcmd.get_bridgeport_attr(bridgename,
                                                ifaceobjrunning.name,
                                                'portnetwork')
        if v and v != 'no':
           ifaceobjrunning.update_config('mstpctl-network', v)

        # XXX: Can we really get path cost of a port ???
        #v = self.mstpctlcmd.get_portpathcost(ifaceobjrunning.name, p)
        #if v and v != self.get_mod_subattr('mstpctl-pathcost',
        #                                   'default'):
        #   ifaceobjrunning.update_config('mstpctl-network', v)

        v = self.mstpctlcmd.get_bridgeport_attr(bridgename,
                          ifaceobjrunning.name, 'portadminedge')
        if v and v != 'no':
           ifaceobjrunning.update_config('mstpctl-portadminedge', v)

        v = self.mstpctlcmd.get_bridgeport_attr(bridgename,
                                       ifaceobjrunning.name,'portp2p')
        if v and v != 'auto':
           ifaceobjrunning.update_config('mstpctl-portp2p', v)

        v = self.mstpctlcmd.get_bridgeport_attr(bridgename,
                        ifaceobjrunning.name, 'portrestrrole')
        if v and v != 'no':
           ifaceobjrunning.update_config('mstpctl-portrestrrole', v)

        v = self.mstpctlcmd.get_bridgeport_attr(bridgename,
                            ifaceobjrunning.name, 'restrtcn')
        if v and v != 'no':
           ifaceobjrunning.update_config('mstpctl-portrestrtcn', v)

        v = self.mstpctlcmd.get_bridgeport_attr(bridgename,
                            ifaceobjrunning.name, 'bpduguard')
        if v and v != 'no':
           ifaceobjrunning.update_config('mstpctl-bpduguard', v)

        # XXX: Can we really get path cost of a port ???
        #v = self.mstpctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
        #            p, 'treeprio')
        #if v and v != self.get_mod_subattr('mstpctl-treeportprio',
        #                                   'default'):
        #    portconfig['mstpctl-treeportprio'] += ' %s=%s' %(p, v)

        #v = self.mstpctlcmd.get_bridgeport_attr(ifaceobjrunning.name,
        #               p, 'treecost')
        #if v and v != self.get_mod_subattr('mstpctl-treeportcost',
        #                                   'default'):
        #    portconfig['mstpctl-treeportcost'] += ' %s=%s' %(p, v)

    def _query_running_bridge(self, ifaceobjrunning):
        if self.brctlcmd.get_stp(ifaceobjrunning.name) == 'no':
           # This bridge does not run stp, return
           return
        # if userspace stp not set, return
        if self.sysctl_get('net.bridge.bridge-stp-user-space') != '1':
           return
        # Check if mstp really knows about this bridge
        if not self.mstpctlcmd.mstpbridge_exists(ifaceobjrunning.name):
            return
        ifaceobjrunning.update_config_dict(self._query_running_attrs(
                                           ifaceobjrunning))

    def _query_running(self, ifaceobjrunning, **extra_args):
        if self.brctlcmd.bridge_exists(ifaceobjrunning.name):
            self._query_running_bridge(ifaceobjrunning)
        elif self.brctlcmd.is_bridge_port(ifaceobjrunning.name):
            self._query_running_bridge_port(ifaceobjrunning)

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
        if not self.mstpctlcmd:
            self.mstpctlcmd = mstpctlutil(**flags)

    def run(self, ifaceobj, operation, query_ifaceobj=None,
            ifaceobj_getfunc=None, **extra_args):
        """ run mstp configuration on the interface object passed as argument

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
        if ifaceobj.type == ifaceType.BRIDGE_VLAN:
           return
        op_handler = self._run_ops.get(operation)
        if not op_handler:
           return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
        else:
            op_handler(self, ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
