#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os

from sets import Set

try:
    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.netlink import netlink

    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.policymanager as policymanager

    from ifupdown2.ifupdownaddons.LinkUtils import LinkUtils
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
    from ifupdown2.ifupdownaddons.mstpctlutil import mstpctlutil
    from ifupdown2.ifupdownaddons.systemutils import systemUtils
except ImportError:
    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdown.netlink import netlink

    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.policymanager as policymanager

    from ifupdownaddons.LinkUtils import LinkUtils
    from ifupdownaddons.modulebase import moduleBase
    from ifupdownaddons.mstpctlutil import mstpctlutil
    from ifupdownaddons.systemutils import systemUtils


class mstpctlFlags:
    PORT_PROCESSED = 0x1

class mstpctl(moduleBase):
    """  ifupdown2 addon module to configure mstp attributes """

    _modinfo = {'mhelp' : 'mstp configuration module for bridges',
                'attrs' : {
                   'mstpctl-ports' :
                        {'help' : 'mstp ports',
                         'compat' : True,
                         'deprecated': True,
                         'new-attribute': 'bridge-ports'},
                   'mstpctl-stp' :
                        {'help': 'bridge stp yes/no',
                         'validvals' : ['yes', 'no', 'on', 'off'],
                         'compat' : True,
                         'default' : 'no',
                         'deprecated': True,
                         'new-attribute': 'bridge-stp'},
                   'mstpctl-treeprio' :
                        {'help': 'tree priority',
                         'default' : '32768',
                         'validvals' : ['0', '4096', '8192', '12288', '16384',
                                        '20480', '24576', '28672', '32768',
                                        '36864', '40960', '45056', '49152',
                                        '53248', '57344', '61440'],
                         'required' : False,
                         'example' : ['mstpctl-treeprio 32768']},
                   'mstpctl-ageing' :
                        {'help': 'ageing time',
                         'validrange' : ['0', '4096'],
                         'default' : '300',
                         'required' : False,
                         'jsonAttr': 'ageingTime',
                         'example' : ['mstpctl-ageing 300']},
                    'mstpctl-maxage' :
                        { 'help' : 'max message age',
                          'validrange' : ['0', '255'],
                          'default' : '20',
                          'jsonAttr': 'bridgeMaxAge',
                          'required' : False,
                          'example' : ['mstpctl-maxage 20']},
                    'mstpctl-fdelay' :
                        { 'help' : 'set forwarding delay',
                          'validrange' : ['0', '255'],
                          'default' : '15',
                          'jsonAttr': 'bridgeFwdDelay',
                          'required' : False,
                          'example' : ['mstpctl-fdelay 15']},
                    'mstpctl-maxhops' :
                        { 'help' : 'bridge max hops',
                          'validrange' : ['0', '255'],
                          'default' : '20',
                          'jsonAttr': 'maxHops',
                          'required' : False,
                          'example' : ['mstpctl-maxhops 15']},
                    'mstpctl-txholdcount' :
                        { 'help' : 'bridge transmit holdcount',
                          'validrange' : ['0', '255'],
                          'default' : '6',
                          'jsonAttr': 'txHoldCounter',
                          'required' : False,
                          'example' : ['mstpctl-txholdcount 6']},
                    'mstpctl-forcevers' :
                        { 'help' : 'bridge force stp version',
                          'validvals' : ['rstp', ],
                          'default' : 'rstp',
                          'required' : False,
                          'jsonAttr': 'forceProtocolVersion',
                          'example' : ['mstpctl-forcevers rstp']},
                    'mstpctl-portpathcost' :
                        { 'help' : 'bridge port path cost',
                          'validvals': ['<interface-range-list>'],
                          'validrange' : ['0', '65535'],
                          'default' : '0',
                          'jsonAttr' : 'adminExtPortCost',
                          'required' : False,
                          'example' : ['under the bridge: mstpctl-portpathcost swp1=0 swp2=1',
                                       'under the port (recommended): mstpctl-portpathcost 0']},
                    'mstpctl-portp2p' :
                        { 'help' : 'bridge port p2p detection mode',
                          'default' : 'auto',
                          'jsonAttr' : 'adminPointToPoint',
                          'validvals' : ['<interface-yes-no-auto-list>'],
                          'required' : False,
                          'example' : ['under the bridge: mstpctl-portp2p swp1=yes swp2=no',
                                       'under the port (recommended): mstpctl-portp2p yes']},
                    'mstpctl-portrestrrole' :
                        { 'help' :
                          'enable/disable port ability to take root role of the port',
                          'default' : 'no',
                          'jsonAttr' : 'restrictedRole',
                          'validvals' : ['<interface-yes-no-list>'],
                          'required' : False,
                          'example' : ['under the bridge: mstpctl-portrestrrole swp1=yes swp2=no',
                                       'under the port (recommended): mstpctl-portrestrrole yes']},
                    'mstpctl-portrestrtcn' :
                        { 'help' :
                          'enable/disable port ability to propagate received topology change notification of the port',
                          'default' : 'no',
                          'jsonAttr' : 'restrictedTcn',
                          'validvals' : ['<interface-yes-no-list>'],
                          'required' : False,
                          'example' : ['under the bridge: mstpctl-portrestrtcn swp1=yes swp2=no',
                                       'under the port (recommended): mstpctl-portrestrtcn yes']},
                    'mstpctl-bpduguard' :
                        { 'help' :
                          'enable/disable bpduguard',
                          'default' : 'no',
                          'jsonAttr' : 'bpduGuardPort',
                          'validvals' : ['<interface-yes-no-list>'],
                          'required' : False,
                          'example' : ['under the bridge: mstpctl-bpduguard swp1=yes swp2=no',
                                       'under the port (recommended): mstpctl-bpduguard yes']},
                    'mstpctl-treeportprio' :
                        { 'help': 'Sets the <port>\'s priority MSTI instance. '
                                  'The priority value must be a number between 0 and 240 and a multiple of 16.',
                          'default' : '128',
                          'validvals': ['<interface-range-list-multiple-of-16>'],
                          'validrange' : ['0', '240'],
                          'jsonAttr': 'treeportprio',
                          'required' : False,
                          'example' : ['under the bridge: mstpctl-treeportprio swp1=128 swp2=128',
                                       'under the port (recommended): mstpctl-treeportprio 128']},
                    'mstpctl-hello' :
                        { 'help' : 'set hello time',
                          'validrange' : ['0', '255'],
                          'default' : '2',
                          'required' : False,
                          'jsonAttr': 'helloTime',
                          'example' : ['mstpctl-hello 2']},
                    'mstpctl-portnetwork' :
                        { 'help' : 'enable/disable bridge assurance capability for a port',
                          'validvals' : ['<interface-yes-no-list>'],
                          'default' : 'no',
                          'jsonAttr' : 'networkPort',
                          'required' : False,
                          'example' : ['under the bridge: mstpctl-portnetwork swp1=yes swp2=no',
                                       'under the port (recommended): mstpctl-portnetwork yes']},
                    'mstpctl-portadminedge' :
                        { 'help' : 'enable/disable initial edge state of the port',
                          'validvals' : ['<interface-yes-no-list>'],
                          'default' : 'no',
                          'jsonAttr' : 'adminEdgePort',
                          'required' : False,
                          'example' : ['under the bridge: mstpctl-portadminedge swp1=yes swp2=no',
                                       'under the port (recommended): mstpctl-portadminedge yes']},
                    'mstpctl-portautoedge' :
                        { 'help' : 'enable/disable auto transition to/from edge state of the port',
                          'validvals' : ['<interface-yes-no-list>'],
                          'default' : 'yes',
                          'jsonAttr' : 'autoEdgePort',
                          'required' : False,
                          'example' : ['under the bridge: mstpctl-portautoedge swp1=yes swp2=no',
                                       'under the port (recommended): mstpctl-portautoedge yes']},
                    'mstpctl-treeportcost' :
                        { 'help' : 'port tree cost',
                          'validrange' : ['0', '255'],
                          'required' : False,
                          'jsonAttr': 'extPortCost',
                          },
                    'mstpctl-portbpdufilter' :
                        { 'help' : 'enable/disable bpdu filter on a port. ' +
                                'syntax varies when defined under a bridge ' +
                                'vs under a port',
                          'validvals' : ['<interface-yes-no-list>'],
                          'jsonAttr' : 'bpduFilterPort',
                          'default' : 'no',
                          'required' : False,
                          'example' : ['under a bridge: mstpctl-portbpdufilter swp1=no swp2=no',
                                       'under a port: mstpctl-portbpdufilter yes']},
                        }}

    # Maps mstp bridge attribute names to corresponding mstpctl commands
    # XXX: This can be encoded in the modules dict above
    _attrs_map = OrderedDict([('mstpctl-treeprio' , 'treeprio'),
                  ('mstpctl-ageing' , 'ageing'),
                  ('mstpctl-fdelay' , 'fdelay'),
                  ('mstpctl-maxage' , 'maxage'),
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
        self.mstpd_running = (True if systemUtils.is_process_running('mstpd')
                             else False)

        # Background -
        # The ask is to make "mstpctl-portadminedge yes" part of the default ifupdown2
        # policy for all vxlan interfaces. In the absence of this, the mstp work flow
        # is flawed in the event of vxlan flap.
        # Details -
        # As of today, for vxlan interfaces "oper edge port" is set to 'yes' and also
        # "bpdufilter port" is also set to 'yes'. So, in a case where bridge has multiple
        # vxlan interfaces, if one vxlan interface is flapped, this would trigger mstp
        # re-evaluation of states on other vxlan interfaces, creating momentary traffic
        # glitch on those vxlans. Setting "admin edge port" to yes (in addition to the
        # defaults we already have) prevents this.
        #
        # We use to only support 'mstpctl-vxlan-always-set-bpdu-params' but introducing a
        # separate policy attribute doesn't make sense, we should have one single
        # attribute to handle the whole thing (and deprecate mstpctl-vxlan-always-set-bpdu-params)
        # mstpctl-set-default-vxlan-bridge-attrs=yes will set
        #   mstpctl-portbpdufilter
        #   mstpctl-bpduguard
        #   mstpctl-portadminedge
        #
        self.set_default_mstp_vxlan_bridge_config = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr='mstpctl-vxlan-always-set-bpdu-params'
            )
        ) or utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr='mstpctl-set-default-vxlan-bridge-attrs'
            )
        )

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        if self._is_bridge(ifaceobj):
            if (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE
                    and ifaceobj.get_attr_value_first('mstpctl-portadminedge')):
                self.logger.error('%s: unsupported use of keyword '
                                  '\'mstpctl-portadminedge\' when '
                                  'bridge-vlan-aware is on'
                                  % ifaceobj.name)
                return False
        return True

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
        return self.parse_port_list(ifaceobj.name,
                                    ifaceobj.get_attr_value_first(
                                    'mstpctl-ports'), ifacenames_all)

    def get_dependent_ifacenames_running(self, ifaceobj):
        self._init_command_handlers()
        if (self.brctlcmd.bridge_exists(ifaceobj.name) and
                not self.mstpctlcmd.mstpbridge_exists(ifaceobj.name)):
            return None
        return self.brctlcmd.get_bridge_ports(ifaceobj.name)

    def _get_bridge_port_attr_value(self, bridgename, portname, attr):
        json_attr = self.get_mod_subattr(attr, 'jsonAttr')
        return self.mstpctlcmd.get_bridge_port_attr(bridgename,
                                                    portname,
                                                    json_attr)

    def _get_bridge_port_list(self, ifaceobj):

        # port list is also available in the previously
        # parsed dependent list. Use that if available, instead
        # of parsing port expr again
        port_list = ifaceobj.lowerifaces
        if port_list:
            return port_list
        ports = ifaceobj.get_attr_value_first('mstpctl-ports')
        if ports:
            return self.parse_port_list(ifaceobj.name, ports)
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
        if not ifupdownflags.flags.PERFMODE:
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
                if (not ifupdownflags.flags.DRYRUN and
                    not self.ipcmd.link_exists(bridgeport)):
                    self.log_warn('%s: bridge port %s does not exist'
                            %(ifaceobj.name, bridgeport))
                    err += 1
                    continue
                self.ipcmd.link_set(bridgeport, 'master', ifaceobj.name)
                self.ipcmd.addr_flush(bridgeport)
            except Exception, e:
                self.log_error(str(e), ifaceobj)

        if err:
            self.log_error('error configuring bridge (missing ports)')

    def _apply_bridge_settings(self, ifaceobj, ifaceobj_getfunc):
        check = False if ifupdownflags.flags.PERFMODE else True
        try:
            # set bridge attributes
            for attrname, dstattrname in self._attrs_map.items():
                config_val = ifaceobj.get_attr_value_first(attrname)
                default_val = policymanager.policymanager_api.get_iface_default(module_name=self.__class__.__name__, ifname=ifaceobj.name, attr=attrname)
                if not default_val:
                    default_val = self.get_mod_subattr(attrname, 'default')
                jsonAttr = self.get_mod_subattr(attrname, 'jsonAttr')
                try:
                    running_val = self.mstpctlcmd.get_bridge_attr(
                                    ifaceobj.name, jsonAttr)
                except:
                    self.logger.info('%s: could not get running %s value'
                                     %(ifaceobj.name, attrname))
                    running_val = None
                if (not config_val and default_val and (running_val != default_val)):
                    # this happens when users remove an attribute from a port
                    # and expect the default to be restored with ifreload.
                    config_val = default_val
                elif not config_val:
                    # there is nothing configured and no default to reset
                    continue
                try:
                    if attrname == 'mstpctl-treeprio':
                       self.mstpctlcmd.set_bridge_treeprio(ifaceobj.name,
                                config_val, check)
                    else:
                       self.mstpctlcmd.set_bridge_attr(ifaceobj.name,
                                dstattrname, config_val, check)
                except Exception, e:
                    self.logger.warn('%s' %str(e))
                    pass

            if self.ipcmd.bridge_is_vlan_aware(ifaceobj.name):
                return
            # set bridge port attributes
            for attrname, dstattrname in self._port_attrs_map.items():
                config_val = ifaceobj.get_attr_value_first(attrname)
                default_val = self.get_mod_subattr(attrname,'default')
                if not config_val:
                    # nothing configured, we may need to reset all ports to defaults
                    # if the default exists and jsonAttribute conversion exists
                    try:
                        jsonAttr =  self.get_mod_subattr(attrname, 'jsonAttr')
                        if default_val and jsonAttr:
                            bridgeports = self._get_bridge_port_list(ifaceobj)
                            for port in bridgeports:
                                if not self.brctlcmd.is_bridge_port(port):
                                    continue

                                bport_ifaceobjs = ifaceobj_getfunc(port)
                                if bport_ifaceobjs:
                                    default_val = self._get_default_val(attrname, bport_ifaceobjs[0], ifaceobj)
                                    for brport_ifaceobj in bport_ifaceobjs or []:
                                        attr_value = brport_ifaceobj.get_attr_value_first(attrname)
                                        if attr_value:
                                            default_val = attr_value
                                            break

                                self.mstpctlcmd.set_bridge_port_attr(ifaceobj.name,
                                                                     port,
                                                                     dstattrname,
                                                                     default_val,
                                                                     json_attr=jsonAttr)
                    except Exception as e:
                        self.logger.debug('%s' % str(e))
                        self.logger.info('%s: not resetting %s config'
                                         %(ifaceobj.name, attrname))
                    # leave the loop for this attribute
                    continue

                portlist = self.parse_port_list(ifaceobj.name, config_val)
                if not portlist:
                    self.log_error('%s: error parsing \'%s %s\''
                         %(ifaceobj.name, attrname, config_val), ifaceobj)
                    continue
                # there was a configured value so we need to parse it
                # and set the attribute for each port configured
                for p in portlist:
                    try:
                        (port, val) = p.split('=')
                        # if it is not bridge port, continue
                        if not os.path.exists('/sys/class/net/%s/brport' %port):
                            continue
                        json_attr = self.get_mod_subattr(attrname, 'jsonAttr')
                        self.mstpctlcmd.set_bridge_port_attr(ifaceobj.name,
                                                             port,
                                                             dstattrname,
                                                             val,
                                                             json_attr=json_attr)
                    except Exception, e:
                        self.log_error('%s: error setting %s (%s)'
                                       %(ifaceobj.name, attrname, str(e)),
                                       ifaceobj, raise_error=False)
        except Exception, e:
            self.log_warn(str(e))
            pass

    def _get_default_val(self, attr, ifaceobj, bridgeifaceobj):
        if (self.set_default_mstp_vxlan_bridge_config
            and ifaceobj.link_kind & ifaceLinkKind.VXLAN
                and attr in (
                        'mstpctl-portbpdufilter',
                        'mstpctl-bpduguard',
                        'mstpctl-portadminedge',
                )
        ):
            try:
                config_val = bridgeifaceobj.get_attr_value_first(attr)
            except Exception, e:
                config_val = None
            if config_val:
                if ifaceobj.name not in [v.split('=')[0] for v in config_val.split()]:
                    return 'yes'
                else:
                    index = [v.split('=')[0] for v in config_val.split()].index(ifaceobj.name)
                    return [v.split('=')[1] for v in config_val.split()][index]
            else:
                return 'yes'
        else:
            default_val = policymanager.policymanager_api.get_iface_default(module_name=self.__class__.__name__, ifname=ifaceobj.name, attr=attr)
            if not default_val:
                return self.get_mod_subattr(attr,'default')
            return default_val

    def _apply_bridge_port_settings(self, ifaceobj, bridgename=None,
                                    bridgeifaceobj=None,
                                    stp_running_on=True,
                                    mstpd_running=True):
        check = False if ifupdownflags.flags.PERFMODE else True
        applied = False
        if not bridgename and bridgeifaceobj:
            bridgename = bridgeifaceobj.name

        if not stp_running_on:
            # stp may get turned on at a later point
            self.logger.info('%s: ignoring config'
                             %(ifaceobj.name) +
                             ' (stp on bridge %s is not on yet)' %bridgename)
            return applied
        bvlan_aware = self.ipcmd.bridge_is_vlan_aware(bridgename)
        if (not mstpd_running or
            not os.path.exists('/sys/class/net/%s/brport' %ifaceobj.name) or
            not bvlan_aware):
                if (not bvlan_aware and
                    self.set_default_mstp_vxlan_bridge_config and
                    (ifaceobj.link_kind & ifaceLinkKind.VXLAN)):
                    for attr in (
                            'mstpctl-portbpdufilter',
                            'mstpctl-bpduguard',
                            'mstpctl-portadminedge'
                    ):
                        json_attr = self.get_mod_subattr(attr, 'jsonAttr')
                        config_val = self._get_default_val(attr, ifaceobj,
                                                           bridgeifaceobj)
                        try:
                            self.mstpctlcmd.set_bridge_port_attr(bridgename,
                                                                 ifaceobj.name,
                                                                 self._port_attrs_map[attr],
                                                                 config_val,
                                                                 json_attr=json_attr)
                        except Exception, e:
                            self.log_warn('%s: error setting %s (%s)'
                                          % (ifaceobj.name, attr, str(e)))

                if not bvlan_aware:
                    # for "traditional" bridges we also want to let the user configure
                    # some attributes (possibly all of them in the future)
                    applied = self._apply_bridge_port_settings_attributes_list(
                        (
                            ('mstpctl-portrestrrole', 'portrestrrole'),
                            ('mstpctl-portautoedge', 'portautoedge')
                        ),
                        ifaceobj,
                        bridgeifaceobj,
                        bridgename,
                        applied
                    )
                return applied
        # set bridge port attributes
        return self._apply_bridge_port_settings_attributes_list(
            self._port_attrs_map.items(),
            ifaceobj,
            bridgeifaceobj,
            bridgename,
            applied
        )

    def _apply_bridge_port_settings_attributes_list(self, attributes_list, ifaceobj, bridgeifaceobj, bridgename, applied):
        for attrname, dstattrname in attributes_list:
            config_val = ifaceobj.get_attr_value_first(attrname)
            default_val = self._get_default_val(attrname, ifaceobj, bridgeifaceobj)
            jsonAttr =  self.get_mod_subattr(attrname, 'jsonAttr')
            # to see the running value, stp would have to be on
            # so we would have parsed mstpctl showportdetail json output
            try:
                running_val = self.mstpctlcmd.get_bridge_port_attr(bridgename,
                                                       ifaceobj.name, jsonAttr)
            except:
                self.logger.info('%s %s: could not get running %s value'
                                 %(bridgename, ifaceobj.name, attrname))
                running_val = None
            if (not config_val and default_val and (running_val != default_val)):
                # this happens when users remove an attribute from a port
                # and expect the default to be restored with ifreload.
                config_val = default_val
            elif not config_val:
                # there is nothing configured and no default to reset
                continue

            try:
               self.mstpctlcmd.set_bridge_port_attr(bridgename,
                           ifaceobj.name, dstattrname, config_val, json_attr=jsonAttr)
               applied = True
            except Exception, e:
               self.log_error('%s: error setting %s (%s)'
                              %(ifaceobj.name, attrname, str(e)), ifaceobj,
                               raise_error=False)
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
                    pass
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
            mstpd_running = self.mstpd_running
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
        # we are now here because the ifaceobj is a bridge
        stp = None
        try:
            porterr = False
            porterrstr = ''
            if ifaceobj.get_attr_value_first('mstpctl-ports'):
                # If bridge ports specified with mstpctl attr, create the
                # bridge and also add its ports
                self.ipcmd.batch_start()
                if not ifupdownflags.flags.PERFMODE:
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
                                   self.brctlcmd.bridge_set_stp)
            else:
               stp = self.brctlcmd.bridge_get_stp(ifaceobj.name)
            if (self.mstpd_running and
                    (stp == 'yes' or stp == 'on')):
                self._apply_bridge_settings(ifaceobj, ifaceobj_getfunc)
                self._apply_bridge_port_settings_all(ifaceobj,
                            ifaceobj_getfunc=ifaceobj_getfunc)
        except Exception, e:
            self.log_error(str(e), ifaceobj)
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
            self.log_error(str(e), ifaceobj)

    def _query_running_attrs(self, ifaceobjrunning, bridge_vlan_aware=False):
        bridgeattrdict = {}

        tmpbridgeattrdict = self.mstpctlcmd.get_bridge_attrs(ifaceobjrunning.name)
        #self.logger.info('A' + str(tmpbridgeattrdict))
        if not tmpbridgeattrdict:
            return bridgeattrdict

        for k,v in tmpbridgeattrdict.items():
            if k == 'stp' or not v:
                continue
            if k == 'ports':
                ports = v.keys()
                continue
            attrname = 'mstpctl-' + k
            if (v and v != self.get_mod_subattr(attrname, 'default')
                and attrname != 'mstpctl-maxhops'):
                bridgeattrdict[attrname] = [v]

        ports = self.brctlcmd.get_bridge_ports(ifaceobjrunning.name)
        # Do this only for vlan-UNAWARE-bridge
        if ports and not bridge_vlan_aware:
            portconfig = {'mstpctl-portautoedge' : '',
                          'mstpctl-portbpdufilter' : '',
                          'mstpctl-portnetwork' : '',
                          'mstpctl-portpathcost' : '',
                          'mstpctl-portadminedge' : '',
                          'mstpctl-portp2p' : '',
                          'mstpctl-portrestrrole' : '',
                          'mstpctl-portrestrtcn' : '',
                          'mstpctl-bpduguard' : '',
                          'mstpctl-treeportprio' : '',
                          'mstpctl-treeportcost' : ''}

            for p in ports:

                for attr in ['mstpctl-portautoedge',
                             'mstpctl-portbpdufilter',
                             'mstpctl-portnetwork',
                             'mstpctl-portadminedge',
                             'mstpctl-portp2p',
                             'mstpctl-portrestrrole',
                             'mstpctl-portrestrtcn',
                             'mstpctl-bpduguard',
                             '']:
                    v = self._get_bridge_port_attr_value(ifaceobjrunning.name,
                                                         p, attr)
                    if v and v != 'no':
                        portconfig[attr] += ' %s=%s' % (p, v)

                for attr in ['mstpctl-portpathcost', 'mstpctl-treeportcost']:
                    v = self._get_bridge_port_attr_value(ifaceobjrunning.name,
                                                         p, attr)
                    if v and v != self.get_mod_subattr(attr, 'default'):
                        portconfig[attr] += ' %s=%s' % (p, v)

            bridgeattrdict.update({k : [v] for k, v in portconfig.items()
                                    if v})
        return bridgeattrdict

    def _get_config_stp(self, ifaceobj):
        stp = (ifaceobj.get_attr_value_first('mstpctl-stp') or
               ifaceobj.get_attr_value_first('bridge-stp') or
               policymanager.policymanager_api.get_iface_default(module_name=self.__class__.__name__, ifname=ifaceobj.name, attr='mstpctl-stp') or
               # this is a temporary method to access policy default value of bridge-stp
               policymanager.policymanager_api.get_iface_default(module_name='bridge', ifname=ifaceobj.name, attr='bridge-stp'))
        return utils.get_boolean_from_string(stp)

    def _get_running_stp(self, ifaceobj):
        stp = self.brctlcmd.bridge_get_stp(ifaceobj.name)
        return utils.get_boolean_from_string(stp)

    def _query_check_bridge(self, ifaceobj, ifaceobjcurr,
                            ifaceobj_getfunc=None):
        # list of attributes that are not supported currently
        blacklistedattrs = ['mstpctl-portpathcost',
                'mstpctl-treeportprio', 'mstpctl-treeportcost']
        if not self.brctlcmd.bridge_exists(ifaceobj.name):
            self.logger.debug('bridge %s does not exist' %ifaceobj.name)
            return
        ifaceattrs = self.dict_key_subset(ifaceobj.config,
                                          self.get_mod_attrs())
        if self.set_default_mstp_vxlan_bridge_config:
            for attr in ('mstpctl-portbpdufilter', 'mstpctl-bpduguard', 'mstpctl-portadminedge'):
                if attr not in ifaceattrs:
                    ifaceattrs.append(attr)
        if not ifaceattrs:
            return
        runningattrs = self.mstpctlcmd.get_bridge_attrs(ifaceobj.name)
        #self.logger.info('B' + str(runningattrs))
        if not runningattrs:
            runningattrs = {}
        config_stp = self._get_config_stp(ifaceobj)
        running_stp = self._get_running_stp(ifaceobj)
        running_port_list = self.brctlcmd.get_bridge_ports(ifaceobj.name)
        for k in ifaceattrs:
            # for all mstpctl options
            if k in blacklistedattrs:
                continue
            if k in ('mstpctl-portbpdufilter', 'mstpctl-bpduguard', 'mstpctl-portadminedge'):
                #special case, 'ifquery --check --with-defaults' on a VLAN
                #unaware bridge
                if not running_port_list:
                    continue
                if (not config_stp or not running_stp):
                    continue
                v = ifaceobj.get_attr_value_first(k)
                config_val = {}
                running_val = {}
                result = 0
                bridge_ports = {}
                state = ''
                if v:
                    for bportval in v.split():
                        config_val[bportval.split('=')[0]] = bportval.split('=')[1]
                #for bport in bridgeports:
                for bport in running_port_list:
                    bportifaceobjlist = ifaceobj_getfunc(bport)
                    if not bportifaceobjlist:
                        continue
                    for bportifaceobj in bportifaceobjlist:
                        if (bport not in config_val):
                            if (bportifaceobj.link_kind & ifaceLinkKind.VXLAN):
                                if (not ifupdownflags.flags.WITHDEFAULTS or
                                    (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE)):
                                    continue
                                conf = 'yes'
                            else:
                                continue
                        else:
                            if ((bportifaceobj.link_kind & ifaceLinkKind.VXLAN) and
                                 (ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE)):
                                continue
                            conf = config_val[bport]
                        jsonAttr =  self.get_mod_subattr(k, 'jsonAttr')
                        try:
                            running_val = self.mstpctlcmd.get_bridge_port_attr(ifaceobj.name, bport, jsonAttr)
                        except:
                            self.logger.info('%s %s: could not get running %s value'
                                    %(ifaceobj.name, bport, attr))
                            running_val = None
                        if conf != running_val:
                            result = 1
                        bridge_ports.update({bport : running_val})
                for port, val in bridge_ports.items():
                    #running state format
                    #mstpctl-portbpdufilter swp2=yes swp1=yes vx-14567101=yes    [pass]
                    #mstpctl-bpduguard swp2=yes swp1=yes vx-14567101=yes         [pass]
                    state += port + '=' + val + ' '
                if state:
                    ifaceobjcurr.update_config_with_status(k, state, result)
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
                rv = self.brctlcmd.bridge_get_stp(ifaceobj.name)
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
                vlist = self.parse_port_list(ifaceobj.name, v)
                if not vlist:
                    continue
                for vlistitem in vlist:
                    try:
                        (p, v) = vlistitem.split('=')
                        currv = self._get_bridge_port_attr_value(ifaceobj.name, p, k)
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

    def _query_check_bridge_vxlan_port(self, ifaceobj, ifaceobjcurr,
                            ifaceobj_getfunc=None):
        masters = ifaceobj.upperifaces
        if not masters:
            return
        for bridge in masters:
            bifaceobjlist = ifaceobj_getfunc(bridge)
            for bifaceobj in bifaceobjlist:
                if (self._is_bridge(bifaceobj) and
                    self.set_default_mstp_vxlan_bridge_config and
                    (bifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE)):
                        config_stp = self._get_config_stp(bifaceobj)
                        running_stp = self._get_running_stp(bifaceobj)
                        if (not config_stp or not running_stp):
                            continue
                        for attr in (
                                'mstpctl-portbpdufilter',
                                'mstpctl-bpduguard',
                                'mstpctl-portadminedge'
                        ):
                            jsonAttr =  self.get_mod_subattr(attr, 'jsonAttr')
                            config_val = bifaceobj.get_attr_value_first(attr)
                            if config_val:
                                if ifaceobj.name not in [v.split('=')[0] for v in config_val.split()]:
                                    if not ifupdownflags.flags.WITHDEFAULTS:
                                        continue
                                    config_val = 'yes'
                                else:
                                    index = [v.split('=')[0] for v in config_val.split()].index(ifaceobj.name)
                                    config_val = [v.split('=')[1] for v in config_val.split()][index]
                            else:
                                if not ifupdownflags.flags.WITHDEFAULTS:
                                    continue
                                config_val = 'yes'
                            try:
                                running_val = self.mstpctlcmd.get_bridge_port_attr(bifaceobj.name,
                                                    ifaceobj.name, jsonAttr)
                            except:
                                self.logger.info('%s %s: could not get running %s value'
                                        %(bifaceobj.name, ifaceobj.name, attr))
                                running_val = None
                            ifaceobjcurr.update_config_with_status(attr,
                                        running_val,
                                        0 if running_val == config_val else 1)
                        return


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
        #self.logger.info('C' + str(runningattrs))
        if not runningattrs:
            runningattrs = {}
        for k in ifaceattrs:
            # for all mstpctl options
            # get the corresponding ifaceobj attr
            v = ifaceobj.get_attr_value_first(k)
            if not v or k in blacklistedattrs:
                ifaceobjcurr.update_config_with_status(k, v, -1)
                continue
            currv = self._get_bridge_port_attr_value(bridgename, ifaceobj.name, k)
            if currv:
                if currv != v:
                    ifaceobjcurr.update_config_with_status(k, currv, 1)
                else:
                    ifaceobjcurr.update_config_with_status(k, currv, 0)
            else:
                ifaceobjcurr.update_config_with_status(k, None, 1)

    def _query_check(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        if self._is_bridge(ifaceobj):
            self._query_check_bridge(ifaceobj, ifaceobjcurr, ifaceobj_getfunc)
        elif ifaceobj.link_kind & ifaceLinkKind.VXLAN:
            self._query_check_bridge_vxlan_port(ifaceobj, ifaceobjcurr,
                                              ifaceobj_getfunc)
        else:
            self._query_check_bridge_port(ifaceobj, ifaceobjcurr)

    def _query_bridge_port_attr(self, ifaceobjrunning, bridgename, attr, value_cmp):
        v = self._get_bridge_port_attr_value(bridgename,
                                             ifaceobjrunning.name,
                                             attr)
        if v and value_cmp and v != value_cmp:
            ifaceobjrunning.update_config(attr, v)
        elif v and not value_cmp:
            ifaceobjrunning.update_config(attr, v)

    def _query_running_bridge_port(self, ifaceobjrunning):
        bridgename = self.ipcmd.bridge_port_get_bridge_name(
                                ifaceobjrunning.name)
        if not bridgename:
            self.logger.warn('%s: unable to determine bridgename'
                             %ifaceobjrunning.name)
            return
        if self.brctlcmd.bridge_get_stp(bridgename) == 'no':
           # This bridge does not run stp, return
           return
        # if userspace stp not set, return
        if self.systcl_get_net_bridge_stp_user_space() != '1':
            return

        self._query_bridge_port_attr(ifaceobjrunning, bridgename,
                                     'mstpctl-portautoedge',
                                     self.get_mod_subattr('mstpctl-portautoedge', 'default'))

        self._query_bridge_port_attr(ifaceobjrunning, bridgename,
                                     'mstpctl-portbpdufilter',
                                     'no')

        self._query_bridge_port_attr(ifaceobjrunning, bridgename,
                                     'mstpctl-portnetwork',
                                     'no')

        # XXX: Can we really get path cost of a port ???
        #v = self.mstpctlcmd.get_portpathcost(ifaceobjrunning.name, p)
        #if v and v != self.get_mod_subattr('mstpctl-pathcost',
        #                                   'default'):
        #   ifaceobjrunning.update_config('mstpctl-network', v)

        self._query_bridge_port_attr(ifaceobjrunning, bridgename,
                                     'mstpctl-portadminedge',
                                     'no')

        self._query_bridge_port_attr(ifaceobjrunning, bridgename,
                                     'mstpctl-portp2p',
                                     'auto')

        self._query_bridge_port_attr(ifaceobjrunning, bridgename,
                                     'mstpctl-portrestrrole',
                                     'no')

        self._query_bridge_port_attr(ifaceobjrunning, bridgename,
                                     'mstpctl-portrestrtcn',
                                     'no')

        self._query_bridge_port_attr(ifaceobjrunning, bridgename,
                                     'mstpctl-bpduguard',
                                     'no')

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
        if self.brctlcmd.bridge_get_stp(ifaceobjrunning.name) == 'no':
           # This bridge does not run stp, return
           return
        # if userspace stp not set, return
        if self.systcl_get_net_bridge_stp_user_space() != '1':
            return
        # Check if mstp really knows about this bridge
        if not self.mstpctlcmd.mstpbridge_exists(ifaceobjrunning.name):
            return
        bridge_vlan_aware = False
        if ifaceobjrunning.get_attr_value_first('bridge-vlan-aware') == 'yes':
            bridge_vlan_aware = True
        ifaceobjrunning.update_config_dict(self._query_running_attrs(
                                           ifaceobjrunning,
                                           bridge_vlan_aware))

    def _query_running(self, ifaceobjrunning, **extra_args):
        if self.brctlcmd.bridge_exists(ifaceobjrunning.name):
            self._query_running_bridge(ifaceobjrunning)
        elif self.brctlcmd.is_bridge_port(ifaceobjrunning.name):
            self._query_running_bridge_port(ifaceobjrunning)

    def _query_bridge_port(self, ifaceobj, ifaceobj_getfunc=None):
        """
        Example:
        Configuration:
            auto vxlan1wd
            iface vxlan1wd
                vxlan-id 1001

            auto vxlan2wd
            iface vxlan2wd
                vxlan-id 1002

            auto brwithdef2
            iface brwithdef2
                bridge_ports vxlan1wd vxlan2wd
                bridge-vlan-aware yes

        Output:
        $ ifquery vxlan1wd
            auto vxlan1wd
            iface vxlan1wd
                vxlan-id 1001

        $ ifquery --with-defaults vxlan1wd
            auto vxlan1wd
            iface vxlan1wd
                vxlan-id 1001
                mstpctl-portbpdufilter yes
                mstpctl-bpduguard yes
        """
        masters = ifaceobj.upperifaces
        if not masters:
            return
        try:
            for bridge in masters:
                bifaceobj = ifaceobj_getfunc(bridge)[0]
                if (self._is_bridge(bifaceobj) and
                    self.set_default_mstp_vxlan_bridge_config and
                    (bifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE)):
                        for attr in ('mstpctl-portbpdufilter',
                                     'mstpctl-bpduguard',
                                     'mstpctl-portadminedge'):
                            jsonAttr =  self.get_mod_subattr(attr, 'jsonAttr')
                            config_val = ifaceobj.get_attr_value_first(attr)
                            if config_val or not ifupdownflags.flags.WITHDEFAULTS:
                                continue
                            config_val = 'yes'
                            ifaceobj.replace_config(attr, config_val)
                        return
        except Exception, e:
            self.logger.info("%s: %s" %(ifaceobj.name, str(e)))
            pass

    def _query(self, ifaceobj, ifaceobj_getfunc=None, **kwargs):
        """ add default policy attributes supported by the module """
        if not self._is_bridge(ifaceobj):
            if (ifaceobj.module_flags.get(self.name,0x0) &
                    mstpctlFlags.PORT_PROCESSED):
                return
            self._query_bridge_port(ifaceobj, ifaceobj_getfunc)
            ifaceobj.module_flags[self.name] = (
                        ifaceobj.module_flags.setdefault(self.name,0) |
                        mstpctlFlags.PORT_PROCESSED)
            return
        lowerinfs = ifaceobj.lowerifaces
        if not lowerinfs:
            return
        if ifaceobj.get_attr_value_first('bridge-vlan-aware') != 'yes':
            for attr in ('mstpctl-portbpdufilter', 'mstpctl-bpduguard', 'mstpctl-portadminedge'):
                state = ''
                config = ifaceobj.get_attr_value_first(attr)
                for port in lowerinfs:
                    bportobjlist = ifaceobj_getfunc(port)
                    for bportobj in bportobjlist:
                        if bportobj.get_attr_value_first('vxlan-id'):
                            if config:
                                if port not in [v.split('=')[0] for v in config.split()]:
                                    config += ' %s=yes' %port
                            else:
                                state += '%s=yes ' %port
                ifaceobj.replace_config(attr, config if config else state)
        else:
            for attr in ('mstpctl-portbpdufilter', 'mstpctl-bpduguard', 'mstpctl-portadminedge'):
                state = ''
                config = ifaceobj.get_attr_value_first(attr)
                for port in lowerinfs:
                    bportobjlist = ifaceobj_getfunc(port)
                    for bportobj in bportobjlist:
                        if (bportobj.module_flags.get(self.name,0x0) &
                            mstpctlFlags.PORT_PROCESSED):
                            continue
                        if bportobj.get_attr_value_first('vxlan-id'):
                            if config:
                                if port not in [v.split('=')[0] for v in config.split()]:
                                    bportobj.update_config(attr, 'yes')
                                else:
                                    index = [v.split('=')[0] for v in config.split()].index(port)
                                    state = [v.split('=')[1] for v in config.split()][index]
                                    bportobj.update_config(attr, '%s' %state)
                                    v = config.split()
                                    del v[index]
                                    config = ' '.join(v)
                            else:
                                bportobj.replace_config(attr, 'yes')
                            bportobj.module_flags[self.name] = (
                                bportobj.module_flags.setdefault(self.name,0) |
                                mstpctlFlags.PORT_PROCESSED)
                if config:
                    ifaceobj.replace_config(attr, config)



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
            self.ipcmd = self.brctlcmd = LinkUtils()
        if not self.mstpctlcmd:
            self.mstpctlcmd = mstpctlutil()

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
