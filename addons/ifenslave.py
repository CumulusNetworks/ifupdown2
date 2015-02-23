#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from sets import Set
from ifupdown.iface import *
import ifupdownaddons
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.ifenslaveutil import ifenslaveutil
from ifupdownaddons.iproute2 import iproute2
import ifupdown.rtnetlink_api as rtnetlink_api

class ifenslave(moduleBase):
    """  ifupdown2 addon module to configure bond interfaces """
    _modinfo = { 'mhelp' : 'bond configuration module',
                    'attrs' : {
                    'bond-use-carrier':
                         {'help' : 'bond use carrier',
                          'validvals' : ['0', '1'],
                          'default' : '1',
                          'example': ['bond-use-carrier 1']},
                     'bond-num-grat-arp':
                         {'help' : 'bond use carrier',
                          'validrange' : ['0', '255'],
                          'default' : '1',
                          'example' : ['bond-num-grat-arp 1']},
                     'bond-num-unsol-na' :
                         {'help' : 'bond slave devices',
                          'validrange' : ['0', '255'],
                          'default' : '1',
                          'example' : ['bond-num-unsol-na 1']},
                     'bond-xmit-hash-policy' :
                         {'help' : 'bond slave devices',
                          'validvals' : ['layer2', 'layer3+4', 'layer2+3'],
                          'default' : 'layer2',
                          'example' : ['bond-xmit-hash-policy layer2']},
                     'bond-miimon' :
                         {'help' : 'bond miimon',
                          'validrange' : ['0', '255'],
                          'default' : '0',
                          'example' : ['bond-miimon 0']},
                     'bond-mode' :
                         {'help' : 'bond mode',
                          'validvals' : ['balance-rr', 'active-backup',
                                          'balance-xor', 'broadcast', '802.3ad',
                                          'balance-tlb', 'balance-alb'],
                          'default' : 'balance-rr',
                          'example' : ['bond-mode 802.3ad']},
                     'bond-lacp-rate':
                         {'help' : 'bond lacp rate',
                          'validvals' : ['0', '1'],
                          'default' : '0',
                          'example' : ['bond-lacp-rate 0']},
                     'bond-min-links':
                         {'help' : 'bond min links',
                          'default' : '0',
                          'example' : ['bond-min-links 0']},
                     'bond-ad-sys-priority':
                         {'help' : '802.3ad system priority',
                          'default' : '65535',
                          'example' : ['bond-ad-sys-priority 65535']},
                     'bond-ad-sys-mac-addr':
                         {'help' : '802.3ad system mac address',
                          'default' : '00:00:00:00:00:00',
                         'example' : ['bond-ad-sys-mac-addr 00:00:00:00:00:00']},
                     'bond-lacp-fallback-allow':
                         {'help' : 'allow lacp fall back',
                          'compat' : True,
                          'validvals' : ['0', '1'],
                          'default' : '0',
                          'example' : ['bond-lacp-fallback-allow 0']},
                     'bond-lacp-fallback-period':
                         {'help' : 'grace period (seconds) for lacp fall back',
                          'compat' : True,
                          'validrange' : ['0', '100'],
                          'default' : '90',
                          'example' : ['bond-lacp-fallback-period 100']},
                     'bond-lacp-fallback-priority':
                         {'help' : 'slave priority for lacp fall back',
                          'compat' : True,
                          'example' : ['bond-lacp-fallback-priority swp1=1 swp2=1 swp3=2']},
                     'bond-lacp-bypass-allow':
                         {'help' : 'allow lacp bypass',
                          'validvals' : ['0', '1'],
                          'default' : '0',
                          'example' : ['bond-lacp-bypass-allow 0']},
                     'bond-lacp-bypass-period':
                         {'help' : 'grace period (seconds) for lacp bypass',
                          'validrange' : ['0', '900'],
                          'default' : '0',
                          'example' : ['bond-lacp-bypass-period 100']},
                     'bond-lacp-bypass-priority':
                         {'help' : 'slave priority for lacp bypass',
                          'example' : ['bond-lacp-bypass-priority swp1=1 swp2=1 swp3=2']},
                     'bond-slaves' :
                        {'help' : 'bond slaves',
                         'required' : True,
                         'example' : ['bond-slaves swp1 swp2',
                                      'bond-slaves glob swp1-2',
                                      'bond-slaves regex (swp[1|2)']}}}

    def __init__(self, *args, **kargs):
        ifupdownaddons.modulebase.moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self.ifenslavecmd = None

    def _is_bond(self, ifaceobj):
        if ifaceobj.get_attr_value_first('bond-slaves'):
            return True
        return False

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        """ Returns list of interfaces dependent on ifaceobj """

        if not self._is_bond(ifaceobj):
            return None
        slave_list = self.parse_port_list(ifaceobj.get_attr_value_first(
                                    'bond-slaves'), ifacenames_all)

        # Also save a copy for future use
        ifaceobj.priv_data = list(slave_list)
        if ifaceobj.link_type != ifaceLinkType.LINK_NA:
           ifaceobj.link_type = ifaceLinkType.LINK_MASTER
        return slave_list

    def get_dependent_ifacenames_running(self, ifaceobj):
        self._init_command_handlers()
        return self.ifenslavecmd.get_slaves(ifaceobj.name)

    def _get_slave_list(self, ifaceobj):
        """ Returns slave list present in ifaceobj config """

        # If priv data already has slave list use that first.
        if ifaceobj.priv_data:
            return ifaceobj.priv_data
        slaves = ifaceobj.get_attr_value_first('bond-slaves')
        if slaves:
            return self.parse_port_list(slaves)
        else:
            return None

    def fetch_attr(self, ifaceobj, attrname):
        attrval = ifaceobj.get_attr_value_first(attrname)
        if attrval:
            msg = ('%s: invalid value %s for attr %s.'
                    %(ifaceobj.name, attrval, attrname))
            optiondict = self.get_mod_attr(attrname)
            if not optiondict:
                return None
            validvals = optiondict.get('validvals')
            if validvals and attrval not in validvals:
                raise Exception(msg + ' Valid values are %s' %str(validvals))
            validrange = optiondict.get('validrange')
            if validrange:
                if (int(attrval) < int(validrange[0]) or
                        int(attrval) > int(validrange[1])):
                    raise Exception(msg + ' Valid range is [%s,%s]'
                                    %(validrange[0], validrange[1]))
            if attrname == 'bond-mode' and attrval == '802.3ad':
               dattrname = 'bond-min-links'
               min_links = ifaceobj.get_attr_value_first(dattrname)
               if not min_links or min_links == '0':
                   self.logger.warn('%s: required attribute %s'
                        %(ifaceobj.name, dattrname) +
                        ' not present or set to \'0\'')
        elif attrname in ['bond-lacp-bypass-allow']:
            # For some attrs, set default values
            optiondict = self.get_mod_attr(attrname)
            if optiondict:
                return optiondict.get('default')
        return attrval

    def _apply_master_settings(self, ifaceobj):
        have_attrs_to_set = 0
        linkup = False
        ifenslavecmd_attrmap =  OrderedDict([('bond-mode' , 'mode'),
                                 ('bond-miimon' , 'miimon'),
                                 ('bond-use-carrier', 'use_carrier'),
                                 ('bond-lacp-rate' , 'lacp_rate'),
                                 ('bond-xmit-hash-policy' , 'xmit_hash_policy'),
                                 ('bond-min-links' , 'min_links'),
                                 ('bond-num-grat-arp' , 'num_grat_arp'),
                                 ('bond-num-unsol-na' , 'num_unsol_na'),
                                 ('bond-ad-sys-mac-addr' , 'ad_sys_mac_addr'),
                                 ('bond-ad-sys-priority' , 'ad_sys_priority'),
                                 ('bond-lacp-fallback-allow', 'lacp_bypass_allow'),
                                 ('bond-lacp-fallback-period', 'lacp_bypass_period'),
                                 ('bond-lacp-bypass-allow', 'lacp_bypass_allow'),
                                 ('bond-lacp-bypass-period', 'lacp_bypass_period')])
        linkup = self.ipcmd.is_link_up(ifaceobj.name)
        try:
            # order of attributes set matters for bond, so
            # construct the list sequentially
            attrstoset = OrderedDict()
            for k, dstk in ifenslavecmd_attrmap.items():
                v = self.fetch_attr(ifaceobj, k)
                if v:
                    attrstoset[dstk] = v
            if not attrstoset:
                return
            have_attrs_to_set = 1
            self.ifenslavecmd.set_attrs(ifaceobj.name, attrstoset,
                    self.ipcmd.link_down if linkup else None)
        except:
            raise
        finally:
            if have_attrs_to_set and linkup:
                self.ipcmd.link_up(ifaceobj.name)

    def _add_slaves(self, ifaceobj):
        runningslaves = []

        slaves = self._get_slave_list(ifaceobj)
        if not slaves:
            self.logger.debug('%s: no slaves found' %ifaceobj.name)
            return

        if not self.PERFMODE:
            runningslaves = self.ifenslavecmd.get_slaves(ifaceobj.name);
            if runningslaves:
                # Delete active slaves not in the new slave list
                [ self.ifenslavecmd.remove_slave(ifaceobj.name, s)
                    for s in runningslaves if s not in slaves ]

        for slave in Set(slaves).difference(Set(runningslaves)):
            if not self.PERFMODE and not self.ipcmd.link_exists(slave):
                    self.log_warn('%s: skipping slave %s, does not exist'
                                  %(ifaceobj.name, slave))
                    continue
            link_up = False
            if self.ipcmd.is_link_up(slave):
               rtnetlink_api.rtnl_api.link_set(slave, "down")
               link_up = True
            self.ipcmd.link_set(slave, 'master', ifaceobj.name)
            if link_up or ifaceobj.link_type != ifaceLinkType.LINK_NA:
               rtnetlink_api.rtnl_api.link_set(slave, "up")

    def _set_clag_enable(self, ifaceobj):
        attrval = ifaceobj.get_attr_value_first('clag-id')
        attrval = attrval if attrval else '0'
        self.ifenslavecmd.set_clag_enable(ifaceobj.name, attrval)

    def _apply_slaves_lacp_bypass_prio(self, ifaceobj):
        slaves = self.ifenslavecmd.get_slaves(ifaceobj.name)
        if not slaves:
           return
        attrval = ifaceobj.get_attrs_value_first(['bond-lacp-bypass-priority',
                                'bond-lacp-fallback-priority'])
        if attrval:
            portlist = self.parse_port_list(attrval)
            if not portlist:
                self.log_warn('%s: could not parse \'%s %s\''
                              %(ifaceobj.name, attrname, attrval))
                return
            for p in portlist:
                try:
                    (port, val) = p.split('=')
                    if port not in slaves:
                        self.log_warn('%s: skipping slave %s, does not exist' 
                                      %(ifaceobj.name, port))
                        continue
                    slaves.remove(port)
                    self.ifenslavecmd.set_lacp_fallback_priority(
                                            ifaceobj.name, port, val)
                except Exception, e:
                    self.log_warn('%s: failed to set lacp_fallback_priority %s (%s)'
                                  %(ifaceobj.name, port, str(e)))

        for p in slaves:
            try:
                self.ifenslavecmd.set_lacp_fallback_priority(ifaceobj.name, p, '0')
            except Exception, e:
                self.log_warn('%s: failed to clear lacp_bypass_priority %s (%s)'
                              %(ifaceobj.name, p, str(e)))


    def _up(self, ifaceobj):
        try:
            if not self.ipcmd.link_exists(ifaceobj.name):
                self.ifenslavecmd.create_bond(ifaceobj.name)
            self._apply_master_settings(ifaceobj)
            # clag_enable has to happen before the slaves are added to the bond
            self._set_clag_enable(ifaceobj)
            self._add_slaves(ifaceobj)
            self._apply_slaves_lacp_bypass_prio(ifaceobj)
            if ifaceobj.addr_method == 'manual':
               rtnetlink_api.rtnl_api.link_set(ifaceobj.name, "up")
        except Exception, e:
            self.log_error(str(e))

    def _down(self, ifaceobj):
        try:
            self.ifenslavecmd.delete_bond(ifaceobj.name)
        except Exception, e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        slaves = None

        if not self.ifenslavecmd.bond_exists(ifaceobj.name):
            self.logger.debug('bond iface %s' %ifaceobj.name +
                              ' does not exist')
            return

        ifaceattrs = self.dict_key_subset(ifaceobj.config,
                                          self.get_mod_attrs())
        if not ifaceattrs: return
        runningattrs = self._query_running_attrs(ifaceobj.name)

        # backward compat change
        runningattrs.update({'bond-lacp-fallback-allow': runningattrs.get(
                                                    'bond-lacp-bypass-allow'),
                          'bond-lacp-fallback-period': runningattrs.get(
                                                    'bond-lacp-bypass-period'),
                          'bond-lacp-fallback-priority': runningattrs.get(
                                                'bond-lacp-bypass-priority')})
        for k in ifaceattrs:
            v = ifaceobj.get_attr_value_first(k)
            if not v:
                continue
            if k == 'bond-slaves':
                slaves = self._get_slave_list(ifaceobj)
                continue
            rv = runningattrs.get(k)
            if not rv:
                ifaceobjcurr.update_config_with_status(k, 'None', 1)
            else:
                if (k == 'bond-lacp-bypass-priority' or
                    k == 'bond-lacp-fallback-priority'):
                    prios = v.split()
                    prios.sort()
                    prio_str = ' '.join(prios)
                    ifaceobjcurr.update_config_with_status(k, rv,
                                    1 if prio_str != rv else 0)
                    continue
                ifaceobjcurr.update_config_with_status(k, rv,
                                                       1 if v != rv else 0)
        runningslaves = runningattrs.get('bond-slaves')
        if not slaves and not runningslaves:
            return
        retslave = 1
        if slaves and runningslaves:
            if slaves and runningslaves:
                difference = set(slaves).symmetric_difference(runningslaves)
                if not difference:
                    retslave = 0
        ifaceobjcurr.update_config_with_status('bond-slaves',
                        ' '.join(runningslaves)
                        if runningslaves else 'None', retslave)

    def _query_running_attrs(self, bondname):
        bondattrs = {'bond-mode' :
                            self.ifenslavecmd.get_mode(bondname),
                     'bond-miimon' :
                            self.ifenslavecmd.get_miimon(bondname),
                     'bond-use-carrier' :
                            self.ifenslavecmd.get_use_carrier(bondname),
                     'bond-lacp-rate' :
                            self.ifenslavecmd.get_lacp_rate(bondname),
                     'bond-min-links' :
                            self.ifenslavecmd.get_min_links(bondname),
                     'bond-ad-sys-mac-addr' :
                            self.ifenslavecmd.get_ad_sys_mac_addr(bondname),
                     'bond-ad-sys-priority' :
                            self.ifenslavecmd.get_ad_sys_priority(bondname),
                     'bond-xmit-hash-policy' :
                            self.ifenslavecmd.get_xmit_hash_policy(bondname),
                     'bond-lacp-bypass-allow' :
                            self.ifenslavecmd.get_lacp_fallback_allow(bondname),
                     'bond-lacp-bypass-period' :
                            self.ifenslavecmd.get_lacp_fallback_period(bondname),
                     'bond-lacp-bypass-priority' :
                            self.ifenslavecmd.get_lacp_fallback_priority(bondname)}
        slaves = self.ifenslavecmd.get_slaves(bondname)
        if slaves:
            bondattrs['bond-slaves'] = slaves
        return bondattrs

    def _query_running(self, ifaceobjrunning):
        if not self.ifenslavecmd.bond_exists(ifaceobjrunning.name):
            return
        bondattrs = self._query_running_attrs(ifaceobjrunning.name)
        if bondattrs.get('bond-slaves'):
            bondattrs['bond-slaves'] = ' '.join(bondattrs.get('bond-slaves'))
        [ifaceobjrunning.update_config(k, v)
                    for k, v in bondattrs.items()
                        if v and v != self.get_mod_subattr(k, 'default')]

    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-running' : _query_running,
               'query-checkcurr' : _query_check}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        flags = self.get_flags()
        if not self.ipcmd:
            self.ipcmd = iproute2(**flags)
        if not self.ifenslavecmd:
            self.ifenslavecmd = ifenslaveutil(**flags)

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        """ run bond configuration on the interface object passed as argument

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
        if operation != 'query-running' and not self._is_bond(ifaceobj):
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
