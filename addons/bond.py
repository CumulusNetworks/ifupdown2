#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from sets import Set
from ifupdown.iface import *
import ifupdownaddons
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.bondutil import bondutil
from ifupdownaddons.iproute2 import iproute2
from ifupdown.netlink import netlink
import ifupdown.policymanager as policymanager
import ifupdown.ifupdownflags as ifupdownflags
from ifupdown.utils import utils

class bond(moduleBase):
    """  ifupdown2 addon module to configure bond interfaces """

    overrides_ifupdown_scripts = ['ifenslave', ]

    _modinfo = { 'mhelp' : 'bond configuration module',
                    'attrs' : {
                    'bond-use-carrier':
                         {'help' : 'bond use carrier',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'yes',
                          'example': ['bond-use-carrier yes']},
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
                         {'help': 'bond mode',
                          'validvals': ['0', 'balance-rr',
                                        '1', 'active-backup',
                                        '2', 'balance-xor',
                                        '3', 'broadcast',
                                        '4', '802.3ad',
                                        '5', 'balance-tlb',
                                        '6', 'balance-alb'],
                          'default': 'balance-rr',
                          'example': ['bond-mode 802.3ad']},
                     'bond-lacp-rate':
                         {'help' : 'bond lacp rate',
                          'validvals' : ['0', '1'],
                          'default' : '0',
                          'example' : ['bond-lacp-rate 0']},
                     'bond-min-links':
                         {'help' : 'bond min links',
                          'default' : '0',
                          'validrange' : ['0', '255'],
                          'example' : ['bond-min-links 0']},
                     'bond-ad-sys-priority':
                         {'help' : '802.3ad system priority',
                          'default' : '65535',
                          'validrange' : ['0', '65535'],
                          'example' : ['bond-ad-sys-priority 65535'],
                          'deprecated' : True,
                          'new-attribute' : 'bond-ad-actor-sys-prio'},
                     'bond-ad-actor-sys-prio':
                         {'help' : '802.3ad system priority',
                          'default' : '65535',
                          'validrange' : ['0', '65535'],
                          'example' : ['bond-ad-actor-sys-prio 65535']},
                     'bond-ad-sys-mac-addr':
                         {'help' : '802.3ad system mac address',
                          'default' : '00:00:00:00:00:00',
                          'validvals': ['<mac>', ],
                         'example' : ['bond-ad-sys-mac-addr 00:00:00:00:00:00'],
                         'deprecated' : True,
                         'new-attribute' : 'bond-ad-actor-system'},
                     'bond-ad-actor-system':
                         {'help' : '802.3ad system mac address',
                          'default' : '00:00:00:00:00:00',
                          'validvals': ['<mac>', ],
                         'example' : ['bond-ad-actor-system 00:00:00:00:00:00'],},
                     'bond-lacp-bypass-allow':
                         {'help' : 'allow lacp bypass',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'no',
                          'example' : ['bond-lacp-bypass-allow no']},
                     'bond-slaves' :
                        {'help' : 'bond slaves',
                         'required' : True,
                         'multivalue' : True,
                         'validvals': ['<interface-list>'],
                         'example' : ['bond-slaves swp1 swp2',
                                      'bond-slaves glob swp1-2',
                                      'bond-slaves regex (swp[1|2)']}}}

    _bond_mode_num = {'0': 'balance-rr',
                      '1': 'active-backup',
                      '2': 'balance-xor',
                      '3': 'broadcast',
                      '4': '802.3ad',
                      '5': 'balance-tlb',
                      '6': 'balance-alb'}

    _bond_mode_string = {'balance-rr': '0',
                         'active-backup': '1',
                         'balance-xor': '2',
                         'broadcast': '3',
                         '802.3ad': '4',
                         'balance-tlb': '5',
                         'balance-alb': '6'}

    @staticmethod
    def _get_readable_bond_mode(mode):
        if mode in bond._bond_mode_num:
            return bond._bond_mode_num[mode]
        return mode

    @staticmethod
    def _get_num_bond_mode(mode):
        if mode in bond._bond_mode_string:
            return bond._bond_mode_string[mode]
        return mode

    def __init__(self, *args, **kargs):
        ifupdownaddons.modulebase.moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self.bondcmd = None

    def _is_bond(self, ifaceobj):
        if ifaceobj.get_attr_value_first('bond-slaves'):
            return True
        return False

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        """ Returns list of interfaces dependent on ifaceobj """

        if not self._is_bond(ifaceobj):
            return None
        slave_list = self.parse_port_list(ifaceobj.name,
                                    ifaceobj.get_attr_value_first(
                                    'bond-slaves'), ifacenames_all)
        ifaceobj.dependency_type = ifaceDependencyType.MASTER_SLAVE
        # Also save a copy for future use
        ifaceobj.priv_data = list(slave_list)
        if ifaceobj.link_type != ifaceLinkType.LINK_NA:
           ifaceobj.link_type = ifaceLinkType.LINK_MASTER
        ifaceobj.link_kind |= ifaceLinkKind.BOND
        ifaceobj.role |= ifaceRole.MASTER

        return slave_list

    def get_dependent_ifacenames_running(self, ifaceobj):
        self._init_command_handlers()
        return self.bondcmd.get_slaves(ifaceobj.name)

    def _get_slave_list(self, ifaceobj):
        """ Returns slave list present in ifaceobj config """

        # If priv data already has slave list use that first.
        if ifaceobj.priv_data:
            return ifaceobj.priv_data
        slaves = ifaceobj.get_attr_value_first('bond-slaves')
        if slaves:
            return self.parse_port_list(ifaceobj.name, slaves)
        else:
            return None

    def _is_clag_bond(self, ifaceobj):
        if ifaceobj.get_attr_value_first('bond-slaves'):
            attrval = ifaceobj.get_attr_value_first('clag-id')
            if attrval and attrval != '0':
                return True
        return False

    def fetch_attr(self, ifaceobj, attrname):
        attrval = ifaceobj.get_attr_value_first(attrname)
        # grab the defaults from the policy file in case the
        # user did not specify something.
        policy_default_val = policymanager.policymanager_api.\
                             get_iface_default(module_name=self.__class__.__name__,
                                               ifname=ifaceobj.name,
                                               attr=attrname)
        if attrval:
            if attrname == 'bond-mode':
                attrval = bond._get_readable_bond_mode(attrval)
                if attrval == '802.3ad':
                   dattrname = 'bond-min-links'
                   min_links = ifaceobj.get_attr_value_first(dattrname)
                   if not min_links:
                       min_links = self.bondcmd.get_min_links(ifaceobj.name)
                   if min_links == '0':
                       self.logger.warn('%s: attribute %s'
                            %(ifaceobj.name, dattrname) +
                            ' is set to \'0\'')
        elif policy_default_val:
            return policy_default_val
        return attrval

    def _apply_master_settings(self, ifaceobj):
        have_attrs_to_set = 0
        linkup = False
        bondcmd_attrmap =  OrderedDict([('bond-mode' , 'mode'),
                                 ('bond-miimon' , 'miimon'),
                                 ('bond-use-carrier', 'use_carrier'),
                                 ('bond-lacp-rate' , 'lacp_rate'),
                                 ('bond-xmit-hash-policy' , 'xmit_hash_policy'),
                                 ('bond-min-links' , 'min_links'),
                                 ('bond-num-grat-arp' , 'num_grat_arp'),
                                 ('bond-num-unsol-na' , 'num_unsol_na'),
                                 ('bond-ad-sys-mac-addr' , 'ad_actor_system'),
                                 ('bond-ad-actor-system' , 'ad_actor_system'),
                                 ('bond-ad-sys-priority' , 'ad_actor_sys_prio'),
                                 ('bond-ad-actor-sys-prio' , 'ad_actor_sys_prio'),
                                 ('bond-lacp-bypass-allow', 'lacp_bypass')])
        linkup = self.ipcmd.is_link_up(ifaceobj.name)
        try:
            # order of attributes set matters for bond, so
            # construct the list sequentially
            attrstoset = OrderedDict()
            for k, dstk in bondcmd_attrmap.items():
                v = self.fetch_attr(ifaceobj, k)
                if v:
                    attrstoset[dstk] = v
            if not attrstoset:
                return

            # support yes/no attrs
            utils.support_yesno_attrs(attrstoset, ['use_carrier', 'lacp_bypass'])

            have_attrs_to_set = 1
            self.bondcmd.set_attrs(ifaceobj.name, attrstoset,
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

        if not ifupdownflags.flags.PERFMODE:
            runningslaves = self.bondcmd.get_slaves(ifaceobj.name);

        clag_bond = self._is_clag_bond(ifaceobj)

        for slave in Set(slaves).difference(Set(runningslaves)):
            if (not ifupdownflags.flags.PERFMODE and
                not self.ipcmd.link_exists(slave)):
                    self.log_error('%s: skipping slave %s, does not exist'
                                   %(ifaceobj.name, slave), ifaceobj,
                                     raise_error=False)
                    continue
            link_up = False
            if self.ipcmd.is_link_up(slave):
                netlink.link_set_updown(slave, "down")
                link_up = True
            # If clag bond place the slave in a protodown state; clagd
            # will protoup it when it is ready
            if clag_bond:
                try:
                    netlink.link_set_protodown(slave, "on")
                except Exception, e:
                    self.logger.error('%s: %s' % (ifaceobj.name, str(e)))
            self.ipcmd.link_set(slave, 'master', ifaceobj.name)
            if link_up or ifaceobj.link_type != ifaceLinkType.LINK_NA:
               try:
                    netlink.link_set_updown(slave, "up")
               except Exception, e:
                    self.logger.debug('%s: %s' % (ifaceobj.name, str(e)))
                    pass

        if runningslaves:
            for s in runningslaves:
                if s not in slaves:
                    self.bondcmd.remove_slave(ifaceobj.name, s)
                    if clag_bond:
                        try:
                            netlink.link_set_protodown(s, "off")
                        except Exception, e:
                            self.logger.error('%s: %s' % (ifaceobj.name, str(e)))

    def _up(self, ifaceobj):
        try:
            if not self.ipcmd.link_exists(ifaceobj.name):
                self.bondcmd.create_bond(ifaceobj.name)
            self._apply_master_settings(ifaceobj)
            self._add_slaves(ifaceobj)
            if ifaceobj.addr_method == 'manual':
                netlink.link_set_updown(ifaceobj.name, "up")
        except Exception, e:
            self.log_error(str(e), ifaceobj)

    def _down(self, ifaceobj):
        try:
            self.bondcmd.delete_bond(ifaceobj.name)
        except Exception, e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        slaves = None

        if not self.bondcmd.bond_exists(ifaceobj.name):
            self.logger.debug('bond iface %s' %ifaceobj.name +
                              ' does not exist')
            return

        ifaceattrs = self.dict_key_subset(ifaceobj.config,
                                          self.get_mod_attrs())
        if not ifaceattrs: return
        runningattrs = self._query_running_attrs(ifaceobj.name)

        # support yes/no attributes
        utils.support_yesno_attrs(runningattrs, ['bond-use-carrier',
                                                 'bond-lacp-bypass-allow'],
                                  ifaceobj=ifaceobj)

        # support for numerical bond-mode
        mode = ifaceobj.get_attr_value_first('bond-mode')
        if mode in bond._bond_mode_num:
            if 'bond-mode' in runningattrs:
                runningattrs['bond-mode'] = bond._get_num_bond_mode(runningattrs['bond-mode'])

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
                        ' '.join(slaves)
                        if slaves else 'None', retslave)

    def _query_running_attrs(self, bondname):
        bondattrs = {'bond-mode' :
                            self.bondcmd.get_mode(bondname),
                     'bond-miimon' :
                            self.bondcmd.get_miimon(bondname),
                     'bond-use-carrier' :
                            self.bondcmd.get_use_carrier(bondname),
                     'bond-lacp-rate' :
                            self.bondcmd.get_lacp_rate(bondname),
                     'bond-min-links' :
                            self.bondcmd.get_min_links(bondname),
                     'bond-ad-actor-system' :
                            self.bondcmd.get_ad_actor_system(bondname),
                     'bond-ad-actor-sys-prio' :
                            self.bondcmd.get_ad_actor_sys_prio(bondname),
                     'bond-xmit-hash-policy' :
                            self.bondcmd.get_xmit_hash_policy(bondname),
                     'bond-lacp-bypass-allow' :
                            self.bondcmd.get_lacp_bypass_allow(bondname),
                     'bond-num-unsol-na' :
                            self.bondcmd.get_num_unsol_na(bondname),
                     'bond-num-grat-arp' :
                            self.bondcmd.get_num_grat_arp(bondname)}
        slaves = self.bondcmd.get_slaves(bondname)
        if slaves:
            bondattrs['bond-slaves'] = slaves
        return bondattrs

    def _query_running(self, ifaceobjrunning):
        if not self.bondcmd.bond_exists(ifaceobjrunning.name):
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
        if not self.ipcmd:
            self.ipcmd = iproute2()
        if not self.bondcmd:
            self.bondcmd = bondutil()

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
