#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifupdownMain --
#    ifupdown main module
#

import os
import re
import imp
import pprint
import logging
import sys, traceback
import copy
import json
from statemanager import *
from networkinterfaces import *
from iface import *
from scheduler import *
from collections import deque
from collections import OrderedDict
from graph import *
from sets import Set

"""
.. module:: ifupdownmain
:synopsis: main module for ifupdown package

.. moduleauthor:: Roopa Prabhu <roopa@cumulusnetworks.com>

"""

_tickmark = u'\u2713'
_crossmark = u'\u2717'
_success_sym = '(%s)' %_tickmark
_error_sym = '(%s)' %_crossmark

class ifupdownFlags():
    FORCE = False
    DRYRUN = False
    NOWAIT = False
    PERFMODE = False
    CACHE = False

    # Flags
    CACHE_FLAGS = 0x0

class ifupdownMain(ifupdownBase):
    """ ifupdown2 main class """

    # Flags
    WITH_DEPENDS = False
    ALL = False
    IFACE_CLASS = False
    COMPAT_EXEC_SCRIPTS = False
    STATEMANAGER_ENABLE = True
    STATEMANAGER_UPDATE = True
    ADDONS_ENABLE = False

    # priv flags to mark iface objects
    BUILTIN = 0x0001
    NOCONFIG = 0x0010

    scripts_dir='/etc/network'
    addon_modules_dir='/usr/share/ifupdownaddons'
    addon_modules_configfile='/var/lib/ifupdownaddons/addons.conf'

    # iface dictionary in the below format:
    # { '<ifacename>' : [<ifaceobject1>, <ifaceobject2> ..] }
    # eg:
    # { 'swp1' : [<iface swp1>, <iface swp2> ..] }
    #
    # Each ifaceobject corresponds to a configuration block for
    # that interface
    # The value in the dictionary is a list because the network
    # interface configuration file supports more than one iface section
    # in the interfaces file
    ifaceobjdict = OrderedDict()

    # iface dictionary representing the curr running state of an iface
    # in the below format:
    # {'<ifacename>' : <ifaceobject>}
    ifaceobjcurrdict = OrderedDict()

    # Dictionary representing operation and modules
    # for every operation
    module_ops = OrderedDict([('pre-up', []),
                              ('up' , []),
                              ('post-up' , []),
                              ('query-checkcurr', []),
                              ('query-running', []),
                              ('query-dependency', []),
                              ('query', []),
                              ('query-raw', []),
                              ('pre-down', []),
                              ('down' , []),
                              ('post-down' , [])])

    # For old style /etc/network/ bash scripts
    script_ops = OrderedDict([('pre-up', []),
                                    ('up' , []),
                                    ('post-up' , []),
                                    ('pre-down', []),
                                    ('down' , []),
                                    ('post-down' , [])])

    # Handlers for ops that ifupdown2 owns
    def run_up(self, ifaceobj):
        if (ifaceobj.addr_method and
            ifaceobj.addr_method == 'manual'):
            return
        if self._delay_admin_state:
            self._delay_admin_state_iface_queue.append(ifaceobj.name)
            return
        # If this object is a link slave, ie its link is controlled
        # by its link master interface, then dont set the link state.
        # But do allow user to change state of the link if the interface
        # is already with its link master (hence the master check).
        if ifaceobj.link_type == ifaceLinkType.LINK_SLAVE:
            return
        if not self.link_exists(ifaceobj.name):
           return
        self.link_up(ifaceobj.name)

    def run_down(self, ifaceobj):
        if (ifaceobj.addr_method and
            ifaceobj.addr_method == 'manual'):
            return
        if self._delay_admin_state:
            self._delay_admin_state_iface_queue.append(ifaceobj.name)
            return
        # If this object is a link slave, ie its link is controlled
        # by its link master interface, then dont set the link state.
        # But do allow user to change state of the link if the interface
        # is already with its link master (hence the master check).
        if ifaceobj.link_type == ifaceLinkType.LINK_SLAVE:
           return
        if not self.link_exists(ifaceobj.name):
           return
        self.link_down(ifaceobj.name)

    # ifupdown object interface operation handlers
    ops_handlers = OrderedDict([('up', run_up),
                                ('down', run_down)])

    def run_sched_ifaceobj_posthook(self, ifaceobj, op):
        if ((ifaceobj.priv_flags & self.BUILTIN) or
            (ifaceobj.priv_flags & self.NOCONFIG)):
            return
        if self.STATEMANAGER_UPDATE:
            self.statemanager.ifaceobj_sync(ifaceobj, op)

    # ifupdown object interface scheduler pre and posthooks
    sched_hooks = {'posthook' : run_sched_ifaceobj_posthook}

    def __init__(self, config={},
                 force=False, dryrun=False, nowait=False,
                 perfmode=False, withdepends=False, njobs=1,
                 cache=False, addons_enable=True, statemanager_enable=True,
                 interfacesfile='/etc/network/interfaces',
                 interfacesfileiobuf=None,
                 interfacesfileformat='native'):
        """This member function initializes the ifupdownmain object.

        Kwargs:
            config (dict):  config dict from /etc/network/ifupdown2/ifupdown2.conf
            force (bool): force interface configuration
            dryrun (bool): dryrun interface configuration
            withdepends (bool): apply interface configuration on all depends
            interfacesfile (str): interfaces file. default is /etc/network/interfaces
            interfacesfileformat (str): default is 'native'. Other choices are 'json'

        Raises:
            AttributeError, KeyError """

        self.logger = logging.getLogger('ifupdown')
        self.FORCE = force
        self.DRYRUN = dryrun
        self.NOWAIT = nowait
        self.PERFMODE = perfmode
        self.WITH_DEPENDS = withdepends
        self.STATEMANAGER_ENABLE = statemanager_enable
        self.CACHE = cache
        self.interfacesfile = interfacesfile
        self.interfacesfileiobuf = interfacesfileiobuf
        self.interfacesfileformat = interfacesfileformat
        self.config = config
        self.logger.debug(self.config)

        self.type = ifaceType.UNKNOWN

        # Can be used to provide hints for caching
        self.CACHE_FLAGS = 0x0
        self._DELETE_DEPENDENT_IFACES_WITH_NOCONFIG = False
        self.ADDONS_ENABLE = addons_enable

        # Copy flags into ifupdownFlags
        # XXX: before we transition fully to ifupdownFlags
        ifupdownFlags.FORCE = force
        ifupdownFlags.DRYRUN = dryrun
        ifupdownFlags.NOWAIT = nowait
        ifupdownFlags.PERFMODE = perfmode
        ifupdownFlags.CACHE = cache

        self.ifaces = OrderedDict()
        self.njobs = njobs
        self.pp = pprint.PrettyPrinter(indent=4)
        self.modules = OrderedDict({})
        self.module_attrs = {}
        
        self.load_addon_modules(self.addon_modules_dir)
        if self.COMPAT_EXEC_SCRIPTS:
            self.load_scripts(self.scripts_dir)
        self.dependency_graph = OrderedDict({})

        self._cache_no_repeats = {}

        if self.STATEMANAGER_ENABLE:
            try:
                self.statemanager = stateManager()
                self.statemanager.read_saved_state()
            except Exception, e:
                # XXX Maybe we should continue by ignoring old state
                self.logger.warning('error reading state (%s)' %str(e))
                raise
        else:
            self.STATEMANAGER_UPDATE = False
        self._delay_admin_state = True if self.config.get(
                            'delay_admin_state_change', '0') == '1' else False
        self._delay_admin_state_iface_queue = []
        if self._delay_admin_state:
            self.logger.info('\'delay_admin_state_change\' is set. admin ' +
                             'state changes will be delayed till the end.')

        self._link_master_slave = True if self.config.get(
                      'link_master_slave', '0') == '1' else False
        if self._link_master_slave:
            self.logger.info('\'link_master_slave\' is set. slave admin ' +
                             'state changes will be delayed till the ' +
                             'masters admin state change.')

    def link_master_slave_ignore_error(self, errorstr):
        # If link master slave flag is set, 
        # there may be cases where the lowerdev may not be
        # up resulting in 'Network is down' error
        # This can happen if the lowerdev is a LINK_SLAVE
        # of another interface which is not up yet
        # example of such a case:
        #   bringing up a vlan on a bond interface and the bond
        #   is a LINK_SLAVE of a bridge (in other words the bond is
        #   part of a bridge) which is not up yet
        if self._link_master_slave:
           if 'Network is down':
              return True
        return False

    def get_ifaceobjs(self, ifacename):
        return self.ifaceobjdict.get(ifacename)

    def get_ifaceobjs_saved(self, ifacename):
        """ Return ifaceobjects from statemanager """
        if self.STATEMANAGER_ENABLE:
           return self.statemanager.get_ifaceobjs(ifacename)
        else:
           None

    def get_ifaceobj_first(self, ifacename):
        ifaceobjs = self.get_ifaceobjs(ifacename)
        if ifaceobjs:
            return ifaceobjs[0]
        return None

    def get_ifacenames(self):
        return self.ifaceobjdict.keys()

    def get_iface_obj_last(self, ifacename):
        return self.ifaceobjdict.get(ifacename)[-1]


    def must_follow_upperifaces(self, ifacename):
        #
        # XXX: This bleeds the knowledge of iface
        # types in the infrastructure module.
        # Cant think of a better fix at the moment.
        # In future maybe the module can set a flag
        # to indicate if we should follow upperifaces
        #
        ifaceobj = self.get_ifaceobj_first(ifacename)
        if ifaceobj.type == ifaceType.BRIDGE_VLAN:
            return False
        return True

    def create_n_save_ifaceobj(self, ifacename, priv_flags=None,
                               increfcnt=False):
        """ creates a iface object and adds it to the iface dictionary """
        ifaceobj = iface()
        ifaceobj.name = ifacename
        ifaceobj.priv_flags = priv_flags
        ifaceobj.auto = True
        if increfcnt:
            ifaceobj.inc_refcnt()
        self.ifaceobjdict[ifacename] = [ifaceobj]
        return ifaceobj

    def create_n_save_ifaceobjcurr(self, ifaceobj):
        """ creates a copy of iface object and adds it to the iface
            dict containing current iface objects 
        """
        ifaceobjcurr = iface()
        ifaceobjcurr.name = ifaceobj.name
        ifaceobjcurr.type = ifaceobj.type
        ifaceobjcurr.lowerifaces = ifaceobj.lowerifaces
        ifaceobjcurr.priv_flags = ifaceobj.priv_flags
        ifaceobjcurr.auto = ifaceobj.auto
        self.ifaceobjcurrdict.setdefault(ifaceobj.name,
                                     []).append(ifaceobjcurr)
        return ifaceobjcurr

    def get_ifaceobjcurr(self, ifacename, idx=0):
        ifaceobjlist = self.ifaceobjcurrdict.get(ifacename)
        if not ifaceobjlist:
            return None
        if not idx:
            return ifaceobjlist
        else:
            return ifaceobjlist[idx]

    def get_ifaceobjrunning(self, ifacename):
        return self.ifaceobjrunningdict.get(ifacename)

    def get_iface_refcnt(self, ifacename):
        """ Return iface ref count """
        max = 0
        ifaceobjs = self.get_ifaceobjs(ifacename)
        if not ifaceobjs:
            return 0
        for i in ifaceobjs:
            if i.refcnt > max:
                max = i.refcnt
        return max

    def is_iface_builtin_byname(self, ifacename):
        """ Returns true if iface name is a builtin interface.
        
        A builtin interface is an interface which ifupdown understands.
        The following are currently considered builtin ifaces:
            - vlan interfaces in the format <ifacename>.<vlanid>
        """
        return '.' in ifacename

    def is_ifaceobj_builtin(self, ifaceobj):
        """ Returns true if iface name is a builtin interface.
        
        A builtin interface is an interface which ifupdown understands.
        The following are currently considered builtin ifaces:
            - vlan interfaces in the format <ifacename>.<vlanid>
        """
        return (ifaceobj.priv_flags & self.BUILTIN)

    def is_ifaceobj_noconfig(self, ifaceobj):
        """ Returns true if iface object did not have a user defined config.
       
        These interfaces appear only when they are dependents of interfaces
        which have user defined config
        """
        return (ifaceobj.priv_flags & self.NOCONFIG)

    def is_iface_noconfig(self, ifacename):
        """ Returns true if iface has no config """

        ifaceobj = self.get_ifaceobj_first(ifacename)
        if not ifaceobj: return True
        return self.is_ifaceobj_noconfig(ifaceobj)

    def preprocess_dependency_list(self, upperifaceobj, dlist, ops):
        """ We go through the dependency list and
            delete or add interfaces from the interfaces dict by
            applying the following rules:
                if flag _DELETE_DEPENDENT_IFACES_WITH_NOCONFIG is True:
                    we only consider devices whose configuration was
                    specified in the network interfaces file. We delete
                    any interface whose config was not specified except
                    for vlan devices. vlan devices get special treatment.
                    Even if they are not present they are created and added
                    to the ifacesdict
                elif flag _DELETE_DEPENDENT_IFACES_WITH_NOCONFIG is False:
                    we create objects for all dependent devices that are not
                    present in the ifacesdict
        """
        del_list = []

        for d in dlist:
            dilist = self.get_ifaceobjs(d)
            if not dilist:
                ni = None
                if self.is_iface_builtin_byname(d):
                    ni = self.create_n_save_ifaceobj(d,
                            self.BUILTIN | self.NOCONFIG, True)
                elif not self._DELETE_DEPENDENT_IFACES_WITH_NOCONFIG:
                    ni = self.create_n_save_ifaceobj(d, self.NOCONFIG,
                            True)
                else:
                    del_list.append(d)
                if ni:
                    ni.add_to_upperifaces(upperifaceobj.name)
                    if upperifaceobj.link_type == ifaceLinkType.LINK_MASTER:
                        ni.link_type = ifaceLinkType.LINK_SLAVE
            else:
                for di in dilist:
                    di.inc_refcnt()
                    di.add_to_upperifaces(upperifaceobj.name)
                    if upperifaceobj.link_type == ifaceLinkType.LINK_MASTER:
                        di.link_type = ifaceLinkType.LINK_SLAVE
        for d in del_list:
            dlist.remove(d)

    def query_dependents(self, ifaceobj, ops, ifacenames, type=None):
        """ Gets iface dependents by calling into respective modules """
        ret_dlist = []

        # Get dependents for interface by querying respective modules
        for module in self.modules.values():
            try:
                if ops[0] == 'query-running':
                    if (not hasattr(module,
                        'get_dependent_ifacenames_running')):
                        continue
                    dlist = module.get_dependent_ifacenames_running(ifaceobj)
                else:
                    if (not hasattr(module, 'get_dependent_ifacenames')):
                        continue
                    dlist = module.get_dependent_ifacenames(ifaceobj,
                                        ifacenames)
            except Exception, e:
                self.logger.warn('%s: error getting dependent interfaces (%s)'
                        %(ifaceobj.name, str(e)))
                dlist = None
                pass
            if dlist: ret_dlist.extend(dlist)
        return list(set(ret_dlist))

    def populate_dependency_info(self, ops, ifacenames=None):
        """ recursive function to generate iface dependency info """

        if not ifacenames:
            ifacenames = self.ifaceobjdict.keys()

        iqueue = deque(ifacenames)
        while iqueue:
            i = iqueue.popleft()
            # Go through all modules and find dependent ifaces
            dlist = None
            ifaceobj = self.get_ifaceobj_first(i)
            if not ifaceobj: 
                continue
            dlist = ifaceobj.lowerifaces
            if not dlist:
                dlist = self.query_dependents(ifaceobj, ops, ifacenames)
            else:
                continue
            if dlist:
                self.preprocess_dependency_list(ifaceobj,
                                                dlist, ops)
                ifaceobj.lowerifaces = dlist
                [iqueue.append(d) for d in dlist]
            if not self.dependency_graph.get(i):
                self.dependency_graph[i] = dlist

    def _check_config_no_repeats(self, ifaceobj):
        """ check if object has an attribute that is
        restricted to a single object in the system.
        if yes, warn and return """
        for k,v in self._cache_no_repeats.items():
            iv = ifaceobj.config.get(k)
            if iv and iv[0] == v:
                self.logger.error('ignoring interface %s. ' %ifaceobj.name +
                        'Only one object with attribute ' +
                        '\'%s %s\' allowed.' %(k, v))
                return True
        for k, v in self.config.get('no_repeats', {}).items():
            iv = ifaceobj.config.get(k)
            if iv and iv[0] == v:
                self._cache_no_repeats[k] = v
        return False

    def _save_iface(self, ifaceobj):
        if self._check_config_no_repeats(ifaceobj):
           return
        if not self._link_master_slave:
           ifaceobj.link_type = ifaceLinkType.LINK_NA
        currentifaceobjlist = self.ifaceobjdict.get(ifaceobj.name)
        if not currentifaceobjlist:
           self.ifaceobjdict[ifaceobj.name]= [ifaceobj]
           return
        if ifaceobj.compare(currentifaceobjlist[0]):
            self.logger.warn('duplicate interface %s found' %ifaceobj.name)
            return
        if currentifaceobjlist[0].type == ifaceobj.type:
            currentifaceobjlist[0].flags |= iface.HAS_SIBLINGS
            ifaceobj.flags |= iface.HAS_SIBLINGS
        self.ifaceobjdict[ifaceobj.name].append(ifaceobj)

    def _iface_configattr_syntax_checker(self, attrname, attrval):
        for m, mdict in self.module_attrs.items():
            if not mdict:
                continue
            attrsdict = mdict.get('attrs')
            try:
                if attrsdict.get(attrname):
                    return True
            except AttributeError:
                pass
        return False

    def _ifaceobj_syntax_checker(self, ifaceobj):
        err = False
        for attrname, attrvalue in ifaceobj.config.items():
            found = False
            for k, v in self.module_attrs.items():
                if v and v.get('attrs', {}).get(attrname):
                    found = True
                    break
            if not found:
                err = True
                self.logger.warn('%s: unsupported attribute \'%s\'' %attrname) 
                continue
        return err

    def read_iface_config(self):
        """ Reads default network interface config /etc/network/interfaces. """
        nifaces = networkInterfaces(self.interfacesfile,
                        self.interfacesfileiobuf,
                        self.interfacesfileformat,
                        template_engine=self.config.get('template_engine'),
                template_lookuppath=self.config.get('template_lookuppath'))
        nifaces.subscribe('iface_found', self._save_iface)
        nifaces.subscribe('validateifaceattr',
                          self._iface_configattr_syntax_checker)
        nifaces.subscribe('validateifaceobj', self._ifaceobj_syntax_checker)
        nifaces.load()

    def read_old_iface_config(self):
        """ Reads the saved iface config instead of default iface config.
        And saved iface config is already read by the statemanager """
        self.ifaceobjdict = copy.deepcopy(self.statemanager.ifaceobjdict)

    def _load_addon_modules_config(self):
        """ Load addon modules config file """

        with open(self.addon_modules_configfile, 'r') as f:
            lines = f.readlines()
            for l in lines:
                litems = l.rstrip(' \n\t\r').split(',')
                operation = litems[0]
                mname = litems[1]
                self.module_ops[operation].append(mname)

    def load_addon_modules(self, modules_dir):
        """ load python modules from modules_dir

        Default modules_dir is /usr/share/ifupdownmodules

        """
        self.logger.info('loading builtin modules from %s' %modules_dir)
        self._load_addon_modules_config()
        if not modules_dir in sys.path:
            sys.path.append(modules_dir)
        try:
            for op, mlist in self.module_ops.items():
                for mname in mlist:
                    if self.modules.get(mname):
                        continue
                    mpath = modules_dir + '/' + mname + '.py'
                    if os.path.exists(mpath):
                        try:
                            m = __import__(mname)
                            mclass = getattr(m, mname)
                        except:
                            raise
                        minstance = mclass(force=self.FORCE,
                                        dryrun=self.DRYRUN,
                                        nowait=self.NOWAIT,
                                        perfmode=self.PERFMODE,
                                        cache=self.CACHE,
                                        cacheflags=self.CACHE_FLAGS)
                        self.modules[mname] = minstance
                        try:
                            self.module_attrs[mname] = minstance.get_modinfo()
                        except:
                            pass
        except: 
            raise

        # Assign all modules to query operations
        self.module_ops['query-checkcurr'] = self.modules.keys()
        self.module_ops['query-running'] = self.modules.keys()
        self.module_ops['query-dependency'] = self.modules.keys()
        self.module_ops['query'] = self.modules.keys()
        self.module_ops['query-raw'] = self.modules.keys()


    def _modules_help(self):
        """ Prints addon modules supported syntax """

        indent = '  '
        for m, mdict in self.module_attrs.items():
            if not mdict:
                continue
            print('%s: %s' %(m, mdict.get('mhelp')))
            attrdict = mdict.get('attrs')
            if not attrdict:
                continue
            try:
                for attrname, attrvaldict in attrdict.items():
                    if attrvaldict.get('compat', False):
                        continue
                    print('%s%s' %(indent, attrname))
                    print('%shelp: %s' %(indent + '  ',
                          attrvaldict.get('help', '')))
                    print ('%srequired: %s' %(indent + '  ',
                            attrvaldict.get('required', False)))
                    default = attrvaldict.get('default')
                    if default:
                        print('%sdefault: %s' %(indent + '  ', default))

                    validrange = attrvaldict.get('validrange')
                    if validrange:
                        print('%svalidrange: %s-%s'
                              %(indent + '  ', validrange[0], validrange[1]))

                    validvals = attrvaldict.get('validvals')
                    if validvals:
                        print('%svalidvals: %s'
                              %(indent + '  ', ','.join(validvals)))

                    examples = attrvaldict.get('example')
                    if not examples:
                        continue

                    print '%sexample:' %(indent + '  ')
                    for e in examples:
                        print '%s%s' %(indent + '    ', e)
            except:
                pass
            print ''
            
    def load_scripts(self, modules_dir):
        """ loading user modules from /etc/network/.

        Note that previously loaded python modules override modules found
        under /etc/network if any

        """

        self.logger.info('looking for user scripts under %s' %modules_dir)
        for op, mlist in self.script_ops.items():
            msubdir = modules_dir + '/if-%s.d' %op
            self.logger.info('loading scripts under %s ...' %msubdir)
            try:
                module_list = os.listdir(msubdir)
                for module in module_list:
                    if  self.modules.get(module) is not None:
                        continue
                    self.script_ops[op].append(
                                    msubdir + '/' + module)
            except: 
                # continue reading
                pass

    def _sched_ifaces(self, ifacenames, ops, skipupperifaces=False):
        self.logger.debug('scheduling \'%s\' for %s'
                          %(str(ops), str(ifacenames)))
        self._pretty_print_ordered_dict('dependency graph',
                    self.dependency_graph)
        return ifaceScheduler.sched_ifaces(self, ifacenames, ops,
                        dependency_graph=self.dependency_graph,
                        order=ifaceSchedulerFlags.INORDER
                            if 'down' in ops[0]
                                else ifaceSchedulerFlags.POSTORDER,
                        followdependents=True if self.WITH_DEPENDS else False,
                        skipupperifaces=skipupperifaces)

    def _render_ifacename(self, ifacename):
        new_ifacenames = []
        vlan_match = re.match("^([\d]+)-([\d]+)", ifacename)
        if vlan_match:
            vlan_groups = vlan_match.groups()
            if vlan_groups[0] and vlan_groups[1]:
                [new_ifacenames.append('%d' %v)
                    for v in range(int(vlan_groups[0]),
                            int(vlan_groups[1])+1)]
        return new_ifacenames

    def _preprocess_ifacenames(self, ifacenames):
        """ validates interface list for config existance.
       
        returns -1 if one or more interface not found. else, returns 0

        """
        new_ifacenames = []
        err_iface = ''
        for i in ifacenames:
            ifaceobjs = self.get_ifaceobjs(i)
            if not ifaceobjs:
                # if name not available, render interface name and check again
                rendered_ifacenames = utils.expand_iface_range(i)
                if rendered_ifacenames:
                    for ri in rendered_ifacenames:
                        ifaceobjs = self.get_ifaceobjs(ri)
                        if not ifaceobjs:
                            err_iface += ' ' + ri
                        else:
                            new_ifacenames.append(ri)
                else:
                    err_iface += ' ' + i
            else:
                new_ifacenames.append(i)
        if err_iface:
            raise Exception('cannot find interfaces:%s' %err_iface)
        return new_ifacenames 

    def _iface_whitelisted(self, auto, allow_classes, excludepats, ifacename):
        """ Checks if interface is whitelisted depending on set of parameters.

        interfaces are checked against the allow_classes and auto lists.

        """
        if excludepats:
            for e in excludepats:
                if re.search(e, ifacename):
                    return False
        ifaceobjs = self.get_ifaceobjs(ifacename)
        if not ifaceobjs:
            self.logger.debug('iface %s' %ifacename + ' not found')
            return False
        # We check classes first
        if allow_classes:
            for i in ifaceobjs:
                if i.classes:
                    common = Set([allow_classes]).intersection(
                                Set(i.classes))
                    if common:
                        return True
            return False
        if auto:
            for i in ifaceobjs:
                if i.auto:
                    return True
            return False
        return True

    def _compat_conv_op_to_mode(self, op):
        """ Returns old op name to work with existing scripts """
        if op == 'pre-up':
            return 'start'
        elif op == 'pre-down':
            return 'stop'
        else:
            return op

    def generate_running_env(self, ifaceobj, op):
        """ Generates a dictionary with env variables required for
        an interface. Used to support script execution for interfaces.
        """

        cenv = None
        iface_env = ifaceobj.env
        if iface_env:
            cenv = os.environ
            if cenv:
                cenv.update(iface_env)
            else:
                cenv = iface_env
            cenv['MODE'] = self._compat_conv_op_to_mode(op)
        return cenv

    def _save_state(self):
        if not self.STATEMANAGER_ENABLE or not self.STATEMANAGER_UPDATE:
            return
        try:
            # Update persistant iface states
            self.statemanager.save_state()
        except Exception, e:
            if self.logger.isEnabledFor(logging.DEBUG):
                t = sys.exc_info()[2]
                traceback.print_tb(t)
                self.logger.warning('error saving state (%s)' %str(e))

    def set_type(self, type):
        if type == 'iface':
            self.type = ifaceType.IFACE
        elif type == 'vlan':
            self.type = ifaceType.BRIDGE_VLAN
        else:
            self.type = ifaceType.UNKNOWN

    def _process_delay_admin_state_queue(self, op):
        if not self._delay_admin_state_iface_queue:
           return
        if op == 'up':
           func = self.link_up
        elif op == 'down':
           func = self.link_down
        else:
           return
        for i in self._delay_admin_state_iface_queue:
            try:
                if self.link_exists(i):
                   func(i)
            except Exception, e:
                self.logger.warn(str(e))
                pass

    def up(self, ops, auto=False, allow_classes=None, ifacenames=None,
           excludepats=None, printdependency=None, syntaxcheck=False,
           type=None, skipupperifaces=False):
        """This brings the interface(s) up
        
        Args:
            ops (list): list of ops to perform on the interface(s).
            Eg: ['pre-up', 'up', 'post-up'

        Kwargs:
            auto (bool): act on interfaces marked auto
            allow_classes (list): act on interfaces belonging to classes in the list
            ifacenames (list): act on interfaces specified in this list
            excludepats (list): list of patterns of interfaces to exclude
            syntaxcheck (bool): only perform syntax check
        """

        self.set_type(type)

        if allow_classes:
            self.IFACE_CLASS = True
        if not self.ADDONS_ENABLE: self.STATEMANAGER_UPDATE = False
        if auto:
            self.ALL = True
            self.WITH_DEPENDS = True
        try:
            self.read_iface_config()
        except Exception:
            raise

        # If only syntax check was requested, return here
        if syntaxcheck:
            return

        if ifacenames:
            ifacenames = self._preprocess_ifacenames(ifacenames)

        # if iface list not given by user, assume all from config file
        if not ifacenames: ifacenames = self.ifaceobjdict.keys()

        # filter interfaces based on auto and allow classes
        filtered_ifacenames = [i for i in ifacenames
                               if self._iface_whitelisted(auto, allow_classes,
                                                excludepats, i)]
        if not filtered_ifacenames:
            raise Exception('no ifaces found matching given allow lists')

        if printdependency:
            self.populate_dependency_info(ops, filtered_ifacenames)
            self.print_dependency(filtered_ifacenames, printdependency)
            return
        else:
            self.populate_dependency_info(ops)

        try:
            self._sched_ifaces(filtered_ifacenames, ops,
                    skipupperifaces=skipupperifaces)
        finally:
            self._process_delay_admin_state_queue('up')
            if not self.DRYRUN and self.ADDONS_ENABLE:
                self._save_state()

    def down(self, ops, auto=False, allow_classes=None, ifacenames=None,
             excludepats=None, printdependency=None, usecurrentconfig=False,
             type=None):
        """ down an interface """

        self.set_type(type)

        if allow_classes:
            self.IFACE_CLASS = True
        if not self.ADDONS_ENABLE: self.STATEMANAGER_UPDATE = False
        if auto:
            self.ALL = True
            self.WITH_DEPENDS = True
        # For down we need to look at old state, unless usecurrentconfig
        # is set
        if (not usecurrentconfig and self.STATEMANAGER_ENABLE and
                    self.statemanager.ifaceobjdict):
            # Since we are using state manager objects,
            # skip the updating of state manager objects
            self.logger.debug('Looking at old state ..')
            self.read_old_iface_config()
        else:
            # If no old state available 
            try:
                self.read_iface_config()
            except Exception, e:
                raise Exception('error reading iface config (%s)' %str(e))
        if ifacenames:
            # If iface list is given by the caller, always check if iface
            # is present
            try:
               ifacenames = self._preprocess_ifacenames(ifacenames)
            except Exception, e:
               raise Exception('%s' %str(e) +
                       ' (interface was probably never up ?)')

        # if iface list not given by user, assume all from config file
        if not ifacenames: ifacenames = self.ifaceobjdict.keys()

        # filter interfaces based on auto and allow classes
        filtered_ifacenames = [i for i in ifacenames
                               if self._iface_whitelisted(auto, allow_classes,
                                                excludepats, i)]
        if not filtered_ifacenames:
            raise Exception('no ifaces found matching given allow lists ' +
                    '(or interfaces were probably never up ?)')

        if printdependency:
            self.populate_dependency_info(ops, filtered_ifacenames)
            self.print_dependency(filtered_ifacenames, printdependency)
            return
        else:
            self.populate_dependency_info(ops)

        try:
            self._sched_ifaces(filtered_ifacenames, ops)
        finally:
            self._process_delay_admin_state_queue('down')
            if not self.DRYRUN and self.ADDONS_ENABLE:
                self._save_state()

    def query(self, ops, auto=False, allow_classes=None, ifacenames=None,
              excludepats=None, printdependency=None,
              format='native', type=None):
        """ query an interface """

        self.set_type(type)

        if allow_classes:
            self.IFACE_CLASS = True
        if self.STATEMANAGER_ENABLE and ops[0] == 'query-savedstate':
            return self.statemanager.dump_pretty(ifacenames)
        self.STATEMANAGER_UPDATE = False
        if auto:
            self.logger.debug('setting flag ALL')
            self.ALL = True
            self.WITH_DEPENDS = True

        if ops[0] == 'query-syntax':
            self._modules_help()
            return
        elif ops[0] == 'query-running':
            # create fake devices to all dependents that dont have config
            map(lambda i: self.create_n_save_ifaceobj(i, self.NOCONFIG),
                    ifacenames)
        else:
            try:
                self.read_iface_config()
            except Exception:
                raise

        if ifacenames and ops[0] != 'query-running':
           # If iface list is given, always check if iface is present
           ifacenames = self._preprocess_ifacenames(ifacenames)

        # if iface list not given by user, assume all from config file
        if not ifacenames: ifacenames = self.ifaceobjdict.keys()

        # filter interfaces based on auto and allow classes
        if ops[0] == 'query-running':
            filtered_ifacenames = ifacenames
        else:
            filtered_ifacenames = [i for i in ifacenames
                if self._iface_whitelisted(auto, allow_classes,
                        excludepats, i)]
        if not filtered_ifacenames:
                raise Exception('no ifaces found matching ' +
                        'given allow lists')

        self.populate_dependency_info(ops)
        if ops[0] == 'query-dependency' and printdependency:
            self.print_dependency(filtered_ifacenames, printdependency)
            return

        if ops[0] == 'query':
            return self.print_ifaceobjs_pretty(filtered_ifacenames, format)
        elif ops[0] == 'query-raw':
            return self.print_ifaceobjs_raw(filtered_ifacenames)

        self._sched_ifaces(filtered_ifacenames, ops)

        if ops[0] == 'query-checkcurr':
            ret = self.print_ifaceobjscurr_pretty(filtered_ifacenames, format)
            if ret != 0:
                # if any of the object has an error, signal that silently
                raise Exception('')
        elif ops[0] == 'query-running':
            self.print_ifaceobjsrunning_pretty(filtered_ifacenames, format)
            return

    def _reload_currentlyup(self, upops, downops, auto=True, allow=None,
            ifacenames=None, excludepats=None, usecurrentconfig=False,
            **extra_args):
        """ reload currently up interfaces """
        allow_classes = []
        new_ifaceobjdict = {}

        # Override auto to true
        auto = True
        if auto:
            self.ALL = True
            self.WITH_DEPENDS = True
        try:
            self.read_iface_config()
        except:
            raise
        if not self.ifaceobjdict:
            self.logger.warn("nothing to reload ..exiting.")
            return
        already_up_ifacenames = []
        # generate dependency graph of interfaces
        self.populate_dependency_info(upops)
        if (not usecurrentconfig and self.STATEMANAGER_ENABLE
                and self.statemanager.ifaceobjdict):
            already_up_ifacenames = self.statemanager.ifaceobjdict.keys()

        if not ifacenames: ifacenames = self.ifaceobjdict.keys()
        filtered_ifacenames = [i for i in ifacenames
                               if self._iface_whitelisted(auto, allow_classes,
                               excludepats, i)]
        
        # Get already up interfaces that still exist in the interfaces file
        already_up_ifacenames_not_present = Set(
                        already_up_ifacenames).difference(ifacenames)
        already_up_ifacenames_still_present = Set(
                        already_up_ifacenames).difference(
                        already_up_ifacenames_not_present)
        interfaces_to_up = Set(already_up_ifacenames_still_present).union(
                                            filtered_ifacenames)

        if (already_up_ifacenames_not_present and
                self.config.get('ifreload_currentlyup_down_notpresent') == '1'):
           self.logger.info('reload: schedule down on interfaces: %s'
                            %str(already_up_ifacenames_not_present))

           # Save a copy of new iface objects and dependency_graph
           new_ifaceobjdict = dict(self.ifaceobjdict)
           new_dependency_graph = dict(self.dependency_graph)

           # old interface config is read into self.ifaceobjdict
           self.read_old_iface_config()

           # reinitialize dependency graph 
           self.dependency_graph = OrderedDict({})
           self.populate_dependency_info(downops,
                                         already_up_ifacenames_not_present)
           self._sched_ifaces(already_up_ifacenames_not_present, downops)
        else:
           self.logger.debug('no interfaces to down ..')

        # Now, run 'up' with new config dict
        # reset statemanager update flag to default
        if new_ifaceobjdict:
            self.ifaceobjdict = new_ifaceobjdict
            self.dependency_graph = new_dependency_graph

        if not self.ifaceobjdict:
           return
        self.logger.info('reload: scheduling up on interfaces: %s'
                         %str(interfaces_to_up))
        self._sched_ifaces(interfaces_to_up, upops)
        if self.DRYRUN:
            return
        self._save_state()

    def _reload_default(self, upops, downops, auto=False, allow=None,
            ifacenames=None, excludepats=None, usecurrentconfig=False,
            **extra_args):
        """ reload interface config """
        allow_classes = []
        new_ifaceobjdict = {}

        if auto:
            self.ALL = True
            self.WITH_DEPENDS = True
        try:
            self.read_iface_config()
        except:
            raise

        if not self.ifaceobjdict:
            self.logger.warn("nothing to reload ..exiting.")
            return
        # generate dependency graph of interfaces
        self.populate_dependency_info(upops)
        if (not usecurrentconfig and self.STATEMANAGER_ENABLE
                and self.statemanager.ifaceobjdict):
            # Save a copy of new iface objects and dependency_graph
            new_ifaceobjdict = dict(self.ifaceobjdict)
            new_dependency_graph = dict(self.dependency_graph)

            # if old state is present, read old state and mark op for 'down'
            # followed by 'up' aka: reload
            # old interface config is read into self.ifaceobjdict
            self.read_old_iface_config()
            op = 'reload'
        else:
            # oldconfig not available, continue with 'up' with new config
            op = 'up'

        if not ifacenames: ifacenames = self.ifaceobjdict.keys()
        if op == 'reload' and ifacenames:
            filtered_ifacenames = [i for i in ifacenames
                               if self._iface_whitelisted(auto, allow_classes,
                               excludepats, i)]
            # Generate the interface down list
            # Interfaces that go into the down list:
            #   - interfaces that were present in last config and are not
            #     present in the new config
            #   - interfaces that were changed between the last and current
            #     config
            #
            ifacedownlist = []
            for ifname in filtered_ifacenames:
                lastifaceobjlist = self.ifaceobjdict.get(ifname)
                objidx = 0
                # If interface is not present in the new file
                # append it to the down list
                newifaceobjlist = new_ifaceobjdict.get(ifname)
                if not newifaceobjlist:
                    ifacedownlist.append(ifname)
                    continue
                # If interface has changed between the current file
                # and the last installed append it to the down list
                if len(newifaceobjlist) != len(lastifaceobjlist):
                    ifacedownlist.append(ifname)
                    continue
                # compare object list
                for objidx in range(0, len(lastifaceobjlist)):
                    oldobj = lastifaceobjlist[objidx]
                    newobj = newifaceobjlist[objidx]
                    if not newobj.compare(oldobj):
                        ifacedownlist.append(ifname)
                        continue

            if ifacedownlist:
                self.logger.info('reload: scheduling down on interfaces: %s'
                                  %str(ifacedownlist))
                # reinitialize dependency graph 
                self.dependency_graph = OrderedDict({})
                # Generate dependency info for old config
                self.populate_dependency_info(downops, ifacedownlist)
                try:
                    self._sched_ifaces(ifacedownlist, downops)
                except Exception, e:
                    self.logger.error(str(e))
                    pass
                finally:
                    self._process_delay_admin_state_queue('down')
            else:
                self.logger.debug('no interfaces to down ..')

        # Now, run 'up' with new config dict
        # reset statemanager update flag to default
        if not new_ifaceobjdict:
            return
        self.ifaceobjdict = new_ifaceobjdict
        self.dependency_graph = new_dependency_graph
        ifacenames = self.ifaceobjdict.keys()
        filtered_ifacenames = [i for i in ifacenames
                               if self._iface_whitelisted(auto, allow_classes,
                               excludepats, i)]

        self.logger.info('reload: scheduling up on interfaces: %s'
                         %str(filtered_ifacenames))
        try:
            self._sched_ifaces(filtered_ifacenames, upops)
        except Exception, e:
            self.logger.error(str(e))
            pass
        finally:
            self._process_delay_admin_state_queue('up')
        if self.DRYRUN:
            return
        self._save_state()

    def reload(self, *args, **kargs):
        """ reload interface config """
        self.logger.debug('reloading interface config ..')
        if kargs.get('currentlyup', False):
            self._reload_currentlyup(*args, **kargs)
        else:
            self._reload_default(*args, **kargs)

    def _pretty_print_ordered_dict(self, prefix, argdict):
        outbuf = prefix + ' {\n'
        for k, vlist in argdict.items():
            outbuf += '\t%s : %s\n' %(k, str(vlist))
        self.logger.debug(outbuf + '}')

    def print_dependency(self, ifacenames, format):
        """ prints iface dependency information """

        if not ifacenames:
            ifacenames = self.ifaceobjdict.keys()
        if format == 'list':
            for k,v in self.dependency_graph.items():
                print '%s : %s' %(k, str(v))
        elif format == 'dot':
            indegrees = {}
            map(lambda i: indegrees.update({i :
                self.get_iface_refcnt(i)}),
                self.dependency_graph.keys())
            graph.generate_dots(self.dependency_graph, indegrees)

    def print_ifaceobjs_raw(self, ifacenames):
        """ prints raw lines for ifaces from config file """

        for i in ifacenames:
            for ifaceobj in self.get_ifaceobjs(i):
                if (self.is_ifaceobj_builtin(ifaceobj) or 
                    not ifaceobj.is_config_present()):
                    continue
                ifaceobj.dump_raw(self.logger)
                print '\n'
                if self.WITH_DEPENDS and not self.ALL:
                    dlist = ifaceobj.lowerifaces
                    if not dlist: continue
                    self.print_ifaceobjs_raw(dlist)

    def _get_ifaceobjs_pretty(self, ifacenames, ifaceobjs, running=False):
        """ returns iface obj list """

        for i in ifacenames:
            for ifaceobj in self.get_ifaceobjs(i):
                if ((not running and self.is_ifaceobj_noconfig(ifaceobj)) or
                    (running and not ifaceobj.is_config_present())):
                    continue
                ifaceobjs.append(ifaceobj)
                if self.WITH_DEPENDS and not self.ALL:
                    dlist = ifaceobj.lowerifaces
                    if not dlist: continue
                    self._get_ifaceobjs_pretty(dlist, ifaceobjs, running)

    def print_ifaceobjs_pretty(self, ifacenames, format='native'):
        """ pretty prints iface in format given by keyword arg format """

        ifaceobjs = []
        self._get_ifaceobjs_pretty(ifacenames, ifaceobjs)
        if not ifaceobjs: return
        if format == 'json':
            print json.dumps(ifaceobjs, cls=ifaceJsonEncoder,
                             indent=4, separators=(',', ': '))
        else:
            expand = int(self.config.get('ifquery_ifacename_expand_range', '0'))
            for i in ifaceobjs:
                if not expand and (i.flags & iface.IFACERANGE_ENTRY):
                    # print only the first one
                    if i.flags & iface.IFACERANGE_START:
                       i.dump_pretty(use_realname=True)
                else:
                    i.dump_pretty()

    def _get_ifaceobjscurr_pretty(self, ifacenames, ifaceobjs):
        ret = 0
        for i in ifacenames:
            ifaceobjscurr = self.get_ifaceobjcurr(i)
            if not ifaceobjscurr: continue
            for ifaceobj in ifaceobjscurr:
                if (ifaceobj.status == ifaceStatus.NOTFOUND or
                    ifaceobj.status == ifaceStatus.ERROR):
                    ret = 1
                if self.is_ifaceobj_noconfig(ifaceobj):
                    continue
                ifaceobjs.append(ifaceobj)
                if self.WITH_DEPENDS and not self.ALL:
                    dlist = ifaceobj.lowerifaces
                    if not dlist: continue
                    dret = self._get_ifaceobjscurr_pretty(dlist, ifaceobjs)
                    if dret: ret = 1
        return ret

    def print_ifaceobjscurr_pretty(self, ifacenames, format='native'):
        """ pretty prints current running state of interfaces with status.

        returns 1 if any of the interface has an error,
        else returns 0
        """

        ifaceobjs = []
        ret = self._get_ifaceobjscurr_pretty(ifacenames, ifaceobjs)
        if not ifaceobjs: return
        if format == 'json':
            print json.dumps(ifaceobjs, cls=ifaceJsonEncoder, indent=2,
                       separators=(',', ': '))
        else:
            map(lambda i: i.dump_pretty(with_status=True,
                   successstr=self.config.get('ifquery_check_success_str',
                                              _success_sym),
                   errorstr=self.config.get('ifquery_check_error_str', _error_sym),
                   unknownstr=self.config.get('ifquery_check_unknown_str', '')),
                   ifaceobjs)
        return ret

    def print_ifaceobjsrunning_pretty(self, ifacenames, format='native'):
        """ pretty prints iface running state """

        ifaceobjs = []
        self._get_ifaceobjs_pretty(ifacenames, ifaceobjs, running=True)
        if not ifaceobjs: return
        if format == 'json':
            print json.dumps(ifaceobjs, cls=ifaceJsonEncoder, indent=2,
                       separators=(',', ': '))
        else:
            map(lambda i: i.dump_pretty(), ifaceobjs)

    def _dump(self):
        print 'ifupdown main object dump'
        print self.pp.pprint(self.modules)
        print self.pp.pprint(self.ifaceobjdict)

    def _dump_ifaceobjs(self, ifacenames):
        for i in ifacenames:
            ifaceobjs = self.get_ifaceobjs(i)
            for i in ifaceobjs:
                i.dump(self.logger)
                print '\n'
