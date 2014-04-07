#!/usr/bin/python
#
# Copyright 2013.  Cumulus Networks, Inc.
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
from statemanager import *
from networkinterfaces import *
from iface import *
from scheduler import *
from collections import deque
from collections import OrderedDict
from graph import *
from sets import Set

class ifupdownMain(ifupdownBase):
    """ ifupdown2 main class """

    # Flags
    WITH_DEPENDS = False
    ALL = False
    COMPAT_EXEC_SCRIPTS = False
    STATEMANAGER_ENABLE = True
    STATEMANAGER_UPDATE = True
    ADDONS_ENABLE = False

    # priv flags to mark iface objects
    BUILTIN = 0x1
    NOCONFIG = 0x2

    scripts_dir='/etc/network'
    addon_modules_dir='/usr/share/ifupdownaddons'
    addon_modules_configfile='/etc/network/.addons.conf'

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
        ifacename = ifaceobj.name
        if self.link_exists(ifacename):
            self.link_up(ifacename)

    def run_down(self, ifaceobj):
        ifacename = ifaceobj.name
        if self.link_exists(ifacename):
            self.link_down(ifacename)

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

    def __init__(self, force=False, dryrun=False, nowait=False,
                 perfmode=False, withdepends=False, njobs=1,
                 cache=False, addons_enable=True, statemanager_enable=True):
        self.logger = logging.getLogger('ifupdown')
        self.FORCE = force
        self.DRYRUN = dryrun
        self.NOWAIT = nowait
        self.PERFMODE = perfmode
        self.WITH_DEPENDS = withdepends
        self.STATEMANAGER_ENABLE = statemanager_enable
        self.CACHE = cache

        # Can be used to provide hints for caching
        self.CACHE_FLAGS = 0x0
        self._DELETE_DEPENDENT_IFACES_WITH_NOCONFIG = False
        self.ADDONS_ENABLE = addons_enable

        self.ifaces = OrderedDict()
        self.njobs = njobs
        self.pp = pprint.PrettyPrinter(indent=4)
        self.modules = OrderedDict({})
        self.module_attrs = {}
        
        self.load_addon_modules(self.addon_modules_dir)
        if self.COMPAT_EXEC_SCRIPTS:
            self.load_scripts(self.scripts_dir)
        self.dependency_graph = OrderedDict({})

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

    def get_ifaceobjs(self, ifacename):
        return self.ifaceobjdict.get(ifacename)

    def get_ifaceobj_first(self, ifacename):
        ifaceobjs = self.get_ifaceobjs(ifacename)
        if ifaceobjs:
            return ifaceobjs[0]
        return None

    def get_ifacenames(self):
        return self.ifaceobjdict.keys()

    def get_iface_obj_last(self, ifacename):
        return self.ifaceobjdict.get(ifacename)[-1]

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
        """ creates a copy of iface object and adds it to the iface dict containing current iface objects 
        """
        ifaceobjcurr = self.get_ifaceobjcurr(ifaceobj.name)
        if ifaceobjcurr:
            return ifaceobjcurr
        ifaceobjcurr = iface()
        ifaceobjcurr.name = ifaceobj.name
        ifaceobjcurr.lowerifaces = ifaceobj.lowerifaces
        ifaceobjcurr.priv_flags = ifaceobj.priv_flags
        self.ifaceobjcurrdict[ifaceobj.name] = ifaceobjcurr
        return ifaceobjcurr

    def get_ifaceobjcurr(self, ifacename):
        return self.ifaceobjcurrdict.get(ifacename)

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

    def preprocess_dependency_list(self, upperifacename, dlist, ops):
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
                if self.is_iface_builtin_byname(d):
                    self.create_n_save_ifaceobj(d, self.BUILTIN | self.NOCONFIG,
                            True).add_to_upperifaces(upperifacename)
                elif not self._DELETE_DEPENDENT_IFACES_WITH_NOCONFIG:
                    self.create_n_save_ifaceobj(d, self.NOCONFIG,
                            True).add_to_upperifaces(upperifacename)
                else:
                    del_list.append(d)
            else:
                for di in dilist:
                    di.inc_refcnt()
                    di.add_to_upperifaces(upperifacename)

        for d in del_list:
            dlist.remove(d)

    def query_dependents(self, ifaceobj, ops):
        """ Gets iface dependents by calling into respective modules """
        dlist = None

        # Get dependents for interface by querying respective modules
        for mname, module in self.modules.items():
            module = self.modules.get(mname)
            if ops[0] == 'query-running':
                if (not hasattr(module,
                    'get_dependent_ifacenames_running')):
                    continue
                dlist = module.get_dependent_ifacenames_running(ifaceobj)
            else:
                if (not hasattr(module, 'get_dependent_ifacenames')):
                    continue
                dlist = module.get_dependent_ifacenames(ifaceobj,
                                        self.ifaceobjdict.keys())
            if dlist:
                self.logger.debug('%s: ' %ifaceobj.name +
                                  'lowerifaces/dependents: %s' %str(dlist))
                break
        return dlist

    def populate_dependency_info(self, ops, ifacenames=None):
        """ recursive function to generate iface dependency info """

        if not ifacenames:
            ifacenames = self.ifaceobjdict.keys()

        self.logger.debug('populating dependency info for %s' %str(ifacenames))
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
                dlist = self.query_dependents(ifaceobj, ops)
            else:
                continue
            if dlist:
                self.preprocess_dependency_list(ifaceobj.name,
                                                dlist, ops)
                self.logger.debug('%s: lowerifaces/dependents after processing: %s'
                                  %(i, str(dlist)))
                ifaceobj.lowerifaces = dlist
                [iqueue.append(d) for d in dlist]
            if not self.dependency_graph.get(i):
                self.dependency_graph[i] = dlist

    def _save_iface(self, ifaceobj):
        currentifaceobjlist = self.ifaceobjdict.get(ifaceobj.name)
        if not currentifaceobjlist:
           self.ifaceobjdict[ifaceobj.name]= [ifaceobj]
           return
        if ifaceobj.compare(currentifaceobjlist[0]):
            self.logger.warn('duplicate interface %s found' %ifaceobj.name)
            return
        self.ifaceobjdict[ifaceobj.name].append(ifaceobj)

    def _module_syntax_checker(self, attrname, attrval):
        for m, mdict in self.module_attrs.items():
            attrsdict = mdict.get('attrs')
            if attrsdict and attrname in attrsdict.keys():
                return True
        return False

    def read_default_iface_config(self):
        """ Reads default network interface config /etc/network/interfaces. """
        nifaces = networkInterfaces()
        nifaces.subscribe('iface_found', self._save_iface)
        nifaces.subscribe('validate', self._module_syntax_checker)
        nifaces.load()

    def read_iface_config(self):
        return self.read_default_iface_config()

    def read_old_iface_config(self):
        """ Reads the saved iface config instead of default iface config. """
        self.ifaceobjdict = copy.deepcopy(self.statemanager.ifaceobjdict)

    def _load_addon_modules_config(self):
        """ Load addon modules config file """

        with open(self.addon_modules_configfile, 'r') as f:
            lines = f.readlines()
            for l in lines:
                litems = l.rstrip(' \n').split(',')
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
                        print('%svalidrange: %s'
                              %(indent + '  ', '-'.join(validrange)))

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

    def _sched_ifaces(self, ifacenames, ops):
        self.logger.debug('scheduling \'%s\' for %s'
                          %(str(ops), str(ifacenames)))

        self._pretty_print_ordered_dict('dependency graph',
                    self.dependency_graph)
        return ifaceScheduler.sched_ifaces(self, ifacenames, ops,
                        dependency_graph=self.dependency_graph,
                        order=ifaceSchedulerFlags.INORDER
                            if 'down' in ops[0]
                                else ifaceSchedulerFlags.POSTORDER,
                        followdependents=True if self.WITH_DEPENDS else False)

    def _validate_ifaces(self, ifacenames):
        """ validates interface list for config existance.
       
        returns -1 if one or more interface not found. else, returns 0

        """
        err_iface = ''
        for i in ifacenames:
            ifaceobjs = self.get_ifaceobjs(i)
            if not ifaceobjs:
                err_iface += ' ' + i
        if err_iface:
            self.logger.error('cannot find interfaces: %s' %err_iface)
            return False
        return True

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

    def up(self, ops, auto=False, allow_classes=None, ifacenames=None,
           excludepats=None, printdependency=None, syntaxcheck=False):
        """ up an interface """

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
            # If iface list is given by the caller, always check if iface
            # is present
           if not self._validate_ifaces(ifacenames):
               raise Exception('all or some interfaces not found')

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
            self._sched_ifaces(filtered_ifacenames, ops)
        finally:
            if not self.DRYRUN and self.ADDONS_ENABLE:
                self._save_state()

    def down(self, ops, auto=False, allow_classes=None, ifacenames=None,
             excludepats=None, printdependency=None, usecurrentconfig=False):
        """ down an interface """

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
            self.logger.info('Loading current iface config file')
            try:
                self.read_iface_config()
            except Exception, e:
                raise Exception('error reading iface config (%s)' %str(e))
        if ifacenames:
            # If iface list is given by the caller, always check if iface
            # is present
           if not self._validate_ifaces(ifacenames):
               raise Exception('interface(s) was probably never up')
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
            self._sched_ifaces(filtered_ifacenames, ops)
        finally:
            if not self.DRYRUN and self.ADDONS_ENABLE:
                self._save_state()

    def query(self, ops, auto=False, allow_classes=None, ifacenames=None,
              excludepats=None, printdependency=None,
              format='native'):
        """ query an interface """

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
           if not self._validate_ifaces(ifacenames):
               raise Exception('all or some interfaces not found')

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

        if ops[0] == 'query-dependency' and printdependency:
            self.populate_dependency_info(ops, filtered_ifacenames)
            self.print_dependency(filtered_ifacenames, printdependency)
            return
        else:
            self.populate_dependency_info(ops)

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

    def reload(self, upops, downops, auto=False, allow=None,
            ifacenames=None, excludepats=None):
        """ reload interface config """

        allow_classes = []

        self.logger.debug('reloading interface config ..')
        if auto:
            self.ALL = True
            self.WITH_DEPENDS = True

        try:
            # Read the current interface config
            self.read_iface_config()
        except:
            raise

        # generate dependency graph of interfaces
        self.populate_dependency_info(upops)

        # Save a copy of new iface objects and dependency_graph
        new_ifaceobjdict = dict(self.ifaceobjdict)
        new_dependency_graph = dict(self.dependency_graph)

        if self.STATEMANAGER_ENABLE and self.statemanager.ifaceobjdict:
            # if old state is present, read old state and mark op for 'down'
            # followed by 'up' aka: reload
            # old interface config is read into self.ifaceobjdict
            #
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
            for ifname, lastifaceobjlist in self.ifaceobjdict.items():
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
                self.logger.info('Executing down on interfaces: %s'
                                  %str(ifacedownlist))
                # reinitialize dependency graph 
                self.dependency_graph = OrderedDict({})
                # Generate dependency info for old config
                self.populate_dependency_info(downops)
                self._sched_ifaces(ifacedownlist, downops)
            else:
                self.logger.debug('no interfaces to down ..')

        # Now, run 'up' with new config dict
        # reset statemanager update flag to default
        self.ifaceobjdict = new_ifaceobjdict
        self.dependency_graph = new_dependency_graph
        ifacenames = self.ifaceobjdict.keys()
        filtered_ifacenames = [i for i in ifacenames
                               if self._iface_whitelisted(auto, allow_classes,
                               excludepats, i)]

        self.logger.info('Scheduling up on interfaces: %s'
                                  %str(filtered_ifacenames))
        self._sched_ifaces(filtered_ifacenames, upops)
        if self.DRYRUN:
            return
        self._save_state()

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

    def print_ifaceobjs_pretty(self, ifacenames, format='native'):
        """ pretty prints iface in format given by keyword arg format """

        for i in ifacenames:
            for ifaceobj in self.get_ifaceobjs(i):
                if (self.is_ifaceobj_noconfig(ifaceobj)):
                    continue
                if format == 'json':
                    ifaceobj.dump_json()
                else:
                    ifaceobj.dump_pretty()
                if self.WITH_DEPENDS and not self.ALL:
                    dlist = ifaceobj.lowerifaces
                    if not dlist: continue
                    self.print_ifaceobjs_pretty(dlist, format)

    def print_ifaceobjscurr_pretty(self, ifacenames, format='native'):
        """ pretty prints current running state of interfaces with status.

        returns 1 if any of the interface has an error,
        else returns 0
        """

        ret = 0
        for i in ifacenames:
            ifaceobj = self.get_ifaceobjcurr(i)
            if not ifaceobj: continue
            if ifaceobj.status == ifaceStatus.NOTFOUND:
                print 'iface %s (%s)\n' %(ifaceobj.name,
                            ifaceStatus.to_str(ifaceStatus.NOTFOUND))
                ret = 1
                continue
            elif ifaceobj.status == ifaceStatus.ERROR:
                ret = 1
            if (self.is_ifaceobj_noconfig(ifaceobj)):
                continue
            if format == 'json':
                ifaceobj.dump_json(with_status=True)
            else:
                ifaceobj.dump_pretty(with_status=True)
            if self.WITH_DEPENDS and not self.ALL:
                dlist = ifaceobj.lowerifaces
                if not dlist: continue
                self.print_ifaceobjscurr_pretty(dlist, format)
        return ret

    def print_ifaceobjsrunning_pretty(self, ifacenames, format='native'):
        """ pretty prints iface running state """

        for i in ifacenames:
            ifaceobj = self.get_ifaceobj_first(i)
            if ifaceobj.status == ifaceStatus.NOTFOUND:
                print 'iface %s' %ifaceobj.name + ' (not found)\n'
                continue
            if not ifaceobj.is_config_present():
                continue
            if format == 'json':
                ifaceobj.dump_json()
            else:
                ifaceobj.dump_pretty()
            if self.WITH_DEPENDS and not self.ALL:
                dlist = ifaceobj.lowerifaces
                if not dlist: continue
                self.print_ifaceobjsrunning_pretty(dlist, format)
        return

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
