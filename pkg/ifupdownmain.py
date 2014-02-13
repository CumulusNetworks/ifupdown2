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
from statemanager import *
from networkinterfaces import *
from iface import *
from scheduler import *
from collections import deque
from collections import OrderedDict
from graph import *
from sets import Set

class ifupdownMain():

    # Flags
    WITH_DEPENDS = False
    ALL = False
    STATE_CHECK = False

    # priv flags to mark iface objects
    BUILTIN = 0x1
    NOCONFIG = 0x2

    scripts_dir='/etc/network'
    addon_modules_dir='/usr/share/ifupdownaddons'
    addon_modules_configfile='/etc/network/.addons.conf'

    # iface dictionary in the below format:
    # { '<ifacename>' : [<ifaceobject1>, <ifaceobject2> ..] }
    # eg:
    # { 'swp1' : [<ifaceobject1>, <ifaceobject2> ..] }
    #
    # Each ifaceobject corresponds to a configuration block for
    # that interface
    ifaceobjdict = OrderedDict()


    # iface dictionary representing the curr running state of an iface
    # in the below format:
    # {'<ifacename>' : <ifaceobject>}
    ifaceobjcurrdict = OrderedDict()

    # Dictionary representing operation, sub operation and modules
    # for every sub operation
    operations = OrderedDict([('pre-up', []),
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
    operations_compat = OrderedDict([('pre-up', []),
                                    ('up' , []),
                                    ('post-up' , []),
                                    ('pre-down', []),
                                    ('down' , []),
                                    ('post-down' , [])])


    def __init__(self, force=False, dryrun=False, nowait=False,
                 perfmode=False, withdepends=False, njobs=1,
                 cache=False):
        self.logger = logging.getLogger('ifupdown')

        self.FORCE = force
        self.DRYRUN = dryrun
        self.NOWAIT = nowait
        self.PERFMODE = perfmode
        self.WITH_DEPENDS = withdepends
        self.CACHE = cache
        self._DELETE_DEPENDENT_IFACES_WITH_NOCONFIG = False

        self.ifaces = OrderedDict()
        self.njobs = njobs
        self.pp = pprint.PrettyPrinter(indent=4)
        self.modules = OrderedDict({})
        self.module_attrs = {}
        self.load_addon_modules(self.addon_modules_dir)
        self.load_scripts(self.scripts_dir)
        self.dependency_graph = OrderedDict({})

        try:
            self.statemanager = stateManager()
            self.statemanager.read_saved_state()
        except Exception, e:
            # XXX Maybe we should continue by ignoring old state
            self.logger.warning('error reading state (%s)' %str(e))
            raise

    def get_subops(self, op):
        """ Returns sub-operation list """
        return self.operations.get(op).keys()

    def compat_conv_op_to_mode(self, op):
        """ Returns old op name to work with existing scripts """
        if op == 'pre-up':
            return 'start'
        elif op == 'pre-down':
            return 'stop'
        else:
            return op

    def set_force(self, force):
        """ Set force flag. """
        self.FORCE = force

    def get_force(self):
        """ return force flag. """
        return self.FORCE

    def set_dryrun(self, dryrun):
        self.DRYRUN = dryrun

    def get_dryrun(self):
        return self.DRYRUN

    def get_cache(self):
        return self.CACHE

    def get_ifaceobjdict(self):
        return self.ifaceobjdict

    def set_ifaceobjdict(self, ifaceobjdict):
        del self.ifaceobjdict
        self.ifaceobjdict = ifaceobjdict

    def set_dependency_graph(self, dependency_graph):
        self.dependency_graph = dependency_graph

    def get_dependency_graph(self):
        return self.dependency_graph

    def set_perfmode(self, perfmode):
        self.PERFMODE = perfmode

    def get_perfmode(self):
        return self.PERFMODE

    def set_nowait(self, nowait):
        self.NOWAIT = nowait

    def get_nowait(self):
        return self.NOWAIT

    def set_njobs(self, njobs):
        self.logger.debug('setting njobs to %d' %njobs)
        self.njobs = njobs

    def get_njobs(self):
        return self.njobs

    def get_withdepends(self):
        return self.WITH_DEPENDS

    def set_withdepends(self, withdepends):
        self.logger.debug('setting withdepends to true')
        self.WITH_DEPENDS = withdepends

    def set_iface_state(self, ifaceobj, state, status):
        ifaceobj.set_state(state)
        ifaceobj.set_status(status)
        self.statemanager.update_iface_state(ifaceobj)

    def get_iface_objs(self, ifacename):
        return self.ifaceobjdict.get(ifacename)

    def get_iface_obj_first(self, ifacename):
        ifaceobjs = self.get_iface_objs(ifacename)
        if ifaceobjs is not None:
            return ifaceobjs[0]
        return None

    def get_iface_obj_last(self, ifacename):
        return self.ifaceobjdict.get(ifacename)[-1]

    def create_n_save_ifaceobjcurr(self, ifaceobj):
        ifacename = ifaceobj.get_name()
        ifaceobjcurr = self.get_ifaceobjcurr(ifacename)
        if ifaceobjcurr is not None:
            return ifaceobjcurr

        ifaceobjcurr = iface()
        ifaceobjcurr.set_name(ifacename)
        ifaceobjcurr.set_lowerifaces(ifaceobj.get_lowerifaces())
        self.ifaceobjcurrdict[ifacename] = ifaceobjcurr

        return ifaceobjcurr

    def get_ifaceobjcurr(self, ifacename):
        return self.ifaceobjcurrdict.get(ifacename)

    def get_ifaceobjrunning(self, ifacename):
        return self.ifaceobjrunningdict.get(ifacename)

    def get_iface_status(self, ifacename):
        ifaceobjs = self.get_iface_objs(ifacename)
        for i in ifaceobjs:
            if i.get_status() != ifaceStatus.SUCCESS:
                return i.get_status()

        return ifaceStatus.SUCCESS

    def get_iface_refcnt(self, ifacename):
        max = 0
        ifaceobjs = self.get_iface_objs(ifacename)
        for i in ifaceobjs:
            if i.get_refcnt() > max:
                max = i.get_refcnt()
        return max

    def create_n_save_ifaceobj(self, ifacename, priv_flags=None,
                               increfcnt=False):
        """ creates and returns a fake vlan iface object.
        This was added to support creation of simple vlan
        devices without any user specified configuration.
        """
        ifaceobj = iface()
        ifaceobj.set_name(ifacename)
        ifaceobj.priv_flags = priv_flags
        ifaceobj.set_auto()
        if increfcnt:
            ifaceobj.inc_refcnt()
        self.ifaceobjdict[ifacename] = [ifaceobj]

        return ifaceobj

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
        """ Returns true if iface name did not have a user defined config.
       
        These interfaces appear only when they are dependents of interfaces
        which have user defined config
        """
        return (ifaceobj.priv_flags & self.NOCONFIG)

    def is_iface_noconfig(self, ifacename):
        """ Returns true if iface has no config """

        ifaceobj = self.get_iface_obj_first(ifacename)
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
            dilist = self.get_iface_objs(d)
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
        for op in ops:
            for mname in self.operations.get(op):
                module = self.modules.get(mname)
                if op == 'query-running':
                    if (hasattr(module,
                        'get_dependent_ifacenames_running') == False):
                        continue
                    dlist = module.get_dependent_ifacenames_running(ifaceobj)
                else:
                    if (hasattr(module, 'get_dependent_ifacenames') == False):
                        continue
                    dlist = module.get_dependent_ifacenames(ifaceobj,
                                        self.ifaceobjdict.keys())
                if dlist and len(dlist):
                    self.logger.debug('%s: ' %ifaceobj.get_name() +
                                'got lowerifaces/dependents: %s' %str(dlist))
                    break
        return dlist

    def populate_dependency_info(self, ifacenames, ops):
        """ recursive function to generate iface dependency info """

        if ifacenames is None:
            ifacenames = self.ifaceobjdict.keys()

        self.logger.debug('populating dependency info for %s' %str(ifacenames))

        iqueue = deque(ifacenames)
        while iqueue:
            i = iqueue.popleft()

            # Go through all modules and find dependent ifaces
            dlist = None
            ifaceobj = self.get_iface_obj_first(i)
            if ifaceobj is None: 
                continue

            dlist = ifaceobj.get_lowerifaces()
            if dlist is None:
                dlist = self.query_dependents(ifaceobj, ops)
            else:
                continue

            if dlist is not None:
                self.preprocess_dependency_list(ifaceobj.get_name(),
                                                dlist, ops)
                self.logger.debug('%s: lowerifaces/dependents after processing: %s'
                                  %(i, str(dlist)))
                ifaceobj.set_lowerifaces(dlist)
                [iqueue.append(d) for d in dlist]

            if self.dependency_graph.get(i) is None:
                self.dependency_graph[i] = dlist

    def _save_iface(self, ifaceobj):
        if not self.ifaceobjdict.get(ifaceobj.get_name()):
            self.ifaceobjdict[ifaceobj.get_name()] = [ifaceobj]
        else:
            self.ifaceobjdict[ifaceobj.get_name()].append(ifaceobj)

    def _module_syntax_checker(self, attrname, attrval):
        for m, mdict in self.module_attrs.items():
            attrsdict = mdict.get('attrs')
            if attrsdict and attrname in attrsdict.keys(): return True
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

        # Read it from the statemanager
        self.ifaceobjdict = self.statemanager.get_ifaceobjdict()

    def load_addon_modules_config(self):
        with open(self.addon_modules_configfile, 'r') as f:
            lines = f.readlines()
            for l in lines:
                litems = l.rstrip(' \n').split(',')
                operation = litems[0]
                mname = litems[1]
                self.operations[operation].append(mname)

    def load_addon_modules(self, modules_dir):
        """ load python modules from modules_dir

        Default modules_dir is /usr/share/ifupdownmodules

        """
        self.logger.info('loading builtin modules from %s' %modules_dir)
        self.load_addon_modules_config()
        if not modules_dir in sys.path:
            sys.path.append(modules_dir)
        try:
            for op, mlist in self.operations.items():
                for mname in mlist:
                    if self.modules.get(mname) is not None:
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
                                        cache=self.CACHE)
                        self.modules[mname] = minstance
                        if hasattr(minstance, 'get_modinfo'):
                            self.module_attrs[mname] = minstance.get_modinfo()
        except: 
            raise

        # Assign all modules to query operations
        self.operations['query-checkcurr'] = self.modules.keys()
        self.operations['query-running'] = self.modules.keys()
        self.operations['query-dependency'] = self.modules.keys()
        self.operations['query'] = self.modules.keys()
        self.operations['query-raw'] = self.modules.keys()

    def modules_help(self):
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
        for op, mlist in self.operations_compat.items():
            msubdir = modules_dir + '/if-%s.d' %op
            self.logger.info('loading scripts under %s ...' %msubdir)
            try:
                module_list = os.listdir(msubdir)
                for module in module_list:
                    if  self.modules.get(module) is not None:
                        continue
                    self.operations_compat[op].append(
                                    msubdir + '/' + module)
            except: 
                raise

    def conv_iface_namelist_to_objlist(self, intf_list):
        for intf in intf_list:
            iface_obj = self.get_iface(intf)
            if not iface_obj:
                raise ifupdownInvalidValue('no iface %s', intf)
            iface_objs.append(iface_obj)
        return iface_objs


    def run_without_dependents(self, ops, ifacenames):
        """ Run interface list without their dependents """
        if not ifacenames:
            raise ifupdownInvalidValue('no interfaces found')

        self.logger.debug('run_without_dependents for ops %s for %s'
                %(str(ops), str(ifacenames)))

        ifaceSched = ifaceScheduler(force=self.FORCE)
        ifaceSched.run_iface_list(self, ifacenames, ops, parent=None,
                                  order=ifaceSchedulerFlags.INORDER
                                    if 'down' in ops[0]
                                        else ifaceSchedulerFlags.POSTORDER,
                                                followdependents=False)

    def run_with_dependents(self, ops, ifacenames):
        ret = 0
        self.logger.debug('running \'%s\' with dependents for %s'
                          %(str(ops), str(ifacenames)))

        ifaceSched = ifaceScheduler()
        if ifacenames is None:
            ifacenames = self.ifaceobjdict.keys()

        self.logger.info('dependency graph:')
        self.logger.info(self.pp.pformat(self.dependency_graph))

        if self.njobs > 1:
            ret = ifaceSched.run_iface_dependency_graph_parallel(self,
                        self.dependency_graph, ops)
        else:
            ret = ifaceSched.run_iface_dependency_graphs(self,
                        self.dependency_graph, ops,
                        order=ifaceSchedulerFlags.INORDER
                            if 'down' in ops[0]
                                else ifaceSchedulerFlags.POSTORDER)
        return ret

    def print_dependency(self, ifacenames, format):
        if ifacenames is None:
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

    def validate_ifaces(self, ifacenames):
        """ validates interface list for config existance.
       
        returns -1 if one or more interface not found. else, returns 0

        """

        err_iface = ''
        for i in ifacenames:
            ifaceobjs = self.get_iface_objs(i)
            if ifaceobjs is None:
                err_iface += ' ' + i

        if len(err_iface):
            self.logger.error('could not find interfaces: %s' %err_iface)
            return -1

        return 0


    def iface_whitelisted(self, auto, allow_classes, excludepats, ifacename):
        """ Checks if interface is whitelisted depending on set of parameters.


        interfaces are checked against the allow_classes and auto lists.

        """
        # If the interface matches
        if excludepats and len(excludepats):
            for e in excludepats:
                if re.search(e, ifacename):
                    return False

        ifaceobjs = self.get_iface_objs(ifacename)
        if ifaceobjs is None:
            self.logger.debug('iface %s' %ifacename + ' not found')
            return False

        # We check classes first
        if allow_classes and len(allow_classes):
            for i in ifaceobjs:
                if len(i.get_classes()):
                    common = Set([allow_classes]).intersection(
                                Set(i.get_classes()))
                    if len(common):
                        return True
            return False

        if auto:
            for i in ifaceobjs:
                if i.get_auto():
                    return True
            return False

        return True

    def generate_running_env(self, ifaceobj, op):
        """ Generates a dictionary with env variables required for
        an interface. Used to support script execution for interfaces.
        """

        cenv = None
        iface_env = ifaceobj.get_env()
        if iface_env is not None:
            cenv = os.environ
            if cenv:
                cenv.update(iface_env)
            else:
                cenv = iface_env

            cenv['MODE'] = self.compat_conv_op_to_mode(op)

        return cenv

    def up(self, ops, auto=False, allow_classes=None, ifacenames=None,
           excludepats=None, printdependency=None):
        if auto:
            self.ALL = True
            self.WITH_DEPENDS = True

        try:
            self.read_iface_config()
        except Exception, e:
            raise

        if ifacenames is not None:
            # If iface list is given by the caller, always check if iface
            # is present
           if self.validate_ifaces(ifacenames) != 0:
               raise Exception('all or some interfaces not found')

        # if iface list not given by user, assume all from config file
        if ifacenames is None: ifacenames = self.ifaceobjdict.keys()

        # filter interfaces based on auto and allow classes
        filtered_ifacenames = [i for i in ifacenames
                               if self.iface_whitelisted(auto, allow_classes,
                                                excludepats, i)]
        if not len(filtered_ifacenames):
            raise Exception('no ifaces found matching given allow lists')

        self.populate_dependency_info(filtered_ifacenames, ops)

        if printdependency is not None:
            self.print_dependency(filtered_ifacenames, printdependency)
            return

        if self.WITH_DEPENDS:
            self.run_with_dependents(ops, filtered_ifacenames)
        else:
            self.run_without_dependents(ops, filtered_ifacenames)

        # Update persistant iface states
        try:
            if self.ALL:
                self.statemanager.flush_state(self.ifaceobjdict)
            else:
                self.statemanager.flush_state()
        except Exception, e:
            if self.logger.isEnabledFor(logging.DEBUG):
                t = sys.exc_info()[2]
                traceback.print_tb(t)
            self.logger.warning('error saving state (%s)' %str(e))

    def down(self, ops, auto=False, allow_classes=None, ifacenames=None,
             excludepats=None, printdependency=None):
        loaded_newconfig = False
        if auto:
            self.ALL = True
            self.WITH_DEPENDS = True

        # for down we need to look at old state
        self.logger.debug('Looking at old state ..')

        if len(self.statemanager.get_ifaceobjdict()):
            self.read_old_iface_config()
        elif self.FORCE:
            # If no old state available 
            self.logger.info('old state not available. ' +
                'Force option set. Loading new iface config file')
            try:
                self.read_iface_config()
            except Exception, e:
                raise Exception('error reading iface config (%s)' %str(e))
            loaded_newconfig = True
        else:
            raise Exception('old state not available...aborting.' +
                            ' try running with --force option')

        if ifacenames:
            # If iface list is given by the caller, always check if iface
            # is present
           if self.validate_ifaces(ifacenames) != 0:
               raise Exception('all or some interfaces not found')

        # if iface list not given by user, assume all from config file
        if ifacenames is None: ifacenames = self.ifaceobjdict.keys()

        # filter interfaces based on auto and allow classes
        filtered_ifacenames = [i for i in ifacenames
                               if self.iface_whitelisted(auto, allow_classes,
                                                excludepats, i)]
        if not len(filtered_ifacenames):
            raise Exception('no ifaces found matching given allow lists')

        self.populate_dependency_info(filtered_ifacenames, ops)
        if printdependency:
            self.print_dependency(filtered_ifacenames, printdependency)
            return

        if self.WITH_DEPENDS:
            self.run_with_dependents(ops, filtered_ifacenames)
        else:
            self.run_without_dependents(ops, filtered_ifacenames)

        if loaded_newconfig:
            # Update persistant iface states
            try:
                if self.ALL:
                    self.statemanager.flush_state(self.ifaceobjdict)
                else:
                    self.statemanager.flush_state()
            except Exception, e:
                if self.logger.isEnabledFor(logging.DEBUG):
                    t = sys.exc_info()[2]
                    traceback.print_tb(t)
                self.logger.warning('error saving state (%s)' %str(e))

    def query(self, ops, auto=False, allow_classes=None, ifacenames=None,
              excludepats=None, printdependency=None,
              format='native'):
        if auto:
            self.logger.debug('setting flag ALL')
            self.ALL = True
            self.WITH_DEPENDS = True

        if ops[0] == 'query-syntax':
            self.modules_help()
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

        if ifacenames is not None and ops[0] != 'query-running':
            # If iface list is given, always check if iface is present
           if self.validate_ifaces(ifacenames) != 0:
               raise Exception('all or some interfaces not found')

        # if iface list not given by user, assume all from config file
        if ifacenames is None: ifacenames = self.ifaceobjdict.keys()

        # filter interfaces based on auto and allow classes
        if ops[0] == 'query-running':
            filtered_ifacenames = ifacenames
        else:
            filtered_ifacenames = [i for i in ifacenames
                if self.iface_whitelisted(auto, allow_classes,
                        excludepats, i)]
        if len(filtered_ifacenames) == 0:
                raise Exception('no ifaces found matching ' +
                        'given allow lists')

        self.populate_dependency_info(filtered_ifacenames, ops)
        if ops[0] == 'query-dependency' and printdependency:
            self.print_dependency(filtered_ifacenames, printdependency)
            return

        if ops[0] == 'query':
            return self.print_ifaceobjs_pretty(filtered_ifacenames, format)
        elif ops[0] == 'query-raw':
            return self.print_ifaceobjs_raw(filtered_ifacenames)

        if self.WITH_DEPENDS:
            self.run_with_dependents(ops, filtered_ifacenames)
        else:
            self.run_without_dependents(ops, filtered_ifacenames)

        if ops[0] == 'query-checkcurr':
            ret = self.print_ifaceobjscurr_pretty(filtered_ifacenames, format)
            if ret != 0:
                # if any of the object has an error, signal that silently
                raise Exception('')
        elif ops[0] == 'query-running':
            self.print_ifaceobjsrunning_pretty(filtered_ifacenames, format)
            return

    def reload(self, auto=False, allow=None,
               ifacenames=None, excludepats=None, downchangediface=False):
        """ main ifupdown run method """
        allow_classes = []
        upops = ['pre-up', 'up', 'post-up']
        downops = ['pre-down', 'down', 'post-down']

        self.logger.debug('reloading interface config ..')

        if auto:
            self.ALL = True
            self.WITH_DEPENDS = True

        try:
            # Read the current interface config
            self.read_iface_config()
        except Exception, e:
            raise

        # generate dependency graph of interfaces
        self.populate_dependency_info(ifacenames, upops)

        # Save a copy of new iface objects and dependency_graph
        new_ifaceobjdict = dict(self.get_ifaceobjdict())
        new_dependency_graph = dict(self.get_dependency_graph())

        if len(self.statemanager.get_ifaceobjdict()) > 0:
            # if old state is present, read old state and mark op for 'down'
            # followed by 'up' aka: reload
            # old interface config is read into self.ifaceobjdict
            #
            self.read_old_iface_config()
            op = 'reload'
        else:
            # oldconfig not available, continue with 'up' with new config
            op = 'up'

        if ifacenames is None: ifacenames = self.ifaceobjdict.keys()

        if (op == 'reload' and ifacenames is not None and
                len(ifacenames) != 0):
            filtered_ifacenames = [i for i in ifacenames
                               if self.iface_whitelisted(auto, allow_classes,
                               excludepats, i)]

            # Generate the interface down list
            # Interfaces that go into the down list:
            #   - interfaces that were present in last config and are not
            #     present in the new config
            #   - interfaces that were changed between the last and current
            #     config
            #
            ifacedownlist = []
            for ifname, lastifobjlist in self.ifaceobjdict.items():
                objidx = 0

                # If interface is not present in the new file
                # append it to the down list
                newifobjlist = new_ifaceobjdict.get(ifname)
                if newifobjlist == None:
                    ifacedownlist.append(ifname)
                    continue

                if downchangediface == False:
                    continue

                # If interface has changed between the current file
                # and the last installed append it to the down list
                if len(newifobjlist) != len(lastifobjlist):
                    ifacedownlist.append(ifname)
                    continue

                # compare object list
                for objidx in range(0, len(lastifobjlist)):
                    oldobj = lastifobjlist[objidx]
                    newobj = newifobjlist[objidx]
                    if newobj.is_different(oldobj):
                        ifacedownlist.append(ifname)
                        continue


            if ifacedownlist is not None and len(ifacedownlist) > 0:
                self.logger.info('Executing down on interfaces: %s'
                                  %str(ifacedownlist))
                # Generate dependency info for old config
                self.populate_dependency_info(ifacedownlist, downops)
                if len(ifacedownlist) == len(self.ifaceobjdict):
                    # if you are downing all interfaces, its better run
                    # with dependents
                    self.run_with_dependents(downops, ifacedownlist)
                else:
                    # if not, down only the interfaces that we have in the
                    # down list
                    self.run_without_dependents(downops, ifacedownlist)
                # Update persistant iface states
                try:
                    if self.ALL:
                        self.statemanager.flush_state(self.ifaceobjdict)
                    else:
                        self.statemanager.flush_state()
                except Exception, e:
                    if self.logger.isEnabledFor(logging.DEBUG):
                        t = sys.exc_info()[2]
                        traceback.print_tb(t)
                    self.logger.warning('error saving state (%s)' %str(e))
            else:
                self.logger.debug('no interfaces to down ..')

        # Now, run up with new config dict
        self.set_ifaceobjdict(new_ifaceobjdict)
        self.set_dependency_graph(new_dependency_graph)

        ifacenames = self.ifaceobjdict.keys()
        filtered_ifacenames = [i for i in ifacenames
                               if self.iface_whitelisted(auto, allow_classes,
                               excludepats, i)]

        self.logger.info('Executing up on interfaces: %s'
                                  %str(filtered_ifacenames))
        if self.WITH_DEPENDS:
            self.run_with_dependents(upops, filtered_ifacenames)
        else:
            self.run_without_dependents(upops, filtered_ifacenames)

        # Update persistant iface states
        try:
            if self.ALL:
                self.statemanager.flush_state(self.get_ifaceobjdict())
            else:
                self.statemanager.flush_state()
        except Exception, e:
            if self.logger.isEnabledFor(logging.DEBUG):
                t = sys.exc_info()[2]
                traceback.print_tb(t)
                self.logger.warning('error saving state (%s)' %str(e))

    def dump(self):
        """ all state dump """

        print 'ifupdown object dump'
        print self.pp.pprint(self.modules)
        print self.pp.pprint(self.ifaces)
        self.state_manager.dump()

    def print_state(self, ifacenames=None):
        self.statemanager.dump(ifacenames)

    def print_ifaceobjs_raw(self, ifacenames):
        for i in ifacenames:
            for ifaceobj in self.get_iface_objs(i):
                if (self.is_ifaceobj_builtin(ifaceobj) or 
                    not ifaceobj.is_config_present()):
                    continue
                ifaceobj.dump_raw(self.logger)
                print '\n'
                if self.WITH_DEPENDS:
                    dlist = ifaceobj.get_lowerifaces()
                    if not dlist or not len(dlist): continue
                    self.print_ifaceobjs_pretty(dlist, format)

    def print_ifaceobjs_pretty(self, ifacenames, format='native'):
        for i in ifacenames:
            for ifaceobj in self.get_iface_objs(i):
                if (self.is_ifaceobj_builtin(ifaceobj) or 
                    not ifaceobj.is_config_present()):
                    continue
                if format == 'json':
                    ifaceobj.dump_json()
                else:
                    ifaceobj.dump_pretty()

                if self.WITH_DEPENDS:
                    dlist = ifaceobj.get_lowerifaces()
                    if not dlist or not len(dlist): continue
                    self.print_ifaceobjs_pretty(dlist, format)

    def dump_ifaceobjs(self, ifacenames):
        for i in ifacenames:
            ifaceobjs = self.get_iface_objs(i)
            for i in ifaceobjs:
                i.dump(self.logger)
                print '\n'

    def print_ifaceobjscurr_pretty(self, ifacenames, format='native'):
        """ Dumps current running state of interfaces.

        returns 1 if any of the interface has an error,
        else returns 0
        """
        ret = 0
        for i in ifacenames:
            ifaceobj = self.get_ifaceobjcurr(i)
            if not ifaceobj: continue
            if ifaceobj.get_status() == ifaceStatus.NOTFOUND:
                print 'iface %s' %ifaceobj.get_name() + ' (not found)\n'
                ret = 1
                continue
            elif ifaceobj.get_status() == ifaceStatus.ERROR:
                ret = 1

            if (self.is_ifaceobj_builtin(ifaceobj) or 
                    ifaceobj.is_config_present() == False):
                continue

            if format == 'json':
                ifaceobj.dump_json()
            else:
                ifaceobj.dump_pretty()

            if self.WITH_DEPENDS:
                dlist = ifaceobj.get_lowerifaces()
                if not dlist or not len(dlist): continue
                self.print_ifaceobjscurr_pretty(dlist, format)

        return ret

    def print_ifaceobjsrunning_pretty(self, ifacenames, format='native'):
        for i in ifacenames:
            ifaceobj = self.get_iface_obj_first(i)
            if ifaceobj.get_status() == ifaceStatus.NOTFOUND:
                print 'iface %s' %ifaceobj.get_name() + ' (not found)\n'
                continue

            if ifaceobj.is_config_present() == False:
                continue

            if format == 'json':
                ifaceobj.dump_json()
            else:
                ifaceobj.dump_pretty()

            if self.WITH_DEPENDS:
                dlist = ifaceobj.get_lowerifaces()
                if dlist is None or len(dlist) == 0: continue
                self.print_ifaceobjsrunning_pretty(dlist, format)
        return

    def print_ifaceobjs_saved_state_pretty(self, ifacenames):
        self.statemanager.print_state_pretty(ifacenames, self.logger)

    def print_ifaceobjs_saved_state_detailed_pretty(self, ifacenames):
        self.statemanager.print_state_detailed_pretty(ifacenames, self.logger)
