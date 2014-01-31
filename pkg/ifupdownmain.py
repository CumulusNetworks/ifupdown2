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
    operations = { 'up' :
                    OrderedDict([('pre-up', []),
                                 ('up' , []),
                                 ('post-up' , [])]),
                   'query-checkcurr' :
                    OrderedDict([('query-checkcurr', [])]),

                   'query-running' :
                   OrderedDict([('query-running', [])]),

                   'down' :
                    OrderedDict([('pre-down', []),
                                 ('down' , []),
                                 ('post-down' , [])])}

    # For old style /etc/network/ bash scripts
    operations_compat = { 'up' :
                    OrderedDict([('pre-up', []),
                                 ('up' , []),
                                 ('post-up' , [])]),
                   'down' :
                    OrderedDict([('pre-down', []),
                                 ('down' , []),
                                 ('post-down' , [])])}



    def __init__(self, force=False, dryrun=False, nowait=False,
                 perfmode=False, withdepends=False, njobs=1,
                 format='nwifaces', cache=False):
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
        self.load_addon_modules_config()
        self.load_addon_modules(self.addon_modules_dir)
        self.load_scripts(self.scripts_dir)
        self.dependency_graph = {}

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
        if op == 'up':
            return 'start'
        elif op == 'down':
            return 'stop'
        else:
            return op

    def set_force(self, force):
        """ Set force flag. """
        if force == True:
            self.logger.debug('setting force to true')
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
        if perfmode == True:
            self.logger.debug('setting perfmode to true')
        self.PERFMODE = perfmode

    def get_perfmode(self):
        return self.PERFMODE

    def set_nowait(self, nowait):
        if nowait == True:
            self.logger.debug('setting dryrun to true')
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

    def create_ifaceobjcurr(self, ifaceobj):
        ifacename = ifaceobj.get_name()
        ifaceobjcurr = self.get_ifaceobjcurr(ifacename)
        if ifaceobjcurr is not None:
            return ifaceobjcurr

        ifaceobjcurr = iface()
        ifaceobjcurr.set_name(ifacename)
        ifaceobjcurr.set_dependents(ifaceobj.get_dependents())
        self.ifaceobjcurrdict[ifacename] = ifaceobjcurr

        return ifaceobj

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
        if increfcnt == True:
            ifaceobj.inc_refcnt()
        self.ifaceobjdict[ifacename] = [ifaceobj]

    def is_iface_builtin(self, ifacename):
        """ Returns true if iface name is a builtin interface.
        
        A builtin interface is an interface which ifupdown understands.
        The following are currently considered builtin ifaces:
            - vlan interfaces in the format <ifacename>.<vlanid>
        """
        if re.search(r'\.', ifacename, 0) is not None:
            return True
        return False

    def is_ifaceobj_builtin(self, ifaceobj):
        """ Returns true if iface name is a builtin interface.
        
        A builtin interface is an interface which ifupdown understands.
        The following are currently considered builtin ifaces:
            - vlan interfaces in the format <ifacename>.<vlanid>
        """

        if (ifaceobj.priv_flags & self.BUILTIN) != 0:
            return True

        return False

    def is_ifaceobj_noconfig(self, ifaceobj):
        """ Returns true if iface name did not have a user defined config.
       
        These interfaces appear only when they are dependents of interfaces
        which have user defined config
        """

        if (ifaceobj.priv_flags & self.NOCONFIG) != 0:
            return True

        return False

    def preprocess_dependency_list(self, dlist, op):
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
            if dilist == None:
                if self.is_iface_builtin(d) == True:
                    self.create_n_save_ifaceobj(d, self.BUILTIN, True),
                elif self._DELETE_DEPENDENT_IFACES_WITH_NOCONFIG == False:
                    # create fake devices to all dependents that dont
                    # have config
                    self.create_n_save_ifaceobj(d, self.NOCONFIG, True),
                else:
                    del_list.append(d)
            else:
                for di in dilist:
                    di.inc_refcnt()

        for d in del_list:
            dlist.remove(d)

    def get_dependents(self, ifaceobj, op):
        """ Gets iface dependents by calling into respective modules """
        dlist = None

        # Get dependents for interface by querying respective modules
        subopdict = self.operations.get(op)
        for subop, mlist in subopdict.items():
            for mname in mlist:
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
                if dlist is not None and len(dlist) > 0:
                    ifaceobj.set_realdev_dependents(dlist[:])
                    self.logger.debug('%s: ' %ifaceobj.get_name() +
                                'got dependency list: %s' %str(dlist))
                    break

        return dlist

    def populate_dependency_info(self, ifacenames, op):
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

            dlist = ifaceobj.get_dependents()
            if dlist is None:
                dlist = self.get_dependents(ifaceobj, op)
            else:
                continue

            if dlist is not None:
                self.preprocess_dependency_list(dlist, op)
                self.logger.debug('%s: dependency list after processing: %s'
                                  %(i, str(dlist)))
                ifaceobj.set_dependents(dlist)
                [iqueue.append(d) for d in dlist]

            if self.dependency_graph.get(i) is None:
                self.dependency_graph[i] = dlist

    def is_valid_state_transition(self, ifname, to_be_state):
        return self.statemanager.is_valid_state_transition(ifname,
                to_be_state)

    def save_iface(self, ifaceobj):
        if self.ifaceobjdict.get(ifaceobj.get_name()) is None:
            self.ifaceobjdict[ifaceobj.get_name()] = [ifaceobj]
        else:
            self.ifaceobjdict[ifaceobj.get_name()].append(ifaceobj)

    def read_default_iface_config(self):
        """ Reads default network interface config /etc/network/interfaces. """
        nifaces = networkInterfaces()
        nifaces.subscribe('iface_found', self.save_iface)
        nifaces.load()

    def read_iface_config(self):
        return self.read_default_iface_config()

    def read_old_iface_config(self):
        """ Reads the saved iface config instead of default iface config. """

        # Read it from the statemanager
        self.ifaceobjdict = self.statemanager.get_ifaceobjdict()


    def save_module(self, mkind, msubkind, mname, mftype, module):
        """ saves a module into internal module dict for later use.
        
        mtype - pre-up.d, post-up.d and so on
        mftype - pmodule (python module), bashscript (bash script)
        
        """

        try:
            mmetadata = self.operations[mkind][msubkind].get(mname)
        except KeyError:
            self.logger.warn('unsupported module type %s' %mname)
            return

        if mmetadata is None or mmetadata.get('ftype') != 'pmodule':
            mmetadata = {}
            mmetadata['ftype'] = mftype
            mmetadata['module'] = module
            self.operations[mkind][msubkind][mname] = mmetadata

            self.logger.debug('saved module %s' %mkind +
                             ' %s' %mname + ' %s' %mftype)
        else:
            self.logger.info('ignoring module %s' %mkind + ' %s' %msubkind +
                        ' %s' %mname + ' of type %s' %mftype)


    def load_addon_modules_config(self):
        with open(self.addon_modules_configfile, 'r') as f:
            lines = f.readlines()
            for l in lines:
                litems = l.rstrip(' \n').split(',')
                operation = litems[0]
                mname = litems[1]
                if operation.find('up') != -1:
                    self.operations['up'][operation].append(mname)
                elif operation.find('down') != -1:
                    self.operations['down'][operation].append(mname)

    def load_addon_modules(self, modules_dir):
        """ load python modules from modules_dir

        Default modules_dir is /usr/share/ifupdownmodules

        """
        self.logger.info('loading builtin modules from %s' %modules_dir)

        if not modules_dir in sys.path:
            sys.path.append(modules_dir)
        try:
            for op, opdict in self.operations.items():
                for subop, mlist in opdict.items():
                    for mname in mlist:
                        if self.modules.get(mname) is not None:
                            continue
                        mpath = modules_dir + '/' + mname + '.py'
                        if os.path.exists(mpath) == True:
                            try:
                                m = __import__(mname)
                                mclass = getattr(m, mname)
                            except:
                                raise

                            minstance = mclass(force=self.get_force(),
                                               dryrun=self.get_dryrun(),
                                               nowait=self.get_nowait(),
                                               perfmode=self.get_perfmode(),
                                               cache=self.get_cache())
                            self.modules[mname] = minstance
        except: 
            raise

        # Assign all modules to query operations
        self.operations['query-checkcurr']['query-checkcurr'] = self.modules.keys()
        self.operations['query-running']['query-running'] = self.modules.keys()

    def load_scripts(self, modules_dir):
        """ loading user modules from /etc/network/.

        Note that previously loaded python modules override modules found
        under /etc/network if any

        """

        self.logger.info('looking for user scripts under %s' %modules_dir)
        for op, subops in self.operations_compat.items():
            for subop in subops.keys():
                msubdir = modules_dir + '/if-%s.d' %subop
                self.logger.info('loading scripts under %s ...' %msubdir)
                try:
                    module_list = os.listdir(msubdir)
                    for module in module_list:
                       if  self.modules.get(module) is not None:
                           continue
                       self.operations_compat[op][subop].append(
                                    msubdir + '/' + module)
                except: 
                    raise

    def conv_iface_namelist_to_objlist(self, intf_list):
        for intf in intf_list:
            iface_obj = self.get_iface(intf)
            if iface_obj == None:
                raise ifupdownInvalidValue('no iface %s', intf)

            iface_objs.append(iface_obj)

        return iface_objs


    def run_without_dependents(self, op, ifacenames):
        """ Run interfaces without executing their dependents.

        Even though we are running without dependents here, we will have
        to cover the builtin dependents. Because the only way builtin
        devices are operated on is when they are seen as dependents.
        So we include them. And also we need to execute the user provided
        interface names in order of their dependencies.
        So, we created a special dependency_graph with interfaces matching
        the above constraints here

        if self.ALL is True you are better off using the default 
        dependency graph self.dependency_graph that carries all dependents
        """

        if ifacenames == None:
            raise ifupdownInvalidValue('no interfaces found')

        self.logger.debug('run_without_dependents for op %s' %op +
                ' for %s' %str(ifacenames))

        dependency_graph = {}
        indegrees = {}
        ifaceSched = ifaceScheduler(force=self.FORCE)

        for i in ifacenames:
            if dependency_graph.get(i) is not None:
                continue

            dependency_graph[i] = []
            indegrees[i] = 0
            ifaceobj = self.get_iface_obj_first(i)
            dlist = ifaceobj.get_dependents()
            if dlist is None:
                continue

            for d in dlist:
                ifaceobj = self.get_iface_obj_first(d)
                if (self.is_ifaceobj_builtin(ifaceobj) == True or
                        self.is_ifaceobj_noconfig(ifaceobj) == True or
                            d in ifacenames):
                    dependency_graph[i].append(d)
                    dependency_graph[d] = None
                    indegrees[d] = 1

        self.logger.debug('dependency graph: %s' %str(dependency_graph))
        ifaceSched.run_iface_dependency_graph(self, dependency_graph, op,
                                              indegrees,
                                              graphsortall=True)

    def run_with_dependents(self, op, ifacenames):
        ret = 0
        self.logger.debug('running \'%s\' with dependents for %s'
                          %(op, str(ifacenames)))

        ifaceSched = ifaceScheduler()
        if ifacenames is None:
            ifacenames = self.ifaceobjdict.keys()

        if self.logger.isEnabledFor(logging.DEBUG) == True:
            self.logger.debug('dependency graph:')
            self.logger.debug(self.pp.pformat(self.dependency_graph))

        if self.njobs > 1:
            ret = ifaceSched.run_iface_dependency_graph_parallel(self,
                        self.dependency_graph, op)
        else:
            ret = ifaceSched.run_iface_dependency_graph(self,
                        self.dependency_graph, op)
        return ret

    def print_dependency(self, op, ifacenames, format):
        if ifacenames is None:
            ifacenames = self.ifaceobjdict.keys()

        if format == 'list':
            self.pp.pprint(self.dependency_graph)
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

        if len(err_iface) != 0:
            self.logger.error('could not find interfaces: %s' %err_iface)
            return -1

        return 0


    def iface_whitelisted(self, auto, allow_classes, excludepats, ifacename):
        """ Checks if interface is whitelisted depending on set of parameters.


        interfaces are checked against the allow_classes and auto lists.

        """

        # If the interface matches
        if excludepats is not None and len(excludepats) > 0:
            for e in excludepats:
                if re.search(e, ifacename) is not None:
                    return False

        ifaceobjs = self.get_iface_objs(ifacename)
        if ifaceobjs is None:
            self.logger.debug('iface %s' %ifacename + ' not found')
            return False

        # We check classes first
        if allow_classes is not None and len(allow_classes) > 0:
            for i in ifaceobjs:
                if (len(i.get_classes()) > 0):
                    common = Set([allow_classes]).intersection(
                                Set(i.get_classes()))
                    if len(common) > 0:
                        return True
            return False

        if auto == True:
            for i in ifaceobjs:
                if i.get_auto() == True:
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
            if cenv is not None:
                cenv.update(iface_env)
            else:
                cenv = iface_env

            cenv['MODE'] = self.compat_conv_op_to_mode(op)

        return cenv

    def run(self, op, auto=False, allow_classes=None,
            ifacenames=None, excludepats=None,
            format=None, printdependency=None):
        """ main ifupdown run method """

        if auto == True:
            self.ALL = True
            self.WITH_DEPENDS = True

        # Only read new iface config for 'up'
        # operations. For 'downs' we only rely on
        # old state
        if op == 'up':
            try:
                self.read_iface_config()
            except Exception, e:
                raise
        elif op == 'down':
            # for down we need to look at old state
            self.logger.debug('down op, looking at old state ..')

            if len(self.statemanager.get_ifaceobjdict()) > 0:
                self.read_old_iface_config()
            elif self.FORCE == True:
                # If no old state available 
                self.logger.info('old state not available. ' +
                     'Force option set. Loading new iface config file')
                try:
                    self.read_iface_config()
                except Exception, e:
                    raise Exception('error reading iface config (%s)'
                                    %str(e))
            else:
                raise Exception('old state not available...aborting.' +
                        ' try running with --force option')


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
                                                excludepats, i) == True]
        if len(filtered_ifacenames) == 0:
                raise Exception('no ifaces found matching ' +
                        'given allow lists')

        self.populate_dependency_info(filtered_ifacenames, op)

        if printdependency is not None:
            self.print_dependency(op, filtered_ifacenames, printdependency)
            return

        if self.WITH_DEPENDS == True:
            self.run_with_dependents(op, filtered_ifacenames)
        else:
            self.run_without_dependents(op, filtered_ifacenames)

        # Update persistant iface states
        try:
            if self.ALL == True:
                self.statemanager.flush_state(self.ifaceobjdict)
            else:
                self.statemanager.flush_state()
        except Exception, e:
            if self.logger.isEnabledFor(logging.DEBUG):
                t = sys.exc_info()[2]
                traceback.print_tb(t)
            self.logger.warning('error saving state (%s)' %str(e))

    def up(self, auto=False, allow=None, ifacenames=None,
           excludepats=None, printdependency=None):
        return self.run('up', auto, allow, ifacenames,
                        excludepats=excludepats,
                        printdependency=printdependency)

    def down(self, auto=False, allow=None, ifacenames=None, excludepats=None):
        return self.run('down', auto, allow, ifacenames,
                        excludepats=excludepats);

    def query(self, op, auto=False, allow_classes=None, ifacenames=None,
              excludepats=None, printdependency=None,
              format=None):
        """ main ifupdown run method """
        if auto == True:
            self.logger.debug('setting flag ALL')
            self.ALL = True
            self.WITH_DEPENDS = True

        if op == 'query-running':
            # create fake devices to all dependents that dont have config
            map(lambda i: self.create_n_save_ifaceobj(i, self.NOCONFIG),
                    ifacenames)
        else:
            try:
                self.read_iface_config()
            except Exception:
                raise

        if ifacenames is not None and op != 'query-running':
            # If iface list is given, always check if iface is present
           if self.validate_ifaces(ifacenames) != 0:
               raise Exception('all or some interfaces not found')

        # if iface list not given by user, assume all from config file
        if ifacenames is None: ifacenames = self.ifaceobjdict.keys()

        # filter interfaces based on auto and allow classes
        if op == 'query-running':
            filtered_ifacenames = ifacenames
        else:
            filtered_ifacenames = [i for i in ifacenames
                if self.iface_whitelisted(auto, allow_classes,
                        excludepats, i) == True]

        if len(filtered_ifacenames) == 0:
                raise Exception('no ifaces found matching ' +
                        'given allow lists')

        if op == 'query':
            return self.print_ifaceobjs_raw(filtered_ifacenames)
        elif op == 'query-pretty':
            return self.print_ifaceobjs_pretty(filtered_ifacenames)
        elif op == 'query-presumed':
            return self.print_ifaceobjs_saved_state_pretty(
                                    filtered_ifacenames)
        elif op == 'query-presumeddetailed':
            return self.print_ifaceobjs_saved_state_detailed_pretty(
                                    filtered_ifacenames)


        self.populate_dependency_info(filtered_ifacenames, op)

        #if printdependency is not None:
        #    self.print_dependency(op, filtered_ifacenames, printdependency)
        #    return

        if self.WITH_DEPENDS == True:
            self.run_with_dependents(op, filtered_ifacenames)
        else:
            self.run_without_dependents(op, filtered_ifacenames)

        if op == 'query-checkcurr':
            ret = self.print_ifaceobjscurr_pretty(filtered_ifacenames)
            if ret != 0:
                # if any of the object has an error, signal that silently
                raise Exception('')
        elif op == 'query-running':
            self.print_ifaceobjsrunning_pretty(filtered_ifacenames)
            return


    def reload(self, auto=False, allow=None,
               ifacenames=None, excludepats=None, downchangediface=False):
        """ main ifupdown run method """
        allow_classes = []

        self.logger.debug('reloading interface config ..')

        if auto == True:
            self.ALL = True
            self.WITH_DEPENDS = True

        try:
            # Read the current interface config
            self.read_iface_config()
        except Exception, e:
            raise

        # generate dependency graph of interfaces
        self.populate_dependency_info(ifacenames, 'up')

        # Save a copy of new iface objects and dependency_graph
        new_ifaceobjdict = self.get_ifaceobjdict()
        new_dependency_graph = self.get_dependency_graph()

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
                               excludepats, i) == True]

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
                    if newobj.is_different(oldobj) == True:
                        ifacedownlist.append(ifname)
                        continue


            #ifacedownlist = Set(filtered_ifacenames).difference(
            #                    Set(new_ifaceobjdict.keys()))
            if ifacedownlist is not None and len(ifacedownlist) > 0:
                self.logger.info('Executing down on interfaces: %s'
                                  %str(ifacedownlist))

                # Generate dependency info for old config
                self.populate_dependency_info(ifacedownlist, 'down')

                if len(ifacedownlist) == len(self.ifaceobjdict):
                    # if you are downing all interfaces, its better run
                    # with dependents
                    self.run_with_dependents('down', ifacedownlist)
                else:
                    # if not, down only the interfaces that we have in the
                    # down list
                    self.run_without_dependents('down', ifacedownlist)

                # Update persistant iface states
                try:
                    if self.ALL == True:
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
                               excludepats, i) == True]

        self.logger.info('Executing up on interfaces: %s'
                                  %str(filtered_ifacenames))
        if self.WITH_DEPENDS == True:
            self.run_with_dependents('up', filtered_ifacenames)
        else:
            self.run_without_dependents('up', filtered_ifacenames)

        # Update persistant iface states
        try:
            if self.ALL == True:
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
            ifaceobjs = self.get_iface_objs(i)
            for i in ifaceobjs:
                i.dump_raw(self.logger)
                print '\n'

    def print_ifaceobjs_pretty(self, ifacenames):
        for i in ifacenames:
            [ j.dump_pretty(self.logger)
                    for j in self.get_iface_objs(i)]

    def dump_ifaceobjs(self, ifacenames):
        for i in ifacenames:
            ifaceobjs = self.get_iface_objs(i)
            for i in ifaceobjs:
                i.dump(self.logger)
                print '\n'

    def print_ifaceobjscurr_pretty(self, ifacenames, format=None):
        """ Dumps current running state of interfaces.

        returns 1 if any of the interface has an error,
        else returns 0
        """
        ret = 0
        for i in ifacenames:
            ifaceobj = self.get_ifaceobjcurr(i)
            if ifaceobj is None: continue
            if ifaceobj.get_status() == ifaceStatus.NOTFOUND:
                print 'iface %s' %ifaceobj.get_name() + ' (not found)\n'
                ret = 1
                continue
            elif ifaceobj.get_status() == ifaceStatus.ERROR:
                ret = 1

            if (self.is_iface_builtin(i) or 
                    ifaceobj.is_config_present() == False):
                continue

            if format is None or format == 'nwifaces':
                ifaceobj.dump_pretty(self.logger)
            else:
                ifaceobj.dump_json(self.logger)

            if self.ALL == False or self.WITH_DEPENDS:
                dlist = ifaceobj.get_dependents()
                if dlist is None or len(dlist) == 0: continue
                self.print_ifaceobjscurr_pretty(dlist, format)

        return ret

    def print_ifaceobjsrunning_pretty(self, ifacenames, format=None):
        for i in ifacenames:
            ifaceobj = self.get_iface_obj_first(i)
            if ifaceobj.get_status() == ifaceStatus.NOTFOUND:
                print 'iface %s' %ifaceobj.get_name() + ' (not found)\n'
                continue

            #if (self.is_iface_builtin(i) and
            #        ifaceobj.is_config_present() == False):
            if ifaceobj.is_config_present() == False:
                continue

            if format is None or format == 'nwifaces':
                ifaceobj.dump_pretty(self.logger)
            elif format == 'json':
                ifaceobj.dump_json(self.logger)

            if self.ALL == False or self.WITH_DEPENDS:
                dlist = ifaceobj.get_dependents()
                if dlist is None or len(dlist) == 0: continue
                self.print_ifaceobjsrunning_pretty(dlist, format)
        return

    def print_ifaceobjs_saved_state_pretty(self, ifacenames):
        self.statemanager.print_state_pretty(ifacenames, self.logger)

    def print_ifaceobjs_saved_state_detailed_pretty(self, ifacenames):
        self.statemanager.print_state_detailed_pretty(ifacenames, self.logger)
