#!/usr/bin/python
#
# Copyright 2013.  Cumulus Networks, Inc.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifaceScheduler --
#    interface scheduler
#

from statemanager import *
from iface import *
from graph import *
from collections import deque
from collections import OrderedDict
import logging
import traceback
import sys
from graph import *
from collections import deque
from threading import *
from ifupdownbase import *

class ifaceSchedulerFlags():
    INORDER = 0x1
    POSTORDER = 0x2

class ifaceScheduler():
    """ scheduler functions to schedule configuration of interfaces.

    supports scheduling of interfaces serially in plain interface list
    or dependency graph format.
    """

    _STATE_CHECK = True

    token_pool = None

    @classmethod
    def run_iface_op(cls, ifupdownobj, ifaceobj, op, cenv):
        """ Runs sub operation on an interface """
        ifacename = ifaceobj.name

        if (cls._STATE_CHECK and
            (ifaceobj.state >= ifaceState.from_str(op)) and
            (ifaceobj.status == ifaceStatus.SUCCESS)):
            ifupdownobj.logger.debug('%s: already in state %s' %(ifacename, op))
            return

        # first run ifupdownobj handlers
        handler = ifupdownobj.ops_handlers.get(op)
        if handler:
            if not ifaceobj.addr_method or (ifaceobj.addr_method and
                    ifaceobj.addr_method != 'manual'):
                handler(ifupdownobj, ifaceobj)

        if not ifupdownobj.ADDONS_ENABLE: return

        for mname in ifupdownobj.module_ops.get(op):
            m = ifupdownobj.modules.get(mname)
            err = 0
            try:
                if hasattr(m, 'run'):
                    msg = ('%s: %s : running module %s' %(ifacename, op, mname))
                    if op == 'query-checkcurr':
                        # Dont check curr if the interface object was 
                        # auto generated
                        if (ifaceobj.priv_flags & ifupdownobj.NOCONFIG):
                            continue
                        ifupdownobj.logger.debug(msg)
                        m.run(ifaceobj, op,
                              query_ifaceobj=ifupdownobj.create_n_save_ifaceobjcurr(ifaceobj))
                    else:
                        ifupdownobj.logger.debug(msg)
                        m.run(ifaceobj, op)
            except Exception, e:
                err = 1
                ifupdownobj.log_error(str(e))
            finally:
                if err:
                    ifaceobj.set_state_n_status(ifaceState.from_str(op),
                                                ifaceStatus.ERROR)
                else:
                    ifaceobj.set_state_n_status(ifaceState.from_str(op),
                                                ifaceStatus.SUCCESS)

        if ifupdownobj.COMPAT_EXEC_SCRIPTS:
            # execute /etc/network/ scripts 
            for mname in ifupdownobj.script_ops.get(op, []):
                ifupdownobj.logger.debug('%s: %s : running script %s'
                    %(ifacename, op, mname))
                try:
                    ifupdownobj.exec_command(mname, cmdenv=cenv)
                except Exception, e:
                    ifupdownobj.log_error(str(e))

    @classmethod
    def run_iface_ops(cls, ifupdownobj, ifaceobj, ops):
        """ Runs all operations on an interface """
        ifacename = ifaceobj.name
        # minor optimization. If operation is 'down', proceed only
        # if interface exists in the system
        if 'down' in ops[0] and not ifupdownobj.link_exists(ifacename):
            ifupdownobj.logger.info('%s: does not exist' %ifacename)
            return 
        cenv=None
        if ifupdownobj.COMPAT_EXEC_SCRIPTS:
            # For backward compatibility generate env variables
            # for attributes
            cenv = ifupdownobj.generate_running_env(ifaceobj, ops[0])
        map(lambda op: cls.run_iface_op(ifupdownobj, ifaceobj, op, cenv), ops)
        posthookfunc = ifupdownobj.sched_hooks.get('posthook')
        if posthookfunc:
            posthookfunc(ifupdownobj, ifaceobj)


    @classmethod
    def _check_upperifaces(cls, ifupdownobj, ifaceobj, ops, parent,
                           followdependents=False):
        """ Check if conflicting upper ifaces are around and warn if required

        Returns False if this interface needs to be skipped, else return True """

        if 'up' in ops[0] and followdependents:
            return True

        # Deal with upperdevs first
        ulist = ifaceobj.upperifaces
        if ulist:
            tmpulist = ([u for u in ulist if u != parent] if parent
                            else ulist)
            if not tmpulist:
                return True
            if 'down' in ops[0]:
                # XXX: This is expensive. Find a cheaper way to do this 
                # if any of the upperdevs are present,
                # dont down this interface
                for u in tmpulist:
                    if ifupdownobj.link_exists(u):
                        if not ifupdownobj.FORCE and not ifupdownobj.ALL:
                            ifupdownobj.logger.warn('%s: ' %ifaceobj.name +
                                    'upperiface %s still around' %u)
                            return True
            elif 'up' in ops[0] and not ifupdownobj.ALL:
                # For 'up', just warn that there is an upperdev which is
                # probably not up
                for u in tmpulist:
                    if not ifupdownobj.link_exists(u):
                        ifupdownobj.logger.warn('%s: ' %ifaceobj.name +
                                'upper iface %s does not exist' %u)
        return True

    @classmethod
    def run_iface_graph(cls, ifupdownobj, ifacename, ops, parent=None,
                        order=ifaceSchedulerFlags.POSTORDER,
                        followdependents=True):
        """ runs interface by traversing all nodes rooted at itself """

        # Each ifacename can have a list of iface objects
        ifaceobjs = ifupdownobj.get_ifaceobjs(ifacename)
        if not ifaceobjs:
            raise Exception('%s: not found' %ifacename)

        for ifaceobj in ifaceobjs:
            if not cls._check_upperifaces(ifupdownobj, ifaceobj, ops, parent,
                                          followdependents):
                return
            if order == ifaceSchedulerFlags.INORDER:
                # If inorder, run the iface first and then its dependents
                cls.run_iface_ops(ifupdownobj, ifaceobj, ops)

            # Run lowerifaces or dependents
            dlist = ifaceobj.lowerifaces
            if dlist:
                ifupdownobj.logger.debug('%s: found dependents %s'
                            %(ifacename, str(dlist)))
                try:
                    if not followdependents:
                        # XXX: this is yet another extra step,
                        # but is needed for interfaces that are
                        # implicit dependents. even though we are asked to
                        # not follow dependents, we must follow the ones
                        # that dont have user given config. Because we own them
                        new_dlist = [d for d in dlist
                                     if ifupdownobj.is_iface_noconfig(d)]
                        if new_dlist:
                            cls.run_iface_list(ifupdownobj, new_dlist, ops,
                                                ifacename, order,
                                                followdependents,
                                                continueonfailure=False)
                    else:
                        cls.run_iface_list(ifupdownobj, dlist, ops,
                                            ifacename, order,
                                            followdependents,
                                            continueonfailure=False)
                except Exception, e:
                    if (ifupdownobj.ignore_error(str(e))):
                        pass
                    else:
                        # Dont bring the iface up if children did not come up
                        ifaceobj.set_state_n_status(ifaceState.NEW,
                                                    ifaceStatus.ERROR)
                        raise
            if order == ifaceSchedulerFlags.POSTORDER:
                cls.run_iface_ops(ifupdownobj, ifaceobj, ops)

    @classmethod
    def run_iface_list(cls, ifupdownobj, ifacenames,
                       ops, parent=None, order=ifaceSchedulerFlags.POSTORDER,
                       followdependents=True, continueonfailure=True):
        """ Runs interface list """

        for ifacename in ifacenames:
            try:
              cls.run_iface_graph(ifupdownobj, ifacename, ops, parent,
                      order, followdependents)
            except Exception, e:
                if continueonfailure:
                    if ifupdownobj.logger.isEnabledFor(logging.DEBUG):
                        traceback.print_tb(sys.exc_info()[2])
                    ifupdownobj.logger.error('%s : %s' %(ifacename, str(e)))
                    pass
                else:
                    if (ifupdownobj.ignore_error(str(e))):
                        pass
                    else:
                        raise Exception('error running iface %s (%s)'
                                %(ifacename, str(e)))

    @classmethod
    def run_iface_graph_upper(cls, ifupdownobj, ifacename, ops, parent=None,
                        followdependents=True, skip_root=False):
        """ runs interface by traversing all nodes rooted at itself """

        # Each ifacename can have a list of iface objects
        ifaceobjs = ifupdownobj.get_ifaceobjs(ifacename)
        if not ifaceobjs:
            raise Exception('%s: not found' %ifacename)

        for ifaceobj in ifaceobjs:
            if not skip_root:
                # run the iface first and then its upperifaces
                cls.run_iface_ops(ifupdownobj, ifaceobj, ops)

            # Run upperifaces
            ulist = ifaceobj.upperifaces
            if ulist:
                ifupdownobj.logger.debug('%s: found upperifaces %s'
                                            %(ifacename, str(ulist)))
                try:
                    cls.run_iface_list_upper(ifupdownobj, ulist, ops,
                                            ifacename,
                                            followdependents,
                                            continueonfailure=True)
                except Exception, e:
                    if (ifupdownobj.ignore_error(str(e))):
                        pass
                    else:
                        raise

    @classmethod
    def run_iface_list_upper(cls, ifupdownobj, ifacenames,
                       ops, parent=None, followdependents=True,
                       continueonfailure=True, skip_root=False):
        """ Runs interface list """

        for ifacename in ifacenames:
            try:
              cls.run_iface_graph_upper(ifupdownobj, ifacename, ops, parent,
                      followdependents, skip_root)
            except Exception, e:
                if continueonfailure:
                    if ifupdownobj.logger.isEnabledFor(logging.DEBUG):
                        traceback.print_tb(sys.exc_info()[2])
                    ifupdownobj.logger.error('%s : %s' %(ifacename, str(e)))
                    pass
                else:
                    if (ifupdownobj.ignore_error(str(e))):
                        pass
                    else:
                        raise Exception('error running iface %s (%s)'
                                %(ifacename, str(e)))

    @classmethod
    def sched_ifaces(cls, ifupdownobj, ifacenames, ops,
                dependency_graph=None, indegrees=None,
                order=ifaceSchedulerFlags.POSTORDER,
                followdependents=True):
        """ Runs iface dependeny graph by visiting all the nodes
        
        Parameters:
        -----------
        ifupdownobj : ifupdown object (used for getting and updating iface
                                        object state)
        dependency_graph : dependency graph in adjacency list
                            format (contains more than one dependency graph)
        ops : list of operations to perform eg ['pre-up', 'up', 'post-up']

        indegrees : indegree array if present is used to determine roots
                    of the graphs in the dependency_graph
        """

        if not ifupdownobj.ALL or not followdependents or len(ifacenames) == 1:
            cls.run_iface_list(ifupdownobj, ifacenames, ops,
                                  parent=None,order=order,
                                  followdependents=followdependents)
            if not ifupdownobj.ALL and followdependents and 'up' in ops[0]:
                # If user had given a set of interfaces to bring up
                # try and execute 'up' on the upperifaces
                ifupdownobj.logger.info('running upperifaces if available')
                cls._STATE_CHECK = False
                cls.run_iface_list_upper(ifupdownobj, ifacenames, ops,
                                         skip_root=True)
                cls._STATE_CHECK = True
            return
        run_queue = []

        # Get a sorted list of all interfaces
        if not indegrees:
            indegrees = OrderedDict()
            for ifacename in dependency_graph.keys():
                indegrees[ifacename] = ifupdownobj.get_iface_refcnt(ifacename)
        sorted_ifacenames = graph.topological_sort_graphs_all(dependency_graph,
                                                          dict(indegrees))
        ifupdownobj.logger.debug('sorted ifacenames %s : '
                                 %str(sorted_ifacenames))

        # From the sorted list, pick interfaces that user asked
        # and those that dont have any dependents first
        [run_queue.append(ifacename)
                    for ifacename in sorted_ifacenames
                        if ifacename in ifacenames and
                        not indegrees.get(ifacename)]

        ifupdownobj.logger.debug('graph roots (interfaces that dont have '
                                 'dependents):' + ' %s' %str(run_queue))
        cls.run_iface_list(ifupdownobj, run_queue, ops,
                                  parent=None,order=order,
                                  followdependents=followdependents)

    @classmethod
    def run_iface(cls, ifupdownobj, ifacename, ops):
        """ Runs operation on an interface """

        ifaceobjs = ifupdownobj.get_ifaceobjs(ifacename)
        for i in ifaceobjs:
            cls.run_iface_ops(ifupdownobj, i, ops)

    @classmethod
    def run_iface_list_op(cls, ifupdownobj, ifacenames, op,
                          sorted_by_dependency=False):
        """ Runs interface list through sub operation handler. """

        ifupdownobj.logger.debug('running operation %s on all given interfaces'
                                 %op)
        iface_run_queue = deque(ifacenames)
        for i in range(0, len(iface_run_queue)):
            if op.endswith('up'):
                # XXX: simplify this
                if sorted_by_dependency:
                    ifacename = iface_run_queue.pop()
                else:
                    ifacename = iface_run_queue.popleft()
            else:
                if sorted_by_dependency:
                    ifacename = iface_run_queue.popleft()
                else:
                    ifacename = iface_run_queue.pop()

            try:
                ifaceobjs = ifupdownobj.get_ifaceobjs(ifacename)
                for ifaceobj in ifaceobjs:
                    cenv = ifupdownobj.generate_running_env(ifaceobj, op)
                    cls.run_iface_op(ifupdownobj, ifaceobj, op, cenv)
            except Exception, e:
                ifupdownobj.log_error(str(e))

    @classmethod
    def run_iface_list_ops(cls, ifupdownobj, ifacenames, ops,
                           sorted_by_dependency=False):
        """ Runs interface list through sub operations handler

        Unlike run_iface_list, this method executes a sub operation on the
        entire interface list before proceeding to the next sub-operation.
        ie operation 'pre-up' is run through the entire interface list before
        'up'
        """
        # Each sub operation has a module list
        [cls.run_iface_list_op(ifupdownobj, ifacenames, op,
                sorted_by_dependency) for op in ops]

    @classmethod
    def run_iface_dependency_graphs_sorted(cls, ifupdownobj,
                                           dependency_graphs,
                                           ops, indegrees=None,
                                           graphsortall=False):
        """ runs interface dependency graph by topologically sorting the interfaces """

        if indegrees is None:
            indegrees = OrderedDict()
            for ifacename in dependency_graphs.keys():
                indegrees[ifacename] = ifupdownobj.get_iface_refcnt(ifacename)

        ifupdownobj.logger.debug('indegree array :')
        ifupdownobj.logger.debug(ifupdownobj.pp.pformat(indegrees))

        try:
            ifupdownobj.logger.debug('calling topological sort on the graph ' +
                                      '...')
            if graphsortall:
                sorted_ifacenames = graph.topological_sort_graphs_all(
                                            dependency_graphs, indegrees)
            else:
                sorted_ifacenames = graph.topological_sort_graphs(
                                            dependency_graphs, indegrees)
        except Exception:
            raise

        ifupdownobj.logger.debug('sorted iface list = %s' %sorted_ifacenames)
        cls.run_iface_list_ops(ifupdownobj, sorted_ifacenames, ops,
                               sorted_by_dependency=True)


    """ Methods to execute interfaces in parallel """
    @classmethod
    def init_tokens(cls, count):
        cls.token_pool = BoundedSemaphore(count)

    @classmethod
    def accquire_token(cls, logprefix=''):
        cls.token_pool.acquire()

    @classmethod
    def release_token(cls, logprefix=''):
        cls.token_pool.release()

    @classmethod
    def run_iface_parallel(cls, ifupdownobj, ifacename, op):
        """ Configures interface in parallel.
        
        Executes all its direct dependents in parallel
        
        """

        ifupdownobj.logger.debug('%s: %s' %(ifacename, op))
        cls.accquire_token(iface)

        # Each iface can have a list of objects
        ifaceobjs = ifupdownobj.get_ifaceobjs(ifacename)
        if ifaceobjs is None:
            ifupdownobj.logger.warning('%s: ' %ifacename + 'not found')
            cls.release_token(ifacename)
            return -1

        for ifaceobj in ifaceobjs:
            # Run dependents
            dlist = ifaceobj.lowerifaces
            if dlist:
                ifupdownobj.logger.debug('%s:' %ifacename +
                    ' found dependents: %s' %str(dlist))
                try:
                    cls.release_token(ifacename)
                    cls.run_iface_list_parallel(ifacename, ifupdownobj,
                                                 dlist, op)
                    cls.accquire_token(ifacename)
                except Exception, e:
                    if ifupdownobj.ignore_error(str(e)):
                        pass
                    else:
                        # Dont bring the iface up if children did not come up
                        ifupdownobj.logger.debug('%s:' %ifacename +
                            ' there was an error bringing %s' %op +
                            ' dependents (%s)', str(e))
                        ifupdownobj.set_iface_state(ifaceobj,
                            ifaceState.from_str(ops[0]),
                            ifaceStatus.ERROR)
                        return -1

            # Run all sub operations sequentially
            try:
                ifupdownobj.logger.debug('%s:' %ifacename +
                                         ' running sub-operations')
                cls.run_iface_ops(ifupdownobj, ifaceobj, op)
            except Exception, e:
                ifupdownobj.logger.error('%s:' %ifacename +
                    ' error running sub operations (%s)' %str(e))

        cls.release_token(ifacename)

    @classmethod
    def run_iface_list_parallel(cls, parent, ifupdownobj, ifacenames, op):
        """ Runs interface list in parallel """

        running_threads = OrderedDict()
        err = 0

        for ifacename in ifacenames:
            try:
                cls.accquire_token(parent)
                running_threads[ifacename] = Thread(None,
                    cls.run_iface_parallel, ifacename,
                    args=(ifupdownobj, ifacename, op))
                running_threads[ifacename].start()
                cls.release_token(parent)
            except Exception, e:
                cls.release_token(parent)
                if ifupdownobj.ignore_error(str(e)):
                    pass
                else:
                    raise Exception('error starting thread for iface %s'
                            %ifacename)

        ifupdownobj.logger.debug('%s ' %parent +
                                 'waiting for all the threads ...')
        for ifacename, t  in running_threads.items():
            t.join()
            if ifupdownobj.get_iface_status(ifacename) != ifaceStatus.SUCCESS:
                err += 1

        return err

    @classmethod
    def run_iface_graphs_parallel(cls, parent, ifupdownobj, ifacenames, op):
        """ Runs iface graphs in parallel """

        running_threads = OrderedDict()
        err = 0

        for ifacename in ifacenames:
            try:
                cls.accquire_graph_token(parent)
                running_threads[ifacename] = Thread(None,
                    cls.run_iface_parallel, ifacename,
                    args=(ifupdownobj, ifacename, op))
                running_threads[ifacename].start()
                cls.release_graph_token(parent)
            except Exception, e:
                cls.release_graph_token(parent)
                if ifupdownobj.ignore_error(str(e)):
                    pass
                else:
                    raise Exception('error starting thread for iface %s'
                            %ifacename)

        ifupdownobj.logger.info('%s ' %parent +
                                'waiting for all the threads ...')
        for ifacename, t in running_threads.items():
            t.join()
            # Check status of thread
            # XXX: Check all objs
            if ifupdownobj.get_iface_status(ifacename) != ifaceStatus.SUCCESS:
                err += 1
        return err

    @classmethod
    def run_iface_dependency_graph_parallel(cls, ifupdownobj, dependency_graph,
                                            operation):
        """ Runs iface dependeny graph in parallel.
        
        arguments:
        ifupdownobj -- ifupdown object (used for getting and updating iface
                                        object state)
        dependency_graph -- dependency graph with 
        operation -- 'up' or 'down' or 'query'

        """

        ifupdownobj.logger.debug('running dependency graph in parallel ..')
        run_queue = []
        # Build a list of ifaces that dont have any dependencies
        for ifacename in dependency_graph.keys():
            if ifupdownobj.get_iface_refcnt(ifacename) == 0:
                run_queue.append(ifacename)

        ifupdownobj.logger.debug('graph roots (interfaces that dont'
                    ' have dependents):' + ' %s' %str(run_queue))
        cls.init_tokens(ifupdownobj.get_njobs())
        return cls.run_iface_list_parallel('main', ifupdownobj, run_queue,
                                            operation)

        # OR
        # Run one graph at a time
        #for iface in run_queue:
        #    self.run_iface_list_parallel('main', ifupdownobj, [iface],
        #            operation)

