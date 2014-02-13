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
from graph import *
from collections import deque
from threading import *
from ifupdownbase import *

class ifaceSchedulerFlags():
    INORDER = 1
    POSTORDER = 2

class ifaceScheduler(ifupdownBase):
    """ scheduler to schedule configuration of interfaces.


    supports scheduling of interfaces serially in plain interface list
    or dependency graph format.
    """


    def __init__(self, force=False):
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)
        self.FORCE = force

    def run_iface_op(self, ifupdownobj, ifaceobj, op, cenv):
        """ Runs sub operation on an interface """
        ifacename = ifaceobj.get_name()

        if (ifaceobj.get_state() >= ifaceState.from_str(op) and
           ifaceobj.get_status() == ifaceStatus.SUCCESS):
            self.logger.debug('%s: already in state %s' %(ifacename, op))
            return

        for mname in ifupdownobj.operations.get(op):
            m = ifupdownobj.modules.get(mname)
            err = 0
            try:
                if hasattr(m, 'run'):
                    self.logger.debug('%s: %s : running module %s'
                            %(ifacename, op, mname))
                    if op == 'query-checkcurr':
                        # Dont check curr if the interface object was 
                        # auto generated
                        if (ifaceobj.priv_flags & ifupdownobj.NOCONFIG):
                            continue
                        m.run(ifaceobj, op,
                              query_ifaceobj=ifupdownobj.create_n_save_ifaceobjcurr(ifaceobj))
                    else:
                        m.run(ifaceobj, op)
            except Exception, e:
                err = 1
                self.log_error(str(e))
            finally:
                if err == 1:
                    ifupdownobj.set_iface_state(ifaceobj,
                                ifaceState.from_str(op),
                                ifaceStatus.ERROR)
                else:
                    ifupdownobj.set_iface_state(ifaceobj,
                                ifaceState.from_str(op),
                                ifaceStatus.SUCCESS)

        # execute /etc/network/ scripts 
        mlist = ifupdownobj.operations_compat.get(op)
        if not mlist:
            return
        for mname in mlist:
            self.logger.debug('%s: %s : running script %s'
                    %(ifacename, op, mname))
            try:
                self.exec_command(mname, cmdenv=cenv)
            except Exception, e:
                err = 1
                self.log_error(str(e))


    def run_iface_ops(self, ifupdownobj, ifaceobj, ops):
        """ Runs all sub operations on an interface """

        # For backward compatibility execute scripts with
        # environent set
        cenv = ifupdownobj.generate_running_env(ifaceobj, ops[0])

        # Each sub operation has a module list
        [self.run_iface_op(ifupdownobj, ifaceobj, op, cenv)
                        for op in ops]

    def run_iface_graph(self, ifupdownobj, ifacename, ops, parent=None,
                        order=ifaceSchedulerFlags.POSTORDER,
                        followdependents=True):
        """ runs interface by traversing all nodes rooted at itself """

        # minor optimization. If operation is 'down', proceed only
        # if interface exists in the system
        if 'down' in ops[0] and not self.link_exists(ifacename):
            self.logger.info('%s: does not exist' %ifacename)
            return 

        # Each ifacename can have a list of iface objects
        ifaceobjs = ifupdownobj.get_iface_objs(ifacename)
        if ifaceobjs is None:
            raise Exception('%s: not found' %ifacename)

        for ifaceobj in ifaceobjs:
            # Deal with upperdevs first
            ulist = ifaceobj.get_upperifaces()
            if ulist:
                self.logger.debug('%s: parent = %s, ulist = %s'
                                  %(ifacename, parent, ulist))
                tmpulist = ([u for u in ulist if u != parent] if parent
                            else ulist)
                if tmpulist:
                    self.logger.debug('%s: parent = %s, tmpulist = %s'
                                      %(ifacename, parent, tmpulist))
                    if 'down' in ops[0]:
                        # XXX: This is expensive. Find a cheaper way to do this 
                        # if any of the upperdevs are present,
                        # dont down this interface
                        for u in tmpulist:
                            if self.link_exists(u):
                                if not ifupdownobj.ALL:
                                    self.logger.warn('%s: skip interface '
                                            'down upperiface %s still around'
                                            %(ifacename, u))
                                return
                    elif 'up' in ops[0] and not ifupdownobj.ALL:
                        # For 'up', just warn that there is an upperdev which is
                        # probably not up
                        for u in tmpulist:
                            if not self.link_exists(u):
                                self.logger.warn('%s: upper iface %s does not'
                                        ' exist' %(ifacename, u))

            if order == ifaceSchedulerFlags.INORDER:
                # If inorder, run the iface first and then its dependents
                self.run_iface_ops(ifupdownobj, ifaceobj, ops)

            # Run lowerifaces or dependents
            dlist = ifaceobj.get_lowerifaces()
            if dlist:
                self.logger.info('%s:' %ifacename +
                    ' found dependents: %s' %str(dlist))
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
                            self.run_iface_list(ifupdownobj, new_dlist, ops,
                                                ifacename, order,
                                                followdependents,
                                                continueonfailure=False)
                    else:
                        self.run_iface_list(ifupdownobj, dlist, ops,
                                            ifacename, order,
                                            followdependents,
                                            continueonfailure=False)
                except Exception, e:
                    if (self.ignore_error(str(e))):
                        pass
                    else:
                        # Dont bring the iface up if children did not come up
                        ifaceobj.set_state(ifaceState.NEW)
                        ifaceobj.set_status(ifaceStatus.ERROR)
                        raise
            if order == ifaceSchedulerFlags.POSTORDER:
                self.run_iface_ops(ifupdownobj, ifaceobj, ops)


    def run_iface_list(self, ifupdownobj, ifacenames,
                       ops, parent=None, order=ifaceSchedulerFlags.POSTORDER,
                       followdependents=True, continueonfailure=True):
        """ Runs interface list """

        for ifacename in ifacenames:
            try:
              self.run_iface_graph(ifupdownobj, ifacename, ops, parent,
                      order, followdependents)
            except Exception, e:
                if continueonfailure:
                    self.logger.error('%s : %s' %(ifacename, str(e)))
                    pass
                else:
                    if (self.ignore_error(str(e))):
                        pass
                    else:
                        raise Exception('error running iface %s (%s)'
                                %(ifacename, str(e)))

    def run_iface_dependency_graphs(self, ifupdownobj,
                dependency_graph, ops, indegrees=None,
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
        run_queue = []

        if indegrees is None:
            indegrees = OrderedDict()
            for ifacename in dependency_graph.keys():
                indegrees[ifacename] = ifupdownobj.get_iface_refcnt(ifacename)

        sorted_ifacenames = graph.topological_sort_graphs_all(dependency_graph,
                                                          dict(indegrees))
        self.logger.debug('sorted ifacenames %s : ' %str(sorted_ifacenames))

        # Build a list of ifaces that dont have any dependencies
        for ifacename in sorted_ifacenames:
            if not indegrees.get(ifacename):
                run_queue.append(ifacename)

        self.logger.info('graph roots (interfaces that dont have '
                    'dependents):' + ' %s' %str(run_queue))

        return self.run_iface_list(ifupdownobj, run_queue, ops,
                                   parent=None,order=order,
                                   followdependents=followdependents)


    def run_iface(self, ifupdownobj, ifacename, ops):
        """ Runs operation on an interface """

        ifaceobjs = ifupdownobj.get_iface_objs(ifacename)
        for i in ifaceobjs:
            self.run_iface_ops(ifupdownobj, i, ops)

    def run_iface_list_op(self, ifupdownobj, ifacenames, op,
                             sorted_by_dependency=False):
        """ Runs interface list through sub operation handler. """

        self.logger.debug('running operation %s on all given interfaces'
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
                ifaceobjs = ifupdownobj.get_iface_objs(ifacename)
                for ifaceobj in ifaceobjs:
                    cenv = ifupdownobj.generate_running_env(ifaceobj, op)
                    self.run_iface_op(ifupdownobj, ifaceobj, op, cenv)
            except Exception, e:
                self.log_error(str(e))

    def run_iface_list_ops(self, ifupdownobj, ifacenames, ops,
                              sorted_by_dependency=False):
        """ Runs interface list through sub operations handler

        Unlike run_iface_list, this method executes a sub operation on the
        entire interface list before proceeding to the next sub-operation.
        ie operation 'pre-up' is run through the entire interface list before
        'up'
        """

        # Each sub operation has a module list
        [self.run_iface_list_op(ifupdownobj, ifacenames, op,
                sorted_by_dependency) for op in ops]

    def run_iface_dependency_graphs_sorted(self, ifupdownobj,
                                   dependency_graphs,
                                   ops, indegrees=None,
                                   graphsortall=False):
        """ runs interface dependency graph by topologically sorting the interfaces """

        if indegrees is None:
            indegrees = OrderedDict()
            for ifacename in dependency_graphs.keys():
                indegrees[ifacename] = ifupdownobj.get_iface_refcnt(ifacename)

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('indegree array :')
            self.logger.debug(ifupdownobj.pp.pformat(indegrees))

        try:
            self.logger.debug('calling topological sort on the graph ...')
            if graphsortall:
                sorted_ifacenames = graph.topological_sort_graphs_all(
                                            dependency_graphs, indegrees)
            else:
                sorted_ifacenames = graph.topological_sort_graphs(
                                            dependency_graphs, indegrees)
        except Exception:
            raise

        self.logger.debug('sorted iface list = %s' %sorted_ifacenames)
        self.run_iface_list_ops(ifupdownobj, sorted_ifacenames, ops,
                                sorted_by_dependency=True)


    """ Methods to execute interfaces in parallel """
    def init_tokens(self, count):
        self.token_pool = BoundedSemaphore(count)
        self.logger.debug('initialized bounded semaphore with %d' %count)

    def accquire_token(self, logprefix=''):
        self.token_pool.acquire()
        self.logger.debug('%s ' %logprefix + 'acquired token')

    def release_token(self, logprefix=''):
        self.token_pool.release()
        self.logger.debug('%s ' %logprefix + 'release token')

    def run_iface_parallel(self, ifupdownobj, ifacename, op):
        """ Configures interface in parallel.
        
        Executes all its direct dependents in parallel
        
        """

        self.logger.debug('%s:' %ifacename + ' %s' %op)
        self.accquire_token(iface)

        # Each iface can have a list of objects
        ifaceobjs = ifupdownobj.get_iface_objs(ifacename)
        if ifaceobjs is None:
            self.logger.warning('%s: ' %ifacename + 'not found')
            self.release_token(ifacename)
            return -1

        for ifaceobj in ifaceobjs:
            # Run dependents
            dlist = ifaceobj.get_lowerifaces()
            if dlist is not None and len(dlist) > 0:
                self.logger.debug('%s:' %ifacename +
                    ' found dependents: %s' %str(dlist))
                try:
                    self.release_token(ifacename)
                    self.run_iface_list_parallel(ifacename, ifupdownobj,
                                                 dlist, op)
                    self.accquire_token(ifacename)
                except Exception, e:
                    if self.ignore_error(str(e)):
                        pass
                    else:
                        # Dont bring the iface up if children did not come up
                        self.logger.debug('%s:' %ifacename +
                            ' there was an error bringing %s' %op +
                            ' dependents (%s)', str(e))
                        ifupdownobj.set_iface_state(ifaceobj,
                            ifaceState.from_str(ops[0]),
                            ifaceStatus.ERROR)
                        return -1

            # Run all sub operations sequentially
            try:
                self.logger.debug('%s:' %ifacename + ' running sub-operations')
                self.run_iface_ops(ifupdownobj, ifaceobj, op)
            except Exception, e:
                self.logger.error('%s:' %ifacename +
                    ' error running sub operations (%s)' %str(e))

        self.release_token(ifacename)


    def run_iface_list_parallel(self, parent, ifupdownobj, ifacenames, op):
        """ Runs interface list in parallel """

        running_threads = OrderedDict()
        err = 0

        for ifacename in ifacenames:
            try:
                self.accquire_token(parent)
                running_threads[ifacename] = Thread(None,
                    self.run_iface_parallel, ifacename,
                    args=(ifupdownobj, ifacename, op))
                running_threads[ifacename].start()
                self.release_token(parent)
            except Exception, e:
                self.release_token(parent)
                if ifupdownobj.ignore_error(str(e)):
                    pass
                else:
                    raise Exception('error starting thread for iface %s'
                            %ifacename)


        self.logger.debug('%s' %parent + 'waiting for all the threads ...')
        for ifacename, t  in running_threads.items():
            t.join()
            if ifupdownobj.get_iface_status(ifacename) != ifaceStatus.SUCCESS:
                err += 1

        return err

    def run_iface_graphs_parallel(self, parent, ifupdownobj, ifacenames, op):
        """ Runs iface graphs in parallel """

        running_threads = OrderedDict()
        err = 0

        for ifacename in ifacenames:
            try:
                self.accquire_graph_token(parent)
                running_threads[ifacename] = Thread(None,
                    self.run_iface_parallel, ifacename,
                    args=(ifupdownobj, ifacename, op))
                running_threads[ifacename].start()
                self.release_graph_token(parent)
            except Exception, e:
                self.release_graph_token(parent)
                if ifupdownobj.ignore_error(str(e)):
                    pass
                else:
                    raise Exception('error starting thread for iface %s'
                            %ifacename)

        self.logger.info('%s' %parent + 'waiting for all the threads ...')
        for ifacename, t  in running_threads.items():
            t.join()
            # Check status of thread
            # XXX: Check all objs
            if ifupdownobj.get_iface_status(ifacename) != ifaceStatus.SUCCESS:
                err += 1

        return err

    def run_iface_dependency_graph_parallel(self, ifupdownobj, dependency_graph,
                                            operation):
        """ Runs iface dependeny graph in parallel.
        
        arguments:
        ifupdownobj -- ifupdown object (used for getting and updating iface
                                        object state)
        dependency_graph -- dependency graph with 
        operation -- 'up' or 'down' or 'query'

        """

        self.logger.debug('running dependency graph in parallel ..')

        run_queue = []

        # Build a list of ifaces that dont have any dependencies
        for ifacename in dependency_graph.keys():
            if ifupdownobj.get_iface_refcnt(ifacename) == 0:
                run_queue.append(ifacename)

        self.logger.debug('graph roots (interfaces that dont'
                    ' have dependents):' + ' %s' %str(run_queue))

        self.init_tokens(ifupdownobj.get_njobs())

        return self.run_iface_list_parallel('main', ifupdownobj, run_queue,
                                            operation)

        # OR
        # Run one graph at a time
        #for iface in run_queue:
        #    self.run_iface_list_parallel('main', ifupdownobj, [iface],
        #            operation)

