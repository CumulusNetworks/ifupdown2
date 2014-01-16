#!/usr/bin/python
#
# Copyright 2013.  Cumulus Networks, Inc.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifaceScheduler --
#    interface scheduler
#

import os
import re
from statemanager import *
from iface import *
from graph import *
from collections import deque
from collections import OrderedDict
import imp
import pprint
import logging
from graph import *
from collections import deque
from threading import *
from ifupdownbase import *

class ifaceScheduler(ifupdownBase):
    """ scheduler to schedule configuration of interfaces.


    supports scheduling of interfaces serially in plain interface list
    or dependency graph format.
    """

    def __init__(self, force=False):
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)
        self.FORCE = force

    def run_iface_subop(self, ifupdownobj, ifaceobj, op, subop, mdict, cenv):
        """ Runs sub operation on an interface """

        self.logger.debug('%s: ' %ifaceobj.get_name() + 'op %s' %op +
                          ' subop = %s' %subop)

        for mname, mdata in mdict.items():
            m = mdata.get('module')
            err = 0
            try:
                if (mdata.get('ftype') == 'pmodule' and
                    hasattr(m, 'run') == True):
                    self.logger.debug('%s: ' %ifaceobj.get_name() +
                                      'running module %s' %mname +
                                      ' op %s' %op + ' subop %s' %subop)
                    if op == 'query-checkcurr':
                        m.run(ifaceobj, subop, query_check=True,
                              query_ifaceobj=ifupdownobj.create_ifaceobjcurr(
                                                                ifaceobj))
                    else:
                        m.run(ifaceobj, subop)
                else:
                    self.logger.debug('%s: ' %ifaceobj.get_name() +
                                      'running script %s' %mname +
                                      ' op %s' %op + ' subop %s' %subop)
                    self.exec_command(m, cmdenv=cenv)
            except Exception, e:
                err = 1
                self.log_error(str(e))
            finally:
                if op[:5] != 'query':
                    if err == 1:
                        ifupdownobj.set_iface_state(ifaceobj,
                                ifaceState.from_str(subop),
                                ifaceStatus.ERROR)
                    else:
                        ifupdownobj.set_iface_state(ifaceobj,
                                ifaceState.from_str(subop),
                                ifaceStatus.SUCCESS)

    def run_iface_subops(self, ifupdownobj, ifaceobj, op):
        """ Runs all sub operations on an interface """

        # For backward compatibility execute scripts with
        # environent set
        cenv = ifupdownobj.generate_running_env(ifaceobj, op)

        # Each sub operation has a module list
        subopdict = ifupdownobj.operations.get(op)
        for subop, mdict in subopdict.items():
            self.run_iface_subop(ifupdownobj, ifaceobj, op, subop, mdict, cenv)


    def run_iface(self, ifupdownobj, ifacename, op):
        """ Runs operation on an interface """

        ifaceobjs = ifupdownobj.get_iface_objs(ifacename)
        for i in ifaceobjs:
            if (op != 'query' and ifupdownobj.STATE_CHECK == True and
                ifupdownobj.is_valid_state_transition(i, op) == False and
                ifupdownobj.FORCE == False):
                self.logger.warning('%s' %ifacename +
                        ' already %s' %op)
                continue

            self.run_iface_subops(ifupdownobj, i, op)


    def run_iface_list(self, ifupdownobj, ifacenames, operation,
                      sorted_by_dependency=False):
        """ Runs interface list serially executing all sub operations on
        each interface at a time. """

        self.logger.debug('run_iface_list: running interface list for ' +
                          'operation %s' %operation)

        iface_run_queue = deque(ifacenames)
        for i in range(0, len(iface_run_queue)):
            if operation == 'up':
                # XXX: simplify this
                if sorted_by_dependency == True:
                    ifacename = iface_run_queue.pop()
                else:
                    ifacename = iface_run_queue.popleft()
            else:
                if sorted_by_dependency == True:
                    ifacename = iface_run_queue.popleft()
                else:
                    ifacename = iface_run_queue.pop()

            try:
                self.run_iface(ifupdownobj, ifacename, operation)
            except Exception, e:
                self.log_error(str(e))

    def run_iface_list_subop(self, ifupdownobj, ifacenames, op, subop, mdict,
                             sorted_by_dependency=False):
        """ Runs interface list through sub operation handler. """

        self.logger.debug('running sub operation %s on all given interfaces' %op)
        iface_run_queue = deque(ifacenames)
        for i in range(0, len(iface_run_queue)):
            if op == 'up':
                # XXX: simplify this
                if sorted_by_dependency == True:
                    ifacename = iface_run_queue.pop()
                else:
                    ifacename = iface_run_queue.popleft()
            else:
                if sorted_by_dependency == True:
                    ifacename = iface_run_queue.popleft()
                else:
                    ifacename = iface_run_queue.pop()

            try:
                ifaceobjs = ifupdownobj.get_iface_objs(ifacename)
                for ifaceobj in ifaceobjs:
                    if (op != 'query' and ifupdownobj.STATE_CHECK == True and
                        ifupdownobj.is_valid_state_transition(ifaceobj,
                        op) == False and ifupdownobj.FORCE == False):
                        if subop == 'post-down' or subop == 'post-up':
                            self.logger.warning('%s: ' %ifacename +
                                                ' already %s' %op)
                        continue

                    cenv = ifupdownobj.generate_running_env(ifaceobj, op)
                    self.run_iface_subop(ifupdownobj, ifaceobj, op, subop,
                                         mdict, cenv)
            except Exception, e:
                self.log_error(str(e))

    def run_iface_list_stages(self, ifupdownobj, ifacenames, op,
                              sorted_by_dependency=False):
        """ Runs interface list through sub operations handler

        Unlike run_iface_list, this method executes a sub operation on the
        entire interface list before proceeding to the next sub-operation.
        ie operation 'pre-up' is run through the entire interface list before
        'up'
        """

        self.logger.debug('run_iface_list_stages: running interface list for %s'
                          %op)

        # Each sub operation has a module list
        subopdict = ifupdownobj.operations.get(op)
        for subop, mdict in subopdict.items():
            self.run_iface_list_subop(ifupdownobj, ifacenames, op, subop, mdict,
                    sorted_by_dependency)


    def run_iface_dependency_graph(self, ifupdownobj, dependency_graph,
                                   operation):
        """ runs interface dependency graph """

        indegrees = OrderedDict()

        self.logger.debug('creating indegree array ...')
        for ifacename in dependency_graph.keys():
            indegrees[ifacename] = ifupdownobj.get_iface_refcnt(ifacename)

        if self.logger.isEnabledFor(logging.DEBUG) == True:
            self.logger.debug('indegree array :')
            ifupdownobj.pp.pprint(indegrees)

        try:
            self.logger.debug('calling topological sort on the graph ...')
            sorted_ifacenames = graph.topological_sort(dependency_graph,
                                                       indegrees)
        except Exception, e:
            raise

        self.logger.debug('sorted iface list = %s' %sorted_ifacenames)

        #self.run_iface_list(ifupdownobj, sorted_ifacenames, operation,
        #                    sorted_by_dependency=True)

        self.run_iface_list_stages(ifupdownobj, sorted_ifacenames, operation,
                                   sorted_by_dependency=True)


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
            dlist = ifaceobj.get_dependents()
            if dlist is not None and len(dlist) > 0:
                self.logger.debug('%s:' %ifacename +
                    ' found dependents: %s' %str(dlist))
                try:
                    self.release_token(ifacename)
                    self.run_iface_list_parallel(ifacename, ifupdownobj,
                                                 dlist, op)
                    self.accquire_token(ifacename)
                except Exception, e:
                    if (self.ignore_error(str(e)) == True):
                        pass
                    else:
                        # Dont bring the iface up if children did not come up
                        self.logger.debug('%s:' %ifacename +
                            ' there was an error bringing %s' %op +
                            ' dependents (%s)', str(e))
                        ifupdownobj.set_iface_state(ifaceobj,
                            ifaceState.from_str(
                                    ifupdownobj.get_subops(op)[0]),
                            ifaceStatus.ERROR)
                        return -1

            if (op != 'query' and ifupdownobj.STATE_CHECK == True and
                ifupdownobj.is_valid_state_transition(ifaceobj,
                    op) == False and ifupdownobj.FORCE == False):
                self.logger.warning('%s:' %ifacename + ' already %s' %op)
                continue


            # Run all sub operations sequentially
            try:
                self.logger.debug('%s:' %ifacename + ' running sub-operations')
                self.run_iface_subops(ifupdownobj, ifaceobj, op)
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
                if (ifupdownobj.ignore_error(str(e)) == True):
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
                if (ifupdownobj.ignore_error(str(e)) == True):
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

        self.logger.debug('graph roots (interfaces that dont have dependents):' +
                          ' %s' %str(run_queue))

        self.init_tokens(ifupdownobj.get_njobs())

        return self.run_iface_list_parallel('main', ifupdownobj, run_queue,
                                            operation)

        # OR
        # Run one graph at a time
        #for iface in run_queue:
        #    self.run_iface_list_parallel('main', ifupdownobj, [iface],
        #            operation)

