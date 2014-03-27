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

        Returns False if this interface needs to be skipped,
        else return True """

        # XXX: simply return for now, the warnings this function prints
        # are very confusing. Get rid of this function soon
        return True

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
            if not cls._check_upperifaces(ifupdownobj, ifaceobj,
                                          ops, parent, followdependents):
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
            # If there is any interface that does exist, maybe it is a
            # logical interface and we have to followupperifaces
            followupperifaces = (True if
                                    [i for i in ifacenames
                                            if not ifupdownobj.link_exists(i)]
                                    else False)
            cls.run_iface_list(ifupdownobj, ifacenames, ops,
                                  parent=None,order=order,
                                  followdependents=followdependents)
            if (not ifupdownobj.ALL and
                    (followdependents or followupperifaces) and 'up' in ops[0]):
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
