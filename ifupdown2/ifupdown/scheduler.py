#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifaceScheduler --
#    interface scheduler
#

import os
import sys
import traceback

from collections import OrderedDict


try:
    from ifupdown2.ifupdown.graph import *
    from ifupdown2.ifupdown.iface import ifaceType, ifaceLinkKind, ifaceStatus, ifaceState
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.statemanager import *

    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
except ImportError:
    from ifupdown.graph import *
    from ifupdown.iface import ifaceType, ifaceLinkKind, ifaceStatus, ifaceState
    from ifupdown.utils import utils
    from ifupdown.statemanager import *

    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.policymanager as policymanager


class SchedulerException(Exception):
    pass

class ifaceSchedulerFlags():
    """ Enumerates scheduler flags """

    INORDER = 0x1
    POSTORDER = 0x2

class ifaceScheduler():
    """ scheduler functions to schedule configuration of interfaces.

    supports scheduling of interfaces serially in plain interface list
    or dependency graph format.

    """

    _STATE_CHECK = True

    _SCHED_STATUS = True

    _DIFF_MODE = False
    _RUN_QUEUE = []

    VRF_MGMT_DEVNAME = policymanager.policymanager_api.get_module_globals(
        module_name="vrf",
        attr="vrf-mgmt-devname"
    )

    @classmethod
    def reset(cls):
        cls._STATE_CHECK = True
        cls._SCHED_STATUS = True

    @classmethod
    def get_sched_status(cls):
        return cls._SCHED_STATUS

    @classmethod
    def set_sched_status(cls, state):
        cls._SCHED_STATUS = state

    @classmethod
    def run_iface_op(cls, ifupdownobj, ifaceobj, op, cenv=None):
        """ Runs sub operation on an interface """
        ifacename = ifaceobj.name

        if ifupdownobj.type and ifupdownobj.type != ifaceobj.type:
            return

        if not ifupdownobj.flags.ADDONS_ENABLE: return
        if op == 'query-checkcurr':
            query_ifaceobj=ifupdownobj.create_n_save_ifaceobjcurr(ifaceobj)
            # If not type bridge vlan and the object does not exist,
            # mark not found and return
            if (not ifupdownobj.link_exists(ifaceobj.name) and
                ifaceobj.type != ifaceType.BRIDGE_VLAN):
                query_ifaceobj.set_state_n_status(ifaceState.from_str(op),
                                                  ifaceStatus.NOTFOUND)
                return

        # Very ugly but necessary since we don't support global attributes
        utils.is_pvrst_enabled(ifupdownobj.get_ifaceobjs, no_act="query" in op or "down" in op)

        for mname in ifupdownobj.module_ops.get(op):
            m = ifupdownobj.modules.get(mname)
            err = 0
            try:
                if cls._DIFF_MODE and hasattr(m, "set_runqueue"):
                    m.set_runqueue(list(cls._RUN_QUEUE))

                if hasattr(m, 'run'):
                    msg = ('%s: %s : running module %s' %(ifacename, op, mname))
                    if op == 'query-checkcurr':
                        # Dont check curr if the interface object was
                        # auto generated
                        if (ifaceobj.priv_flags and
                            ifaceobj.priv_flags.NOCONFIG):
                            continue
                        ifupdownobj.logger.debug(msg)
                        m.run(ifaceobj, op, query_ifaceobj,
                              ifaceobj_getfunc=ifupdownobj.get_ifaceobjs)
                    else:
                        ifupdownobj.logger.debug(msg)
                        m.run(ifaceobj, op,
                              ifaceobj_getfunc=ifupdownobj.get_ifaceobjs)
            except Exception as e:
                if not ifupdownobj.ignore_error(str(e)):
                    err = 1
                    #import traceback
                    #traceback.print_exc()

                    ifupdownobj.logger.error(str(e))
                # Continue with rest of the modules
            finally:
                if err or ifaceobj.status == ifaceStatus.ERROR:
                    ifaceobj.set_state_n_status(ifaceState.from_str(op),
                                                ifaceStatus.ERROR)
                    if 'up' in  op or 'down' in op or 'query-checkcurr' in op:
                        cls.set_sched_status(False)
                else:
                    # Mark success only if the interface was not already
                    # marked with error
                    status = (ifaceobj.status
                              if ifaceobj.status == ifaceStatus.ERROR
                              else ifaceStatus.SUCCESS)
                    ifaceobj.set_state_n_status(ifaceState.from_str(op),
                                                status)

        if ifupdownobj.config.get('addon_scripts_support', '0') == '1':
            # execute /etc/network/ scripts
            command_env = (cenv or {}).copy()
            command_env.update({
                "IFACE": ifaceobj.name if ifaceobj.name else "",
                "LOGICAL": ifaceobj.name if ifaceobj.name else "",
                "METHOD": ifaceobj.addr_method if ifaceobj.addr_method else "",
                "ADDRFAM": ','.join(ifaceobj.addr_family) if ifaceobj.addr_family else "",
            })

            for mname in ifupdownobj.script_ops.get(op, []):
                ifupdownobj.logger.debug("%s: %s : running script %s" % (ifacename, op, mname))
                try:
                    utils.exec_command(mname, env=command_env, stdout=False)
                except Exception as e:
                    if "permission denied" in str(e).lower():
                        ifupdownobj.logger.warning('%s: %s %s' % (ifacename, op, str(e)))
                    else:
                        ifupdownobj.log_error('%s: %s %s' % (ifacename, op, str(e)))

    @classmethod
    def run_iface_list_ops(cls, ifupdownobj, ifaceobjs, ops):
        """ Runs all operations on a list of interface
            configurations for the same interface
        """

        # minor optimization. If operation is 'down', proceed only
        # if interface exists in the system
        ifacename = ifaceobjs[0].name
        ifupdownobj.logger.info('%s: running ops ...' %ifacename)
        if ('down' in ops[0] and
                ifaceobjs[0].type != ifaceType.BRIDGE_VLAN and
                ifaceobjs[0].addr_method != 'ppp' and
                not ifupdownobj.link_exists(ifacename)):
            ifupdownobj.logger.debug('%s: does not exist' %ifacename)
            # run posthook before you get out of here, so that
            # appropriate cleanup is done
            posthookfunc = ifupdownobj.sched_hooks.get('posthook')
            if posthookfunc:
                for ifaceobj in ifaceobjs:
                    ifaceobj.status = ifaceStatus.SUCCESS
                    posthookfunc(ifupdownobj, ifaceobj, 'down')
            return
        for op in ops:
            # first run ifupdownobj handlers. This is good enough
            # for the first object in the list
            handler = ifupdownobj.ops_handlers.get(op)
            if handler:
                try:
                    handler(ifupdownobj, ifaceobjs[0])
                except Exception as e:
                    if not ifupdownobj.link_master_slave_ignore_error(str(e)):
                       ifupdownobj.logger.warning('%s: %s'
                                   %(ifaceobjs[0].name, str(e)))
            for ifaceobj in ifaceobjs:
                cls.run_iface_op(ifupdownobj, ifaceobj, op,
                    cenv=ifupdownobj.generate_running_env(ifaceobj, op)
                        if ifupdownobj.config.get('addon_scripts_support',
                            '0') == '1' else None)
        posthookfunc = ifupdownobj.sched_hooks.get('posthook')
        if posthookfunc:
            try:
                [posthookfunc(ifupdownobj, ifaceobj, ops[0])
                    for ifaceobj in ifaceobjs]
            except Exception as e:
                ifupdownobj.logger.warning('%s' %str(e))

    @classmethod
    def _check_upperifaces(cls, ifupdownobj, ifaceobj, ops, parent,
                           followdependents=False):
        """ Check if upperifaces are hanging off us and help caller decide
        if he can proceed with the ops on this device

        Returns True or False indicating the caller to proceed with the
        operation.
        """
        # proceed only for down operation
        if 'down' not in ops[0]:
            return True

        if (ifupdownobj.flags.SCHED_SKIP_CHECK_UPPERIFACES):
            return True

        if (ifupdownflags.flags.FORCE or
                not ifupdownobj.flags.ADDONS_ENABLE or
                (not ifupdownobj.is_ifaceobj_noconfig(ifaceobj) and
                ifupdownobj.config.get('warn_on_ifdown', '0') == '0' and
                not ifupdownflags.flags.ALL)):
            return True

        ulist = ifaceobj.upperifaces
        if not ulist:
            return True

        # Get the list of upper ifaces other than the parent
        tmpulist = ([u for u in ulist if u != parent] if parent
                    else ulist)
        if not tmpulist:
            return True
        # XXX: This is expensive. Find a cheaper way to do this.
        # if any of the upperdevs are present,
        # return false to the caller to skip this interface
        for u in tmpulist:
            if ifupdownobj.link_exists(u):
                if not ifupdownflags.flags.ALL:
                    if ifupdownobj.is_ifaceobj_noconfig(ifaceobj):
                        ifupdownobj.logger.info('%s: skipping interface down,'
                            %ifaceobj.name + ' upperiface %s still around ' %u)
                    else:
                        ifupdownobj.logger.warning('%s: skipping interface down,'
                            %ifaceobj.name + ' upperiface %s still around ' %u)
                return False
        return True

    @classmethod
    def run_iface_graph(cls, ifupdownobj, ifacename, ops, parent=None,
                        order=ifaceSchedulerFlags.POSTORDER,
                        followdependents=True):
        """ runs interface by traversing all nodes rooted at itself """

        # Each ifacename can have a list of iface objects
        ifaceobjs = ifupdownobj.get_ifaceobjs(ifacename)
        if not ifaceobjs:
            raise SchedulerException('%s: not found' %ifacename)

        # Check state of the dependent. If it is already brought up, return
        if (cls._STATE_CHECK and
            (ifaceobjs[0].state == ifaceState.from_str(ops[-1]))):
            ifupdownobj.logger.debug('%s: already processed' %ifacename)
            return

        for ifaceobj in ifaceobjs:
            if not cls._check_upperifaces(ifupdownobj, ifaceobj,
                                          ops, parent, followdependents):
               return

        # If inorder, run the iface first and then its dependents
        if order == ifaceSchedulerFlags.INORDER:
            cls.run_iface_list_ops(ifupdownobj, ifaceobjs, ops)

        for ifaceobj in ifaceobjs:
            # Run lowerifaces or dependents
            dlist = ifaceobj.lowerifaces
            if dlist:

                if ifaceobj.link_kind == ifaceLinkKind.VRF:
                    # remove non-auto lowerifaces from 'dlist'
                    for lower_ifname in list(dlist):
                        for lower_ifaceobj in ifupdownobj.get_ifaceobjs(lower_ifname) or []:
                            if lower_ifaceobj and not lower_ifaceobj.auto and ifaceobj.name == cls.VRF_MGMT_DEVNAME:
                                dlist.remove(lower_ifname)

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
                                           ifacename, order, followdependents,
                                           continueonfailure=False)
                    else:
                        cls.run_iface_list(ifupdownobj, dlist, ops,
                                            ifacename, order,
                                            followdependents,
                                            continueonfailure=False)
                except Exception as e:
                    if not ifupdownobj.ignore_error(str(e)):
                        # Dont bring the iface up if children did not come up
                        ifaceobj.set_state_n_status(ifaceState.NEW,
                                                ifaceStatus.ERROR)
                        raise
        if order == ifaceSchedulerFlags.POSTORDER:
            cls.run_iface_list_ops(ifupdownobj, ifaceobjs, ops)

    @classmethod
    def run_iface_list(cls, ifupdownobj, ifacenames,
                       ops, parent=None, order=ifaceSchedulerFlags.POSTORDER,
                       followdependents=True, continueonfailure=True):
        """ Runs interface list """

        for ifacename in ifacenames:

            if cls._DIFF_MODE and ifacename not in cls._RUN_QUEUE:
                ifupdownobj.logger.debug(f"diff mode: skipping interface {ifacename} - not present in run queue")
                continue

            try:
              cls.run_iface_graph(ifupdownobj, ifacename, ops, parent,
                      order, followdependents)
            except Exception as e:
                if continueonfailure:
                    if ifupdownobj.logger.isEnabledFor(logging.DEBUG):
                        traceback.print_tb(sys.exc_info()[2])
                    ifupdownobj.logger.error('%s : %s' %(ifacename, str(e)))
                else:
                    if not (ifupdownobj.ignore_error(str(e))):
                        raise SchedulerException('%s : (%s)' %(ifacename, str(e)))

    @classmethod
    def run_iface_graph_upper(cls, ifupdownobj, ifacename, ops, parent=None,
                        followdependents=True, skip_root=False):
        """ runs interface by traversing all nodes rooted at itself """

        # Each ifacename can have a list of iface objects
        ifaceobjs = ifupdownobj.get_ifaceobjs(ifacename)
        if not ifaceobjs:
            raise SchedulerException('%s: not found' %ifacename)

        if (cls._STATE_CHECK and
            (ifaceobjs[0].state == ifaceState.from_str(ops[-1]))):
            ifupdownobj.logger.debug('%s: already processed' %ifacename)
            return

        if not skip_root:
            # run the iface first and then its upperifaces
            cls.run_iface_list_ops(ifupdownobj, ifaceobjs, ops)
        for ifaceobj in ifaceobjs:
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
                except Exception as e:
                    if not ifupdownobj.ignore_error(str(e)):
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
            except Exception as e:
                if ifupdownobj.logger.isEnabledFor(logging.DEBUG):
                    traceback.print_tb(sys.exc_info()[2])
                ifupdownobj.logger.warning('%s : %s' %(ifacename, str(e)))

    @classmethod
    def _get_valid_upperifaces(cls, ifupdownobj, ifacenames,
                               allupperifacenames):
        """ Recursively find valid upperifaces

        valid upperifaces are:
            - An upperiface which had no user config (example builtin
              interfaces. usually vlan interfaces.)
            - or had config and previously up
            - and interface currently does not exist
            - or is a bridge (because if your upperiface was a bridge
            - u will have to execute up on the bridge
              to enslave the port and apply bridge attributes to the port) """

        upperifacenames = []
        for ifacename in ifacenames:
            # get upperifaces
            ifaceobj = ifupdownobj.get_ifaceobj_first(ifacename)
            if not ifaceobj:
               continue
            ulist = set(ifaceobj.upperifaces or []).difference(upperifacenames)
            nulist = []
            for u in ulist:
                uifaceobj = ifupdownobj.get_ifaceobj_first(u)
                if not uifaceobj:
                   continue
                has_config = not (uifaceobj.priv_flags and
                                  uifaceobj.priv_flags.NOCONFIG)
                if (((has_config and ifupdownobj.get_ifaceobjs_saved(u)) or
                     not has_config) and (not ifupdownobj.link_exists(u)
                         # Do this always for a bridge. Note that this is
                         # not done for a vlan aware bridge because,
                         # in the vlan aware bridge case, the bridge module
                         # applies the bridge port configuration on the port
                         # when up is scheduled on the port.
                         or (uifaceobj.link_kind == ifaceLinkKind.BRIDGE))):
                     nulist.append(u)
            upperifacenames.extend(nulist)
        allupperifacenames.extend(upperifacenames)
        if upperifacenames:
            cls._get_valid_upperifaces(ifupdownobj, upperifacenames,
                                       allupperifacenames)

    @classmethod
    def run_upperifaces(cls, ifupdownobj, ifacenames, ops,
                        continueonfailure=True):
        """ Run through valid upperifaces """
        upperifaces = []

        cls._get_valid_upperifaces(ifupdownobj, ifacenames, upperifaces)
        if not upperifaces:
           return
        # dump valid upperifaces
        ifupdownobj.logger.debug(upperifaces)
        for u in upperifaces:

            if cls._DIFF_MODE and u not in cls._RUN_QUEUE:
                ifupdownobj.logger.debug(f"diff mode: upperifaces: skipping interface {u} - not present in run queue")
                continue


            try:
                ifaceobjs = ifupdownobj.get_ifaceobjs(u)
                if not ifaceobjs:
                   continue
                cls.run_iface_list_ops(ifupdownobj, ifaceobjs, ops)
            except Exception as e:
                if continueonfailure:
                    ifupdownobj.logger.warning('%s' %str(e))

    @classmethod
    def _dump_dependency_info(cls, ifupdownobj, ifacenames,
                              dependency_graph=None, indegrees=None):
        ifupdownobj.logger.info('{\n')
        ifupdownobj.logger.info('\nifaceobjs:')
        for iname in ifacenames:
            iobjs = ifupdownobj.get_ifaceobjs(iname)
            for iobj in iobjs:
                iobj.dump(ifupdownobj.logger)
        if (dependency_graph):
            ifupdownobj.logger.info('\nDependency Graph:')
            ifupdownobj.logger.info(dependency_graph)
        if (indegrees):
            ifupdownobj.logger.info('\nIndegrees:')
            ifupdownobj.logger.info(indegrees)
        ifupdownobj.logger.info('}\n')

    @classmethod
    def get_sorted_iface_list(cls, ifupdownobj, ifacenames, ops,
                              dependency_graph, indegrees=None):
        if len(ifacenames) == 1:
            return ifacenames
        # Get a sorted list of all interfaces
        if not indegrees:
            indegrees = OrderedDict()
            for ifacename in list(dependency_graph.keys()):
                indegrees[ifacename] = ifupdownobj.get_iface_refcnt(ifacename)

        #cls._dump_dependency_info(ifupdownobj, ifacenames,
        #                          dependency_graph, indegrees)

        ifacenames_all_sorted = graph.topological_sort_graphs_all(
                                        dependency_graph, indegrees)
        # if ALL was set, return all interfaces
        if ifupdownflags.flags.ALL:
            return ifacenames_all_sorted

        # else return ifacenames passed as argument in sorted order
        ifacenames_sorted = []
        [ifacenames_sorted.append(ifacename)
                        for ifacename in ifacenames_all_sorted
                            if ifacename in ifacenames]
        return ifacenames_sorted

    @classmethod
    def sched_ifaces(cls, ifupdownobj, ifacenames, ops,
                dependency_graph=None, indegrees=None,
                order=ifaceSchedulerFlags.POSTORDER,
                followdependents=True, skipupperifaces=False, sort=False, diff_mode=False):
        """ runs interface configuration modules on interfaces passed as
            argument. Runs topological sort on interface dependency graph.

        Args:
            **ifupdownobj** (object): ifupdownMain object

            **ifacenames** (list): list of interface names

            **ops** : list of operations to perform eg ['pre-up', 'up', 'post-up']

            **dependency_graph** (dict): dependency graph in adjacency list format

        Kwargs:
            **indegrees** (dict): indegree array of the dependency graph

            **order** (int): ifaceSchedulerFlags (POSTORDER, INORDER)

            **followdependents** (bool): follow dependent interfaces if true

            **sort** (bool): sort ifacelist in the case where ALL is not set

        """
        #
        # Algo:
        # if ALL/auto interfaces are specified,
        #   - walk the dependency tree in postorder or inorder depending
        #     on the operation.
        #     (This is to run interfaces correctly in order)
        # else:
        #   - sort iface list if the ifaces belong to a "class"
        #   - else just run iface list in the order they were specified
        #
        # Run any upperifaces if available
        #

        cls._DIFF_MODE = diff_mode
        cls._RUN_QUEUE = list(ifacenames)

        ifupdownobj.logger.debug(f"full run queue: {cls._RUN_QUEUE}")

        followupperifaces = False
        run_queue = []
        skip_ifacesort = int(ifupdownobj.config.get('skip_ifacesort', '0'))
        if not skip_ifacesort and not indegrees:
            indegrees = OrderedDict()
            for ifacename in list(dependency_graph.keys()):
                indegrees[ifacename] = ifupdownobj.get_iface_refcnt(ifacename)

        if not ifupdownflags.flags.ALL:
            if 'up' in ops[0]:
                # If there is any interface that does not exist, maybe it
                # is a logical interface and we have to followupperifaces
                # when it comes up, so lets get that list.
                if any([True for i in ifacenames
                        if ifupdownobj.must_follow_upperifaces(i)]):
                    followupperifaces = (True if
                                    [i for i in ifacenames
                                        if not ifupdownobj.link_exists(i)]
                                        else False)
            # sort interfaces only if the caller asked to sort
            # and skip_ifacesort is not on.
            if not skip_ifacesort and sort:
                run_queue = cls.get_sorted_iface_list(ifupdownobj, ifacenames,
                                    ops, dependency_graph, indegrees)
                if run_queue and 'up' in ops[0]:
                    run_queue.reverse()
        elif cls._DIFF_MODE:
            run_queue = cls._RUN_QUEUE
        else:
            # if -a is set, we pick the interfaces
            # that have no parents and use a sorted list of those
            if not skip_ifacesort:
                sorted_ifacenames = cls.get_sorted_iface_list(ifupdownobj,
                                            ifacenames, ops, dependency_graph,
                                            indegrees)
                if sorted_ifacenames:
                    # pick interfaces that user asked
                    # and those that dont have any dependents first
                    [run_queue.append(ifacename)
                        for ifacename in sorted_ifacenames
                            if ifacename in ifacenames and
                            not indegrees.get(ifacename)]
                    ifupdownobj.logger.debug('graph roots (interfaces that ' +
                            'dont have dependents):' + ' %s' %str(run_queue))
                else:
                    ifupdownobj.logger.warning('interface sort returned None')

        # If queue not present, just run interfaces that were asked by the
        # user
        if not run_queue:
            run_queue = list(ifacenames)
            # if we are taking the order of interfaces as specified
            # in the interfaces file, we should reverse the list if we
            # want to down. This can happen if 'skip_ifacesort'
            # is been specified.
            if 'down' in ops[0]:
                run_queue.reverse()

        # run interface list
        cls.run_iface_list(ifupdownobj, run_queue, ops,
                           parent=None, order=order,
                           followdependents=followdependents)
        if not cls.get_sched_status():
            return

        if (not cls._DIFF_MODE and not skipupperifaces and
                ifupdownobj.config.get('skip_upperifaces', '0') == '0' and
                ((not ifupdownflags.flags.ALL and followdependents) or
                 followupperifaces) and
                'up' in ops[0]):
            # If user had given a set of interfaces to bring up
            # try and execute 'up' on the upperifaces
            ifupdownobj.logger.info('running upperifaces (parent interfaces) ' +
                                    'if available ..')
            try:
                # upperiface bring up is best effort.
                # eg case: if we are bringing up a bridge port
                # this section does an 'ifup on the bridge'
                # so that the recently up'ed bridge port gets enslaved
                # to the bridge. But the up on the bridge may
                # throw out more errors if the bridge is not
                # in the correct state. Lets not surprise
                # the user with such errors when he has
                # only requested to bring up the bridge port.
                cls._STATE_CHECK = False
                ifupdownflags.flags.IGNORE_ERRORS = True
                cls.run_upperifaces(ifupdownobj, ifacenames, ops)
            finally:
                ifupdownflags.flags.IGNORE_ERRORS = False
                cls._STATE_CHECK = True
                # upperiface bringup is best effort, so dont propagate errors
                # reset scheduler status to True
                cls.set_sched_status(True)
