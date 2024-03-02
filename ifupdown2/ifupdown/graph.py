#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# graph --
#    graph helper module for ifupdown
#

import copy
import logging

from collections import deque


try:
    from ifupdown2.lib.gvgen import GvGen
except ImportError:
    from lib.gvgen import GvGen


class GraphException(Exception):
    pass


class graph():
    """ graph functions to sort and print interface graph """

    logger = logging.getLogger('ifupdown.graph')

    @classmethod
    def topological_sort_graphs_all(cls, dependency_graphs, indegrees_arg):
        """ runs topological sort on interface list passed as dependency graph

        Args:
            **dependency_graphs** (dict): dependency graph with dependency
                                          lists for interfaces

            **indegrees_arg** (dict): indegrees array for all interfaces
        """
        S = []
        Q = deque()

        indegrees = copy.deepcopy(indegrees_arg)
        for ifname,indegree in list(indegrees.items()):
            if indegree == 0:
                Q.append(ifname)

        while len(Q):
            # initialize queue
            x = Q.popleft()

            # Get dependents of x
            dlist = dependency_graphs.get(x)
            if not dlist:
                S.append(x)
                continue

            for y in dlist:
                try:
                    indegrees[y] = indegrees.get(y) - 1
                except Exception:
                    cls.logger.debug('topological_sort_graphs_all: did not find %s' %y)
                    indegrees[y] = 0
                if indegrees.get(y) == 0:
                    Q.append(y)

            S.append(x)

        for ifname,indegree in list(indegrees.items()):
            if indegree != 0:
                raise GraphException('cycle found involving iface %s' %ifname +
                                ' (indegree %d)' %indegree)

        return S

    @classmethod
    def generate_dots(cls, dependency_graph, indegrees):
        """ spits out interface dependency graph in dot format

        Args:
            **dependency_graphs** (dict): dependency graph with dependency
                                          lists for interfaces

            **indegrees_arg** (dict): indegrees array for all interfaces
        """

        gvgraph = GvGen()
        graphnodes = {}
        for v in list(dependency_graph.keys()):
            graphnodes[v] = gvgraph.newItem(v)

        for i, v in list(graphnodes.items()):
            dlist = dependency_graph.get(i, [])
            if not dlist:
                continue
            for d in dlist:
                gvgraph.newLink(v, graphnodes.get(d))
        gvgraph.dot()
