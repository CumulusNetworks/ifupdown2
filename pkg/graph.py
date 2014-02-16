#!/usr/bin/python
#
# Copyright 2013.  Cumulus Networks, Inc.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# graph --
#    graph helper module for ifupdown
#

import logging
from collections import deque
try:
    from gvgen import *
except ImportError, e:
    pass

class graph():

    def __init__(self):
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)

    @classmethod
    def topological_sort_graphs_all(cls, dependency_graphs, indegrees):
        S = []
        Q = deque()

        for ifname,indegree in indegrees.items():
            if indegree == 0:
                Q.append(ifname)

        while len(Q) != 0:
            # initialize queue
            x = Q.popleft()

            # Get dependents of x
            dlist = dependency_graphs.get(x)
            if dlist == None or len(dlist) == 0:
                S.append(x)
                continue

            for y in dlist:
                indegrees[y] = indegrees.get(y) - 1
                if indegrees.get(y) == 0:
                    Q.append(y)

            S.append(x)

        for ifname,indegree in indegrees.items():
            if indegree != 0:
                raise Exception('cycle found involving iface %s' %ifname +
                                ' (indegree %d)' %indegree)

        return S

    @classmethod
    def topological_sort_graph(cls, dependency_graph, indegrees, rootifname):
        S = []
        Q = deque()

        Q.append(rootifname)

        while len(Q) != 0:
            # initialize queue
            x = Q.popleft()

            # Get dependents of x
            dlist = dependency_graph.get(x)
            if dlist == None or len(dlist) == 0:
                S.append(x)
                continue

            for y in dlist:
                indegrees[y] = indegrees.get(y) - 1
                if indegrees.get(y) == 0:
                    Q.append(y)

            S.append(x)

        return S

    @classmethod
    def topological_sort_graphs(cls, dependency_graphs, indegrees):
        """ Sorts graph one at a time merges all the sorted graph
        lists and returns a combined list
       
        """
        sorted_graphs_list = []
        for ifname,indegree in indegrees.items():
            if indegree == 0:
                sorted_graphs_list += cls.topological_sort_graph(
                                        dependency_graphs, indegrees, ifname)
        # If some indegrees are non zero, we have a cycle
        for ifname,indegree in indegrees.items():
            if indegree != 0:
                raise Exception('cycle found involving iface %s' %ifname +
                                ' (indegree %d)' %indegree)

        return sorted_graphs_list

    @classmethod
    def generate_dots(cls, dependency_graph, indegrees):
        gvgraph = GvGen()
        graphnodes = {}
        for v in dependency_graph.keys():
            graphnodes[v] = gvgraph.newItem(v)

        for i, v in graphnodes.items():
            dlist = dependency_graph.get(i, [])
            if not dlist:
                continue
            for d in dlist:
                gvgraph.newLink(v, graphnodes.get(d))
        gvgraph.dot()
