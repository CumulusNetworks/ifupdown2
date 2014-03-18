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

        while len(Q):
            # initialize queue
            x = Q.popleft()

            # Get dependents of x
            dlist = dependency_graphs.get(x)
            if not dlist:
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
