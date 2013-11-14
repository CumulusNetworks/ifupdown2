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

class graph():

    def __init__(self):
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)

    @classmethod
    def topological_sort(cls, dependency_graph, indegrees=None):
        S = []
        Q = deque()

        for ifname,indegree in indegrees.items():
            if indegree == 0:
                Q.append(ifname)

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

        # If some indegrees are non zero, we have a cycle
        for ifname,indegree in indegrees.items():
            if indegree != 0:
                raise Exception('cycle found involving iface %s' %ifname +
                                ' (indegree %d)' %indegree)

        return S
