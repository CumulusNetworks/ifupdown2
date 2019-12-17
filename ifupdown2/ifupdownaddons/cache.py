#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#


class MSTPAttrsCache():
    bridges = {}

    @classmethod
    def get(cls, bridgename, default=None):
        if bridgename in MSTPAttrsCache.bridges:
            return MSTPAttrsCache.bridges[bridgename]
        else:
            return default

    @classmethod
    def set(cls, bridgename, attrs):
        MSTPAttrsCache.bridges[bridgename] = attrs

    @classmethod
    def invalidate(cls):
        MSTPAttrsCache.bridges = {}
