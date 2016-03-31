#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import pprint
from collections import OrderedDict

class linkCache():
    """ This class contains methods and instance variables to cache
    link info """

    _shared_state = {}

    """ { <ifacename> : { 'ifindex': <index>,
                          'mtu': <mtu>,
                          'state' : <state>',
                          'flags' : <flags>,
                          'kind' : <kind: bridge, bond, vlan>,
                          'linkinfo' : {<attr1> : <attrval1>,
                                        <attr2> : <attrval2>,
                                        <ports> : {
                                                  } """
    links = {}
    vrfs = {}

    @classmethod
    def get_attr(cls, mapList):
        return reduce(lambda d, k: d[k], mapList, linkCache.links)

    @classmethod
    def set_attr(cls, mapList, value):
        cls.get_attr(mapList[:-1])[mapList[-1]] = value

    @classmethod
    def del_attr(cls, mapList):
        try:
            del cls.get_attr(mapList[:-1])[mapList[-1]]
        except:
            pass

    @classmethod
    def update_attrdict(cls, mapList, valuedict):
        try:
            cls.get_attr(mapList[:-1])[mapList[-1]].update(valuedict)
        except:
            cls.get_attr(mapList[:-1])[mapList[-1]] = valuedict
            pass

    @classmethod
    def append_to_attrlist(cls, mapList, value):
        cls.get_attr(mapList[:-1])[mapList[-1]].append(value)

    @classmethod
    def remove_from_attrlist(cls, mapList, value):
        try:
            cls.get_attr(mapList[:-1])[mapList[-1]].remove(value)
        except:
            pass

    @classmethod
    def check_attr(cls, attrlist, value=None):
        try:
            cachedvalue = cls.get_attr(attrlist)
            if value:
                if cachedvalue == value:
                    return True
                else:
                    return False
            elif cachedvalue:
                return True
            else:
                return False
        except:
            return False

    @classmethod
    def invalidate(cls):
        cls.links = {}

    @classmethod
    def dump(cls):
        print 'Dumping link cache'
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(cls.links)

    @classmethod
    def dump_link(cls, linkname):
        print 'Dumping link %s' %linkname
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(cls.links.get(linkname))
