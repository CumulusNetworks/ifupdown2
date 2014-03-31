#!/usr/bin/python
#
# Copyright 2013.  Cumulus Networks, Inc.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# stateManager --
#    interface state manager
#
import cPickle
from collections import OrderedDict
import logging
import os
from iface import *

class pickling():
    """ class with helper methods for pickling/unpickling iface objects """

    @classmethod
    def save(cls, filename, list_of_objects):
        try:
            with open(filename, 'w') as f:
                for obj in list_of_objects:
                    cPickle.dump(obj, f, cPickle.HIGHEST_PROTOCOL)
        except:
            raise

    @classmethod
    def save_obj(cls, f, obj):
        try:
            cPickle.dump(obj, f, cPickle.HIGHEST_PROTOCOL)
        except:
            raise

    @classmethod
    def load(cls, filename):
        with open(filename, 'r') as f:
            while True:
                try: yield cPickle.load(f)
                except EOFError: break
                except: raise

class stateManager():
    """ state manager for managing ifupdown iface obj state """

    state_dir = '/var/tmp/network/'
    state_filename = 'ifstatenew'

    def __init__(self):
        self.ifaceobjdict = OrderedDict()
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)
        if not os.path.exists(self.state_dir):
            os.mkdir(self.state_dir)
        self.state_file = self.state_dir + self.state_filename

    def save_ifaceobj(self, ifaceobj):
        self.ifaceobjdict.setdefault(ifaceobj.name,
                            []).append(ifaceobj)

    def read_saved_state(self, filename=None):
        pickle_filename = filename
        if not pickle_filename:
            pickle_filename = self.state_file
        if not os.path.exists(pickle_filename):
            return
        for ifaceobj in pickling.load(pickle_filename):
            self.save_ifaceobj(ifaceobj)

    def get_ifaceobjs(self, ifacename):
        return self.ifaceobjdict.get(ifacename)

    def ifaceobj_sync(self, ifaceobj, op):
        self.logger.debug('%s: statemanager sync state' %ifaceobj.name)
        old_ifaceobjs = self.ifaceobjdict.get(ifaceobj.name)
        if 'up' in op:
            if not old_ifaceobjs:
                self.ifaceobjdict[ifaceobj.name] = [ifaceobj]
            else:
                # If it matches any of the object, return
                if any(o.compare(ifaceobj) for o in old_ifaceobjs):
                    return
                # If it does not match any of the objects, and if
                # all objs in the list came from the pickled file,
                # then reset the list and add this object as a fresh one,
                # else append to the list
                if old_ifaceobjs[0].flags & iface._PICKLED:
                    del self.ifaceobjdict[ifaceobj.name]
                    self.ifaceobjdict[ifaceobj.name] = [ifaceobj]
                else:
                    self.ifaceobjdict[ifaceobj.name].append(ifaceobj)
        elif 'down' in op:
            # If down of object successfull, delete object from state manager
            if not old_ifaceobjs:
                return
            if ifaceobj.status != ifaceStatus.SUCCESS:
                return
            # If it matches any of the object, return
            oidx = 0
            for o in old_ifaceobjs:
                if o.compare(ifaceobj):
                    old_ifaceobjs.pop(oidx)
                    if not len(old_ifaceobjs):
                        del self.ifaceobjdict[ifaceobj.name]
                    return
                oidx += 1

    def save_state(self):
        try:
            with open(self.state_file, 'w') as f:
                if not len(self.ifaceobjdict):
                    os.remove(self.state_file)
                    return
                for ifaceobjs in self.ifaceobjdict.values():
                    [pickling.save_obj(f, i) for i in ifaceobjs]
        except:
            raise

    def dump_pretty(self, ifacenames, format='native'):
        if not ifacenames:
            ifacenames = self.ifaceobjdict.keys()
        for i in ifacenames:
            ifaceobjs = self.get_ifaceobjs(i)
            if not ifaceobjs:
                continue
            for ifaceobj in ifaceobjs:
                if format == 'json':
                    ifaceobj.dump_json()
                else:
                    ifaceobj.dump_pretty()

    def dump(self, ifacenames=None):
        self.logger.debug('statemanager iface state:')
        if ifacenames:
            for i in ifacenames:
                ifaceobj = self.ifaces.get(i)
                if ifaceobj is None:
                    raise ifaceNotFoundError('ifname %s'
                        %i + ' not found')
                ifaceobj.dump(self.logger)
        else:
            for ifacename, ifaceobjs in self.ifaceobjdict.items():
                [i.dump(self.logger) for i in ifaceobjs]
