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
import copy
import marshal

class pickling():

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
        self.ifaceobjdict.setdefault(ifaceobj.get_name(),
                            []).append(ifaceobj)

    def read_saved_state(self, filename=None):
        pickle_filename = filename
        if not pickle_filename:
            pickle_filename = self.state_file

        if not os.path.exists(pickle_filename):
            return

        # Read all ifaces from file
        for ifaceobj in pickling.load(pickle_filename):
            self.save_ifaceobj(ifaceobj)

        return 0

    def get_ifaceobjdict(self):
        return self.ifaceobjdict

    def get_ifaceobjs(self, ifacename):
        return self.ifaceobjdict.get(ifacename)

    def compare_iface_state(ifaceobj1, ifaceobj2):
        ifaceobj1_state = ifaceobj1.get_state()
        ifaceobj2_state = ifaceobj2.get_state()

        if ifaceobj1_state < ifaceobj2_state:
            return -1
        elif ifaceobj1_state > ifaceobj2_state:
            return 1
        elif ifaceobj1_state == ifaceobj2_state:
            return 0

    def cmp_old_new_state(self, ifacename, operation):
        """ compares current operation with old state """

        state_arg = ifaceState.from_str(operation)
        if state_arg == ifaceState.UP:
            old_ifaceobj = self.ifaceobjdict.get(ifacename)
            if old_ifaceobj != None:
                # found old state for iface
                # Check its state
                if (old_ifaceobj.get_state() == state_arg and
                    old_ifaceobj.get_status() == ifaceStatus.SUCCESS):
                    self.statemsg = 'iface already up'
                    return 0
        elif state_arg == ifaceState.DOWN:
            old_ifaceobj = self.ifaceobjdict.get(ifname)
            if old_ifaceobj != None:
                # found old state for iface
                # Check its state
                if (old_ifaceobj.get_state() == state_arg and
                    old_ifaceobj.get_status() == ifaceStatus.SUCCESS):
                    self.statemsg = 'iface already down'
                    return 0

        return 1

    def ifaceobj_compare(self, ifaceobj_a, ifaceobj_b):
        if ifaceobj_a.get_name() != ifaceobj_b.get_name():
            return False

        if (ifaceobj_a.get_addr_family() is None and
            ifaceobj_b.get_addr_family() is not None):
                return False

        if (ifaceobj_a.get_addr_family() is not None and
            ifaceobj_b.get_addr_family() is None):
                return False

        if (ifaceobj_a.get_addr_family() is None and
            ifaceobj_b.get_addr_family() is None):
                return True

        if ifaceobj_a.get_addr_family() != ifaceobj_b.get_addr_family():
           return False

        return True

    def ifaceobj_sync(self, ifaceobj):
        ifacename = ifaceobj.get_name()
        self.logger.debug('%s: statemanager sync state' %ifacename)
        old_ifaceobjs = self.ifaceobjdict.get(ifacename)
        if not old_ifaceobjs:
            self.ifaceobjdict[ifacename] = [ifaceobj]
        else:
            if old_ifaceobjs[0].flags & iface.PICKLED:
                del self.ifaceobjdict[ifacename]
                self.ifaceobjdict[ifacename] = [ifaceobj]
            else:
                self.ifaceobjdict[ifacename].append(ifaceobj)

    def save_state(self):
        try:
            with open(self.state_file, 'w') as f:
                for ifaceobjs in self.ifaceobjdict.values():
                    for i in ifaceobjs:
                        pickling.save_obj(f, i)
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
