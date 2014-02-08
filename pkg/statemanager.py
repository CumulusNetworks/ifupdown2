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
from exceptions import *
import logging
import pprint
import os
from iface import *

class pickling():

    @classmethod
    def save(cls, filename, list_of_objects):
        try:
            with open(filename, 'w') as f:
                for obj in list_of_objects:
                    cPickle.dump(obj, f)
        except:
            raise

    @classmethod
    def save_obj(cls, f, obj):
        try:
            cPickle.dump(obj, f)
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

    state_file = '/run/network/ifstatenew'


    def __init__(self):
        self.ifaceobjdict = OrderedDict()
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)

    def save_ifaceobj(self, ifaceobj):
        if self.ifaceobjdict.get(ifaceobj.get_name()) is None:
            self.ifaceobjdict[ifaceobj.get_name()] = [ifaceobj]
        else:
            self.ifaceobjdict[ifaceobj.get_name()].append(ifaceobj)

    def read_saved_state(self, filename=None):
        pickle_filename = filename
        if pickle_filename == None:
            pickle_filename = self.state_file

        if not os.path.exists(pickle_filename):
            return

        # Read all ifaces from file
        for ifaceobj in pickling.load(pickle_filename):
            self.save_ifaceobj(ifaceobj)
            #ifaceobj.set_refcnt(0)
            #ifaceobj.set_dependents(None)

        return 0

    def get_ifaceobjdict(self):
        return self.ifaceobjdict

    def save_state(self, ifaceobjs, filename=None):
        pickle_filename = filename
        if pickle_filename == None:
            pickle_filename = self.state_file

        pickling.save(pickle_filename, ifaceobjs)


    def compare_iface_state(ifaceobj1, ifaceobj2):
        ifaceobj1_state = ifaceobj1.get_state()
        ifaceobj2_state = ifaceobj2.get_state()

        if ifaceobj1_state < ifaceobj2_state:
            return -1
        elif ifaceobj1_state > ifaceobj2_state:
            return 1
        elif ifaceobj1_state == ifaceobj2_state:
            return 0

    def compare_iface_with_old(self, ifaceobj):
        old_ifaceobj = self.ifaceobjdict.get(ifaceobj.get_name())
        if old_ifaceobj == None:
            raise ifacenotfound(ifaceobj.get_name())

        if ifaceobj.get_addr_family() != old_ifaceobj.get_addr_family():
            return -1

        if ifaceobj.get_method() != old_ifaceobj.get_method():
            return -1

        # compare config items
        unmatched_item = set(ifaceobj.items()) ^ set(old_ifaceobj.items())
        if len(unmatched_item) != 0:
            return -1

        return 0

    def get_iface_state_old(self, ifaceobj):
        old_ifaceobj = self.ifaceobjdict.get(ifaceobj.get_name())
        if old_ifaceobj == None:
            raise ifacenotfound(ifaceobj.get_name())

        return old_ifaceobj.get_state()

    def get_iface_status_old(self, ifaceobj):
        old_ifaceobj = self.ifaceobjdict.get(ifaceobj.get_name())
        if old_ifaceobj == None:
            raise ifacenotfound(ifaceobj.get_name())

        return old_ifaceobj.get_status()

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

    def iface_obj_compare(self, ifaceobj_a, ifaceobj_b):
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


    def update_iface_state(self, ifaceobj):
        old_ifaceobjs = self.ifaceobjdict.get(ifaceobj.get_name())
        if old_ifaceobjs is None:
            self.ifaceobjdict[ifaceobj.get_name()] = [ifaceobj]
        else:
            for oi in old_ifaceobjs:
                if self.iface_obj_compare(ifaceobj, oi) == True:
                    oi.set_state(ifaceobj.get_state())
                    oi.set_status(ifaceobj.get_status())
                    return

            self.ifaceobjdict[ifaceobj.get_name()].append(ifaceobj)

    def flush_state(self, ifaceobjdict=None):
        if ifaceobjdict is None:
            ifaceobjdict = self.ifaceobjdict

        try:
            with open(self.state_file, 'w') as f:
                for ifaceobjs in ifaceobjdict.values():
                    for i in ifaceobjs:
                        pickling.save_obj(f, i)
        except:
            raise


    def is_valid_state_transition(self, ifaceobj, tobe_state):
        if self.ifaceobjdict is None:
            return True

        if tobe_state == 'up':
            max_tobe_state = ifaceState.POST_UP
        elif tobe_state == 'down':
            max_tobe_state = ifaceState.POST_DOWN
        else:
            return True

        old_ifaceobjs = self.ifaceobjdict.get(ifaceobj.get_name())
        if old_ifaceobjs is not None:
            for oi in old_ifaceobjs:
                if self.iface_obj_compare(ifaceobj, oi) == True:
                    if (oi.get_state() == max_tobe_state and
                        oi.get_status() == ifaceStatus.SUCCESS):
                        # if old state is greater than or equal to
                        # tobe_state
                        return False
                    else:
                        return True

            return True
        else:
            return True

    def print_state(self, ifaceobj, prefix, indent):
        print (indent + '%s' %prefix +
               '%s' %ifaceobj.get_state_str() +
               ', %s' %ifaceobj.get_status_str())

    def print_state_pretty(self, ifacenames, logger):
        for ifacename in ifacenames:
            old_ifaceobjs = self.ifaceobjdict.get(ifacename)
            if old_ifaceobjs is not None:
                firstifaceobj = old_ifaceobjs[0]
                self.print_state(firstifaceobj,
                        '%s: ' %firstifaceobj.get_name(), '')

    def print_state_detailed_pretty(self, ifacenames, logger):
        indent = '\t'
        for ifacename in ifacenames:
            old_ifaceobjs = self.ifaceobjdict.get(ifacename)
            if old_ifaceobjs is not None:
                for i in old_ifaceobjs:
                    i.dump_pretty(logger)
                    self.print_state(i, '', indent)
            print '\n'

    def dump(self, ifacenames=None):
        print 'iface state:'
        if ifacenames is not None and len(ifacenames) > 0:
            for i in ifacenames:
                ifaceobj = self.ifaces.get(i)
                if ifaceobj is None:
                    raise ifaceNotFoundError('ifname %s'
                        %i + ' not found')
                ifaceobj.dump(self.logger)
        else:
            for ifacename, ifaceobj in self.ifaceobjdict.items():
                ifaceobj.dump(self.logger)
