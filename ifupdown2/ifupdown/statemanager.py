#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# stateManager --
#    interface state manager
#

import os
import cPickle
import logging

try:
    from ifupdown2.ifupdown.iface import *

    import ifupdown2.ifupdown.exceptions as exceptions
except ImportError:
    from ifupdown.iface import *

    import ifupdown.exceptions as exceptions


class pickling():
    """ class with helper methods for pickling/unpickling iface objects """

    @classmethod
    def save(cls, filename, list_of_objects):
        """ pickle a list of iface objects """
        try:
            with open(filename, 'w') as f:
                for obj in list_of_objects:
                    cPickle.dump(obj, f, cPickle.HIGHEST_PROTOCOL)
        except:
            raise

    @classmethod
    def save_obj(cls, f, obj):
        """ pickle iface object """
        try:
            cPickle.dump(obj, f, cPickle.HIGHEST_PROTOCOL)
        except:
            raise

    @classmethod
    def load(cls, filename):
        """ load picked iface object """
        with open(filename, 'r') as f:
            while True:
                try: yield cPickle.load(f)
                except EOFError: break
                except: raise

class stateManager():
    """ state manager for managing ifupdown iface obj state

    ifupdown2 has to maitain old objects for down operation on
    interfaces. ie to down or delete old configuration.

    This class uses pickle to store iface objects.

    """

    state_dir = '/var/tmp/network/'
    """directory where the state file is stored """

    state_filename = 'ifstatenew'
    """name of the satefile """

    state_rundir = '/run/network/'
    """name of the state run dir """

    state_runlockfile = 'ifstatelock'
    """name of the state run lock file """

    def __init__(self):
        """ Initializes statemanager internal state

        which includes a dictionary of last pickled iface objects
        """
        self.ifaceobjdict = OrderedDict()
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)
        if not os.path.exists(self.state_dir):
            os.mkdir(self.state_dir)
        if not os.path.exists(self.state_rundir):
            os.mkdir(self.state_rundir)
        self.state_file = self.state_dir + self.state_filename

    def save_ifaceobj(self, ifaceobj):
        self.ifaceobjdict.setdefault(ifaceobj.name,
                            []).append(ifaceobj)

    def read_saved_state(self, filename=None):
        """This member function reads saved iface objects

        Kwargs:
            filename (str): name of the state file
        """

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
        """This member function sync's new obj state to old statemanager state

        Args:
            ifaceobj (object): new iface object
            op (str): ifupdown operation
        """

        self.logger.debug('%s: statemanager sync state %s'
                          %(ifaceobj.name, op))
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
        """ saves state (ifaceobjects) to persistent state file """

        try:
            with open(self.state_file, 'w') as f:
                if not len(self.ifaceobjdict):
                    f.truncate(0)
                    return
                self.logger.debug('saving state ..')
                for ifaceobjs in self.ifaceobjdict.values():
                    [pickling.save_obj(f, i) for i in ifaceobjs]
            open('%s/%s' %(self.state_rundir, self.state_runlockfile), 'w').close()
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
                    raise exceptions.ifaceNotFoundError('ifname %s'
                                                        % i + ' not found')
                ifaceobj.dump(self.logger)
        else:
            for ifacename, ifaceobjs in self.ifaceobjdict.items():
                [i.dump(self.logger) for i in ifaceobjs]

statemanager_api = stateManager()

def reset():
    global statemanager_api
    statemanager_api = stateManager()
