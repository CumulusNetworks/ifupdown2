#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# stateManager --
#    interface state manager
#

import os
import pickle
import logging

try:
    from ifupdown2.ifupdown.iface import *

    import ifupdown2.ifupdown.exceptions as exceptions
    import ifupdown2.ifupdown.ifupdownconfig as ifupdownConfig
except ImportError:
    from ifupdown.iface import *

    import ifupdown.exceptions as exceptions
    import ifupdown.ifupdownconfig as ifupdownConfig


class StateManagerException(Exception):
    pass


class pickling():
    """ class with helper methods for pickling/unpickling iface objects """

    @classmethod
    def save(cls, filename, list_of_objects):
        """ pickle a list of iface objects """
        with open(filename, 'wb') as f:
            for obj in list_of_objects:
                pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

    @classmethod
    def save_obj(cls, f, obj):
        """ pickle iface object """
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, filename):
        """ load picked iface object """
        with open(filename, 'rb') as f:
            while True:
                try: yield pickle.load(f)
                except EOFError: break

class stateManager():
    """ state manager for managing ifupdown iface obj state

    ifupdown2 has to maitain old objects for down operation on
    interfaces. ie to down or delete old configuration.

    This class uses pickle to store iface objects.

    """

    __DEFAULT_STATE_DIR = "/var/tmp/network/"

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
        self.state_dir = None
        self.state_file = None
        self.ifaceobjdict = OrderedDict()
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)

    def init(self):
        self.state_dir = ifupdownConfig.config.get("state_dir")
        used_default = False

        if not self.state_dir:
            self.logger.debug("statemanager: state_dir not defined in config file, using default: %s" % self.__DEFAULT_STATE_DIR)
            self.state_dir = self.__DEFAULT_STATE_DIR
            used_default = True

        try:
            self._init_makedirs_state_dir()
        except Exception as e:
            if used_default:
                # if the default path was used but still throws an exception...
                raise
            self.logger.info("statemanager: %s: using default directory: %s" % (e, self.__DEFAULT_STATE_DIR))
            self.state_dir = self.__DEFAULT_STATE_DIR
            try:
                self._init_makedirs_state_dir()
            except Exception as e:
                raise StateManagerException("statemanager: unable to create required directory: %s" % str(e))

        if not os.path.exists(self.state_rundir):
            os.makedirs(self.state_rundir, exist_ok=True)

        self.state_file = "%s/%s" % (self.state_dir, self.state_filename)

    def _init_makedirs_state_dir(self):
        if not os.path.exists(self.state_dir):
            os.makedirs(self.state_dir, exist_ok=True)


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
            # ifupdown2 prevents user from bringing the loopback interface
            # down - to avoid any issue (like wrong error messages) we
            # shouldn't remove lo ifaceobj from the statemanager
            if ifaceobj.link_privflags & ifaceLinkPrivFlags.LOOPBACK:
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
        with open(self.state_file, 'wb') as f:
            if not len(self.ifaceobjdict):
                f.truncate(0)
                return
            self.logger.debug('saving state ..')
            for ifaceobjs in list(self.ifaceobjdict.values()):
                [pickling.save_obj(f, i) for i in ifaceobjs]
        open('%s/%s' % (self.state_rundir, self.state_runlockfile), 'w').close()

    def dump_pretty(self, ifacenames, format='native'):
        if not ifacenames:
            ifacenames = list(self.ifaceobjdict.keys())
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
            for ifacename, ifaceobjs in list(self.ifaceobjdict.items()):
                [i.dump(self.logger) for i in ifaceobjs]

statemanager_api = stateManager()

def reset():
    global statemanager_api
    statemanager_api = stateManager()
