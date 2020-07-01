#!/usr/bin/env python3
# Copyright (C) 2019 Cumulus Networks, Inc. all rights reserved
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# https://www.gnu.org/licenses/gpl-2.0-standalone.html
#
# Author:
#       Julien Fortin, julien@cumulusnetworks.com
#
# ifupdown2 -- dry_run module
#
#
# __WeakMethodBound and __WeakMethodFree classes as well as the WeakMethod
# function were inspired by the implementation of ActiveState recipes 81253
# weakmethod.
# This code solves an important issue here. You can't have weakrefs on bound
# methods. Here is quote from the recipie:
#
# "Normal weakref.refs to bound methods don't quite work the way one expects,
# because bound methods are first-class objects; weakrefs to bound methods are
# dead-on-arrival unless some other strong reference to the same bound method
# exists."
#

import logging
import inspect
import weakref


class __WeakMethodBound:
    """ ActiveState recipes 81253-weakmethod """

    def __init__(self, f):
        self.f = f.__func__
        self.c = weakref.ref(f.__self__)

    def __call__(self, *arg, **kwargs):
        if not self.c():
            raise TypeError("Method called on dead object")
        self.f(*(self.c(),) + arg, **kwargs)


class __WeakMethodFree:
    """ ActiveState recipes 81253-weakmethod """

    def __init__(self, f):
        self.f = weakref.ref(f)

    def __call__(self, *arg, **kwargs):
        if not self.f():
            raise TypeError("Function no longer exist")
        self.f()(*arg, **kwargs)


def WeakMethod(f):
    """ ActiveState recipes 81253-weakmethod """
    try:
        f.__func__
    except AttributeError:
        return __WeakMethodFree(f)
    return __WeakMethodBound(f)


def _weakref_call_back_delete(reference):
    try:
        DryRunManager.get_instance().unregister_dry_run_handler_weakref_callback(reference)
    except Exception:
        pass


class DryRun(object):
    """
    Detect dry_run functions and save the associated handler
    """
    __DRY_RUN_PREFIX = "DRY-RUN"

    def __init__(self):
        self.logger = logging.getLogger("ifupdown2.%s" % self.__class__.__name__)

        for attr_name in dir(self):
            try:
                # We need to iterate through the object attribute
                # to find dryrun methods
                if attr_name.lower().endswith("_dry_run"):
                    attr_value = getattr(self, attr_name)

                    # When we find a dryrun attribute we need to make sure
                    # it is a callable function or method.
                    if not self.__is_method_or_function(attr_value):
                        continue

                    base_attr_name = attr_name[:-8]
                    base_attr_value = getattr(self, base_attr_name)
                    # We try infere the base method/function name
                    # then make sure its a function or method
                    if not self.__is_method_or_function(base_attr_value):
                        continue

                    # now we are pretty sure we have want we want:
                    # - the base function
                    # - the associated dry_run code
                    # we will now register this couple in the DryRunManager
                    DryRunManager.get_instance().register_dry_run_handler(
                        weakref.ref(self, _weakref_call_back_delete),
                        handler_name=base_attr_name,
                        handler_code_weakref=WeakMethod(base_attr_value),
                        dry_run_code_weakref=WeakMethod(attr_value)
                    )
            except Exception:
                pass

    def log_info_ifname_dry_run(self, ifname, string):
        self.logger.info("DRY-RUN: %s: %s" % (ifname, string))

    def log_info_dry_run(self, string):
        self.logger.info("DRY-RUN: %s" % string)

    @staticmethod
    def __is_method_or_function(obj):
        return callable(obj) and (inspect.ismethod(obj) or inspect.isfunction(obj))


class _DryRunEntry(object):
    def __init__(self, target_module_weakref, handler_name, handler_code_weakref, dry_run_code_weakref):
        self.target_module_weakref = target_module_weakref
        self.handler_name = handler_name
        self.handler_code_weakref = handler_code_weakref
        self.dry_run_code_weakref = dry_run_code_weakref
        self.__status = False

    def set(self):
        target_module_ref = self.target_module_weakref()

        if target_module_ref:
            if self.dry_run_code_weakref:
                target_module_ref.__dict__[self.handler_name] = self.dry_run_code_weakref
                self.__status = True
        else:
            # if the reference is dead we need to unregister it
            DryRunManager.get_instance().unregister_dry_run_handler_weakref_callback(self.target_module_weakref)

    def unset(self):
        target_module_ref = self.target_module_weakref()

        if target_module_ref:
            if self.handler_code_weakref:
                target_module_ref.__dict__[self.handler_name] = self.handler_code_weakref
                self.__status = False
        else:
            # if the reference is dead we need to unregister it
            DryRunManager.get_instance().unregister_dry_run_handler_weakref_callback(self.target_module_weakref)

    def get_status(self):
        return self.__status


class DryRunManager(object):
    __instance = None

    @staticmethod
    def get_instance():
        if not DryRunManager.__instance:
            DryRunManager.__instance = DryRunManager()
        return DryRunManager.__instance

    def __init__(self):
        if DryRunManager.__instance:
            raise RuntimeError("DryRunManager: invalid access. Please use DryRunManager.getInstance()")
        else:
            DryRunManager.__instance = self

        self.__entries = dict()
        self.__is_on = False

    def register_dry_run_handler(self, module_weakref, handler_name, handler_code_weakref, dry_run_code_weakref):
        """
        Register the dry run handler only using weakrefs - we don't want to mess up with garbage collection
        :param module_weakref:
        :param handler_name:
        :param handler_code_weakref:
        :param dry_run_code_weakref:
        :return:
        """
        dry_run_entry = _DryRunEntry(
            target_module_weakref=module_weakref,
            handler_name=handler_name,
            handler_code_weakref=handler_code_weakref,
            dry_run_code_weakref=dry_run_code_weakref
        )
        if self.__is_on:
            dry_run_entry.set()

        if module_weakref in self.__entries:
            self.__entries[module_weakref].append(dry_run_entry)
        else:
            self.__entries[module_weakref] = [dry_run_entry]

    def unregister_dry_run_handler_weakref_callback(self, reference):
        """
        If we detect a dead reference, we should remove this reference from our
        internal data structure
        """
        try:
            del self.__entries[reference]
        except Exception:
            pass

    def dry_run_mode_on(self):
        """
        Enable the dry run mode
        WARNING: not thread-safe
        """
        for entries in self.__entries.values():
            for entry in entries:
                entry.set()
        self.__is_on = True

    def dry_run_mode_off(self):
        """
        Disable the dry run mode
        WARNING: not thread-safe
        """
        for entries in self.__entries.values():
            for entry in entries:
                entry.unset()
        self.__is_on = False

    def dump_entries_stdout(self):
        print("== DryRunManager dump ==")
        print("  MODULE:    HANDLER  STATUS")
        for entries in self.__entries.values():
            for entry in entries:
                print("  %s: %s() %s" % (repr(entry.target_module_weakref), entry.handler_name, "ON" if entry.get_status() else "OFF"))
        print("========================")

    def is_dry_mode_on(self):
        return self.__is_on
