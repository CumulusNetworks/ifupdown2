#!/usr/bin/env python3
#
# Copyright 2015-2017 Cumulus Networks, Inc. All rights reserved.
#
#
'''
The PolicyManager should be subclassed by addon modules
to read a JSON policy config file that is later used to
set defaults:

Initialize: This module defines a list of config file location based
          on module.  There are defined in the __init__():  All the
          addon modules need to do is import the policymanager module.

          import ifupdown2.ifupdown.policymanager as policymanager


Provides: an API to retrieve link attributes based on addon module name,
          interface name, and attribute.

        The ifupdown.policymanager module provides a global object policymanager_api
        that can be called like so:

        speed_default = policymanager.policymanager_api.get_default(
            module_name='ethtool',
            ifname=ifaceobj.name,
            attr='link-speed'
            )
'''

import json
import glob
import logging


class policymanager():
    def __init__(self):
        # we should check for these files in order
        # so that customers can override the /var/lib file settings
        self.logger = logging.getLogger('ifupdown.' +
                            self.__class__.__name__)

        self.logger.info("policymanager init")

        # we grab the json files from a known location and make sure that
        # the defaults_policy is checked first
        user_files = glob.glob('/etc/network/ifupdown2/policy.d/*.json')
        # grab the default module files
        default_files = glob.glob('/var/lib/ifupdown2/policy.d/*.json')
        # keep an array of defaults indexed by module name
        self.system_policy_array = {}
        for filename in default_files:
            system_array  = {}
            try:
                with open(filename, 'r') as fd:
                    system_array = json.load(fd)
                self.logger.debug('reading %s system policy defaults config' \
                                  % filename)
            except Exception as e:
                self.logger.warning('could not read %s system policy defaults config' \
                                  % filename)
                self.logger.warning('    exception is %s' % str(e))

            for module in list(system_array.keys()):
                if module in self.system_policy_array:
                    self.logger.debug("policymanager: merging system module %s policy with file %s" % (module, filename))
                    self.system_policy_array[module].update(system_array[module])
                else:
                    json_dict = system_array[module]

                    if isinstance(json_dict, dict):
                        self.system_policy_array[module] = system_array[module]
                    elif module != "README":
                        self.logger.warning(
                            "file %s contains an invalid policy schema, key "
                            "\"%s\" contains %s when a dictionary is expected" %
                            (filename, module, type(json_dict))
                        )

        # take care of user defined policy defaults
        self.user_policy_array = {}
        for filename in user_files:
            user_array  = {}
            try:
                with open(filename, 'r') as fd:
                    user_array = json.load(fd)
                self.logger.debug('reading %s policy user defaults config' \
                                  % filename)
            except Exception as e:
                self.logger.warning('could not read %s user policy defaults config' \
                                  % filename)
                self.logger.warning('    exception is %s' % str(e))
            # customer added module attributes
            for module in list(user_array.keys()):
                if module == "README":
                    continue
                if module in self.system_policy_array:
                    # warn user that we are overriding the system module setting
                    self.logger.debug('warning: overwriting system with user module %s from file %s' \
                                      % (module,filename))
                if module in self.user_policy_array:
                    self.logger.debug("policymanager: merging user module %s policy with file %s" % (module, filename))
                    self.user_policy_array[module].update(user_array[module])
                else:
                    self.user_policy_array[module] = user_array[module]

    def get_iface_default(self,module_name=None,ifname=None,attr=None):
        '''
        get_iface_default: Addon modules must use one of two types of access methods to
        the default configs.   In this method, we expect the default to be
        either in
            [module]['iface_defaults'][ifname][attr] or
            [module]['defaults'][attr]
        We first check the user_policy_array and return that value. But if
        the user did not specify an override, we use the system_policy_array.
        '''
        # make sure we have an index
        if (not ifname or not attr or not module_name):
            return None

        val = None
        # users can specify defaults to override the systemwide settings
        # look for user specific interface attribute iface_defaults first
        try:
            # looks for user specified value
            val = self.user_policy_array[module_name]['iface_defaults'][ifname][attr]
            return val
        except (TypeError, KeyError, IndexError):
            pass
        try:
            # failing that, there may be a user default for all intefaces
            val = self.user_policy_array[module_name]['defaults'][attr]
            return val
        except (TypeError, KeyError, IndexError):
            pass
        try:
            # failing that, look for  system setting for the interface
            val = self.system_policy_array[module_name]['iface_defaults'][ifname][attr]
            return val
        except (TypeError, KeyError, IndexError):
            pass
        try:
            # failing that, look for  system setting for all interfaces
            val = self.system_policy_array[module_name]['defaults'][attr]
            return val
        except (TypeError, KeyError, IndexError):
            pass

        # could not find any system or user default so return Non
        return val

    def get_attr_default(self,module_name=None,attr=None):
        '''
        get_attr_default: Addon modules must use one of two types of access methods to
        the default configs.   In this method, we expect the default to be in

        [module]['defaults'][attr]

        We first check the user_policy_array and return that value. But if
        the user did not specify an override, we use the system_policy_array.
        '''
        if (not attr or not module_name):
            return None
        # users can specify defaults to override the systemwide settings
        # look for user specific attribute defaults first
        val = None
        try:
            # looks for user specified value
            val = self.user_policy_array[module_name]['defaults'][attr]
            return val
        except (TypeError, KeyError, IndexError):
            pass
        try:
            # failing that, look for system setting
            val = self.system_policy_array[module_name]['defaults'][attr]
            return val
        except (TypeError, KeyError, IndexError):
            pass

        return val

    def get_module_globals(self,module_name=None,attr=None):
        '''
        get_module_globals: Addon modules must use one of two types of access methods to
        the default configs.   In this method, we expect the default to be in

        [module]['module_globals'][attr]

        We first check the user_policy_array and return that value. But if
        the user did not specify an override, we use the system_policy_array.
        '''

        if (not attr or not module_name):
            return None
        # users can specify defaults to override the systemwide settings
        # look for user specific attribute defaults first
        val = None
        try:
            # looks for user specified value
            val = self.user_policy_array[module_name]['module_globals'][attr]
            return val
        except (TypeError, KeyError, IndexError):
            pass
        try:
            # failing that, look for system setting
            val = self.system_policy_array[module_name]['module_globals'][attr]
            return val
        except (TypeError, KeyError, IndexError):
            pass

        return val

    def get_module_defaults(self, module_name):
        """
            get_module_defaults: returns a merged dictionary of default values
            specified in policy files. Users provided values override system
            values.
        """

        if not module_name:
            raise NotImplementedError('get_module_defaults: module name can\'t be None')

        defaults = dict()
        defaults.update(self.system_policy_array.get(module_name, {}).get('defaults', {}))
        defaults.update(self.user_policy_array.get(module_name, {}).get('defaults', {}))
        return defaults

    def get_iface_defaults(self, module_name):
        defaults = dict()

        if not module_name:
            self.logger.info('get_iface_defaults: module name can\'t be None')
        else:
            defaults.update(self.system_policy_array.get(module_name, {}).get('iface_defaults', {}))
            defaults.update(self.user_policy_array.get(module_name, {}).get('iface_defaults', {}))
        return defaults


policymanager_api = policymanager()

def reset():
    global policymanager_api
    policymanager_api = policymanager()
