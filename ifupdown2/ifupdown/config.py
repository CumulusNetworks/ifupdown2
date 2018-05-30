#!/usr/bin/python
#
# Copyright 2017 Cumulus Networks, Inc. All rights reserved.
# Authors:
#           Julien Fortin, julien@cumulusnetworks.com
#
# ifupdown2 --
#    tool to configure network interfaces
#

import os
import resource

IFUPDOWN2_ADDON_DROPIN_FOLDER = '/usr/share/ifupdown2/addons'

# ifupdown2/core/config.py -> we need to use dirname twice.
_ = {
    IFUPDOWN2_ADDON_DROPIN_FOLDER,
    '%s/addons' % (os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
}

try:
    addon_module_dir_list = list(_)
    if addon_module_dir_list[0] is not IFUPDOWN2_ADDON_DROPIN_FOLDER:
        addon_module_dir_list.remove(IFUPDOWN2_ADDON_DROPIN_FOLDER)
        ADDON_MODULES_DIR = [IFUPDOWN2_ADDON_DROPIN_FOLDER] + addon_module_dir_list
    else:
        ADDON_MODULES_DIR = addon_module_dir_list
except:
    ADDON_MODULES_DIR = [IFUPDOWN2_ADDON_DROPIN_FOLDER]

__version__ = ''


def get_configuration_file_real_path(path_to_file):
    """
    When install via pypi or `pip install .` ifupdown2 is install in a virtualenv
    config file that should be installed in /etc/network/ifupdown2 end-up being
    installed in /usr/local/lib/python2.7/dist-packages/etc/network/ifupdown2/
    """
    if not os.path.exists(path_to_file):
        # we will try to resolve the location of our conf file
        # otherwise default to the input argument
        package_dir = os.path.dirname(os.path.realpath(__file__))
        parent_dir = os.path.dirname(package_dir)
        resolved_path = '%s%s' % (parent_dir, path_to_file)

        if os.path.exists(resolved_path):
            return resolved_path

    return path_to_file


IFUPDOWN2_CONF_PATH = get_configuration_file_real_path('/etc/network/ifupdown2/ifupdown2.conf')
ADDONS_CONF_PATH = get_configuration_file_real_path('/etc/network/ifupdown2/addons.conf')

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
