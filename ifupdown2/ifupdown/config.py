#!/usr/bin/env python3
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

try:
    # ifupdown2/ifupdown/config.py -> we need to use dirname twice.
    ADDON_MODULES_DIR = ['%s/addons' % (os.path.dirname(os.path.dirname(os.path.realpath(__file__))))]

    if ADDON_MODULES_DIR[0] != IFUPDOWN2_ADDON_DROPIN_FOLDER:
        ADDON_MODULES_DIR.append(IFUPDOWN2_ADDON_DROPIN_FOLDER)
except Exception as e:
    print("debug: error resolving ifupdown2 addons module directory: %s" % str(e))
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
