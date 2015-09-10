#!/usr/bin/python
#
# Copyright 2015 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
from utilsbase import *

class systemUtils():
    @classmethod
    def is_service_running(cls, procname=None, pidfile=None):
        utilsobj = utilsBase()
        if pidfile:
            if os.path.exists(pidfile):
                pid = utilsobj.read_file_oneline(pidfile)
                if not os.path.exists('/proc/%s' %pid):
                    return False
            else:
                return False
            return True

        if procname:
            try:
                utilsobj.exec_command('/bin/pidof %s' %procname)
            except:
                return False
            else:
                return True

        return False
