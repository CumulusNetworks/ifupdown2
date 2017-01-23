#!/usr/bin/python
#
# Copyright 2015 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
from utilsbase import *
from ifupdown.utils import utils

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
                utils.exec_command('/bin/pidof %s' % procname)
            except:
                return False
            else:
                return True

        return False

    @classmethod
    def check_service_status(cls, servicename=None):
        if not servicename:
            return False
        try:
            utils.exec_commandl(['/usr/sbin/service', servicename, 'status'])
        except Exception:
            # XXX: check for subprocess errors vs os error
            return False
        return True

    @classmethod
    def is_process_running(self, processname):
        if not processname:
            return False
        try:
            utils.exec_command('/bin/pidof %s' % processname)
        except:
            return False
        else:
            return True
