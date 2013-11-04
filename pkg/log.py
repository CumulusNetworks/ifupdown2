#!/usr/bin/python

import logging


class log:

    @staticmethod
    def log_error(obj, prefix, *args, **kwargs):
        obj.get_logger().logger.log_error(''.join(args))

    @staticmethod
    def log_warn(obj, *args, **kwargs):
        msg = ''
        logger = obj.get_logger()
        errmsg = obj.get_errmsg()
        msg += ''.join(args)
        if errmsg is not None and len(errmsg) > 0:
            msg += '(%s)' %errmsg


    @staticmethod
    def log(obj, log_prefix, *args, **kwargs):
        msg = ''
        logger = obj.get_logger()
        msg += ''.join(args)


