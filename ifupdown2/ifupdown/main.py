#!/usr/bin/env python3
#
# Copyright 2014-2019 Cumulus Networks, Inc. All rights reserved.
# Authors:
#           Roopa Prabhu, roopa@cumulusnetworks.com
#           Julien Fortin, julien@cumulusnetworks.com
# ifupdown2 --
#    tool to configure network interfaces
#

import os
import sys
import logging
import io
import configparser

try:
    from ifupdown2.ifupdown.argv import Parse
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.config import IFUPDOWN2_CONF_PATH
    from ifupdown2.ifupdown.ifupdownmain import ifupdownMain

    from ifupdown2.lib.dry_run import DryRunManager
    from ifupdown2.lib.status import Status

except ImportError:
    from ifupdown.argv import Parse
    from ifupdown.utils import utils
    from ifupdown.config import IFUPDOWN2_CONF_PATH
    from ifupdown.ifupdownmain import ifupdownMain
    from lib.status import Status

    from lib.dry_run import DryRunManager

log = logging.getLogger()
configmap_g = None


class MainException(Exception):
    pass


class Ifupdown2:
    def __init__(self, daemon, uid):
        self.daemon = daemon
        self.uid = uid
        self.args = None
        self.op = None

        self.interfaces_filename = None
        self.interfaces_file_iobuf = None

        self.handlers = {
            'up': self.run_up,
            'down': self.run_down,
            'query': self.run_query,
            'reload': self.run_reload
        }

    def parse_argv(self, argv):
        args_parse = Parse(argv)
        args_parse.validate()

        self.args = args_parse.get_args()
        self.op = args_parse.get_op()

    def main(self, stdin_buffer=None):
        if self.op != 'query' and self.uid != 0:
            raise MainException('must be root to run this command')

        try:
            self.read_config()
            self.init(stdin_buffer)

            try:
                if self.op != 'query' and not utils.lockFile(self.args.lockfile):
                    log.error("Another instance of this program is already running.")
                    return Status.Client.STATUS_ALREADY_RUNNING
            except FileExistsError as e:
                log.info("%s: lockfile error: %s" % (self.args.lockfile, str(e)))

            self.handlers.get(self.op)(self.args)
        except Exception as e:
            if not str(e):
                return 1
                # if args and args.debug:
                # raise
            # else:
            if log:
                log.error('main exception: ' + str(e))
                # import traceback
                # traceback.print_exc()
            else:
                print(str(e))
                # if args and not args.debug:
                #    print '\nrerun the command with \'-d\' for a detailed errormsg'
            return 1
        return 0

    def init(self, stdin_buffer):
        ##############
        # dry run mode
        ##############
        dry_run_mode_on = DryRunManager.get_instance().is_dry_mode_on()

        if hasattr(self.args, 'noact'):
            if self.args.noact and not dry_run_mode_on:
                DryRunManager.get_instance().dry_run_mode_on()
            elif not self.args.noact and dry_run_mode_on:
                DryRunManager.get_instance().dry_run_mode_off()
        elif dry_run_mode_on:
            # if noact is not in self.args we are probably in
            # ifquery mode so we need to turn off dry run mode.
            DryRunManager.get_instance().dry_run_mode_off()

        ###

        if hasattr(self.args, 'interfacesfile') and self.args.interfacesfile != None:
            # Check to see if -i option is allowed by config file
            # But for ifquery, we will not check this
            if (self.op != 'query' and
                    configmap_g.get('disable_cli_interfacesfile', '0') == '1'):
                log.error('disable_cli_interfacesfile is set so users '
                          'not allowed to specify interfaces file on cli.')
                raise MainException("")
            if self.args.interfacesfile == '-':
                # If interfaces file is stdin, read
                if self.daemon:
                    self.interfaces_file_iobuf = stdin_buffer
                else:
                    self.interfaces_file_iobuf = sys.stdin.read()
            else:
                self.interfaces_filename = self.args.interfacesfile
        else:
            # if the ifupdown2 config file does not have it, default to standard
            self.interfaces_filename = configmap_g.get('default_interfaces_configfile',
                                                       '/etc/network/interfaces')

    def read_config(self):
        global configmap_g

        with open(IFUPDOWN2_CONF_PATH, 'r') as f:
            config = f.read()
        configStr = '[ifupdown2]\n' + config
        configFP = io.StringIO(configStr)
        parser = configparser.RawConfigParser()
        parser.read_file(configFP)
        configmap_g = dict(parser.items('ifupdown2'))

        # Preprocess config map
        configval = configmap_g.get('multiple_vlan_aware_bridge_support', '0')
        if configval == '0':
            # if multiple bridges not allowed, set the bridge-vlan-aware
            # attribute in the 'no_repeats' config, so that the ifupdownmain
            # module can catch it appropriately
            configmap_g['no_repeats'] = {'bridge-vlan-aware': 'yes'}

        configval = configmap_g.get('link_master_slave', '0')
        if configval == '1':
            # link_master_slave is only valid when all is set
            if hasattr(self.args, 'all') and not self.args.all:
                configmap_g['link_master_slave'] = '0'

        configval = configmap_g.get('delay_admin_state_change', '0')
        if configval == '1':
            # reset link_master_slave if delay_admin_state_change is on
            configmap_g['link_master_slave'] = '0'

    def run_up(self, args):
        log.debug('args = %s' % str(args))

        iflist = args.iflist
        if len(args.iflist) == 0:
            iflist = None
        log.debug('creating ifupdown object ..')
        cachearg = (False if (iflist or args.nocache or args.noact)
                    else True)
        ifupdown_handle = ifupdownMain(daemon=self.daemon, args=args,
                                       config=configmap_g,
                                       force=args.force,
                                       withdepends=args.withdepends,
                                       perfmode=args.perfmode,
                                       dryrun=args.noact,
                                       cache=cachearg,
                                       addons_enable=not args.noaddons,
                                       statemanager_enable=not args.noaddons,
                                       interfacesfile=self.interfaces_filename,
                                       interfacesfileiobuf=self.interfaces_file_iobuf,
                                       interfacesfileformat=args.interfacesfileformat)
        if args.noaddons:
            ifupdown_handle.up(['up'], args.all, args.CLASS, iflist,
                               excludepats=args.excludepats,
                               printdependency=args.printdependency,
                               syntaxcheck=args.syntaxcheck, type=args.type,
                               skipupperifaces=args.skipupperifaces)
        else:
            ifupdown_handle.up(['pre-up', 'up', 'post-up'],
                               args.all, args.CLASS, iflist,
                               excludepats=args.excludepats,
                               printdependency=args.printdependency,
                               syntaxcheck=args.syntaxcheck, type=args.type,
                               skipupperifaces=args.skipupperifaces)

    def run_down(self, args):
        log.debug('args = %s' % str(args))

        iflist = args.iflist
        log.debug('creating ifupdown object ..')
        ifupdown_handle = ifupdownMain(daemon=self.daemon, args=args,
                                       config=configmap_g, force=args.force,
                                       withdepends=args.withdepends,
                                       perfmode=args.perfmode,
                                       dryrun=args.noact,
                                       addons_enable=not args.noaddons,
                                       statemanager_enable=not args.noaddons,
                                       interfacesfile=self.interfaces_filename,
                                       interfacesfileiobuf=self.interfaces_file_iobuf,
                                       interfacesfileformat=args.interfacesfileformat)

        ifupdown_handle.down(['pre-down', 'down', 'post-down'],
                             args.all, args.CLASS, iflist,
                             excludepats=args.excludepats,
                             printdependency=args.printdependency,
                             usecurrentconfig=args.usecurrentconfig,
                             type=args.type)

    def run_query(self, args):
        log.debug('args = %s' % str(args))

        iflist = args.iflist
        if args.checkcurr:
            qop = 'query-checkcurr'
        elif args.running:
            qop = 'query-running'
        elif args.raw:
            qop = 'query-raw'
        elif args.syntaxhelp:
            qop = 'query-syntax'
        elif args.printdependency:
            qop = 'query-dependency'
        elif args.printsavedstate:
            qop = 'query-savedstate'
        else:
            qop = 'query'
        cachearg = (False if (iflist or args.nocache or args.syntaxhelp or
                              (qop != 'query-checkcurr' and
                               qop != 'query-running')) else True)
        if not iflist and qop == 'query-running':
            iflist = [i for i in os.listdir('/sys/class/net/')
                      if os.path.isdir('/sys/class/net/%s' % i)]
        log.debug('creating ifupdown object ..')
        ifupdown_handle = ifupdownMain(daemon=self.daemon, args=args,
                                       config=configmap_g,
                                       withdepends=args.withdepends,
                                       perfmode=args.perfmode,
                                       cache=cachearg,
                                       interfacesfile=self.interfaces_filename,
                                       interfacesfileiobuf=self.interfaces_file_iobuf,
                                       interfacesfileformat=args.interfacesfileformat,
                                       withdefaults=args.withdefaults)
        # list implies all auto interfaces (this is how ifupdown behaves)
        if args.list:
            args.all = True
        ifupdown_handle.query([qop], args.all, args.list, args.CLASS, iflist,
                              excludepats=args.excludepats,
                              printdependency=args.printdependency,
                              format=args.format, type=args.type)

    def run_reload(self, args):
        log.debug('args = %s' % str(args))

        log.debug('creating ifupdown object ..')
        ifupdown_handle = ifupdownMain(daemon=self.daemon, args=args,
                                       config=configmap_g,
                                       interfacesfile=self.interfaces_filename,
                                       withdepends=args.withdepends,
                                       perfmode=args.perfmode,
                                       dryrun=args.noact)
        ifupdown_handle.reload(['pre-up', 'up', 'post-up'],
                               ['pre-down', 'down', 'post-down'],
                               auto=args.all, allow=args.CLASS, ifacenames=None,
                               excludepats=args.excludepats,
                               usecurrentconfig=args.usecurrentconfig,
                               syntaxcheck=args.syntaxcheck,
                               currentlyup=args.currentlyup,
                               diff=args.diff)
