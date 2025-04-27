#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Authors:
#           Roopa Prabhu, roopa@cumulusnetworks.com
#           Julien Fortin, julien@cumulusnetworks.com
#

import sys
from functools import reduce
import argparse

try:
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.exceptions import ArgvParseError, ArgvParseHelp
except (ImportError, ModuleNotFoundError):
    from ifupdown.utils import utils
    from ifupdown.exceptions import ArgvParseError, ArgvParseHelp


class VersionAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):

        try:
            dpkg = utils.exec_commandl([utils.dpkg_cmd, '-l', 'ifupdown2'])

            if not dpkg:
                raise Exception('dpkg -l ifupdown2 returns without output')

            dpkg = dpkg.split('\n')

            if not dpkg:
                raise Exception('dpkg -l ifupdown2 returns without output')

            for line in dpkg:
                if 'ifupdown2' in line:
                    info = line.split()

                    sys.stdout.write('ifupdown2:%s\n' % (info[2]))
                    sys.exit(0)

            raise Exception('ifupdown2 package not found using dpkg -l')

        except Exception as e:
            sys.stderr.write('error: cannot get current version using dpkg: %s\n' % str(e))
            sys.exit(1)


class Parse:
    valid_ops = {
        'ifup': 'up',
        'ifdown': 'down',
        'ifreload': 'reload',
        'ifquery': 'query'
    }

    def __init__(self, argv):
        self.executable_name = argv[0]
        self.op = self.get_op()
        self.argv = argv[1:]

        if self.op == 'query':
            descr = 'query interfaces (all or interface list)'
        elif self.op == 'reload':
            descr = 'reload interface configuration.'
        else:
            descr = 'interface management'
        argparser = argparse.ArgumentParser(description=descr)
        if self.op == 'reload':
            self.update_ifreload_argparser(argparser)
        else:
            self.update_argparser(argparser)
            if self.op == 'up':
                self.update_ifup_argparser(argparser)
            elif self.op == 'down':
                self.update_ifdown_argparser(argparser)
            elif self.op == 'query':
                self.update_ifquery_argparser(argparser)
        self.update_common_argparser(argparser)

        try:
            self.args = argparser.parse_args(self.argv)
        except SystemExit as e:
            # on "--help" parse_args will raise SystemExit.
            # We need to catch this behavior and raise a custom
            # exception to return 0 properly
            #raise ArgvParseHelp()
            for help_str in ('-h', '--help'):
                if help_str in argv:
                    raise ArgvParseHelp()
            raise

    def validate(self):
        # Implicit -a/--all for all query operations
        if self.op == 'query' and not self.args.iflist:
            self.args.all = True

        # Implicit -a/--all for reload currentlyup option
        if self.op == 'reload':
            if self.args.iflist:
                raise ArgvParseError("Unsupported IFLIST for reload operation")
            elif not self.args.all and not self.args.currentlyup:
                raise ArgvParseError("-a/--all or -c/--currently-up option is required")
            # Early return to prevent interfaces_selection_post_validate to add [auto] in --allow
            if self.args.currentlyup:
                self.args.all = True
                return True

        self.argparser_interfaces_selection_post_validate()

        return True

    def get_op(self):
        try:
            for key, value in self.valid_ops.items():
                if self.executable_name.endswith(key):
                    return value
            raise ArgvParseError("Unexpected executable. Should be '%s'" % "' or '".join(list(self.valid_ops.keys())))
        except Exception:
            raise ArgvParseError("Unexpected executable. Should be '%s'" % "' or '".join(list(self.valid_ops.keys())))

    def get_args(self):
        return self.args

    def argparser_interfaces_selection(self, argparser):
        """
        Manage interfaces selection like ifupdown1 does
        * -a/--all and iflist options target a list of interfaces
        * --allow filter this interfaces list with the specified scope
        * --allow default value is [auto] when -a/--all option is used
        Some commands have an implicit -a/--all (ifquery, ifreload)
        """

        class ExpandItfListAction(argparse.Action):
            def __call__(self, _parser, namespace, values, option_string=None):
                expanded = (utils.expand_iface_range(itf) or [itf] for itf in values)
                flattened = reduce(lambda xs, x: xs + x, expanded, [])
                uniq_itfs = reduce(lambda xs, x: xs if x in xs else xs + [x], flattened, [])
                setattr(namespace, self.dest, uniq_itfs)

        argparser.add_argument('iflist', metavar='IFACE', nargs='*', action=ExpandItfListAction,
                help='interface list separated by spaces. ')
        argparser.add_argument('-a', '--all', action='store_true',
                help='process all interfaces (limited by  --allow= filter)')
        allow_group = argparser.add_mutually_exclusive_group(required=False)
        allow_group.add_argument('--allow', dest='CLASS', action='append',
                help='ignore non-"allow-CLASS" interfaces (default is [auto] when -a/--all else [])')
        # For ifupdown compatibility, '--all' implies '--allow auto'. '--allow-all' parameter offers
        # a way to have all interfaces without implicit filter.
        allow_group.add_argument('--allow-all', action='store_true',
                help='ensure non-"allow-CLASS" is set to []')

    def argparser_interfaces_selection_post_validate(self):
        """ Set and validate interfaces selection options """

        if self.args.allow_all:
            self.args.CLASS = []
        elif self.args.all and not self.args.CLASS:
            # Default filter scope is auto/allow-auto when -a/--all option is set
            self.args.CLASS = ['auto']

        if self.args.iflist and self.args.all:
            raise ArgvParseError("IFACE list is mutually exclusive with -a/--all option")
        elif not self.args.iflist and not self.args.all:
            raise ArgvParseError("no interface(s) specified. IFACE list or -a/--all option is required")

    def update_argparser(self, argparser):
        """ base parser, common to all commands """
        self.argparser_interfaces_selection(argparser)

        argparser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose')
        argparser.add_argument('-d', '--debug', dest='debug', action='store_true', help='output debug info')
        argparser.add_argument('-q', '--quiet', dest='quiet', action='store_true', help=argparse.SUPPRESS)
        argparser.add_argument('-w', '--with-depends', dest='withdepends', action='store_true',
                               help="run with all dependent interfaces. "
                                    "This option is redundant when '-a' is specified. "
                                    "With '-a' interfaces are always executed in dependency order")
        argparser.add_argument('--perfmode', dest='perfmode', action='store_true', help=argparse.SUPPRESS)
        argparser.add_argument('--nocache', dest='nocache', action='store_true', help=argparse.SUPPRESS)
        argparser.add_argument('-X', '--exclude', dest='excludepats', action='append',
                               help='Exclude interfaces from the list of interfaces to operate on. '
                                    'Can be specified multiple times.')
        argparser.add_argument('-i', '--interfaces', dest='interfacesfile', default=None,
                               help='Specify interfaces file instead of file defined in ifupdown2.conf file')
        argparser.add_argument('-t', '--interfaces-format', dest='interfacesfileformat', default='native',
                               choices=['native', 'json'], help='interfaces file format')
        argparser.add_argument('-T', '--type', dest='type', default=None, choices=['iface', 'vlan'],
                               help='type of interface entry (iface or vlan). '
                                    'This option can be used in case of ambiguity between '
                                    'a vlan interface and an iface interface of the same name')

    def update_ifupdown_argparser(self, argparser):
        """ common arg parser for ifup and ifdown """
        argparser.add_argument('-f', '--force', dest='force', action='store_true', help='force run all operations')
        argparser.add_argument('-l', '--syslog', dest='syslog', action='store_true')
        argparser.add_argument('--systemd', dest='systemd', action='store_true', help="enable journalctl logging")
        group = argparser.add_mutually_exclusive_group(required=False)
        group.add_argument('-n', '--no-act', dest='noact', action='store_true',
                           help="print out what would happen, but don't do it")
        group.add_argument('-p', '--print-dependency', dest='printdependency',
                           choices=['list', 'dot'], help='print iface dependency')
        group.add_argument('--no-scripts', '--admin-state', dest='noaddons', action='store_true',
                           help='dont run any addon modules/scripts. Only bring the interface administratively up/down')

    def update_ifup_argparser(self, argparser):
        argparser.add_argument('-s', '--syntax-check', dest='syntaxcheck',
                               action='store_true', help='Only run the interfaces file parser')
        argparser.add_argument('-k', '--skip-upperifaces', dest='skipupperifaces', action='store_true',
                               help='ifup by default tries to add newly created interfaces into its upper/parent '
                                    'interfaces. Eg. if a bridge port is created as a result of ifup on the port, '
                                    'ifup automatically adds the port to the bridge. This option can be used to '
                                    'disable this default behaviour')
        self.update_ifupdown_argparser(argparser)

    def update_ifdown_argparser(self, argparser):
        self.update_ifupdown_argparser(argparser)
        argparser.add_argument('-u', '--use-current-config',
                               dest='usecurrentconfig', action='store_true',
                               help='By default ifdown looks at the saved state for interfaces to bring down. '
                                    'This option allows ifdown to look at the current interfaces file. '
                                    'Useful when your state file is corrupted or you want down to use '
                                    'the latest from the interfaces file')

    def update_ifquery_argparser(self, argparser):
        """ arg parser for ifquery options """

        # -l is same as '-a', only here for backward compatibility
        argparser.add_argument('-l', '--list', action='store_true', dest='list',
                               help='list all matching known interfaces')
        group = argparser.add_mutually_exclusive_group(required=False)
        group.add_argument('-r', '--running', dest='running', action='store_true',
                           help='query running state of an interface')
        group.add_argument('-c', '--check', dest='checkcurr', action='store_true',
                           help='check interface file contents against running state of an interface')
        group.add_argument('-x', '--raw', action='store_true', dest='raw', help='print raw config file entries')
        group.add_argument('--print-savedstate', action='store_true', dest='printsavedstate', help=argparse.SUPPRESS)
        argparser.add_argument('-o', '--format', dest='format', default='native',
                               choices=['native', 'json'], help='interface display format')
        argparser.add_argument('-p', '--print-dependency', dest='printdependency',
                               choices=['list', 'dot'], help='print interface dependency')
        argparser.add_argument('-s', '--syntax-help', action='store_true', dest='syntaxhelp',
                               help='print supported interface config syntax')
        argparser.add_argument('--with-defaults', action='store_true', dest='withdefaults',
                               help='check policy default file contents, for unconfigured attributes, '
                                    'against running state of an interface')

    def update_ifreload_argparser(self, argparser):
        """ parser for ifreload """
        self.argparser_interfaces_selection(argparser)

        argparser.add_argument('-c', '--currently-up', dest='currentlyup', action='store_true',
                           help='Reload the configuration for all interfaces which are '
                                'currently up regardless of whether an interface has '
                                '"auto <interface>" configuration within the /etc/network/interfaces file.')
        argparser.add_argument('-n', '--no-act', dest='noact', action='store_true',
                               help='print out what would happen, but don\'t do it')
        argparser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose')
        argparser.add_argument('-d', '--debug', dest='debug', action='store_true', help='output debug info')
        argparser.add_argument('-w', '--with-depends', dest='withdepends', action='store_true', help=argparse.SUPPRESS)
        argparser.add_argument('--perfmode', dest='perfmode', action='store_true', help=argparse.SUPPRESS)
        argparser.add_argument('--nocache', dest='nocache', action='store_true', help=argparse.SUPPRESS)
        argparser.add_argument('-X', '--exclude', dest='excludepats', action='append', help=argparse.SUPPRESS)
        # argparser.add_argument('-j', '--jobs', dest='jobs', type=int,
        #            default=-1, choices=range(1,12), help=argparse.SUPPRESS)
        # argparser.add_argument('-i', '--interfaces', dest='interfacesfile',
        #            default='/etc/network/interfaces',
        #            help='use interfaces file instead of default ' +
        #            '/etc/network/interfaces')
        argparser.add_argument('-u', '--use-current-config', dest='usecurrentconfig', action='store_true',
                               help='By default ifreload looks at saved state for interfaces to bring down. '
                                    'With this option ifreload will only look at the current interfaces file. '
                                    'Useful when your state file is corrupted or you want down to use the latest '
                                    'from the interfaces file')
        argparser.add_argument('-l', '--syslog', dest='syslog', action='store_true')
        argparser.add_argument('--systemd', dest='systemd', action='store_true', help="enable journalctl logging")
        argparser.add_argument('-f', '--force', dest='force', action='store_true', help='force run all operations')
        argparser.add_argument('-s', '--syntax-check', dest='syntaxcheck', action='store_true',
                               help='Only run the interfaces file parser')

    def update_common_argparser(self, argparser):
        ''' general parsing rules '''

        argparser.add_argument('-V', '--version', action=VersionAction, nargs=0)
        argparser.add_argument(
            '-L', '--lock', default='/run/network/.lock', dest='lockfile',
            help='use lock file instead of default /run/network/.lock'
        )
        argparser.add_argument(
            "--nldebug",
            dest="nldebug",
            action="store_true",
            default=False,
            help="print netlink debug messages"
        )
