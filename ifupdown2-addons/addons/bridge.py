#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from sets import Set
from ifupdown.iface import *
from ifupdownaddons.modulebase import moduleBase
from ifupdownaddons.bridgeutils import brctl
from ifupdownaddons.iproute2 import iproute2

class bridge(moduleBase):
    """  ifupdown2 addon module to configure linux bridges """

    _modinfo = { 'mhelp' : 'bridge configuration module',
                 'attrs' : {
                   'bridge-ports' :
                        {'help' : 'bridge ports',
                         'required' : True,
                         'example' : ['bridge-ports swp1.100 swp2.100 swp3.100',
                                      'bridge-ports glob swp1-3.100',
                                      'bridge-ports regex (swp[1|2|3].100)']},
                   'bridge-stp' :
                        {'help': 'bridge-stp yes/no',
                         'example' : ['bridge-stp no'],
                         'validvals' : ['yes', 'on', 'off', 'no'],
                         'default' : 'no'},
                   'bridge-bridgeprio' :
                        {'help': 'bridge priority',
                         'example' : ['bridge-bridgeprio 32768'],
                         'default' : '32768'},
                   'bridge-ageing' :
                       {'help': 'bridge ageing',
                         'example' : ['bridge-ageing 300'],
                         'default' : '300'},
                   'bridge-fd' :
                        { 'help' : 'bridge forward delay',
                          'example' : ['bridge-fd 15'],
                          'default' : '15'},
                   'bridge-gcint' :
                        # XXX: recheck values
                        { 'help' : 'bridge garbage collection interval in secs',
                          'example' : ['bridge-gcint 4'],
                          'default' : '4'},
                   'bridge-hello' :
                        { 'help' : 'bridge set hello time',
                          'example' : ['bridge-hello 2'],
                          'default' : '2'},
                   'bridge-maxage' :
                        { 'help' : 'bridge set maxage',
                          'example' : ['bridge-maxage 20'],
                          'default' : '20'},
                   'bridge-pathcosts' :
                        { 'help' : 'bridge set port path costs',
                          'example' : ['bridge-pathcosts swp1=100 swp2=100'],
                          'default' : '100'},
                   'bridge-portprios' :
                        { 'help' : 'bridge port prios',
                          'example' : ['bridge-portprios swp1=32 swp2=32'],
                          'default' : '32'},
                   'bridge-mclmc' :
                        { 'help' : 'set multicast last member count',
                          'example' : ['bridge-mclmc 2'],
                          'default' : '2'},
                    'bridge-mcrouter' :
                        { 'help' : 'set multicast router',
                          'default' : '1',
                          'example' : ['bridge-mcrouter 1']},
                    'bridge-mcsnoop' :
                        { 'help' : 'set multicast snooping',
                          'default' : '1',
                          'example' : ['bridge-mcsnoop 1']},
                    'bridge-mcsqc' :
                        { 'help' : 'set multicast startup query count',
                          'default' : '2',
                          'example' : ['bridge-mcsqc 2']},
                    'bridge-mcqifaddr' :
                        { 'help' : 'set multicast query to use ifaddr',
                          'default' : '0',
                          'example' : ['bridge-mcqifaddr 0']},
                    'bridge-mcquerier' :
                        { 'help' : 'set multicast querier',
                          'default' : '0',
                          'example' : ['bridge-mcquerier 0']},
                    'bridge-hashel' :
                        { 'help' : 'set hash elasticity',
                          'default' : '4096',
                          'example' : ['bridge-hashel 4096']},
                    'bridge-hashmax' :
                        { 'help' : 'set hash max',
                          'default' : '4096',
                          'example' : ['bridge-hashmax 4096']},
                    'bridge-mclmi' :
                        { 'help' : 'set multicast last member interval (in secs)',
                          'default' : '1',
                          'example' : ['bridge-mclmi 1']},
                    'bridge-mcmi' :
                        { 'help' : 'set multicast membership interval (in secs)',
                          'default' : '260',
                          'example' : ['bridge-mcmi 260']},
                    'bridge-mcqpi' :
                        { 'help' : 'set multicast querier interval (in secs)',
                          'default' : '255',
                          'example' : ['bridge-mcqpi 255']},
                    'bridge-mcqi' :
                        { 'help' : 'set multicast query interval (in secs)',
                          'default' : '125',
                          'example' : ['bridge-mcqi 125']},
                    'bridge-mcqri' :
                        { 'help' : 'set multicast query response interval (in secs)',
                          'default' : '10',
                          'example' : ['bridge-mcqri 10']},
                    'bridge-mcsqi' :
                        { 'help' : 'set multicast startup query interval (in secs)',
                          'default' : '31',
                          'example' : ['bridge-mcsqi 31']},
                    'bridge-portmcrouter' :
                        { 'help' : 'set port multicast routers',
                          'default' : '1',
                          'example' : ['bridge-portmcrouter swp1=1 swp2=1']},
                    'bridge-portmcfl' :
                        { 'help' : 'port multicast fast leave',
                          'default' : '0',
                          'example' : ['bridge-portmcfl swp1=0 swp2=0']},
                    'bridge-waitport' :
                        { 'help' : 'wait for a max of time secs for the' +
                                ' specified ports to become available,' +
                                'if no ports are specified then those' +
                                ' specified on bridge-ports will be' +
                                ' used here. Specifying no ports here ' +
                                'should not be used if we are using ' +
                                'regex or \"all\" on bridge_ports,' +
                                'as it wouldnt work.',
                          'default' : '0',
                          'example' : ['bridge-waitport 4 swp1 swp2']},
                    'bridge-maxwait' :
                        { 'help' : 'forces to time seconds the maximum time ' +
                                'that the Debian bridge setup  scripts will ' +
                                'wait for the bridge ports to get to the ' +
                                'forwarding status, doesn\'t allow factional ' +
                                'part. If it is equal to 0 then no waiting' +
                                ' is done',
                          'default' : '0',
                          'example' : ['bridge-maxwait 3']}}}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self.brctlcmd = None

    def _is_bridge(self, ifaceobj):
        if ifaceobj.get_attr_value_first('bridge-ports'):
            return True
        return False

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        if not self._is_bridge(ifaceobj):
            return None
        return self.parse_port_list(ifaceobj.get_attr_value_first(
                                    'bridge-ports'), ifacenames_all)

    def get_dependent_ifacenames_running(self, ifaceobj):
        self._init_command_handlers()
        if not self.brctlcmd.bridge_exists(ifaceobj.name):
            return None
        return self.brctlcmd.get_bridge_ports(ifaceobj.name)

    def _get_bridge_port_list(self, ifaceobj):

        # port list is also available in the previously
        # parsed dependent list. Use that if available, instead
        # of parsing port expr again
        port_list = ifaceobj.lowerifaces
        if port_list:
            return port_list
        ports = ifaceobj.get_attr_value_first('bridge-ports')
        if ports:
            return self.parse_port_list(ports)
        else:
            return None

    def _process_bridge_waitport(self, ifaceobj, portlist):
        waitport_value = ifaceobj.get_attr_value_first('bridge-waitport')
        if not waitport_value: return
        try:
            waitportvals = re.split(r'[\s\t]\s*', waitport_value, 1)
            if not waitportvals: return
            try:
                waitporttime = int(waitportvals[0])
            except:
                self.log_warn('%s: invalid waitport value \'%s\''
                        %(ifaceobj.name, waitporttime))
                return
            if waitporttime <= 0: return
            try:
                waitportlist = self.parse_port_list(waitportvals[1])
            except IndexError, e:
                # ignore error and use all bridge ports
                waitportlist = portlist
                pass
            if not waitportlist: return
            self.logger.info('%s: waiting for ports %s to exist ...'
                    %(ifaceobj.name, str(waitportlist)))
            starttime = time.time()
            while ((time.time() - starttime) < waitporttime):
                if all([False for p in waitportlist
                        if not self.ipcmd.link_exists(p)]):
                    break;
                time.sleep(1)
        except Exception, e:
            self.log_warn('%s: unable to process waitport: %s'
                    %(ifaceobj.name, str(e)))

    def _add_ports(self, ifaceobj):
        bridgeports = self._get_bridge_port_list(ifaceobj)
        runningbridgeports = []

        self._process_bridge_waitport(ifaceobj, bridgeports)
        # Delete active ports not in the new port list
        if not self.PERFMODE:
            runningbridgeports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
            if runningbridgeports:
                [self.ipcmd.link_set(bport, 'nomaster')
                    for bport in runningbridgeports
                        if not bridgeports or bport not in bridgeports]
            else:
                runningbridgeports = []
        if not bridgeports:
            return
        err = 0
        for bridgeport in Set(bridgeports).difference(Set(runningbridgeports)):
            try:
                if not self.DRYRUN and not self.ipcmd.link_exists(bridgeport):
                    self.log_warn('%s: bridge port %s does not exist'
                                   %(ifaceobj.name, bridgeport))
                    err += 1
                    continue
                self.ipcmd.link_set(bridgeport, 'master', ifaceobj.name)
                self.write_file('/proc/sys/net/ipv6/conf/%s' %bridgeport +
                                '/disable_ipv6', '1')
                self.ipcmd.addr_flush(bridgeport)
            except Exception, e:
                self.log_error(str(e))
        if err:
            self.log_error('bridge configuration failed (missing ports)')

    def _process_bridge_maxwait(self, ifaceobj, portlist):
        maxwait = ifaceobj.get_attr_value_first('bridge-maxwait')
        if not maxwait: return
        try:
            maxwait = int(maxwait)
        except:
            self.log_warn('%s: invalid maxwait value \'%s\'' %(ifaceobj.name,
                    maxwait))
            return
        if not maxwait: return
        self.logger.info('%s: waiting for ports to go to fowarding state ..'
                %ifaceobj.name)
        try:
            starttime = time.time()
            while ((time.time() - starttime) < maxwait):
                if all([False for p in portlist
                    if self.read_file_oneline(
                            '/sys/class/net/%s/brif/%s/state'
                            %(ifaceobj.name, p)) != '3']):
                    break;
                time.sleep(1)
        except Exception, e:
            self.log_warn('%s: unable to process maxwait: %s'
                    %(ifaceobj.name, str(e)))

    def _apply_bridge_settings(self, ifaceobj):
        try:
            stp = ifaceobj.get_attr_value_first('bridge-stp')
            if stp:
                self.brctlcmd.set_stp(ifaceobj.name, stp)
            # Use the brctlcmd bulk set method: first build a dictionary
            # and then call set
            bridgeattrs = { k:v for k,v in
                             {'ageing' :
                                ifaceobj.get_attr_value_first('bridge-ageing'),
                              'bridgeprio' :
                                ifaceobj.get_attr_value_first(
                                                        'bridge-bridgeprio'),
                              'fd' :
                                ifaceobj.get_attr_value_first('bridge-fd'),
                              'gcint' :
                                ifaceobj.get_attr_value_first('bridge-gcint'),
                              'hello' :
                                ifaceobj.get_attr_value_first('bridge-hello'),
                              'maxage' :
                                ifaceobj.get_attr_value_first('bridge-maxage'),
                              'mclmc' :
                                ifaceobj.get_attr_value_first('bridge-mclmc'),
                              'mcrouter' :
                                ifaceobj.get_attr_value_first(
                                                            'bridge-mcrouter'),
                              'mcsnoop' :
                                ifaceobj.get_attr_value_first('bridge-mcsnoop'),
                              'mcsqc' :
                                ifaceobj.get_attr_value_first('bridge-mcsqc'),
                              'mcqifaddr' :
                                ifaceobj.get_attr_value_first(
                                                            'bridge-mcqifaddr'),
                              'mcquerier' :
                                ifaceobj.get_attr_value_first(
                                                            'bridge-mcquerier'),
                              'hashel' :
                                ifaceobj.get_attr_value_first('bridge-hashel'),
                              'hashmax' :
                                ifaceobj.get_attr_value_first('bridge-hashmax'),
                              'mclmi' :
                                ifaceobj.get_attr_value_first('bridge-mclmi'),
                              'mcmi' :
                                ifaceobj.get_attr_value_first('bridge-mcmi'),
                              'mcqpi' :
                                ifaceobj.get_attr_value_first('bridge-mcqpi'),
                              'mcqi' :
                                ifaceobj.get_attr_value_first('bridge-mcqi'),
                              'mcqri' :
                                ifaceobj.get_attr_value_first('bridge-mcqri'),
                              'mcsqi' :
                                ifaceobj.get_attr_value_first('bridge-mcsqi')
                               }.items()
                            if v }
            if bridgeattrs:
                self.brctlcmd.set_bridge_attrs(ifaceobj.name, bridgeattrs)
            portattrs = {}
            for attrname, dstattrname in {'bridge-pathcosts' : 'pathcost',
                                'bridge-portprios' : 'portprio',
                                'bridge-portmcrouter' : 'portmcrouter',
                                'bridge-portmcfl' : 'portmcfl'}.items():
                attrval = ifaceobj.get_attr_value_first(attrname)
                if not attrval:
                    continue
                portlist = self.parse_port_list(attrval)
                if not portlist:
                    self.log_warn('%s: could not parse \'%s %s\''
                         %(ifaceobj.name, attrname, attrval))
                    continue
                for p in portlist:
                    try:
                        (port, val) = p.split('=')
                        if not portattrs.get(port):
                            portattrs[port] = {}
                        portattrs[port].update({dstattrname : val})
                    except Exception, e:
                        self.log_warn('%s: could not parse %s (%s)'
                                    %(ifaceobj.name, attrname, str(e)))
            for port, attrdict in portattrs.iteritems():
                self.brctlcmd.set_bridgeport_attrs(ifaceobj.name, port,
                                                   attrdict)
            self._process_bridge_maxwait(ifaceobj,
                    self._get_bridge_port_list(ifaceobj))
        except Exception, e:
            self.log_warn(str(e))

    def _up(self, ifaceobj):
        try:
            self.ipcmd.batch_start()
            if not self.PERFMODE:
                if not self.ipcmd.link_exists(ifaceobj.name):
                    self.ipcmd.link_create(ifaceobj.name, 'bridge')
            else:
                self.ipcmd.link_create(ifaceobj.name, 'bridge')
            try:
                self._add_ports(ifaceobj)
            finally:
                self.ipcmd.batch_commit()
            self._apply_bridge_settings(ifaceobj)
        except Exception, e:
            self.log_error(str(e))

    def _down(self, ifaceobj):
        try:
            if ifaceobj.get_attr_value_first('bridge-ports'):
                ports = self.brctlcmd.get_bridge_ports(ifaceobj.name)
                if ports:
                    for p in ports:
                        proc_file = ('/proc/sys/net/ipv6/conf/%s' %p +
                                     '/disable_ipv6')
                        self.write_file(proc_file, '0')
                self.brctlcmd.delete_bridge(ifaceobj.name)
        except Exception, e:
            self.log_error(str(e))

    def _query_running_attrs(self, ifaceobjrunning):
        bridgeattrdict = {}
        userspace_stp = 0
        ports = None
        skip_kernel_stp_attrs = 0

        if self.sysctl_get('net.bridge.bridge-stp-user-space') == '1':
            userspace_stp = 1

        tmpbridgeattrdict = self.brctlcmd.get_bridge_attrs(ifaceobjrunning.name)
        if not tmpbridgeattrdict:
            self.logger.warn('%s: unable to get bridge attrs'
                    %ifaceobjrunning.name)
            return bridgeattrdict

        # Fill bridge_ports and bridge stp attributes first
        ports = tmpbridgeattrdict.get('ports')
        if ports:
            bridgeattrdict['bridge-ports'] = [' '.join(ports.keys())]
        stp = tmpbridgeattrdict.get('stp', 'no')
        if stp != self.get_mod_subattr('bridge-stp', 'default'):
            bridgeattrdict['bridge-stp'] = [stp]

        if  stp == 'yes' and userspace_stp:
            skip_kernel_stp_attrs = 1

        # pick all other attributes
        for k,v in tmpbridgeattrdict.items():
            if not v:
                continue
            if k == 'ports' or k == 'stp':
                continue

            if skip_kernel_stp_attrs and k[:2] != 'mc':
                # only include igmp attributes if kernel stp is off
                continue
            attrname = 'bridge-' + k
            if v != self.get_mod_subattr(attrname, 'default'):
                bridgeattrdict[attrname] = [v]

        if skip_kernel_stp_attrs:
            return bridgeattrdict

        if ports:
            portconfig = {'bridge-pathcosts' : '',
                          'bridge-portprios' : ''}
            for p, v in ports.items():
                v = self.brctlcmd.get_pathcost(ifaceobjrunning.name, p)
                if v and v != self.get_mod_subattr('bridge-pathcosts',
                                                   'default'):
                    portconfig['bridge-pathcosts'] += ' %s=%s' %(p, v)

                v = self.brctlcmd.get_portprio(ifaceobjrunning.name, p)
                if v and v != self.get_mod_subattr('bridge-portprios',
                                                   'default'):
                    portconfig['bridge-portprios'] += ' %s=%s' %(p, v)

            bridgeattrdict.update({k : [v] for k, v in portconfig.items()
                                    if v})
        return bridgeattrdict

    def _query_check(self, ifaceobj, ifaceobjcurr):
            if not self.brctlcmd.bridge_exists(ifaceobj.name):
                self.logger.info('%s: bridge: does not exist' %(ifaceobj.name))
                ifaceobjcurr.status = ifaceStatus.NOTFOUND
                return
            ifaceattrs = self.dict_key_subset(ifaceobj.config,
                                              self.get_mod_attrs())
            if not ifaceattrs:
                return
            try:
                runningattrs = self.brctlcmd.get_bridge_attrs(ifaceobj.name)
                if not runningattrs:
                    self.logger.debug('%s: bridge: unable to get bridge attrs'
                                     %ifaceobj.name)
                    runningattrs = {}
            except Exception, e:
                self.logger.warn(str(e))
                runningattrs = {}
            for k in ifaceattrs:
                # get the corresponding ifaceobj attr
                v = ifaceobj.get_attr_value_first(k)
                if not v:
                    continue
                rv = runningattrs.get(k[7:])
                if k == 'bridge-stp':
                    # special case stp compare because it may
                    # contain more than one valid values
                    stp_on_vals = ['on', 'yes']
                    stp_off_vals = ['off']
                    if ((v in stp_on_vals and rv in stp_on_vals) or
                        (v in stp_off_vals and rv in stp_off_vals)):
                        ifaceobjcurr.update_config_with_status('bridge-stp',
                                v, 0)
                    else:
                        ifaceobjcurr.update_config_with_status('bridge-stp',
                                v, 1)
                elif k == 'bridge-ports':
                    # special case ports because it can contain regex or glob
                    running_port_list = rv.keys() if rv else []
                    bridge_port_list = self._get_bridge_port_list(ifaceobj)
                    if not running_port_list and not bridge_port_list:
                       continue
                    portliststatus = 1
                    if running_port_list and bridge_port_list:
                       difference = set(running_port_list
                                        ).symmetric_difference(bridge_port_list)
                       if not difference:
                           portliststatus = 0
                    ifaceobjcurr.update_config_with_status('bridge-ports',
                                ' '.join(running_port_list)
                                if running_port_list else '', portliststatus)
                elif (k == 'bridge-pathcosts' or
                      k == 'bridge-portprios' or k == 'bridge-portmcrouter'
                      or k == 'bridge-portmcfl'):
                    brctlcmdattrname = k[11:].rstrip('s')
                    # for port attributes, the attributes are in a list
                    # <portname>=<portattrvalue>
                    status = 0
                    currstr = ''
                    vlist = self.parse_port_list(v)
                    if not vlist:
                        continue
                    for vlistitem in vlist:
                        try:
                            (p, v) = vlistitem.split('=')
                            currv = self.brctlcmd.get_bridgeport_attr(
                                                        ifaceobj.name, p,
                                                        brctlcmdattrname)
                            if currv:
                                currstr += ' %s=%s' %(p, currv)
                            else:
                                currstr += ' %s=%s' %(p, 'None')
                            if currv != v:
                                status = 1
                        except Exception, e:
                            self.log_warn(str(e))
                            pass
                    ifaceobjcurr.update_config_with_status(k, currstr, status)
                elif not rv:
                  ifaceobjcurr.update_config_with_status(k, 'notfound', 1)
                  continue
                elif v != rv:
                  ifaceobjcurr.update_config_with_status(k, rv, 1)
                else:
                  ifaceobjcurr.update_config_with_status(k, rv, 0)
       
    def _query_running(self, ifaceobjrunning):
        if not self.brctlcmd.bridge_exists(ifaceobjrunning.name):
            return
        ifaceobjrunning.update_config_dict(self._query_running_attrs(
                                           ifaceobjrunning))

    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        flags = self.get_flags()
        if not self.ipcmd:
            self.ipcmd = iproute2(**flags)
        if not self.brctlcmd:
            self.brctlcmd = brctl(**flags)

    def run(self, ifaceobj, operation, query_ifaceobj=None):
        """ run bridge configuration on the interface object passed as
            argument. Can create bridge interfaces if they dont exist already

        Args:
            **ifaceobj** (object): iface object

            **operation** (str): any of 'pre-up', 'post-down', 'query-checkcurr',
                                 'query-running'

        Kwargs:
            **query_ifaceobj** (object): query check ifaceobject. This is only
                valid when op is 'query-checkcurr'. It is an object same as
                ifaceobj, but contains running attribute values and its config
                status. The modules can use it to return queried running state
                of interfaces. status is success if the running state is same
                as user required state in ifaceobj. error otherwise.
        """
        op_handler = self._run_ops.get(operation)
        if not op_handler:
           return
        if (operation != 'query-running' and
                not self._is_bridge(ifaceobj)):
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
