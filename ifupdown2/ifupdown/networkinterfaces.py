#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# networkInterfaces --
#    ifupdown network interfaces file parser
#

import collections
import logging
import glob
import re
import os
from iface import *
from template import templateEngine

whitespaces = '\n\t\r '

class networkInterfaces():
    """ debian ifupdown /etc/network/interfaces file parser """

    hotplugs = {}
    auto_ifaces = []
    callbacks = {}

    _addrfams = {'inet' : ['static', 'manual', 'loopback', 'dhcp', 'dhcp6'],
                 'inet6' : ['static', 'manual', 'loopback', 'dhcp', 'dhcp6']}

    def __init__(self, interfacesfile='/etc/network/interfaces',
                 interfacesfileiobuf=None, interfacesfileformat='native',
                 template_engine=None, template_lookuppath=None):
        """This member function initializes the networkinterfaces parser object.

        Kwargs:
            **interfacesfile** (str):  path to the interfaces file (default is /etc/network/interfaces)

            **interfacesfileiobuf** (object): interfaces file io stream

            **interfacesfileformat** (str): format of interfaces file (choices are 'native' and 'json'. 'native' being the default)

            **template_engine** (str): template engine name

            **template_lookuppath** (str): template lookup path

        Raises:
            AttributeError, KeyError """

        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)
        self.callbacks = {'iface_found' : None,
                          'validateifaceattr' : None,
                          'validateifaceobj' : None}
        self.allow_classes = {}
        self.interfacesfile = interfacesfile
        self.interfacesfileiobuf = interfacesfileiobuf
        self.interfacesfileformat = interfacesfileformat
        self._filestack = [self.interfacesfile]
        self._template_engine = templateEngine(template_engine,
                                    template_lookuppath)
        self._currentfile_has_template = False
        self._ws_split_regex = re.compile(r'[\s\t]\s*')

    @property
    def _currentfile(self):
        try:
            return self._filestack[-1]
        except:
            return self.interfacesfile

    def _parse_error(self, filename, lineno, msg):
        if lineno == -1 or self._currentfile_has_template:
            self.logger.error('%s: %s' %(filename, msg))
        else:
            self.logger.error('%s: line%d: %s' %(filename, lineno, msg))

    def _validate_addr_family(self, ifaceobj, lineno=-1):
        if ifaceobj.addr_family:
            if not self._addrfams.get(ifaceobj.addr_family):
                self._parse_error(self._currentfile, lineno,
                    'iface %s: unsupported address family \'%s\''
                    %(ifaceobj.name, ifaceobj.addr_family))
                ifaceobj.addr_family = None
                ifaceobj.addr_method = None
                return
            if ifaceobj.addr_method:
                if (ifaceobj.addr_method not in
                        self._addrfams.get(ifaceobj.addr_family)):
                    self._parse_error(self._currentfile, lineno,
                        'iface %s: unsupported address method \'%s\''
                        %(ifaceobj.name, ifaceobj.addr_method))
            else:
                ifaceobj.addr_method = 'static'

    def subscribe(self, callback_name, callback_func):
        """This member function registers callback functions.

        Args:
            **callback_name** (str): callback function name (supported names: 'iface_found', 'validateifaceattr', 'validateifaceobj')

            **callback_func** (function pointer): callback function pointer

        Warns on error
        """

        if callback_name not in self.callbacks.keys():
            print 'warning: invalid callback ' + callback_name
            return -1

        self.callbacks[callback_name] = callback_func

    def ignore_line(self, line):
        l = line.strip(whitespaces)
        if not l or l[0] == '#':
            return 1
        return 0

    def process_allow(self, lines, cur_idx, lineno):
        allow_line = lines[cur_idx]

        words = re.split(self._ws_split_regex, allow_line)
        if len(words) <= 1:
            raise Exception('invalid allow line \'%s\' at line %d'
                            %(allow_line, lineno))

        allow_class = words[0].split('-')[1]
        ifacenames = words[1:]

        if self.allow_classes.get(allow_class):
            for i in ifacenames:
                self.allow_classes[allow_class].append(i)
        else:
                self.allow_classes[allow_class] = ifacenames
        return 0

    def process_source(self, lines, cur_idx, lineno):
        # Support regex
        self.logger.debug('processing sourced line ..\'%s\'' %lines[cur_idx])
        sourced_file = re.split(self._ws_split_regex, lines[cur_idx], 2)[1]
        if sourced_file:
            for f in glob.glob(sourced_file):
                self.read_file(f)
        else:
            self._parse_error(self._currentfile, lineno,
                    'unable to read source line')
        return 0

    def process_auto(self, lines, cur_idx, lineno):
        auto_ifaces = re.split(self._ws_split_regex, lines[cur_idx])[1:]
        if not auto_ifaces:
            self._parse_error(self._currentfile, lineno,
                    'invalid auto line \'%s\''%lines[cur_idx])
            return 0
        [self.auto_ifaces.append(a) for a in auto_ifaces]
        return 0

    def _add_to_iface_config(self, ifacename, iface_config, attrname,
                             attrval, lineno):
        newattrname = attrname.replace("_", "-")
        try:
            if not self.callbacks.get('validateifaceattr')(newattrname, attrval):
                self._parse_error(self._currentfile, lineno,
                        'iface %s: unsupported keyword (%s)'
                        %(ifacename, attrname))
                return
        except:
            pass
        attrvallist = iface_config.get(newattrname, [])
        if newattrname in ['scope', 'netmask', 'broadcast', 'preferred-lifetime']:
            # For attributes that are related and that can have multiple
            # entries, store them at the same index as their parent attribute.
            # The example of such attributes is 'address' and its related
            # attributes. since the related attributes can be optional, 
            # we add null string '' in places where they are optional.
            # XXX: this introduces awareness of attribute names in
            # this class which is a violation.

            # get the index corresponding to the 'address'
            addrlist = iface_config.get('address')
            if addrlist:
                # find the index of last address element
                for i in range(0, len(addrlist) - len(attrvallist) -1):
                    attrvallist.append('')
                attrvallist.append(attrval)
                iface_config[newattrname] = attrvallist
        elif not attrvallist:
            iface_config[newattrname] = [attrval]
        else:
            iface_config[newattrname].append(attrval)

    def process_iface(self, lines, cur_idx, lineno):
        lines_consumed = 0
        line_idx = cur_idx

        ifaceobj = iface()
        iface_line = lines[cur_idx].strip(whitespaces)
        iface_attrs = re.split(self._ws_split_regex, iface_line)
        ifacename = iface_attrs[1]

        ifaceobj.raw_config.append(iface_line)
    
        iface_config = collections.OrderedDict()
        for line_idx in range(cur_idx + 1, len(lines)):
            l = lines[line_idx].strip(whitespaces)
            if self.ignore_line(l) == 1:
                continue
            attrs = re.split(self._ws_split_regex, l, 1)
            if self._is_keyword(attrs[0]):
                line_idx -= 1
                break
            # if not a keyword, every line must have at least a key and value
            if len(attrs) < 2:
                self._parse_error(self._currentfile, line_idx,
                        'iface %s: invalid syntax \'%s\'' %(ifacename, l))
                continue
            ifaceobj.raw_config.append(l)
            attrname = attrs[0]
            # preprocess vars (XXX: only preprocesses $IFACE for now)
            attrval = re.sub(r'\$IFACE', ifacename, attrs[1])
            self._add_to_iface_config(ifacename, iface_config, attrname,
                                      attrval, line_idx+1)
        lines_consumed = line_idx - cur_idx

        # Create iface object
        if ifacename.find(':') != -1:
            ifaceobj.name = ifacename.split(':')[0]
        else:
            ifaceobj.name = ifacename

        ifaceobj.config = iface_config
        ifaceobj.generate_env()

        try:
            ifaceobj.addr_family = iface_attrs[2]
            ifaceobj.addr_method = iface_attrs[3]
        except IndexError:
            # ignore
            pass
        self._validate_addr_family(ifaceobj, lineno)

        if ifaceobj.name in self.auto_ifaces:
            ifaceobj.auto = True

        classes = self.get_allow_classes_for_iface(ifaceobj.name)
        if classes:
            [ifaceobj.set_class(c) for c in classes]

        # Call iface found callback
        self.callbacks.get('iface_found')(ifaceobj)
        return lines_consumed       # Return next index


    network_elems = { 'source'      : process_source,
                      'allow'      : process_allow,
                      'auto'        : process_auto,
                      'iface'       : process_iface}

    def _is_keyword(self, str):
        # The additional split here is for allow- keyword
        tmp_str = str.split('-')[0]
        if tmp_str in self.network_elems.keys():
            return 1
        return 0

    def _get_keyword_func(self, str):
        tmp_str = str.split('-')[0]
        return self.network_elems.get(tmp_str)

    def get_allow_classes_for_iface(self, ifacename):
        classes = []
        for class_name, ifacenames in self.allow_classes.items():
            if ifacename in ifacenames:
                classes.append(class_name)
        return classes

    def process_interfaces(self, filedata):
        line_idx = 0
        lines_consumed = 0
        raw_config = filedata.split('\n')
        lines = [l.strip(whitespaces) for l in raw_config]
        while (line_idx < len(lines)):
            if self.ignore_line(lines[line_idx]):
                line_idx += 1
                continue
            words = re.split(self._ws_split_regex, lines[line_idx])
            if not words:
                line_idx += 1
                continue
            # Check if first element is a supported keyword
            if self._is_keyword(words[0]):
                keyword_func = self._get_keyword_func(words[0])
                lines_consumed = keyword_func(self, lines, line_idx, line_idx+1)
                line_idx += lines_consumed
            else:
                self._parse_error(self._currentfile, line_idx + 1,
                        'error processing line \'%s\'' %lines[line_idx])
            line_idx += 1
        return 0

    def read_filedata(self, filedata):
        self._currentfile_has_template = False
        # process line continuations
        filedata = ' '.join(d.strip() for d in filedata.split('\\'))
        # run through template engine
        try:
            rendered_filedata = self._template_engine.render(filedata)
            if rendered_filedata is filedata:
                self._currentfile_has_template = True
            else:
                self._currentfile_has_template = False
        except Exception, e:
            self._parse_error(self._currentfile, -1,
                    'failed to render template (%s). ' %str(e) +
                    'Continue without template rendering ...')
            rendered_filedata = None
            pass
        if rendered_filedata:
            self.process_interfaces(rendered_filedata)
        else:
            self.process_interfaces(filedata)

    def read_file(self, filename, fileiobuf=None):
        if fileiobuf:
            self.read_filedata(fileiobuf)
            return
        self._filestack.append(filename)
        self.logger.info('processing interfaces file %s' %filename)
        f = open(filename)
        filedata = f.read()
        f.close()
        self.read_filedata(filedata)
        self._filestack.pop()

    def read_file_json(self, filename, fileiobuf=None):
        if fileiobuf:
            ifacedicts = json.loads(fileiobuf, encoding="utf-8")
                              #object_hook=ifaceJsonDecoder.json_object_hook)
        elif filename:
            self.logger.info('processing interfaces file %s' %filename)
            fp = open(filename)
            ifacedicts = json.load(fp)
                            #object_hook=ifaceJsonDecoder.json_object_hook)
        for ifacedict in ifacedicts:
            ifaceobj = ifaceJsonDecoder.json_to_ifaceobj(ifacedict)
            if ifaceobj:
                self._validate_addr_family(ifaceobj)
                self.callbacks.get('validateifaceobj')(ifaceobj)
                self.callbacks.get('iface_found')(ifaceobj)
        
    def load(self):
        """ This member function loads the networkinterfaces file.

        Assumes networkinterfaces parser object is initialized with the
        parser arguments
        """
        if self.interfacesfileformat == 'json':
            return self.read_file_json(self.interfacesfile,
                                       self.interfacesfileiobuf)
        return self.read_file(self.interfacesfile,
                              self.interfacesfileiobuf)
