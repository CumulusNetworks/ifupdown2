#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# networkInterfaces --
#    ifupdown network interfaces file parser
#

import collections
import copy
import glob
import logging
import os
import re

from json import loads, JSONDecodeError

try:
    from ifupdown2.ifupdown.iface import ifaceType, ifaceJsonDecoder, iface
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.template import templateEngine
except ImportError:
    from ifupdown.iface import ifaceType, ifaceJsonDecoder, iface
    from ifupdown.utils import utils
    from ifupdown.template import templateEngine


whitespaces = '\n\t\r '

class ENIException(Exception):
    pass

class networkInterfaces():
    """ debian ifupdown /etc/network/interfaces file parser """

    _addrfams = {'inet' : ['static', 'manual', 'loopback', 'dhcp', 'dhcp6', 'ppp', 'tunnel'],
                 'inet6' : ['static', 'manual', 'loopback', 'dhcp', 'dhcp6', 'ppp', 'tunnel']}
    # tunnel is part of the address family for backward compatibility but is not required.

    def __init__(self, interfacesfile='/etc/network/interfaces',
                 interfacesfileiobuf=None, interfacesfileformat='native',
                 template_enable='0', template_engine=None,
                 template_lookuppath=None, raw=False):
        """This member function initializes the networkinterfaces parser object.

        Kwargs:
            **interfacesfile** (str):  path to the interfaces file (default is /etc/network/interfaces)

            **interfacesfileiobuf** (object): interfaces file io stream

            **interfacesfileformat** (str): format of interfaces file (choices are 'native' and 'json'. 'native' being the default)

            **template_engine** (str): template engine name

            **template_lookuppath** (str): template lookup path

        Raises:
            AttributeError, KeyError """

        self.callbacks = {}
        self.auto_all = False
        self.raw = raw
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)
        self.callbacks = {'iface_found' : None,
                          'validateifaceattr' : None,
                          'validateifaceobj' : None}
        self.allow_classes = {'auto': []}
        # auto is only an aliases of allow-auto
        self.auto_ifaces = self.allow_classes['auto']
        self.interfacesfile = interfacesfile
        self.interfacesfileiobuf = interfacesfileiobuf
        self.interfacesfileformat = interfacesfileformat
        self._filestack = [self.interfacesfile]

        self._template_engine = None
        self._template_enable = template_enable
        self._template_engine_name = template_engine
        self._template_engine_path = template_lookuppath

        self._currentfile_has_template = False
        self._ws_split_regex = re.compile(r'[\s\t]\s*')

        self.errors = 0
        self.warns = 0

    @property
    def _currentfile(self):
        try:
            return self._filestack[-1]
        except Exception:
            return self.interfacesfile

    def _parse_error(self, filename, lineno, msg):
        if lineno == -1 or self._currentfile_has_template:
            self.logger.error('%s: %s' %(filename, msg))
        else:
            self.logger.error('%s: line%d: %s' %(filename, lineno, msg))
        self.errors += 1

    def _parse_warn(self, filename, lineno, msg):
        if lineno == -1 or self._currentfile_has_template:
            self.logger.warning('%s: %s' %(filename, msg))
        else:
            self.logger.warning('%s: line%d: %s' %(filename, lineno, msg))
        self.warns += 1

    def _validate_addr_family(self, ifaceobj, lineno=-1):
        for family in ifaceobj.addr_family:
            if not self._addrfams.get(family):
                self._parse_error(self._currentfile, lineno,
                                  'iface %s: unsupported address family \'%s\''
                                  % (ifaceobj.name, family))
                ifaceobj.addr_family = []
                ifaceobj.addr_method = None
                return
            if ifaceobj.addr_method:
                if ifaceobj.addr_method not in self._addrfams.get(family):
                    self._parse_error(self._currentfile, lineno,
                                      'iface %s: unsupported '
                                      'address method \'%s\''
                                      % (ifaceobj.name, ifaceobj.addr_method))
            else:
                ifaceobj.addr_method = 'static'

    def subscribe(self, callback_name, callback_func):
        """This member function registers callback functions.

        Args:
            **callback_name** (str): callback function name (supported names: 'iface_found', 'validateifaceattr', 'validateifaceobj')

            **callback_func** (function pointer): callback function pointer

        Warns on error
        """

        if callback_name not in list(self.callbacks.keys()):
            print('warning: invalid callback ' + callback_name)
            return -1

        self.callbacks[callback_name] = callback_func

    def ignore_line(self, line):
        l = line.strip(whitespaces)
        if not l or l[0] == '#':
            return 1
        return 0

    def _add_ifaces_to_class(self, classname, ifaces):
        if classname not in self.allow_classes:
            self.allow_classes[classname] = []

        # This is a specific uses case: everything is considered auto if all
        # is being given to the auto or allow-auto classe.
        if classname == 'auto' and 'all' in ifaces:
            self.auto_all = True
            return  # nothing is to be done.

        for ifname in ifaces:
            ifnames = utils.expand_iface_range(ifname) or [ifname]
            self.allow_classes[classname].extend(ifnames)

    def process_allow(self, lines, cur_idx, lineno):
        allow_line = lines[cur_idx]

        words = re.split(self._ws_split_regex, allow_line)
        try:
            allow_class = words[0].split('-')[1]
            ifacenames = words[1:]
            if not ifacenames or not allow_class:
                raise IndexError()
        except IndexError:
            raise Exception(f'invalid allow line {allow_line} at line {lineno}')
        self._add_ifaces_to_class(allow_class, ifacenames)
        return 0

    def process_source(self, lines, cur_idx, lineno):
        # Support regex
        self.logger.debug('processing sourced line ..\'%s\'' % lines[cur_idx])
        sourced_file = re.split(self._ws_split_regex, lines[cur_idx], 2)[1]

        if sourced_file:
            if not os.path.isabs(sourced_file):
                sourced_file = os.path.join(os.path.dirname(self._currentfile), sourced_file)

            filenames = sorted(glob.glob(sourced_file))
            if not filenames:
                if '*' not in sourced_file:
                    self._parse_warn(self._currentfile, lineno,
                            'cannot find source file %s' %sourced_file)
                return 0
            for f in filenames:
                self.read_file(f)
        else:
            self._parse_error(self._currentfile, lineno,
                    'unable to read source line')
        return 0

    def process_source_directory(self, lines, cur_idx, lineno):
        self.logger.debug('processing source-directory line ..\'%s\'' % lines[cur_idx])
        sourced_directory = re.split(self._ws_split_regex, lines[cur_idx], 2)[1]

        if sourced_directory:
            if not os.path.isabs(sourced_directory):
                sourced_directory = os.path.join(os.path.dirname(self._currentfile), sourced_directory)

            folders = glob.glob(sourced_directory)
            for folder in folders:
                for file in os.listdir(folder):
                    self.read_file(os.path.join(folder, file))
        else:
            self._parse_error(self._currentfile, lineno,
                              'unable to read source-directory line')
        return 0

    def process_auto(self, lines, cur_idx, lineno):
        auto_ifaces = re.split(self._ws_split_regex, lines[cur_idx])[1:]

        if not auto_ifaces:
            self._parse_error(self._currentfile, lineno,
                    'invalid auto line \'%s\''%lines[cur_idx])
        else:
            self._add_ifaces_to_class('auto', auto_ifaces)
        return 0

    def _add_to_iface_config(self, ifacename, iface_config, attrname,
                             attrval, lineno):
        newattrname = attrname.replace("_", "-")
        try:
            if not self.callbacks.get('validateifaceattr')(newattrname,
                                      attrval):
                self._parse_error(self._currentfile, lineno,
                        'iface %s: unsupported keyword (%s)'
                        %(ifacename, attrname))
                return
        except Exception:
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
                for _ in range(0, len(addrlist) - len(attrvallist) -1):
                    attrvallist.append('')
                attrvallist.append(attrval)
                iface_config[newattrname] = attrvallist
        elif not attrvallist:
            iface_config[newattrname] = [attrval]
        else:
            iface_config[newattrname].append(attrval)

    def parse_iface(self, lines, cur_idx, lineno, ifaceobj):
        lines_consumed = 0
        line_idx = cur_idx

        iface_line = lines[cur_idx].strip(whitespaces)
        iface_attrs = re.split(self._ws_split_regex, iface_line)
        ifacename = iface_attrs[1]

        if (not utils.is_ifname_range(ifacename) and
            utils.check_ifname_size_invalid(ifacename)):
            self._parse_warn(self._currentfile, lineno,
                             '%s: interface name too long' %ifacename)

        # in cases where mako is unable to render the template
        # or incorrectly renders it due to user template
        # errors, we maybe left with interface names with
        # mako variables in them. There is no easy way to
        # recognize and warn about these. In the below check
        # we try to warn the user of such cases by looking for
        # variable patterns ('$') in interface names.
        if '$' in ifacename:
           self._parse_warn(self._currentfile, lineno,
                    '%s: unexpected characters in interface name' %ifacename)

        if self.raw:
            ifaceobj.raw_config.append(iface_line)
        iface_config = collections.OrderedDict()
        for line_idx in range(cur_idx + 1, len(lines)):
            l = lines[line_idx].strip(whitespaces)
            if self.ignore_line(l) == 1:
                if self.raw:
                    ifaceobj.raw_config.append(l)
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
            if self.raw:
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
            if iface_attrs[2]:
                ifaceobj.addr_family.append(iface_attrs[2])
            ifaceobj.addr_method = iface_attrs[3]
        except IndexError:
            # ignore
            pass
        self._validate_addr_family(ifaceobj, lineno)

        if self.auto_all or (ifaceobj.name in self.auto_ifaces):
            ifaceobj.auto = True

        classes = self.get_allow_classes_for_iface(ifaceobj.name)
        if classes:
            [ifaceobj.set_class(c) for c in classes]

        return lines_consumed       # Return next index

    def _create_ifaceobj_clone(self, ifaceobj, newifaceobjname,
                               newifaceobjtype, newifaceobjflags):
        ifaceobj_new = copy.deepcopy(ifaceobj)
        ifaceobj_new.realname = '%s' %ifaceobj.name
        ifaceobj_new.name = newifaceobjname
        ifaceobj_new.type = newifaceobjtype
        ifaceobj_new.flags = newifaceobjflags

        return ifaceobj_new

    def _clone_iface_range(self, iface_range, iface_orig, iftype=None):
        iftype = iftype or iface_orig.type
        for name in iface_range:
            flags = iface.IFACERANGE_ENTRY
            if name == iface_range[0]:
                flags |= iface.IFACERANGE_START
            obj = self._create_ifaceobj_clone(iface_orig, name, iftype, flags)
            yield obj

    def process_iface(self, lines, cur_idx, lineno):
        ifaceobj = iface()
        lines_consumed = self.parse_iface(lines, cur_idx, lineno, ifaceobj)
        found_cb = self.callbacks['iface_found']
        ifrange = utils.expand_iface_range(ifaceobj.name)

        if not ifrange:
            found_cb(ifaceobj)

        for ifclone in self._clone_iface_range(ifrange, ifaceobj):
            if utils.check_ifname_size_invalid(ifclone.name):
                self._parse_warn(self._currentfile, lineno,
                                 f'{ifclone.name}: interface name too long')
            found_cb(ifclone)

        return lines_consumed       # Return next index

    def process_vlan(self, lines, cur_idx, lineno):
        ifaceobj = iface()
        lines_consumed = self.parse_iface(lines, cur_idx, lineno, ifaceobj)
        found_cb = self.callbacks['iface_found']
        ifrange = utils.expand_iface_range(ifaceobj.name)
        iftype = ifaceType.BRIDGE_VLAN

        if not ifrange:
            ifaceobj.type = iftype
            found_cb(ifaceobj)

        for ifclone in self._clone_iface_range(ifrange, ifaceobj, iftype):
            found_cb(ifclone)

        return lines_consumed       # Return next index

    network_elems = {
        'source': process_source,
        'source-directory': process_source_directory,
        'allow': process_allow,
        'auto': process_auto,
        'iface': process_iface,
        'vlan': process_vlan
    }

    def _is_keyword(self, str):
        # The additional split here is for allow- keyword
        if (str in list(self.network_elems.keys()) or
            str.split('-')[0] == 'allow'):
            return 1
        return 0

    def _get_keyword_func(self, str_):
        tmp_str = str_.split('-')[0]
        if tmp_str == "allow":
            return self.network_elems.get(tmp_str)
        else:
            return self.network_elems.get(str_)

    def get_allow_classes_for_iface(self, ifacename):
        classes = []
        for class_name, ifacenames in list(self.allow_classes.items()):
            if ifacename in ifacenames:
                classes.append(class_name)
        return classes

    def process_interfaces(self, filedata):

        # process line continuations
        filedata = ' '.join(d.strip() for d in filedata.split('\\'))

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
        # run through template engine
        if filedata and '%' in filedata:
            try:
                if not self._template_engine:
                    self._template_engine = templateEngine(
                        template_engine=self._template_engine_name,
                        template_enable=self._template_enable,
                        template_lookuppath=self._template_engine_path)
                rendered_filedata = self._template_engine.render(filedata)
                if rendered_filedata is filedata:
                    self._currentfile_has_template = False
                else:
                    self._currentfile_has_template = True
            except Exception as e:
                self._parse_error(self._currentfile, -1,
                                  'failed to render template (%s). Continue without template rendering ...'
                                  % str(e))
                rendered_filedata = None
            if rendered_filedata:

                if isinstance(rendered_filedata, bytes):
                    # some template engine might return bytes but we want str
                    rendered_filedata = rendered_filedata.decode()

                self.process_interfaces(rendered_filedata)
                return
        self.process_interfaces(filedata)

    def read_file(self, filename, fileiobuf=None):
        if fileiobuf:
            self.read_filedata(fileiobuf)
            return
        self._filestack.append(filename)
        self.logger.info('processing interfaces file %s' %filename)
        try:
            with open(filename) as f:
                filedata = f.read()
        except Exception as e:
            self.logger.warning('error processing file %s (%s)',
                             filename, str(e))
            return
        self.read_filedata(filedata)
        self._filestack.pop()

    def read_file_json(self, filename, fileiobuf=None):
        if fileiobuf:
            ifacedicts = loads(fileiobuf, encoding="utf-8")
                              #object_hook=ifaceJsonDecoder.json_object_hook)
        elif filename:
            self.logger.info('processing JSON formatted interfaces file %s' % filename)

            # Check we can open and read the file
            try:
                with open(filename) as f:
                    filedata = f.read()
            except Exception as e:
                self.logger.warning('error processing file %s (%s)',
                                    filename, str(e))
                return

            # Check we can decode JSON data from the file
            try:
                ifacedicts = loads(filedata)
            except JSONDecodeError as e:
                self.logger.warning('error loading JSON content from file %s (%s)',
                                    filename, str(e))
                return

        # we need to handle both lists and non lists formats (e.g. {{}})
        if not isinstance(ifacedicts, list):
            ifacedicts = [ifacedicts]

        errors = 0
        for ifacedict in ifacedicts:
            ifaceobj = ifaceJsonDecoder.json_to_ifaceobj(ifacedict)
            if ifaceobj:
                self._validate_addr_family(ifaceobj)
                if not self.callbacks.get('validateifaceobj')(ifaceobj):
                    errors += 1
                self.callbacks.get('iface_found')(ifaceobj)
        self.errors += errors

    def load(self):
        """ This member function loads the networkinterfaces file.

        Assumes networkinterfaces parser object is initialized with the
        parser arguments
        """
        if not self.interfacesfile and not self.interfacesfileiobuf:
            self.logger.warning('no terminal line stdin used or ')
            self.logger.warning('no network interfaces file defined.')
            self.warns += 1
            return

        if self.interfacesfileformat == 'json':
            return self.read_file_json(self.interfacesfile,
                                       self.interfacesfileiobuf)
        return self.read_file(self.interfacesfile,
                              self.interfacesfileiobuf)
