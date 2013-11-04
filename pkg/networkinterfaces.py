#!/usr/bin/python

import collections
from iface import *
import logging
import glob


class networkInterfaces():

    hotplugs = {}
    auto_ifaces = []
    callbacks = {}

    ifaces_file = "/etc/network/interfaces"

    def __init__(self):
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)
        self.callbacks = {'iface_found' : None}
        self.allow_classes = {}


    def subscribe(self, callback_name, callback_func):
        if callback_name not in self.callbacks.keys():
            print 'warning: invalid callback ' + callback_name
            return -1

        self.callbacks[callback_name] = callback_func


    def ignore_line(self, line):
        l = line.strip('\n ')

        if len(l) == 0 or l[0] == '#':
            return 1

        return 0

    def process_allow(self, lines, cur_idx, lineno):
        allow_line = self.lines[cur_idx]

        words = allow_line.split()
        if len(words) <= 1:
            raise Exception('invalid allow line \'%s\'' %allow_line)

        allow_class = words[0].split('-')[1]
        ifacenames = words[1:]

        if self.allow_classes.get(allow_class) is not None:
            for i in ifacenames:
                self.allow_classes[allow_class].append(i)
        else:
                self.allow_classes[allow_class] = ifacenames

        return 0


    def process_source(self, lines, cur_idx, lineno):
        # Support regex
        sourced_file = lines[cur_idx].split(' ', 2)[1]
        if sourced_file is not None:
            for f in glob.glob(sourced_file):
                self.read_file(self, sourced_file)
        else:
            self.logger.warn('unable to read source line at %d', lineno)

        return 0

    def process_auto(self, lines, cur_idx, lineno):
        # XXX: Need to do more
        attrs = lines[cur_idx].split()
        if len(attrs) != 2:
            raise Exception('line%d: ' %lineno + 'incomplete \'auto\' line')

        self.auto_ifaces.append(lines[cur_idx].split()[1])

        return 0


    def process_iface(self, lines, cur_idx, lineno):
        lines_consumed = 0

        ifaceobj = iface()

        iface_line = lines[cur_idx].strip('\n ')
        iface_attrs = iface_line.split()

        ifaceobj.raw_lines.append(iface_line)
    
        iface_config = collections.OrderedDict()
        for line_idx in range(cur_idx + 1, len(lines)):
            l = lines[line_idx].strip('\n\t ')

            if self.ignore_line(l) == 1:
                continue

            ifaceobj.raw_lines.append(l)

            if self.is_keyword(l.split()[0]) == True:
                line_idx -= 1
                break

            (attr_name, attrs) = l.split(' ', 1)

            if iface_config.get(attr_name) == None:
                iface_config[attr_name] = [attrs.strip(' ')]
            else:
                iface_config[attr_name].append(attrs.strip(' '))

        lines_consumed = line_idx - cur_idx

        # Create iface object
        ifaceobj.set_name(iface_attrs[1])
        ifaceobj.set_config(iface_config)
        ifaceobj.generate_env()
        if len(iface_attrs) > 2:
            ifaceobj.set_addr_family(iface_attrs[2])
            ifaceobj.set_addr_method(iface_attrs[3])

        if ifaceobj.get_name() in self.auto_ifaces:
            ifaceobj.set_auto()

        classes = ifaceobj.set_classes(
                    self.get_allow_classes_for_iface(ifaceobj.get_name()))
        if classes is not None and len(classes) > 0:
            for c in classes:
                ifaceobj.set_class(c)

        # Call iface found callback
        self.logger.debug('saving interface %s' %ifaceobj.get_name())
        self.callbacks.get('iface_found')(ifaceobj)

        return lines_consumed       # Return next index


    network_elems = { 'source'      : process_source,
                      'allow'      : process_allow,
                      'auto'        : process_auto,
                      'iface'       : process_iface}


    def is_keyword(self, str):

        # The additional split here is for allow- keyword
        tmp_str = str.split('-')[0]
        if tmp_str in self.network_elems.keys():
            return 1

        return 0

    def get_keyword_func(self, str):
        tmp_str = str.split('-')[0]

        return self.network_elems.get(tmp_str)

    def get_allow_classes_for_iface(self, ifacename):
        classes = []
        for class_name, ifacenames in self.allow_classes.items():
            if ifacename in ifacenames:
                classes.append(class_name)

        return classes


    def read_file(self, filename=None):
        lineno = 0
        line_idx = 0
        lines_consumed = 0

        ifaces_file = filename
        if ifaces_file == None:
            ifaces_file=self.ifaces_file

        self.logger.debug('reading ifaces_file %s' %ifaces_file)

        with open(ifaces_file) as f:
            lines = f.readlines()

            while (line_idx < len(lines)):
                lineno = lineno + 1

                if self.ignore_line(lines[line_idx]):
                    line_idx += 1
                    continue
        
                l = lines[line_idx].strip('\n ')
                words = l.split()

                # Check if first element is a supported keyword
                if self.is_keyword(words[0]):
                    keyword_func = self.get_keyword_func(
                                words[0])
                    lines_consumed = keyword_func(self,
                                        lines, line_idx, lineno)

                    line_idx += lines_consumed
                else:
                    self.logger.warning('could not ' +
                        'process line %s' %l + ' at' +
                        ' lineno %d' %lineno)

                line_idx += 1

        return 0


    def load(self, filename=None):
        self.logger.debug('loading ifaces file ..')
        return self.read_file(filename)
