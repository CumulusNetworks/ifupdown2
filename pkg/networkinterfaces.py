#!/usr/bin/python
#
# Copyright 2013.  Cumulus Networks, Inc.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# networkInterfaces --
#    ifupdown network interfaces file parser
#

import collections
import logging
import glob
import re
from iface import *

class networkInterfaces():

    hotplugs = {}
    auto_ifaces = []
    callbacks = {}

    ifaces_file = "/etc/network/interfaces"

    def __init__(self):
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)
        self.callbacks = {'iface_found' : None,
                          'validate' : None}
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
        allow_line = lines[cur_idx]

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
        self.logger.debug('processing sourced line ..\'%s\'' %lines[cur_idx])
        sourced_file = lines[cur_idx].split(' ', 2)[1]
        if sourced_file is not None:
            for f in glob.glob(sourced_file):
                self.read_file(f)
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
        line_idx = cur_idx

        ifaceobj = iface()

        iface_line = lines[cur_idx].strip('\n ')
        iface_attrs = iface_line.split()
        ifacename = iface_attrs[1]

        ifaceobj.raw_lines.append(iface_line)
    
        iface_config = collections.OrderedDict()
        for line_idx in range(cur_idx + 1, len(lines)):
            l = lines[line_idx].strip('\n\t ')

            if self.ignore_line(l) == 1:
                continue

            if self.is_keyword(l.split()[0]) == True:
                line_idx -= 1
                break

            ifaceobj.raw_lines.append(l)

            # preprocess vars (XXX: only preprocesses $IFACE for now)
            l = re.sub(r'\$IFACE', ifacename, l)

            attrs = l.split(' ', 1)
            if len(attrs) < 2:
                self.logger.warn('invalid syntax at line %d' %(line_idx + 1))
                continue
            attrname = attrs[0]
            attrval = attrs[1].strip(' ')
            try:
                if not self.callbacks.get('validate')(attrname, attrval):
                    self.logger.warn('unsupported keyword (%s) at line %d'
                                    %(l, line_idx + 1))
            except:
                pass
            if not iface_config.get(attrname):
                iface_config[attrname] = [attrval]
            else:
                iface_config[attrname].append(attrval)

        lines_consumed = line_idx - cur_idx

        # Create iface object
        if ifacename.find(':') != -1:
            ifaceobj.set_name(ifacename.split(':')[0])
        else:
            ifaceobj.set_name(ifacename)

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

    def process_filedata(self, filedata):
        lineno = 0
        line_idx = 0
        lines_consumed = 0

        raw_lines = filedata.split('\n')
        lines = [l.strip(' \n') for l in raw_lines]

        while (line_idx < len(lines)):
            lineno = lineno + 1

            if self.ignore_line(lines[line_idx]):
                line_idx += 1
                continue
        
            words = lines[line_idx].split()

            # Check if first element is a supported keyword
            if self.is_keyword(words[0]):
                keyword_func = self.get_keyword_func(words[0])
                lines_consumed = keyword_func(self, lines, line_idx, lineno)
                line_idx += lines_consumed
            else:
                self.logger.warning('could not process line %s' %l + ' at' +
                    ' lineno %d' %lineno)

            line_idx += 1

        return 0

    def run_template_engine(self, textdata):
        try:
            from mako.template import Template
        except:
            self.logger.warning('template engine mako not found. ' +
                                'skip template parsing ..');
            return textdata

        t = Template(text=textdata, output_encoding='utf-8')
        return t.render()

    def read_file(self, filename=None):
        ifaces_file = filename
        if ifaces_file == None:
            ifaces_file=self.ifaces_file

        self.logger.debug('reading interfaces file %s' %ifaces_file)
        f = open(ifaces_file)
        filedata = f.read()
        f.close()

        # process line continuations
        filedata = ' '.join(d.strip() for d in filedata.split('\\'))

        # run through template engine
        filedata = self.run_template_engine(filedata)

        self.process_filedata(filedata)


    def load(self, filename=None):
        return self.read_file(filename)
