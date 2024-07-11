#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# template --
#    helper class to render templates
#

try:
    from ifupdown2.ifupdown.utils import *
except ImportError:
    from ifupdown.utils import *


class templateEngine():
    """ provides template rendering methods """

    def __init__(self, template_engine, template_enable='0',
                 template_lookuppath=None):
        self.logger = logging.getLogger('ifupdown.' +
                    self.__class__.__name__)
        self.tclass = None
        self.tclassargs = {}
        self.render = self._render_default
        if template_enable == '0':
            return
        if template_engine == 'mako':
            try:
                self.tclass = utils.importName('mako.template', 'Template')
            except Exception as e:
                self.logger.warning('unable to load template engine %s (%s)'
                        %(template_engine, str(e)))
            if template_lookuppath:
                try:
                    self.logger.debug('setting template lookuppath to %s'
                            %template_lookuppath)
                    lc = utils.importName('mako.lookup', 'TemplateLookup')
                    self.tclassargs['lookup'] = lc(
                                directories=template_lookuppath.split(':'))
                except Exception as e:
                    self.logger.warning('unable to set template lookup path'
                                     ' %s (%s): are you sure \'python3-mako\''
                                     'is installed?'
                                     % (template_lookuppath, str(e)))
            self.render = self._render_mako
        else:
            self.logger.info('skip template processing.., ' +
                    'template engine not found')

    def _render_default(self, textdata):
        return textdata

    def _render_mako(self, textdata):
        """ render textdata passed as argument using mako

        Returns rendered textdata """

        if not self.tclass:
            return textdata
        self.logger.info('template processing on interfaces file ...')
        t = self.tclass(text=textdata, output_encoding='utf-8',
                     lookup=self.tclassargs.get('lookup'))
        return t.render()
