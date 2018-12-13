#!/usr/bin/env python
#
# Copyright 2015-2017 Cumulus Networks, Inc. All rights reserved.
#
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

class ifupdownConfig():

	def __init__(self):
		self.conf = {}

config = ifupdownConfig()

def reset():
	global config
	config = ifupdownConfig()
