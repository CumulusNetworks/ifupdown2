#!/usr/bin/env python3
#
# Copyright 2015-2017 Cumulus Networks, Inc. All rights reserved.
#
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

class ifupdownConfig():

	def __init__(self):
		self.conf = {}

config = ifupdownConfig()
diff_mode = False

def reset():
	global config
	config = ifupdownConfig()
