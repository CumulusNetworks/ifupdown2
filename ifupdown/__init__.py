""" ifupdown2 package.

.. moduleauthor:: Roopa Prabhu <roopa@cumulusnetworks.com>
.. moduleauthor:: Julien Fortin <julien@cumulusnetworks.com>

"""

import os
import resource

import ifupdown.config

os.putenv('PATH', ifupdown.config.ENVPATH)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
