=========
ifupdown2
=========

Linux Interface Network Manager

* Free software: GNU General Public License v2

============
Installation
============

As of today (early june 2018), the preferred method to install ifupdown2, is by
building the source code (as it will always install the most recent stable
release). See `Installing latest stable release from sources`_ chapter.

Installing latest stable release from sources
---------------------------------------------

The sources for ifupdown2 can be downloaded from the `Github repo`_.

You can either clone the public repository:

.. code-block:: console

    $ git clone git://github.com/CumulusNetworks/ifupdown2

Or download the `tarball`_:

.. code-block:: console

    $ curl  -OL https://github.com/CumulusNetworks/ifupdown2/tarball/master

Once you have a copy of the source, you should build a deb-package and install it

.. code-block:: console

    $ cd ifupdown2 && git checkout master-next && make deb

The generated deb should be in the root directory (``../ifupdown2_2.0.0_all.deb``)

.. code-block:: console

    $ dpkg -i ../ifupdown2_2.0.0_all.deb

We don't recommend using ``setup.py install`` directly, as it's still missing systemd/init.d scripts.
This capability should be added in the near future.

You might need to manually download dependencies. Mandatory dependencies:

.. code-block:: console

    $ apt-get install dh-systemd python-all python-docutils iproute2 python-ipaddr python-argcomplete

Suggested dependencies:

.. code-block:: console

    $ apt-get install ethtool bridge-utils python-gvgen python-mako

.. _Github repo: https://github.com/CumulusNetworks/ifupdown2
.. _tarball: https://github.com/CumulusNetworks/ifupdown2/tarball/master


============
Contributing
============

Contributions are welcome, and they are greatly appreciated! Every little bit
helps, and credit will always be given.

You can contribute in many ways:

Types of Contributions
----------------------

Report Bugs
~~~~~~~~~~~

Report bugs at https://github.com/CumulusNetworks/ifupdown2/issues.

If you are reporting a bug, please include:

* Your operating system name and version (``uname -a``).
* Any details about your setup that might be helpful in troubleshooting.
* Content of configuration files such as ``/etc/network/interfaces``
* Detailed steps to reproduce the bug.
* Debug output of the ifupdown2 command (see ``--debug`` option)

Write Documentation
~~~~~~~~~~~~~~~~~~~

ifupdown2 could always use more documentation, whether as part of the
official ifupdown2 docs, in docstrings, or even on the web in blog posts,
articles, and such.

Submit Feedback
~~~~~~~~~~~~~~~

The best way to send feedback is to file an issue at https://github.com/CumulusNetworks/ifupdown2/issues.

If you are proposing a feature:

* Explain in detail how it would work.
* Keep the scope as narrow as possible, to make it easier to implement.

=======
Credits
=======

Development Lead
----------------

* Roopa Prabhu <roopa@cumulusnetworks.com>
* Julien Fortin <julien@cumulusnetworks.com>

Contributors
------------

* Nikhil Gajendrakumar <nikhil.gajendrakumar@gmail.com>
* Maximilian Wilhelm <max@sdn.clinic>
* Sven Auhagen <sven.auhagen@voleatech.de>
* skorpy <magnus@skorpy.space>
* Sam Tannous <stannous@cumulusnetworks.com>
* Wilson Kok <wkok@cumulusnetworks.com>
* John Berezovik <berezovik@gmail.com>
* Daniel Walton <dwalton76@gmail.com>
* Anuradha Karuppiah <anuradhak@cumulusnetworks.com>
* Balakrishnan Raman <balkee@yahoo.com>
* Scott Emery <scotte@cumulusnetworks.com>
* Dave Olson <olson@cumulusnetworks.com>
* David Ahern <dsa@cumulusnetworks.com>
* Jonathan Toppins <>
* Nolan Leake <nolan@cumulusnetworks.com>
* Sergey Sudakovich <sergey@cumulusnetworks.com>
* Andy Gospodarek <>
* Satish Ashok <sashok@cumulusnetworks.com>
* Scott Laffer <slaffer@cumulusnetworks.com>
* Vidya Sagar Ravipati <vidya.ravipati@gmail.com>
* Marek Grzybowski <marek.grzybowski@rtbhouse.com>
* Gaudenz Steinlin <gaudenz@users.noreply.github.com>
* Nigel Kukard <nkukard@lbsd.net>
* Jeffrey <jeffrey.bosma@gmail.com>
* kokel <kokel@users.noreply.github.com>

Why not you too? :)


=======
History
=======

See changelog here: https://github.com/CumulusNetworks/ifupdown2/blob/master/debian/changelog


Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
