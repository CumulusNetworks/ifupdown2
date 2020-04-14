Getting Started
===============

Prerequisites
-------------
* python-ifupdown2 is currently only tested on debian wheezy
* python-ifupdown2 needs python version 2.6 or greater
* Depends on: python-stdeb (for deb builds), python-docutils
  (for rst2man), 'python-ipaddr'
* Depends on python-gvgen package for printing interface graphs (this will be made optional in the future)
* Optional dependency for template engine: python-mako


Building
--------
$git clone <ifupdown2 git url> ifupdown2

$cd ifupdown2/ifupdown2

$./build.sh

Installing
----------
install generated python-ifupdown2-<ver>.deb

$dpkg -i <python-ifupdown2-<ver>.deb

