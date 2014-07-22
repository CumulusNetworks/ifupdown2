#!/bin/bash

TOPDIR=.

${TOPDIR}/scripts/genmanpages.sh ${TOPDIR}/man.rst ${TOPDIR}/man

python setup.py --command-packages=stdeb.command sdist_dsc bdist_deb

