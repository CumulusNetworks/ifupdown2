#!/bin/sh
#
# Copyright 2013 Cumulus Networks, Inc.
# All rights reserved.
#

# Install the man pages into the sysroot
SRC_MAN_DIR=$1
DST_MAN_DIR=$2

echo "Generating man pages .."
# Loop over all the man directories
mkdir -p $DST_MAN_DIR

for p in $(ls $SRC_MAN_DIR/*.rst) ; do
    # strip src man path
    src_file=$p
    dst_file=${p##.*\/}
    dst_file="${DST_MAN_DIR}/${dst_file%.rst}"
    # treat warnings as errors
    rst2man --halt=2 "$p" > $dst_file || {
        echo
        echo "Error: problems generating man page: $p"
        rm -f $dst_file &>/dev/null
        exit 1
    }
    echo -n "."
done
echo " done."
