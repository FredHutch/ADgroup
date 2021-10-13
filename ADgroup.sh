#!/bin/bash

#scriptname=${0##*/}
unset PYTHONPATH
unset PYTHONHOME

export PYTHONUSERBASE=/usr/local//lib/python3.6.9
export PYTHONPATH=/usr/local/lib/python3.6.9/lib/python3.6/site-packages/
target=$(readlink -f $0)
/usr/bin/python ${target}.py "$@"
