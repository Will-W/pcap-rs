#!/bin/sh

if [ "$1" == "" ] ; then
    >&2 echo "Supply location of bindgen exe as argument"
    exit 1
fi

BINDGEN_EXE=$1
OUTFILE=src/binding.rs

cat > $OUTFILE <<EOF
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code)]

extern crate libc;
#[link(name = "pcap")]
extern "C" {}

EOF

$BINDGEN_EXE -builtins /usr/include/pcap/pcap.h >> $OUTFILE
