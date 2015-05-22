extern crate libc;

use std::ffi;
use std::str;

mod binding;
use binding::*;

#[test]
fn it_works() {
}

pub fn lib_version() -> &'static str {
    let slice = unsafe { ffi::CStr::from_ptr(pcap_lib_version()) };
    str::from_utf8(slice.to_bytes()).unwrap()
}
