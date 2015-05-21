extern crate libc;

use std::ffi;
use std::str;

mod binding;
use binding::*;

#[test]
fn it_works() {
    println!("Hello!");
}

pub fn lib_version() {
    let s = unsafe { ffi::CStr::from_ptr(pcap_lib_version()) };
    println!("{}", s.to_bytes().len());
}
