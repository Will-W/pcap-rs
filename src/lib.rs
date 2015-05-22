extern crate libc;

use std::ffi;
use std::str;

mod binding;
use binding::*;

const ERRBUFF_SIZE: usize = 256;

#[test]
fn it_works() {
}

pub fn lib_version() -> &'static str {
    let slice = unsafe { ffi::CStr::from_ptr(pcap_lib_version()) };
    str::from_utf8(slice.to_bytes()).unwrap()
}

pub fn lookupdev() -> Result<String, String> {
    let mut errbuff = [0 as libc::c_char; ERRBUFF_SIZE];
    unsafe {
        let dev = pcap_lookupdev(errbuff.as_mut_ptr());
        if dev.is_null() {
            let slice = ffi::CStr::from_ptr(errbuff.as_ptr());
            Err(str::from_utf8(slice.to_bytes()).unwrap().to_string())
        }
        else {
            let slice = ffi::CStr::from_ptr(dev);
            Ok(str::from_utf8(slice.to_bytes()).unwrap().to_string())
        }
    }
}
