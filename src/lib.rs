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

pub struct Session {
    handle: *mut pcap_t,
}

impl Session {
    pub fn open_live(dev: &str) -> Result<Session, String> {
        let mut errbuff = [0 as libc::c_uchar; ERRBUFF_SIZE];
        let handle = unsafe {
             pcap_open_live(ffi::CString::new(dev).unwrap().as_ptr(),
                            libc::consts::os::c95::BUFSIZ as i32,
                            1,
                            1000,
                            errbuff.as_mut_ptr() as *mut i8
                            )
        };

        if handle.is_null() {
            let slice = str::from_utf8(&errbuff[..]).unwrap();
            Err(slice.to_owned())
        }
        else {
            Ok( Session { handle: handle } )
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            pcap_close(self.handle);
        }
    }
}
