extern crate libc;

use std::ffi;
use std::str;

mod binding;
use binding::*;

const ERRBUFF_SIZE: usize = 256;

#[test]
fn it_works() {
}

fn str_to_c(input: &str) -> *const i8 {
    ffi::CString::new(input).unwrap().as_ptr()
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
    dev: String
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
            Ok( Session { handle: handle, dev: dev.to_owned() } )
        }
    }

    pub fn set_filter(&self, expr: &str, netmask: u32) -> Result<(), &str> {
        unsafe {
            let mut bpf_prog = Struct_bpf_program { bf_len: 0, bf_insns: (std::ptr::null::<Struct_bpf_insn>() as *mut Struct_bpf_insn) };

            if -1 == pcap_compile(self.handle,
                                  &mut bpf_prog,
                                  str_to_c(expr),
                                  0,
                                  netmask) {
                Err("Failed to compile expression")
            }
            else {
                if -1 == pcap_setfilter(self.handle, &mut bpf_prog) {
                    Err("Failed to set filter")
                }
                else {
                    Ok(())
                }
            }
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
