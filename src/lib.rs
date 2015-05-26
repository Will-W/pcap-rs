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

unsafe fn c_to_str(p: *const i8) -> &'static str {
    let slice = ffi::CStr::from_ptr(p);
    str::from_utf8(slice.to_bytes()).unwrap()
}

unsafe fn c_to_string(p: *const i8) -> String {
    c_to_str(p).to_string()
}


pub fn lib_version() -> &'static str {
    unsafe {
        c_to_str( pcap_lib_version() )
    }
}

pub fn lookupdev() -> Result<String, String> {
    let mut errbuff = [0 as libc::c_char; ERRBUFF_SIZE];
    unsafe {
        let dev = pcap_lookupdev(errbuff.as_mut_ptr());

        if dev.is_null() {
            Err( c_to_string(errbuff.as_ptr()) )
        }
        else {
            Ok( c_to_string(dev) )
        }
    }
}

pub struct Session {
    handle: *mut pcap_t,
    dev: String
}

impl Session {
    pub fn open_live(dev: &str) -> Result<Session, String> {
        let mut errbuff = [0 as libc::c_char; ERRBUFF_SIZE];
        let handle = unsafe {
             pcap_open_live(str_to_c(dev),
                            libc::consts::os::c95::BUFSIZ as i32,
                            1,
                            1000,
                            errbuff.as_mut_ptr()
                            )
        };

        if handle.is_null() {
            Err( unsafe { c_to_string(errbuff.as_ptr()) } )
        }
        else {
            Ok( Session { handle: handle, dev: String::from(dev) } )
        }
    }

    pub fn set_filter(&self, expr: &str) -> Result<(), String> {

        let mut errbuff = [0 as libc::c_char; ERRBUFF_SIZE];
        let mut net: u32 = 0;
        let mut mask: u32 = 0;

        let ret = unsafe { pcap_lookupnet(str_to_c(&self.dev),
                                          &mut net,
                                          &mut mask,
                                          errbuff.as_mut_ptr()) };

        if ret == -1 {
            return Err( unsafe { c_to_string(errbuff.as_ptr()) } );
        }

        unsafe {
            let mut bpf_prog = Struct_bpf_program { bf_len: 0,
                                                    bf_insns: (std::ptr::null::<Struct_bpf_insn>()
                                                               as *mut Struct_bpf_insn) };

            if -1 == pcap_compile(self.handle,
                                  &mut bpf_prog,
                                  str_to_c(expr),
                                  0,
                                  mask) {
                Err("Failed to compile expression".to_string())
            }
            else {
                if -1 == pcap_setfilter(self.handle, &mut bpf_prog) {
                    Err("Failed to set filter".to_string())
                }
                else {
                    Ok( () )
                }
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        println!("Session Closing");
        unsafe {
            pcap_close(self.handle);
        }
    }
}
