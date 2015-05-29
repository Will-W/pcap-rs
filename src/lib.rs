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

/// Get the pcap library version string
pub fn lib_version() -> &'static str {
    unsafe {
        c_to_str( pcap_lib_version() )
    }
}

/// Get the name of the default ethernet device
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

/// Encapsulates an instance of a pcap session
///
/// Construct with open_live()
pub struct Session {
    handle: *mut pcap_t,
    dev: String
}

impl Session {
    /// Attempts to construct a pcap session on the requested device
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

    /// Applies the provided BPF filter to the pcap session
    pub fn set_filter(&self, expr: &str) -> Result<(), String> {

        let mut errbuff = [0 as libc::c_char; ERRBUFF_SIZE];
        let mut net: u32 = 0;
        let mut mask: u32 = 0;

        // Get the netmask for the current device.
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
            // Compile and set the filter
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

    /// Retrieve the next packet and pass to the closure
    pub fn next_packet<F>(&self, on_packet: F) -> ()
        where F : Fn(&[u8]) -> () {
            let mut hdr: Struct_pcap_pkthdr = unsafe { std::mem::uninitialized() };
            unsafe {
                let data = pcap_next(self.handle, &mut hdr);
                if !data.is_null() {
                    let slice: &[u8] = std::slice::from_raw_parts(data, hdr.len as usize);
                    on_packet(slice);
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
