extern crate pcap;

fn main() {
    println!("Version: '{}'", pcap::lib_version());

    match pcap::lookupdev() {
        Ok(x) => println!("Device found: {}", x),
        Err(x) => println!("Lookupdev failed: {}", x),
    };

}
