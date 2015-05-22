extern crate pcap;

fn main() {
    println!("Version: '{}'", pcap::lib_version());

    match pcap::lookupdev() {
        Ok(x) => println!("Device found: '{}'", x),
        Err(x) => println!("Lookupdev failed: {}", x),
    };

    match pcap::Session::open_live("eth0") {
        Err(x) => println!("Error: **{}**", x),
        Ok(_) => println!("Session opened Ok"),
    };

    // pcap::Session::open_live("eth0").unwrap();

}
