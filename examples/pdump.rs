extern crate pcap;

fn main() {

    let filter = match std::env::args().nth(1) {
        Some(arg1) => arg1,
        None => "".to_string(),
    };

    println!("Pcap Version: '{}'", pcap::lib_version());

    let device = match pcap::lookupdev() {
        Ok(x) => x,
        Err(x) => {println!("Lookupdev failed: {}", x); return},
    };

    let cap = pcap::Session::open_live(&device).unwrap();

    cap.set_filter(&filter).unwrap();

    loop {
        cap.next_packet(|data| { println!("len: {:?}", data); } );
    }
}
