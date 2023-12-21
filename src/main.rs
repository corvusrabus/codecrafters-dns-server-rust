// Uncomment this block to pass the first stage
use std::net::UdpSocket;

#[derive(Default)]
#[repr(C)]
pub struct DNSMessage {
    pub packet_id: u16,
    qr_oc_aa_tc_rd: u8,
    ra_z_rcode: u8,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl DNSMessage {
    fn set_qr(&mut self, bit: bool) -> &mut Self {
        let bit = (bit as u8) << 7;
        self.qr_oc_aa_tc_rd |= bit;
        self
    }
}


fn to_bytes<T>(t: &T) -> &[u8]{
    let p: *const T = t;
    let p = p as *const u8;
    unsafe{
        std::slice::from_raw_parts(p, std::mem::size_of::<T>())
    }
}
// const DNS_HEADER_SIZE: usize = size_of::<DNSMessage>();

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                // debug_assert_eq!(size,DNS_HEADER_SIZE);
                let mut header = DNSMessage { packet_id: u16::from_ne_bytes(1234u16.to_be_bytes()), ..Default::default() };
                header.set_qr(true);
                let bytes = to_bytes(&header);
                println!("{bytes:?}");
                udp_socket
                    .send_to(bytes, source)
                    .expect("Failed to send response");
                println!("sent");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
