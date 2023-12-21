// Uncomment this block to pass the first stage
use std::net::UdpSocket;

#[derive(Default)]
pub struct DNSMessageHeader {
    pub packet_id: u16,
    qr_oc_aa_tc_rd: u8,
    ra_z_rcode: u8,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

#[derive(Default)]
pub struct DNSMessageQuestion {
    names: Vec<String>,
    r#type: u16,
    class: u16,
}

pub struct DNSMessageBuilder {
    header: DNSMessageHeader,
    question: DNSMessageQuestion,
}

impl DNSMessageBuilder {
    fn build(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend(self.header.packet_id.to_be_bytes());
        res.push(self.header.qr_oc_aa_tc_rd);
        res.push(self.header.ra_z_rcode);
        res.extend(self.header.qd_count.to_be_bytes());
        res.extend(self.header.an_count.to_be_bytes());
        res.extend(self.header.ns_count.to_be_bytes());
        res.extend(self.header.ar_count.to_be_bytes());
        for name in self.question.names.iter() {
            for label in name.split('.') {
                res.extend((label.len() as u8).to_be_bytes());
                res.extend(label.as_bytes())
            }
            res.push(0u8);
        }
        res.extend(self.question.r#type.to_be_bytes());
        res.extend(self.question.class.to_be_bytes());
        res
    }
    pub fn new() -> Self {
        Self {
            header: DNSMessageHeader { packet_id: 1234u16, ..Default::default() },
            question: DNSMessageQuestion {
                names: vec![],
                r#type: 1,
                class: 1,
            },
        }
    }
    pub fn add_name(&mut self, name: &str) {
        self.question.names.push(name.to_string());
        self.header.qd_count += 1;
    }
}

impl DNSMessageBuilder {
    fn set_qr(&mut self, bit: bool) -> &mut Self {
        let bit = (bit as u8) << 7;
        self.header.qr_oc_aa_tc_rd |= bit;
        self
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
                let mut resp = DNSMessageBuilder::new();
                resp.set_qr(true);
                resp.add_name("codecrafters.io");
                let bytes = resp.build();
                println!("{bytes:?}");
                udp_socket
                    .send_to(bytes.as_slice(), source)
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
