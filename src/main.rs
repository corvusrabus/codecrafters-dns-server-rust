use std::mem::size_of;
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

impl From<[u8; size_of::<DNSMessageHeader>()]> for DNSMessageHeader {
    fn from(value: [u8; size_of::<DNSMessageHeader>()]) -> Self {
        Self {
            packet_id: u16::from_be_bytes(value[0..2].try_into().unwrap()),
            qr_oc_aa_tc_rd: value[2],
            ra_z_rcode: value[3],
            qd_count: u16::from_be_bytes(value[4..6].try_into().unwrap()),
            an_count: u16::from_be_bytes(value[6..8].try_into().unwrap()),
            ns_count: u16::from_be_bytes(value[8..10].try_into().unwrap()),
            ar_count: u16::from_be_bytes(value[10..12].try_into().unwrap()),
        }
    }
}

impl DNSMessageHeader {
    fn get_opcode(&self) -> u8 {
        (self.qr_oc_aa_tc_rd & 0b0111_1000) >> 3
    }
    fn set_opcode(&mut self, op_code: u8) {
        self.qr_oc_aa_tc_rd &= 0b1000_0111;
        self.qr_oc_aa_tc_rd |= (op_code << 3) & 0b0111_1000;
    }
    fn get_rd(&self) -> u8 {
        (self.qr_oc_aa_tc_rd & 0b0000_0001)
    }
    fn set_rd(&mut self,rd : u8)  {
        self.qr_oc_aa_tc_rd &= 0b1111_1110;
        self.qr_oc_aa_tc_rd |= rd &0b0000_0001;
    }
    fn set_rcode(&mut self, rcode: u8) {
        self.ra_z_rcode &= 0b1111_0000;
        self.ra_z_rcode |= rcode & 0b0000_1111;
    }
}

#[derive(Default, Clone)]
pub struct DNSMessageQuestion {
    names: Vec<String>,
    r#type: u16,
    class: u16,
}

#[derive(Default)]
pub struct DNSMessageAnswer {
    question: DNSMessageQuestion,
    ttl: u64,
    length: u16,
    data: Vec<u8>,
}

pub struct DNSMessageBuilder {
    pub header: DNSMessageHeader,
    pub question: DNSMessageQuestion,
    pub answer: DNSMessageAnswer,
}

impl DNSMessageBuilder {
    fn extend_header(&self, res: &mut Vec<u8>) {
        res.extend(self.header.packet_id.to_be_bytes());
        res.push(self.header.qr_oc_aa_tc_rd);
        res.push(self.header.ra_z_rcode);
        res.extend(self.header.qd_count.to_be_bytes());
        res.extend(self.header.an_count.to_be_bytes());
        res.extend(self.header.ns_count.to_be_bytes());
        res.extend(self.header.ar_count.to_be_bytes());
    }
    fn extend_question(&self, res: &mut Vec<u8>) {
        Self::extend_question_type(&self.question, res);
    }
    fn extend_question_type(question: &DNSMessageQuestion, res: &mut Vec<u8>) {
        for name in question.names.iter() {
            for label in name.split('.') {
                res.extend((label.len() as u8).to_be_bytes());
                res.extend(label.as_bytes())
            }
            res.push(0u8);
        }
        res.extend(question.r#type.to_be_bytes());
        res.extend(question.class.to_be_bytes());
    }
    fn extend_answer(&self, res: &mut Vec<u8>) {
        Self::extend_question_type(&self.answer.question, res);
        res.extend(self.answer.ttl.to_be_bytes());
        res.extend(self.answer.length.to_be_bytes());
        res.extend(self.answer.data.as_slice());
    }
    fn build(&self) -> Vec<u8> {
        let mut res = Vec::new();
        self.extend_header(&mut res);
        self.extend_question(&mut res);
        self.extend_answer(&mut res);
        res
    }
    pub fn new() -> Self {
        let question = DNSMessageQuestion {
            names: vec![],
            r#type: 1,
            class: 1,
        };
        Self {
            header: DNSMessageHeader { packet_id: 1234u16, ..Default::default() },
            question: question.clone(),
            answer: DNSMessageAnswer { question, ttl: 60u64, ..Default::default() },
        }
    }
    pub fn add_question_name(&mut self, name: &str) {
        self.question.names.push(name.to_string());
        self.header.qd_count += 1;
    }
    pub fn add_answer_name(&mut self, name: &str) {
        self.answer.question.names.push(name.to_string());
        self.header.an_count += 1;
    }
    pub fn add_answer_data(&mut self, data: &[u8]) {
        self.answer.length += data.len() as u16;
        self.answer.data.extend(data);
    }
}

impl DNSMessageBuilder {
    fn set_header_qr(&mut self, bit: bool) -> &mut Self {
        let bit = (bit as u8) << 7;
        self.header.qr_oc_aa_tc_rd |= bit;
        self
    }
    fn set_header_qr_oc_aa_tc_rd(&mut self, qr_oc_aa_tc_rd: u8) {
        self.header.qr_oc_aa_tc_rd = qr_oc_aa_tc_rd;
    }
}


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
                let msg_header = DNSMessageHeader::from(TryInto::<[u8;12]>::try_into(&buf[0..12]).unwrap());
                let mut resp = DNSMessageBuilder::new();
                let opcode = msg_header.get_opcode();
                resp.header.set_opcode(opcode);
                resp.header.packet_id = msg_header.packet_id;
                resp.set_header_qr(true);
                let rcode = if opcode == 0 {
                    0
                }
                else {
                    4
                };
                resp.header.set_rcode(rcode);
                resp.header.set_rd(msg_header.get_rd());
                resp.add_question_name("codecrafters.io");
                resp.add_answer_name("codecrafters.io");
                resp.add_answer_data("8888".as_bytes());
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
