use std::mem::size_of;
// Uncomment this block to pass the first stage
use std::net::UdpSocket;
use std::str::from_utf8;

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
        self.qr_oc_aa_tc_rd & 0b0000_0001
    }
    fn set_rd(&mut self, rd: u8) {
        self.qr_oc_aa_tc_rd &= 0b1111_1110;
        self.qr_oc_aa_tc_rd |= rd & 0b0000_0001;
    }
    fn set_rcode(&mut self, rcode: u8) {
        self.ra_z_rcode &= 0b1111_0000;
        self.ra_z_rcode |= rcode & 0b0000_1111;
    }
}

#[derive(Default, Clone)]
pub struct DNSMessageQuestion {
    name: String,
    r#type: u16,
    class: u16,
}

impl DNSMessageQuestion {
    fn parse_from_slice(slice: &[u8]) -> Result<(Self, usize), ()> {
        let mut slice = slice;
        if slice.len() < 5 {
            return Err(());
        }
        let mut bytes_read = 5;
        let mut string = String::new();
        let mut size = u8::from_be_bytes([slice[0]]);
        while size != 0 {
            if slice.len() <= size as usize + 1 {
                return Err(());
            }
            if !string.is_empty() {
                string.push('.');
            }

            let string_part = from_utf8(&slice[1..1 + size as usize]).map_err(|_| ())?;
            string.push_str(string_part);
            bytes_read += 1 + size;
            slice = &slice[1 + size as usize..];
            size = u8::from_be_bytes([slice[0]]);

        }
        if slice.len() < 5 {
            return Err(());
        }
        Ok((Self {
            name: string,
            r#type: u16::from_be_bytes(slice[1..3].try_into().unwrap()),
            class: u16::from_be_bytes(slice[3..5].try_into().unwrap()),
        }, bytes_read as usize))
    }
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
    pub question: Vec<DNSMessageQuestion>,
    pub answer: Vec<DNSMessageAnswer>,
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
        for question in self.question.iter() {
            Self::extend_question_type(question, res);
        }
    }
    fn extend_question_type(question: &DNSMessageQuestion, res: &mut Vec<u8>) {
        let name = &question.name;
        for label in name.split('.') {
            res.extend((label.len() as u8).to_be_bytes());
            res.extend(label.as_bytes())
        }
        res.push(0u8);
        res.extend(question.r#type.to_be_bytes());
        res.extend(question.class.to_be_bytes());
    }
    fn extend_answer(&self, res: &mut Vec<u8>) {
        for answer in self.answer.iter() {
            Self::extend_question_type(&answer.question, res);
            res.extend(answer.ttl.to_be_bytes());
            res.extend(answer.length.to_be_bytes());
            res.extend(answer.data.as_slice());
        }
    }
    fn build(&self) -> Vec<u8> {
        let mut res = Vec::new();
        self.extend_header(&mut res);
        self.extend_question(&mut res);
        self.extend_answer(&mut res);
        res
    }
    pub fn new() -> Self {
        //     let question = DNSMessageQuestion {
        //         name: String::new(),
        //         r#type: 1,
        //         class: 1,
        //     };
        Self {
            header: DNSMessageHeader { packet_id: 1234u16, ..Default::default() },
            question: vec![],
            answer: vec![],
        }
    }
    // pub fn set_question_name(&mut self, name: &str) {
    //     self.question.name = name.to_string();
    //     self.header.qd_count = 1;
    // }
    // pub fn set_answer_name(&mut self, name: &str) {
    //     self.answer.question.name = name.to_string();
    //     self.header.an_count = 1;
    // }
    // pub fn add_answer_data(&mut self, data: &[u8]) {
    //     self.answer.length += data.len() as u16;
    //     self.answer.data.extend(data);
    // }
    pub fn set_questions(&mut self, questions: Vec<DNSMessageQuestion>) {
        self.header.qd_count = questions.len() as u16;
        self.question = questions;
    }
    pub fn set_answers(&mut self, answers: Vec<DNSMessageAnswer>) {
        self.header.an_count = answers.len() as u16;
        self.answer = answers;
    }
}

impl DNSMessageBuilder {
    fn set_header_qr(&mut self, bit: bool) -> &mut Self {
        let bit = (bit as u8) << 7;
        self.header.qr_oc_aa_tc_rd |= bit;
        self
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

                let msg_header = DNSMessageHeader::from(TryInto::<[u8; 12]>::try_into(&buf[0..12]).unwrap());
                let mut questions = vec![];
                let mut answers = vec![];
                let mut next_question_start = 12;
                for _ in 0..msg_header.qd_count {
                    let (msg_question, bytes_read) = DNSMessageQuestion::parse_from_slice(&buf[next_question_start..]).unwrap();
                    next_question_start += bytes_read;
                    questions.push(msg_question.clone());
                    answers.push(DNSMessageAnswer {
                        question: msg_question,
                        ttl: 60,
                        length: 0,
                        data: vec![],
                    })
                }
                let mut resp = DNSMessageBuilder::new();
                let opcode = msg_header.get_opcode();
                resp.header.set_opcode(opcode);
                resp.header.packet_id = msg_header.packet_id;
                resp.set_header_qr(true);
                let rcode = if opcode == 0 {
                    0
                } else {
                    4
                };
                resp.header.set_rcode(rcode);
                resp.header.set_rd(msg_header.get_rd());
                resp.set_questions(questions);
                resp.set_answers(answers);
                // resp.question = msg_question.clone();
                // resp.answer.question = msg_question;
                // resp.header.an_count = 1;
                // resp.header.qd_count = 1;
                // resp.set_question_name("codecrafters.io");
                // resp.set_answer_name("codecrafters.io");
                // resp.add_answer_data("8888".as_bytes());
                let bytes = resp.build();
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
