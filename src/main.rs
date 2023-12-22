use std::mem::size_of;
// Uncomment this block to pass the first stage
use std::net::UdpSocket;
use std::str::from_utf8;

#[derive(Default, Clone, Debug)]
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

#[derive(Default, Clone, Debug)]
pub struct DNSMessageQuestion {
    name: String,
    r#type: u16,
    class: u16,
}

impl DNSMessageQuestion {
    fn parse_from_slice(slice: &[u8], real_start: usize) -> Result<(Self, usize), ()> {
        println!("Parsing question from {real_start}");
        let mut start = real_start;
        let mut string = String::new();
        let is_pointer = (slice[start] & 0b1100_0000) == 0b1100_0000;
        println!("Slice start binary {:08b}",slice[start]);
        if is_pointer {
            let mut n: [u8; 2] = slice[start..start + 2].try_into().unwrap();

            n[0] &= 0b0011_1111;
            let pointer = u16::from_be_bytes(n);
            println!("pointer is {pointer}");
            start = pointer as usize;
        }
        let mut size = u8::from_be_bytes([slice[start]]);

        while size != 0 {
            println!("Starting from size {size} and ispointer {is_pointer}");

            if !string.is_empty() {
                string.push('.');
            }

            let string_part = from_utf8(&slice[start + 1..start + 1 + size as usize]).map_err(|_| ())?;
            println!("string part {string_part}");
            string.push_str(string_part);
            start += 1 + size as usize;
            let is_pointer = (slice[start] & 0b1100_0000) == 0b1100_0000;
            println!("Slice start binary {:08b}",slice[start]);
            if is_pointer {
                let mut n: [u8; 2] = slice[start..start + 2].try_into().unwrap();

                n[0] &= 0b0011_1111;
                let pointer = u16::from_be_bytes(n);
                println!("pointer is {pointer}");
                start = pointer as usize;
            }
            size = u8::from_be_bytes([slice[start]]);
        }
        let r#type = u16::from_be_bytes(slice[start + 1..start + 3].try_into().unwrap());
        let class = u16::from_be_bytes(slice[start + 3..start + 5].try_into().unwrap());
        let end = if is_pointer {
            real_start + 2
        }
        else {
            start +5
        };
        Ok((Self {
            name: string,
            r#type,
            class,
        }, end))
    }
}

#[derive(Default, Clone, Debug)]
pub struct DNSMessageAnswer {
    question: DNSMessageQuestion,
    ttl: u32,
    length: u16,
    data: Vec<u8>,
}

impl DNSMessageAnswer {
    fn parse_from_slice(slice: &[u8], real_start: usize) -> Result<(Self, usize), ()> {
        let (question,  end) = DNSMessageQuestion::parse_from_slice(slice, real_start)?;
        println!("Answer end {end}");
        let ttl = u32::from_be_bytes((&slice[end..end + 4]).try_into().unwrap());
        let length = u16::from_be_bytes((&slice[end + 4..end + 6]).try_into().unwrap());
        let length_usize = length as usize;

        let data = Vec::from(&slice[end + 6..end + 6 + length_usize]);
        Ok((
            Self {
                question,
                ttl,
                length,
                data,
            }, end + 6 + length_usize))
    }
}

#[derive(Clone, Debug)]
pub struct DNSMessage {
    pub header: DNSMessageHeader,
    pub questions: Vec<DNSMessageQuestion>,
    pub answers: Vec<DNSMessageAnswer>,
}

impl DNSMessage {
    fn parse_from_slice(slice: &[u8]) -> Result<Self, ()> {
        if slice.len() < 12 {
            return Err(());
        }
        let header = DNSMessageHeader::from(TryInto::<[u8; 12]>::try_into(&slice[0..12]).unwrap());
        let mut questions = vec![];
        let mut answers = vec![];
        let mut next_question_start = 12;
        for _ in 0..header.qd_count {
            let (question, end) = DNSMessageQuestion::parse_from_slice(slice,next_question_start).unwrap();
            println!("end {end}");
            next_question_start = end;
            questions.push(question);
        }
        for _ in 0..header.an_count {
            let (answer, end) = DNSMessageAnswer::parse_from_slice(slice,next_question_start).unwrap();
            next_question_start = end;
            answers.push(answer);
        }
        Ok(Self {
            header,
            questions,
            answers,
        })
    }

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
        for question in self.questions.iter() {
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
        for answer in self.answers.iter() {
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
            questions: vec![],
            answers: vec![],
        }
    }
    pub fn set_questions(&mut self, questions: Vec<DNSMessageQuestion>) {
        self.header.qd_count = questions.len() as u16;
        self.questions = questions;
    }
    pub fn set_answers(&mut self, answers: Vec<DNSMessageAnswer>) {
        self.header.an_count = answers.len() as u16;
        self.answers = answers;
    }
}

impl DNSMessage {
    fn set_header_qr(&mut self, bit: bool) -> &mut Self {
        let bit = (bit as u8) << 7;
        self.header.qr_oc_aa_tc_rd |= bit;
        self
    }
}


fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");
    let args: Vec<String> = std::env::args().collect();
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    let udp_socket2 = UdpSocket::bind("127.0.0.1:2054").expect("Failed to bind to address");
    let mut counter = 0u16;
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                println!("Received {:X?}", &buf[12..size]);
                let msg = DNSMessage::parse_from_slice(&buf).unwrap();
                println!("Received Message {msg:?}");

                let mut answers = vec![];
                if let Some(ip) = args.get(2) {
                    println!("Relaying to {ip}");
                    let mut new_msg = msg.clone();
                    new_msg.answers = vec![];
                    for a in msg.questions.iter() {
                        let mut msg_clone = new_msg.clone();
                        msg_clone.set_questions(vec![a.clone()]);
                        msg_clone.header.packet_id = counter;
                        counter = (counter + 1) % 10;
                        println!("Sending {msg_clone:?}");
                        let bytes = msg_clone.build();
                        udp_socket2.send_to(&bytes, ip).unwrap();
                        let mut buf2 = [0; 512];
                        let (size, source) = udp_socket2.recv_from(&mut buf2).unwrap();
                        println!("Received2 {} bytes from {}", size, source);
                        let mut msg2 = DNSMessage::parse_from_slice(&buf2).unwrap();
                        println!("Got answers {:?}", msg2.answers);
                        answers.append(&mut msg2.answers)
                    }
                } else {
                    for question in msg.questions.iter() {
                        answers.push(DNSMessageAnswer {
                            question: question.clone(),
                            ttl: 60,
                            length: 0,
                            data: vec![],
                        })
                    }
                }
                let mut resp = DNSMessage::new();

                let opcode = msg.header.get_opcode();
                resp.header.set_opcode(opcode);
                resp.header.packet_id = msg.header.packet_id;
                resp.set_header_qr(true);
                let rcode = if opcode == 0 {
                    0
                } else {
                    4
                };
                resp.header.set_rcode(rcode);
                resp.header.set_rd(msg.header.get_rd());
                resp.set_answers(answers);
                resp.set_questions(msg.questions);
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
