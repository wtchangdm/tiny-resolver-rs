use rand::Rng;

use crate::{utils, RecordClass, RecordType, ResourceRecord};
use crate::{Error, NameServerError};

// Message format:
//
// +---------------------+
// |        Header       |
// +---------------------+
// |       Question      | the question for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+
//
/// See [RFC 1035, section 4.1. Format: MESSAGES](https://www.rfc-editor.org/rfc/inline-errata/rfc1035.html).
#[derive(Debug)]
pub struct Message {
    pub header: MessageHeader,
    pub question: MessageQuestion,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    pub fn new_query(domain: &str, record_type: &RecordType) -> Self {
        Self {
            header: MessageHeader::with_qd_count(1),
            question: MessageQuestion::with_domain(domain, record_type),
            // We don't need these fields for a query message.
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    /// Build byte array. This is only used for a standard query.
    ///
    /// See [RFC 1035, section 4.1. Format: MESSAGES](https://www.rfc-editor.org/rfc/inline-errata/rfc1035.html).
    pub fn to_query_bytes(&self) -> Vec<u8> {
        // We only need to include header and question secotions.
        let mut payload = self.header.to_be_bytes();
        payload.extend_from_slice(&self.question.to_bytes());

        payload
    }
}

impl Message {
    pub(crate) fn with_response(buf: &[u8], query: &Self) -> Result<Self, Error> {
        // headers take fixed 12 bytes (or 96 bits = 16 bits * 6 fields)
        let header = MessageHeader::try_from(&buf[0..=11])?;
        MessageHeader::validate(&query.header, &header)?;

        // question starts with 13th bytes but has variant length
        let (question, question_end) = MessageQuestion::from_response(buf, 12)?;
        MessageQuestion::validate(&query.question, &question)?;

        let mut last_pos = question_end;
        let mut answer_records = vec![];
        let mut authority_records = vec![];
        let mut additional_records = vec![];

        let rr_looper = vec![
            (header.an_count, &mut answer_records),
            (header.ns_count, &mut authority_records),
            (header.ar_count, &mut additional_records),
        ];

        for (count, records) in rr_looper {
            for _ in 0..count {
                let (resource_record, record_end) = ResourceRecord::from_response(buf, last_pos)?;
                records.push(resource_record);
                last_pos = record_end;
            }
        }

        Ok(Self {
            header,
            question,
            answers: answer_records,
            authorities: authority_records,
            additionals: additional_records,
        })
    }
}

// The header contains the following fields:
//
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug)]
pub struct MessageHeader {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

impl MessageHeader {
    fn with_qd_count(qd_count: u16) -> Self {
        Self {
            id: rand::thread_rng().gen(),
            // For a standard query, we only care about QR & OPCODE fields.
            // And QR = 0 stands for query (1 = response); OPCODE = 0 stands for standard query (1 = inverse query, etc)
            // So we can safely put a 0 here for a question header.
            flags: 0,
            qd_count,
            // Left 0 here because we don't need it in a question;
            an_count: 0,
            // Left 0 here because we don't need it in a question;
            ns_count: 0,
            // Left 0 here because we don't need it in a question;
            ar_count: 0,
        }
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        // See the representation on MessageHeader struct
        let mut header = Vec::with_capacity(12);
        // id header
        header.extend_from_slice(&self.id.to_be_bytes());
        // flag header
        header.extend_from_slice(&self.flags.to_be_bytes());
        // `QDCOUNT`: hardcoded `1` as we just have 1 question in question section.
        header.extend_from_slice(&self.qd_count.to_be_bytes());
        // `ANCOUNT` (the number of resource records in the answer section)
        header.extend_from_slice(&self.an_count.to_be_bytes());
        // `NSCOUNT` (the number of name server resource records in the authority records section)
        header.extend_from_slice(&self.ns_count.to_be_bytes());
        // `ARCOUNT` (the number of resource records in the additional records section)
        header.extend_from_slice(&self.ar_count.to_be_bytes());

        header
    }

    fn validate(question: &Self, response: &Self) -> Result<(), Error> {
        Self::check_rcode(&response.flags)?;

        if question.id == response.id && question.qd_count == response.qd_count
        // we don't compare other fields like an_count, ns_count, ar_count here as we don't have the corresponding data yet.
        {
            Ok(())
        } else {
            Err(Error::ResolverError("mismatched response header".into()))
        }
    }

    /// See [RFC 1035, 4.1.1. Header section format](https://www.rfc-editor.org/rfc/inline-errata/rfc1035.html).
    fn check_rcode(flags: &u16) -> Result<(), Error> {
        // Last 4 bit indicating the RCODE section
        let r_code = flags & 0x000F;

        match r_code {
            0 => Ok(()),
            _ => Err(Error::ServerError(NameServerError::from(r_code))),
        }
    }
}

impl TryFrom<&[u8]> for MessageHeader {
    type Error = Error;

    /// Try to construct a message from name server's response.
    fn try_from(header: &[u8]) -> Result<Self, Self::Error> {
        // See the representation on MessageHeader struct.
        // There are 6 sections in the header. Each section contains 16 bits (2 * u8).
        // Therefore the length of header is 12 (6 * 2 bytes)
        if header.len() != 12 {
            return Err(Error::ResolverError(format!(
                "can't parse response header with length: {}",
                header.len()
            )));
        }

        Ok(Self {
            id: u16::from_be_bytes([header[0], header[1]]),
            flags: u16::from_be_bytes([header[2], header[3]]),
            qd_count: u16::from_be_bytes([header[4], header[5]]),
            an_count: u16::from_be_bytes([header[6], header[7]]),
            ns_count: u16::from_be_bytes([header[8], header[9]]),
            ar_count: u16::from_be_bytes([header[10], header[11]]),
        })
    }
}

#[derive(Debug)]
pub struct MessageQuestion {
    domain: String,
    q_type: RecordType,
    q_class: RecordClass,
}

impl MessageQuestion {
    /// Construct a new question with given domain name.
    fn with_domain(domain: &str, record_type: &RecordType) -> Self {
        Self {
            domain: domain.to_string(),
            q_type: *record_type,
            q_class: RecordClass::IN,
        }
    }

    /// Construct a new question with response buffer.
    /// Returns the Question and the position where it ends
    fn from_response(buf: &[u8], start_pos: usize) -> Result<(Self, usize), Error> {
        let (domain, qname_end_pos) = utils::parse_domain(buf, start_pos)?;

        // qname_end is the 0 byte indicating QNAME's end, followed by 2 bytes for QTYPE, 2 bytes for QCLASS
        if qname_end_pos + 4 > buf.len() {
            return Err(Error::ResolverError(
                "Question field is our of bound".into(),
            ));
        }

        let q_type = RecordType::try_from(u16::from_be_bytes([
            buf[qname_end_pos],
            buf[qname_end_pos + 1],
        ]))?;

        let q_class = RecordClass::try_from(u16::from_be_bytes([
            buf[qname_end_pos + 2],
            buf[qname_end_pos + 3],
        ]))?;

        Ok((
            Self {
                domain,
                q_type,
                q_class,
            },
            qname_end_pos + 4,
        ))
    }

    fn to_bytes(&self) -> Vec<u8> {
        // The binary representation of Question section:
        //
        //                               1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                                               |
        // /                     QNAME                     /
        // /                                               /
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     QTYPE                     |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     QCLASS                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let mut question = self.build_qname();
        question.extend_from_slice(&self.q_type.to_u16().to_be_bytes());
        question.extend_from_slice(&self.q_class.to_u16().to_be_bytes());

        question
    }

    fn build_qname(&self) -> Vec<u8> {
        let mut qname = vec![];

        // A domain representation is made of labels.
        //
        // For domain "blog.wtcx.dev", we make it look like: `"4blog4wtcx3dev0"` in a byte array
        // the 0 byte indicates the domain (QNAME) is terminated.
        for label in self.domain.split('.') {
            qname.push(label.len() as u8);
            qname.extend_from_slice(label.as_bytes());
        }

        // Every domain ends with a null label.
        // > ...Since every domain name ends with the null label of the root, a domain name is terminated by a length byte of zero.
        //
        // Ref: [3.1. Name space definitions](https://www.rfc-editor.org/rfc/inline-errata/rfc1035.html)
        qname.push(0);

        qname
    }

    fn validate(query: &Self, response: &Self) -> Result<(), Error> {
        if query.domain == response.domain
            && query.q_class == response.q_class
            && query.q_type == response.q_type
        {
            Ok(())
        } else {
            Err(Error::ResolverError(
                "response data doesn't match question".into(),
            ))
        }
    }
}
