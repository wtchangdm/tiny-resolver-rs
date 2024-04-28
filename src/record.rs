use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{utils, Error};

/// See See [RFC 1035, 3.2.2. TYPE values](https://www.rfc-editor.org/rfc/inline-errata/rfc1035.html).
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RecordType {
    /// host address
    A = 1,
    /// authoritative name server
    NS = 2,
    /// mail destination (Obsolete - use MX)
    MD = 3,
    /// mail forwarder (Obsolete - use MX)
    MF = 4,
    /// the canonical name for an alias
    CNAME = 5,
    /// marks the start of a zone of authority
    SOA = 6,
    /// mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// mail group member (EXPERIMENTAL)
    MG = 8,
    /// mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// null RR (EXPERIMENTAL)
    NULL = 10,
    /// well known service description
    WKS = 11,
    /// domain name pointer
    PTR = 12,
    /// host information
    HINFO = 13,
    /// mailbox or mail list information
    MINFO = 14,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
    /// IPv6 address
    AAAA = 28,
}

impl RecordType {
    pub fn to_u16(&self) -> u16 {
        *self as u16
    }
}

impl TryFrom<u16> for RecordType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(RecordType::A),
            2 => Ok(RecordType::NS),
            3 => Ok(RecordType::MD),
            4 => Ok(RecordType::MF),
            5 => Ok(RecordType::CNAME),
            6 => Ok(RecordType::SOA),
            7 => Ok(RecordType::MB),
            8 => Ok(RecordType::MG),
            9 => Ok(RecordType::MR),
            10 => Ok(RecordType::NULL),
            11 => Ok(RecordType::WKS),
            12 => Ok(RecordType::PTR),
            13 => Ok(RecordType::HINFO),
            14 => Ok(RecordType::MINFO),
            15 => Ok(RecordType::MX),
            16 => Ok(RecordType::TXT),
            // RFC 3596: https://www.rfc-editor.org/rfc/rfc3596.html
            // The AAAA resource record type is a record specific to the Internet class that stores a single IPv6 address.
            // The IANA assigned value of the type is 28 (decimal).
            28 => Ok(RecordType::AAAA),
            _ => Err(Error::ResolverError(format!(
                "can't parse unknown record type: {value}"
            ))),
        }
    }
}

/// See See [RFC 1035, 3.2.3. QTYPE values](https://www.rfc-editor.org/rfc/inline-errata/rfc1035.html).
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RecordClass {
    /// The Internet. We probably only care about this.
    IN = 1,
    /// The CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS = 2,
    /// The CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
}

impl RecordClass {
    pub fn to_u16(&self) -> u16 {
        *self as u16
    }
}

impl TryFrom<u16> for RecordClass {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(RecordClass::IN),
            2 => Ok(RecordClass::CS),
            3 => Ok(RecordClass::CH),
            4 => Ok(RecordClass::HS),
            _ => Err(Error::ResolverError(format!(
                "unknown RR class: {}",
                value
            ))),
        }
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum RecordData {
    CNAME(String),
    NS(String),
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    SOA(SoaRecord),
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SoaRecord {
    m_name: String,
    r_name: String,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

impl RecordData {
    /// Returns the Question and the position where it ends
    pub fn from_response(
        buf: &[u8],
        record_type: &RecordType,
        start_pos: usize,
    ) -> Result<(RecordData, usize), Error> {
        match record_type {
            RecordType::A => Self::parse_a(buf, start_pos),
            RecordType::AAAA => Self::parse_aaaa(buf, start_pos),
            RecordType::CNAME => Self::parse_cname(buf, start_pos),
            RecordType::NS => Self::parse_ns(buf, start_pos),
            RecordType::SOA => Self::parse_soa(buf, start_pos),
            _ => unimplemented!(),
        }
    }

    /// A record has fixed 32 bit IPv4 data
    fn parse_a(buf: &[u8], start_pos: usize) -> Result<(RecordData, usize), Error> {
        let len = start_pos + 4;

        if buf.len() < len {
            return Err(Error::ResolverError(format!(
                "can't parse IPv4 address with length {}, expect {}",
                buf.len(),
                len
            )));
        }

        let ip = Ipv4Addr::from(u32::from_be_bytes([
            buf[start_pos],
            buf[start_pos + 1],
            buf[start_pos + 2],
            buf[start_pos + 3],
        ]));

        Ok((RecordData::A(ip), len))
    }

    /// AAAA record has fixed 128 bit IPv6 data
    fn parse_aaaa(buf: &[u8], start_pos: usize) -> Result<(RecordData, usize), Error> {
        let len = start_pos + 16;

        if buf.len() < len {
            return Err(Error::ResolverError(format!(
                "can't parse IPv6 address with length {}, expect {}",
                buf.len(),
                len
            )));
        }

        let ip = Ipv6Addr::from([
            u16::from_be_bytes([buf[start_pos], buf[start_pos + 1]]),
            u16::from_be_bytes([buf[start_pos + 2], buf[start_pos + 3]]),
            u16::from_be_bytes([buf[start_pos + 4], buf[start_pos + 5]]),
            u16::from_be_bytes([buf[start_pos + 6], buf[start_pos + 7]]),
            u16::from_be_bytes([buf[start_pos + 8], buf[start_pos + 9]]),
            u16::from_be_bytes([buf[start_pos + 10], buf[start_pos + 11]]),
            u16::from_be_bytes([buf[start_pos + 12], buf[start_pos + 13]]),
            u16::from_be_bytes([buf[start_pos + 14], buf[start_pos + 15]]),
        ]);

        Ok((RecordData::AAAA(ip), len))
    }

    fn parse_cname(buf: &[u8], start_pos: usize) -> Result<(RecordData, usize), Error> {
        let (domain, domain_end) = utils::parse_domain(buf, start_pos)?;

        Ok((RecordData::CNAME(domain), domain_end))
    }

    fn parse_ns(buf: &[u8], start_pos: usize) -> Result<(RecordData, usize), Error> {
        let (domain, domain_end) = utils::parse_domain(buf, start_pos)?;

        Ok((RecordData::NS(domain), domain_end))
    }

    fn parse_soa(buf: &[u8], start_pos: usize) -> Result<(RecordData, usize), Error> {
        let (m_name, domain_end) = utils::parse_domain(buf, start_pos)?;
        let (r_name, domain_end) = utils::parse_domain(buf, domain_end)?;

        let len = domain_end + 20;

        if buf.len() < len {
            return Err(Error::ResolverError(format!(
                "can't parse SOA record with length {}, expect {}",
                buf.len(),
                len
            )));
        }

        let serial = u32::from_be_bytes([
            buf[domain_end],
            buf[domain_end + 1],
            buf[domain_end + 2],
            buf[domain_end + 3],
        ]);

        let refresh = i32::from_be_bytes([
            buf[domain_end + 4],
            buf[domain_end + 5],
            buf[domain_end + 6],
            buf[domain_end + 7],
        ]);

        let retry = i32::from_be_bytes([
            buf[domain_end + 8],
            buf[domain_end + 9],
            buf[domain_end + 10],
            buf[domain_end + 11],
        ]);

        let expire = i32::from_be_bytes([
            buf[domain_end + 12],
            buf[domain_end + 13],
            buf[domain_end + 14],
            buf[domain_end + 15],
        ]);

        let minimum = u32::from_be_bytes([
            buf[domain_end + 16],
            buf[domain_end + 17],
            buf[domain_end + 18],
            buf[domain_end + 19],
        ]);

        Ok((
            RecordData::SOA(SoaRecord {
                m_name,
                r_name,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            }),
            len,
        ))
    }
}

// 4.1.3. Resource record format
//
// The answer, authority, and additional sections all share the same
// format: a variable number of resource records, where the number of
// records is specified in the corresponding count field in the header.
// Each resource record has the following format:
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                                               /
//     /                      NAME                     /
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     CLASS                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TTL                      |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                   RDLENGTH                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//     /                     RDATA                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
/// See See [RFC 1035, section 4.1.3. Resource record format](https://www.rfc-editor.org/rfc/inline-errata/rfc1035.html).
#[derive(Debug)]
pub struct ResourceRecord {
    /// `NAME`: a domain name to which this resource record pertains
    pub name: String,
    /// `TYPE`: two octets containing one of the RR type codes.
    /// This field specifies the meaning of the data in the RDATA field.
    pub r_type: RecordType,
    // `CLASS`: two octets which specify the class of the data in the RDATA field.
    pub r_class: RecordClass,
    // `TTL`: a 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded.
    // Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached.
    pub ttl: u32,
    // `RDLENGTH`: an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    pub rd_length: u16,
    // `RDATA`: a variable length string of octets that describes theresource.
    // The format of this information varies according to the TYPE and CLASS of the resource record.
    // For example, the if the TYPE is A and the CLASS is IN, the RDATA field is a 4 octet ARPA Internet address.
    pub r_data: RecordData,
}

impl ResourceRecord {
    /// Construct a new question with response buffer.
    /// Returns the resource record and the position where it ends
    pub(crate) fn from_response(buf: &[u8], start_pos: usize) -> Result<(Self, usize), Error> {
        let (name, name_end) = utils::parse_domain(buf, start_pos)?;

        // There need to be at least 2 + 2 + 4 + 2 bytes for TYPE, CLASS, TTL, and RDLENGTH fields.
        if buf.len() < name_end + 10 {
            return Err(Error::ResolverError(
                "resource record is out of bound".into(),
            ));
        }

        let rr_type = RecordType::try_from(u16::from_be_bytes([buf[name_end], buf[name_end + 1]]))?;
        let rr_class =
            RecordClass::try_from(u16::from_be_bytes([buf[name_end + 2], buf[name_end + 3]]))?;
        let ttl = u32::from_be_bytes([
            buf[name_end + 4],
            buf[name_end + 5],
            buf[name_end + 6],
            buf[name_end + 7],
        ]);
        let rd_length = u16::from_be_bytes([buf[name_end + 8], buf[name_end + 9]]);
        let rdata_len = name_end + 10 + rd_length as usize;

        if buf.len() < rdata_len {
            return Err(Error::ResolverError(format!(
                "resource record doesn't contain enough space for RDATA, expect: {}, got: {}",
                rdata_len,
                buf.len()
            )));
        }

        let (r_data, rdata_end) = RecordData::from_response(buf, &rr_type, name_end + 10)?;

        let rr = Self {
            name,
            r_type: rr_type,
            r_class: rr_class,
            ttl,
            rd_length,
            r_data,
        };

        Ok((rr, rdata_end))
    }

    pub fn ipv4_ip(&self) -> Option<Ipv4Addr> {
        match self.r_data {
            RecordData::A(ip) => Some(ip),
            _ => None,
        }
    }
}
