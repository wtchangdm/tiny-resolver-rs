use crate::record::*;
use crate::Error;
use crate::{message::Message, utils};
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::net::Ipv4Addr;
use std::net::UdpSocket;

struct Resolver;

const MAX_ATTEMPTS: usize = 5;

impl Resolver {
    fn extract_domains(records: &[ResourceRecord], record_type: &RecordType) -> Vec<String> {
        records
            .iter()
            .filter(|rr| rr.r_type == *record_type)
            .filter_map(|rr| match &rr.r_data {
                RecordData::NS(domain) => Some(domain.to_owned()),
                _ => None,
            })
            .collect()
    }

    fn extract_ipv4_ips(records: &[ResourceRecord]) -> Vec<Ipv4Addr> {
        records
            .iter()
            .filter_map(|rr| {
                if rr.r_type == RecordType::A {
                    rr.ipv4_ip()
                } else {
                    None
                }
            })
            .collect()
    }

    fn pick_random<T>(candicates: &[T]) -> Result<T, Error>
    where
        T: Clone,
    {
        let mut rng = thread_rng();
        let res = candicates
            .choose(&mut rng)
            .ok_or_else(|| Error::ResolverError("can't pick name server".into()))?
            .to_owned();

        Ok(res)
    }

    fn resolve(domain: &str, record_type: &RecordType) -> Result<Message, Error> {
        println!("Looking up {domain}");

        let mut attempts = 0;
        let mut name_server_ip = Self::pick_random(&ROOT_NAME_SERVERS_V4)?;
        let mut message = Self::resolve_answer(domain, record_type, &name_server_ip)?;

        while attempts < MAX_ATTEMPTS {
            if !message.answers.is_empty() {
                return Ok(message);
            }

            // Use name server IPs from "additional" fields in resource records
            name_server_ip = if !message.additionals.is_empty() {
                let name_server_ips = Self::extract_ipv4_ips(&message.additionals);
                let ip = Self::pick_random(&name_server_ips)?;
                println!("got {ip} from additional sections");
                ip
            }
            // If there is no IP from additional resource records, we need to parse from authority domains
            // e.g., max.ns.cloudflare.com (the authoritative server for blog.wtcx.dev)
            else if !message.authorities.is_empty() {
                let name_server_domains: Vec<_> =
                    Self::extract_domains(&message.authorities, &RecordType::NS);
                let name_server_domain = Self::pick_random(&name_server_domains)?;
                let ns_message = Self::resolve(&name_server_domain, &RecordType::A)?;
                let name_server_ips = Self::extract_ipv4_ips(&ns_message.answers);
                println!("Looking up {domain} using {name_server_ip} ({name_server_domain})");
                Self::pick_random(&name_server_ips)?
            } else {
                return Err(Error::ResolverError(
                    "it's really impossible but let's just explode".into(),
                ));
            };

            println!("continue to look up {domain} with name server IP {name_server_ip}");
            message = Self::resolve_answer(domain, record_type, &name_server_ip)?;

            attempts += 1;
        }

        Err(Error::ResolverError(format!(
            "problem resolving address: {domain}"
        )))
    }

    fn resolve_answer(
        domain: &str,
        record_type: &RecordType,
        name_server_ip: &Ipv4Addr,
    ) -> Result<Message, Error> {
        let query = Message::new_query(domain, record_type);
        let addr = format!("{name_server_ip}:53");
        // port 0 = randomly picked by OS
        // -> called `Result::unwrap()` on an `Err` value: NetworkError(Os { code: 49, kind: AddrNotAvailable, message: "Can't assign requested address" })
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(Error::NetworkError)?;
        let bytes_sent = socket
            .send_to(&query.to_query_bytes(), addr)
            .map_err(Error::NetworkError)?;

        // 4.2.1. UDP usage
        // ...Messages carried by UDP are restricted to 512 bytes (not counting the IP or UDP headers).
        let mut response = [0; 512];
        let bytes_received = socket.recv(&mut response).map_err(Error::NetworkError)?;

        println!("sent: {bytes_sent} bytes, received: {bytes_received} bytes");

        Message::with_response(&response, &query)
    }
}

/// Currently supported DNS query protocols.
#[non_exhaustive]
#[derive(Debug)]
pub enum Protocol {
    DOH,
    DOT,
    TCP,
    UDP,
}

const ROOT_NAME_SERVERS_V4: [Ipv4Addr; 13] = [
    Ipv4Addr::new(198, 41, 0, 4),     // a.root-servers.net
    Ipv4Addr::new(170, 247, 170, 2),  // b.root-servers.net
    Ipv4Addr::new(192, 33, 4, 12),    // c.root-servers.net
    Ipv4Addr::new(199, 7, 91, 13),    // d.root-servers.net
    Ipv4Addr::new(192, 203, 230, 10), // e.root-servers.net
    Ipv4Addr::new(192, 5, 5, 241),    // f.root-servers.net
    Ipv4Addr::new(192, 112, 36, 4),   // g.root-servers.net
    Ipv4Addr::new(198, 97, 190, 53),  // h.root-servers.net
    Ipv4Addr::new(192, 36, 148, 17),  // i.root-servers.net
    Ipv4Addr::new(192, 58, 128, 30),  // j.root-servers.net
    Ipv4Addr::new(193, 0, 14, 129),   // k.root-servers.net
    Ipv4Addr::new(199, 7, 83, 42),    // l.root-servers.net
    Ipv4Addr::new(202, 12, 27, 33),   // m.root-servers.net
];

/// Query domain with given domain, protocol, and type.
///
/// ```
/// use tiny_resolver_rs::{query, Protocol, RecordType};
/// let record_type = RecordType::A;
/// let res = query("google.com", &record_type).unwrap();
/// ```
pub fn query(domain: &str, record_type: &RecordType) -> Result<Message, Error> {
    utils::validate_domain(domain)?;

    Resolver::resolve(domain, record_type)
}
