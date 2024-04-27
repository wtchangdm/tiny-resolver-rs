use tiny_resolver_rs::{query, RecordData, RecordType};

fn main() {
    for domain in ["blog.wtcx.dev", "www.google.com", "www.facebook.com"] {
        let record_type = RecordType::A;
        let res = query(domain, &record_type).unwrap();

        for answer in res.answers {
            let result: String = match answer.r_data {
                RecordData::A(ip) => ip.to_string(),
                RecordData::CNAME(domain) => domain,
                RecordData::NS(domain) => domain,
                _ => unimplemented!(),
            };

            println!("{} -> {}", domain, result);
        }
    }
}
