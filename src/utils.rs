use std::collections::HashSet;

use crate::error::Error;

/// Parse domain name with various length of byte array. Returns the domain and where the domain ends.
///
/// Thanks to ChatGPT
pub(crate) fn parse_domain(buf: &[u8], start_pos: usize) -> Result<(String, usize), Error> {
    let mut domain = String::new();
    let mut stack = vec![start_pos];
    let mut set_end = false;
    let mut end = 0;
    let mut visited = HashSet::new();

    while let Some(mut curr_pos) = stack.pop() {
        if visited.contains(&curr_pos) {
            return Err(Error::ResolverError("found recursive pointer".into()));
        }
        visited.insert(curr_pos);

        // 0 byte indicates the end of domain.
        while buf[curr_pos] != 0 {
            // There are two kinds of domain representation.
            // One is uncompressed and contains every label. there will be a byte indicating the lenth and characters followed by the byte.
            // The QNAME format will look like: "4blog4wtcx3dev0"
            //
            // Another one is compressed format.
            //
            // Whether a domain is compressed can be checked with the first 2 bits of length.
            // A label (e.g., "blog" of blog.wtcx.dev) can only be at most 63 characters long.
            // This limitation leaves the first two bits of a byte unused.
            //
            // If the first two bit is "00", it's the uncompressed format and the length number indicates how many characters
            // after the length byte is the actual label. i.e., the first byte of "4wtcx" is 0x04 and the next 4 byte is the actual label.
            //
            // Otherwise, if the first two bits of the byte is 11, meaning the domain is compressed.
            // We will need to take the rest 6 bit + next 8 bit to calculate the offset and fetch the rest of domain from there.
            //
            // [RFC 1035, 4.1.4. Message compression](https://www.rfc-editor.org/rfc/inline-errata/rfc1035.html).
            let len = buf[curr_pos] as usize;
            // 0xC0 = 0b11000000
            // Check the two bits of the pointer are "11".
            let is_compressed = len & 0xC0 == 0xC0;

            if is_compressed {
                if curr_pos + 1 >= buf.len() {
                    return Err(Error::ResolverError("QNAME is malformed".into()));
                }

                // 0x3FFF = 0b0011111111111111, use this to set first 2 bits (out of 16 bits) of the pointer to zero.
                let offset =
                    (u16::from_be_bytes([buf[curr_pos], buf[curr_pos + 1]]) & 0x3FFF) as usize;
                if offset >= buf.len() {
                    return Err(Error::ResolverError("offset is out of bounds".into()));
                }

                stack.push(offset);

                if !set_end {
                    end = curr_pos + 2;
                    set_end = true;
                }
                break;
            } else {
                curr_pos += 1;

                if curr_pos + len >= buf.len() {
                    return Err(Error::ResolverError("QNAME is out of bound".into()));
                }

                let label = std::str::from_utf8(&buf[curr_pos..curr_pos + len])
                    .map_err(|_| Error::ResolverError("QNAME contains invalid characters".into()))?;
                domain.push_str(label);

                curr_pos += len;

                if buf[curr_pos] != 0 {
                    domain.push('.');
                }

                if !set_end {
                    end = curr_pos + 1;
                }
            }
        }
    }

    Ok((domain, end))
}

/// Validates whether a domain is eligible for query.
pub(crate) fn validate_domain(domain: &str) -> Result<(), Error> {
    // handle trailing dot of FQDN
    let domain = domain.trim_end_matches('.');

    if domain.is_empty() || domain.len() > 255 {
        return Err(Error::InvalidHostname);
    }

    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::InvalidHostname);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidHostname);
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return Err(Error::InvalidHostname);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_domain() {
        assert_eq!(validate_domain(""), Err(Error::InvalidHostname));
    }

    #[test]
    fn test_hyphen_domain() {
        assert_eq!(validate_domain("-"), Err(Error::InvalidHostname));
    }

    #[test]
    fn test_domain_starts_with_hyphen() {
        assert_eq!(validate_domain("-.google.com"), Err(Error::InvalidHostname));
    }

    #[test]
    fn test_domain_ends_with_hyphen() {
        assert_eq!(validate_domain("google.com-"), Err(Error::InvalidHostname));
    }

    #[test]
    fn test_domain_with_invalid_chars() {
        assert_eq!(
            validate_domain("www#google.com"),
            Err(Error::InvalidHostname)
        );
    }

    #[test]
    fn test_domain_with_invalid_label() {
        assert_eq!(validate_domain("..google.com"), Err(Error::InvalidHostname));
    }

    #[test]
    fn test_domain_with_trailing_dot() {
        assert!(validate_domain("google.com.").is_ok());
    }
}
