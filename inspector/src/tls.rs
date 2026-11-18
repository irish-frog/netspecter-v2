use serde::Serialize;
use tls_parser::{TlsExtension, parse_tls_extension, parse_tls_handshake_client_hello};

pub const MAX_HELLO_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HelloMetadata {
    pub hostname: Option<String>,
    pub ech_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloResult {
    Incomplete,
    Invalid,
    Complete(HelloMetadata),
}

fn hostname(bytes: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(bytes).ok()?;
    if name.len() > 253 || !name.contains('.') || name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return None;
        }
    }
    Some(name.to_ascii_lowercase())
}

/// Parse only the initial ClientHello, which may span multiple TLS records.
/// An ECH outer name is deliberately suppressed rather than treated as service evidence.
pub fn inspect_client_hello(bytes: &[u8]) -> HelloResult {
    if bytes.len() > MAX_HELLO_BYTES {
        return HelloResult::Invalid;
    }
    let mut offset = 0;
    let mut handshake = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 5 {
            return HelloResult::Incomplete;
        }
        let header = &bytes[offset..offset + 5];
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != 22
            || header[1] != 3
            || !(1..=4).contains(&header[2])
            || length == 0
            || length > 16_384
        {
            return HelloResult::Invalid;
        }
        if bytes.len() - offset - 5 < length {
            return HelloResult::Incomplete;
        }
        handshake.extend_from_slice(&bytes[offset + 5..offset + 5 + length]);
        offset += 5 + length;
        if handshake.len() < 4 {
            continue;
        }
        if handshake[0] != 1 {
            return HelloResult::Invalid;
        }
        let hello_len = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | handshake[3] as usize;
        if hello_len + 4 > MAX_HELLO_BYTES {
            return HelloResult::Invalid;
        }
        if handshake.len() < hello_len + 4 {
            continue;
        }
        let Ok((remaining, hello)) = parse_tls_handshake_client_hello(&handshake[4..hello_len + 4])
        else {
            return HelloResult::Invalid;
        };
        if !remaining.is_empty() {
            return HelloResult::Invalid;
        }
        let mut extensions = hello.ext.unwrap_or_default();
        let mut found = None;
        let mut seen_types = std::collections::HashSet::new();
        let mut ech_present = false;
        while !extensions.is_empty() {
            if extensions.len() < 4 {
                return HelloResult::Invalid;
            }
            let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
            let size = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
            if extensions.len() < size + 4 || !seen_types.insert(kind) {
                return HelloResult::Invalid;
            }
            let encoded = &extensions[..size + 4];
            let Ok((rest, parsed)) = parse_tls_extension(encoded) else {
                return HelloResult::Invalid;
            };
            if !rest.is_empty() {
                return HelloResult::Invalid;
            }
            if kind == 0xfe0d {
                ech_present = true;
            }
            if let TlsExtension::SNI(names) = parsed {
                // Strictly check the SNI lengths; permissive nested parsers may accept trailing junk.
                let content = &encoded[4..];
                if content.len() < 5
                    || u16::from_be_bytes([content[0], content[1]]) as usize + 2 != content.len()
                    || names.len() != 1
                    || names[0].0.0 != 0
                    || u16::from_be_bytes([content[3], content[4]]) as usize + 5 != content.len()
                {
                    return HelloResult::Invalid;
                }
                found = hostname(names[0].1);
                if found.is_none() {
                    return HelloResult::Invalid;
                }
            }
            extensions = &extensions[size + 4..];
        }
        return HelloResult::Complete(HelloMetadata {
            hostname: if ech_present { None } else { found },
            ech_present,
        });
    }
    HelloResult::Incomplete
}
