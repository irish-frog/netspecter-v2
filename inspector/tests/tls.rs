use netspecter_tls_inspector::tls::{HelloMetadata, HelloResult, inspect_client_hello};

mod common;
use common::{hello, record};
#[test]
fn extracts_validated_lowercase_name() {
    assert_eq!(
        inspect_client_hello(&hello(Some(b"WWW.Example.com"), false)),
        HelloResult::Complete(HelloMetadata {
            hostname: Some("www.example.com".into()),
            ech_present: false
        })
    );
}
#[test]
fn all_truncations_are_incomplete() {
    let bytes = hello(Some(b"example.com"), false);
    for end in 0..bytes.len() {
        assert_eq!(inspect_client_hello(&bytes[..end]), HelloResult::Incomplete);
    }
}
#[test]
fn reconstructs_handshake_split_across_records() {
    let bytes = hello(Some(b"example.com"), false);
    for split in 1..bytes.len() - 5 {
        let mut divided = record(&bytes[5..5 + split]);
        divided.extend(record(&bytes[5 + split..]));
        assert_eq!(inspect_client_hello(&divided), inspect_client_hello(&bytes));
    }
}
#[test]
fn ech_outer_name_cannot_be_attributed() {
    assert_eq!(
        inspect_client_hello(&hello(Some(b"public.example.com"), true)),
        HelloResult::Complete(HelloMetadata {
            hostname: None,
            ech_present: true
        })
    );
}
#[test]
fn no_sni_is_explicit() {
    assert_eq!(
        inspect_client_hello(&hello(None, false)),
        HelloResult::Complete(HelloMetadata {
            hostname: None,
            ech_present: false
        })
    );
}
#[test]
fn rejects_invalid_hostnames() {
    for name in [
        b"<script>.com".as_slice(),
        b"a\nb.com",
        b"127.0.0.1",
        b"-bad.com",
        b"a..com",
        b"single",
        b"a.com.",
    ] {
        assert_eq!(
            inspect_client_hello(&hello(Some(name), false)),
            HelloResult::Invalid
        );
    }
}
#[test]
fn hostile_input_is_bounded_and_does_not_panic() {
    assert_eq!(
        inspect_client_hello(&vec![22; 65_537]),
        HelloResult::Invalid
    );
    for len in 0..1024 {
        let bytes: Vec<u8> = (0..len)
            .map(|n| ((n * 73 + len * 17) % 256) as u8)
            .collect();
        let _ = inspect_client_hello(&bytes);
    }
}
