use netspecter_tls_inspector::{output::Observation, reassembly::Connection, tls::HelloMetadata};
#[test]
fn wire_contract_is_versioned_and_contains_no_payload_or_byte_claim() {
    let observation = Observation::new(
        Connection {
            source: "192.0.2.1".parse().unwrap(),
            destination: "203.0.113.1".parse().unwrap(),
            source_port: 12345,
            destination_port: 443,
        },
        HelloMetadata {
            hostname: Some("example.com".into()),
            ech_present: false,
        },
        1000,
        1500,
    );
    let bytes = observation.json_line().unwrap();
    assert_eq!(bytes.last(), Some(&b'\n'));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["connection"]["source"], "192.0.2.1");
    assert_eq!(value["connection_started_at_unix_ms"], 1000);
    assert_eq!(value["hostname"], "example.com");
    for key in ["payload", "bytes", "url", "certificate", "secret"] {
        assert!(value.get(key).is_none());
    }
}
