use etherparse::PacketBuilder;
use netspecter_tls_inspector::{
    packet::{PacketError, parse_ethernet},
    reassembly::{Limits, Tracker},
};
mod common;
#[test]
fn ipv4_packet_to_connection_to_observation() {
    let mut tracker = Tracker::new(Limits::default());
    for (syn, sequence, bytes) in [
        (true, 100, Vec::new()),
        (false, 101, common::hello(Some(b"example.com"), false)),
    ] {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([192, 0, 2, 1], [203, 0, 113, 1], 64)
            .tcp(12345, 443, sequence, 65535);
        let builder = if syn { builder.syn() } else { builder };
        let mut packet = Vec::new();
        builder.write(&mut packet, &bytes).unwrap();
        let (connection, segment) = parse_ethernet(&packet).unwrap();
        assert_eq!(connection.source_port, 12345);
        assert_eq!(connection.destination.to_string(), "203.0.113.1");
        let result = tracker.ingest(connection, 0, segment);
        if !syn {
            assert_eq!(result.unwrap().hostname.as_deref(), Some("example.com"));
        }
    }
}
#[test]
fn vlan_ipv6_preserves_exact_tuple() {
    let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
        .single_vlan(42.try_into().unwrap())
        .ipv6([1; 16], [2; 16], 64)
        .tcp(23456, 8443, 42, 65535)
        .syn();
    let mut bytes = Vec::new();
    builder.write(&mut bytes, &[]).unwrap();
    let (key, segment) = parse_ethernet(&bytes).unwrap();
    assert!(key.source.is_ipv6());
    assert_eq!(key.destination_port, 8443);
    assert!(segment.syn);
}
#[test]
fn fragmented_ipv4_and_udp_are_not_guessed() {
    let mut bytes = Vec::new();
    PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4([1; 4], [2; 4], 64)
        .tcp(1, 443, 1, 1024)
        .syn()
        .write(&mut bytes, &[])
        .unwrap();
    bytes[20] |= 0x20; // IPv4 more-fragments bit; checksums are intentionally not interpreted.
    assert!(matches!(
        parse_ethernet(&bytes),
        Err(PacketError::Fragmented)
    ));
    let mut udp = Vec::new();
    PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4([1; 4], [2; 4], 64)
        .udp(1, 443)
        .write(&mut udp, &[0; 24])
        .unwrap();
    assert!(matches!(
        parse_ethernet(&udp),
        Err(PacketError::Unsupported)
    ));
}
#[test]
fn truncated_and_random_frames_do_not_panic() {
    for length in 0..256 {
        let bytes = vec![0xff; length];
        assert!(parse_ethernet(&bytes).is_err());
    }
}
