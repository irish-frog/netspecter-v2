use netspecter_tls_inspector::reassembly::{Connection, Limits, Segment, Tracker};
fn key(port: u16) -> Connection {
    Connection {
        source: "192.0.2.1".parse().unwrap(),
        destination: "203.0.113.1".parse().unwrap(),
        source_port: port,
        destination_port: 443,
    }
}
fn segment(sequence: u32, syn: bool, payload: &[u8]) -> Segment<'_> {
    Segment {
        sequence,
        syn,
        fin: false,
        rst: false,
        payload,
    }
}
fn tracker() -> Tracker {
    Tracker::new(Limits {
        connections: 2,
        bytes_per_connection: 128,
        total_bytes: 512,
        idle_ms: 100,
        lifetime_ms: 200,
        max_segments: 128,
    })
}
#[test]
fn resource_pressure_evicts_and_releases_buffers() {
    let mut t = tracker();
    for port in 1..100 {
        t.ingest(key(port), 0, segment(1, true, &[]));
        assert!(t.connection_count() <= 2);
        assert!(t.reserved_bytes() <= 512);
    }
    assert_eq!(t.counters.evicted, 97);
    t.expire(100);
    assert_eq!(t.reserved_bytes(), 0);
    assert_eq!(t.connection_count(), 0);
}
#[test]
fn conflicts_fail_closed_and_cannot_restart_without_new_syn() {
    let mut t = tracker();
    t.ingest(key(1), 0, segment(10, true, &[]));
    t.ingest(key(1), 1, segment(11, false, &[22, 3]));
    t.ingest(key(1), 2, segment(11, false, &[22, 4]));
    assert_eq!(t.counters.conflicts, 1);
    assert_eq!(t.reserved_bytes(), 0);
    t.ingest(key(1), 3, segment(10, true, &[]));
    assert_eq!(t.reserved_bytes(), 0);
    t.ingest(key(1), 4, segment(100, true, &[]));
    assert_eq!(t.reserved_bytes(), 256);
}
#[test]
fn missing_syn_is_unknown() {
    let mut t = tracker();
    assert!(t.ingest(key(1), 0, segment(11, false, &[22, 3])).is_none());
    assert_eq!(t.counters.midstream, 1);
    assert_eq!(t.reserved_bytes(), 0);
}
#[test]
fn out_of_order_and_wrapped_sequence_are_accepted() {
    let mut t = tracker();
    t.ingest(key(1), 0, segment(u32::MAX - 1, true, &[]));
    t.ingest(key(1), 1, segment(1, false, &[0, 10]));
    t.ingest(key(1), 2, segment(u32::MAX, false, &[22, 3]));
    assert_eq!(t.counters.invalid, 0);
    assert_eq!(t.counters.conflicts, 0);
    // Duplicate overlapping bytes are harmless.
    t.ingest(key(1), 3, segment(u32::MAX, false, &[22, 3]));
    assert_eq!(t.counters.conflicts, 0);
}
#[test]
fn absolute_lifetime_applies_even_with_activity() {
    let mut t = tracker();
    t.ingest(key(1), 0, segment(10, true, &[]));
    for now in [50, 100, 150] {
        t.ingest(key(1), now, segment(11, false, &[]));
    }
    t.expire(200);
    assert_eq!(t.connection_count(), 0);
}
#[test]
fn oversized_and_far_segments_release_memory() {
    let mut t = tracker();
    t.ingest(key(1), 0, segment(10, true, &[]));
    t.ingest(key(1), 1, segment(1000, false, &[1]));
    assert_eq!(t.counters.invalid, 1);
    assert_eq!(t.reserved_bytes(), 0);
}

mod common;
#[test]
fn every_split_reassembles_one_hello_even_out_of_order() {
    let bytes = common::hello(Some(b"example.com"), false);
    for split in 1..bytes.len() {
        let mut t = tracker();
        t.ingest(key(1), 0, segment(100, true, &[]));
        assert!(
            t.ingest(
                key(1),
                1,
                segment(101 + split as u32, false, &bytes[split..])
            )
            .is_none()
        );
        let observation = t
            .ingest(key(1), 2, segment(101, false, &bytes[..split]))
            .unwrap();
        assert_eq!(observation.hostname.as_deref(), Some("example.com"));
        assert!(t.ingest(key(1), 3, segment(101, false, &bytes)).is_none());
        assert_eq!(t.counters.completed, 1);
        assert_eq!(t.reserved_bytes(), 0);
    }
}
#[test]
fn segment_count_bounds_repeated_work() {
    let mut t = tracker();
    t.ingest(key(1), 0, segment(100, true, &[]));
    for _ in 0..129 {
        t.ingest(key(1), 1, segment(103, false, &[3]));
    }
    assert_eq!(t.counters.segment_limit, 1);
    assert_eq!(t.reserved_bytes(), 0);
}
