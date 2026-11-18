#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("TLS inspector stopped: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Live capture requires Linux; portable parser tests are available on this platform.");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use netspecter_tls_inspector::{
        output::{Observation, unix::Output},
        packet::parse_ethernet,
        reassembly::{Limits, Tracker},
    };
    use std::{
        path::PathBuf,
        sync::atomic::Ordering,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--version" {
        println!("netspecter-tls-inspector {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.len() != 3 {
        return Err("usage: netspecter-tls-inspector INTERFACE /absolute/metadata.sock".into());
    }
    let interface = &args[1];
    let socket = PathBuf::from(&args[2]);
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
        || !socket.is_absolute()
    {
        return Err("invalid capture interface or socket path".into());
    }
    let mut capture = pcap::Capture::from_device(interface.as_str())?
        .promisc(false)
        .snaplen(65_535)
        .buffer_size(4 * 1024 * 1024)
        .timeout(250)
        .immediate_mode(true)
        .open()?;
    if capture.get_datalink() != pcap::Linktype::ETHERNET {
        return Err("capture interface must provide Ethernet frames".into());
    }
    // Keep VLAN frames; the packet adapter validates their inner protocol.
    capture.filter(
        "tcp or ip6 or ether proto 0x8100 or ether proto 0x88a8",
        true,
    )?;
    let output = Output::spawn(socket);
    eprintln!("capture_ready");
    let mut tracker = Tracker::new(Limits::default());
    let origin = Instant::now();
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let mut next_report = 60_000;
    let mut unsupported = 0u64;
    let mut malformed = 0u64;
    let mut fragmented = 0u64;
    loop {
        let now = origin.elapsed().as_millis() as u64;
        match capture.next_packet() {
            Ok(packet) => match parse_ethernet(packet.data) {
                Ok((key, segment)) => {
                    let started = if segment.syn {
                        now
                    } else {
                        tracker.started_at(&key).unwrap_or(now)
                    };
                    if let Some(hello) = tracker.ingest(key.clone(), now, segment) {
                        output.send(Observation::new(key, hello, epoch + started, epoch + now));
                    }
                }
                Err(netspecter_tls_inspector::packet::PacketError::Malformed) => malformed += 1,
                Err(netspecter_tls_inspector::packet::PacketError::Fragmented) => fragmented += 1,
                Err(_) => unsupported += 1,
            },
            Err(pcap::Error::TimeoutExpired) => tracker.expire(now),
            Err(error) => return Err(error.into()),
        }
        if now >= next_report {
            let dropped = capture.stats().map(|s| s.dropped).unwrap_or_default();
            eprintln!(
                "connections={} reserved_bytes={} completed={} expired={} evicted={} invalid={} conflicts={} midstream={} segment_limit={} malformed={} fragmented={} unsupported={} capture_drops={} output_drops={}",
                tracker.connection_count(),
                tracker.reserved_bytes(),
                tracker.counters.completed,
                tracker.counters.expired,
                tracker.counters.evicted,
                tracker.counters.invalid,
                tracker.counters.conflicts,
                tracker.counters.midstream,
                tracker.counters.segment_limit,
                malformed,
                fragmented,
                unsupported,
                dropped,
                output.dropped.load(Ordering::Relaxed)
            );
            next_report = now + 60_000;
        }
    }
}
