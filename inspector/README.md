# Passive TLS inspector

Integrated passive sensor, local authenticated collector intake and measured-flow attribution. Deployment requires the verified prebuilt Linux bundle and the Linux pipeline checks. History reset remains explicit.

Rust 1.100.0 is pinned. Run `cargo test --locked`, `cargo fmt --check`, and `cargo clippy --locked --all-targets -- -D warnings` in this directory. Linux additionally needs the libpcap development package at build time, and the libpcap runtime at execution. No compiler is required on production appliances.

The portable library parses Ethernet/VLAN/IPv4/IPv6/TCP and reconstructs the initial TLS ClientHello. Opening SYN is required. Conflicting overlap, fragments, oversized input and stale connections are rejected. QUIC and encrypted ClientHello names are not decrypted. ECH outer names are suppressed. Only validated hostnames are emitted.

Limits: 4096 tracked connections (including completed tombstones); 64 KiB data and 64 KiB presence map per incomplete flow; 64 MiB aggregate reassembly allocation; 128 payload segments; 15-second idle and 30-second absolute lifetime. Memory pressure deterministically evicts oldest work. Completed buffers are freed immediately. A 1024-item output queue is nonblocking to capture; unavailable or slow consumers cause counted drops, never backpressure to network forwarding.

Linux command: `netspecter-tls-inspector br0 /run/netspecter-metadata/tls.sock`. This opens packet capture only, using temporary promiscuous capture membership on the bridge (required for forwarded frames), without packet injection. It does not configure the interface, bridge or firewall. The systemd template uses a dedicated account and CAP_NET_RAW, with 160 MiB and 50% CPU limits. A capture capability permits reading traffic and must never be granted to the web application.

A root-owned systemd socket unit must create a root-owned runtime directory with mode 0750 and group netspecter-metadata, then a root-owned UNIX stream socket with mode 0660 and pass its listening descriptor to the unprivileged collector. The sensor refuses world-accessible sockets and writable parent directories. The runtime directory is not created by the sensor. A dedicated group grants the sensor access to this socket only; the collector must independently validate metadata before persisting it.

JSONL schema v1: event_type=tls_client_hello; observed_at_unix_ms; connection_started_at_unix_ms; connection containing source, destination, source_port, destination_port (TCP); hostname (nullable); ech_present. No packet payload, certificate, TLS secret, URL or byte estimate. Hostnames are unauthenticated client claims. Correlate exact tuple and connection time with independently measured flow bytes. Never apply a name to all traffic sharing a remote address.

Every minute, journal counters report capture/output drops, malformed/fragmented/unsupported packets, expiry, memory pressure, overlap rejection, segment-limit rejection and completions. Unsupported is a packet counter, not an application coverage percentage. Windows tests validate the portable code only. Cross-target cargo check validates Linux code compilation but does not prove a linked Linux binary or live capture behavior.


The repository ships a CI-built Linux x86_64 binary under `prebuilt/linux-x86_64/`. `build.json` records its SHA-256, normalized source fingerprint, build commit, toolchain and minimum glibc. `build_manifest.py verify` rejects mismatched code or binary contents before installation. CI recompiles from the pinned toolchain/lockfile and exercises the real pipeline; no compiler is installed on appliances. Source fingerprint normalization only removes CRLF line-ending differences.

Primary bridge accounting currently covers IPv4 LANs and configured internal/VPN client networks with at most 1024 addresses per network and 4096 clients total. Larger networks remain destination exclusions. IPv6 packet parsing and NetFlow decoding are tested; global IPv6 client accounting needs explicit configured prefixes and is not included in the IPv4 bridge coverage headline. Unknown scope/encrypted names remain limitations rather than guessed applications.

SNI byte attribution requires the measured connection's opening timestamp (within the exporter clock resolution), both ports and both addresses. Later active-timeout intervals whose start no longer identifies the opening handshake use only unambiguous client DNS or remain unknown. Retaining a stale hostname for a reused tuple is prohibited.
