# Spec: tls-metadata

Status: approved by the operator on 2026-11-18. Traces to tls-metadata in attribution-rebuild-capabilities.md.

## Objective
Replace the retired IDS dependency with a passive metadata sensor. Observe TLS ClientHello SNI on the configured bridge, associate it with the exact TCP connection and timestamp, and emit metadata for flow attribution. Do not decrypt TLS or alter traffic. Sensor failure must leave forwarding and DNS functional.

## Tech stack
Rust 1.100.0; pcap 2.5.0, etherparse 0.21.0, tls-parser 0.12.2, serde and serde_json, pinned in Cargo.lock. Windows development tests exercise parsing and reassembly without packet capture; deployment targets Debian 13 x86_64 Linux. Local toolchain installation was selected by the operator. Linux packaging must be tested before deployment; a Windows executable cannot run on the appliances.

## Interface
Versioned JSON lines over a filesystem UNIX socket on Linux. The collector owns the socket with restrictive group permissions. No TCP listener. Each observation contains schema_version, observed_at, address family, source/destination IP and port, protocol, validated hostname, evidence type, and limitation flags. No TLS secrets, certificates, raw payload, or URLs. Treat SNI as unauthenticated client-supplied evidence, never as an authorization fact.

Emit ECH presence as a limitation; an outer/public hostname cannot justify confident application attribution. Unsupported QUIC remains unknown. A metadata observation alone contributes zero attributed bytes. Exact tuple and bounded time correlation is the responsibility of flow-attribution.

## Commands
From inspector/: cargo test --locked; cargo fmt --check; cargo clippy --locked --all-targets -- -D warnings. On Linux: cargo build --locked --release. Capture requires the explicitly configured bridge and narrowly scoped CAP_NET_RAW; parsing tests require no privileges.

## Project structure
inspector/Cargo.toml and Cargo.lock; inspector/src/ for packet parsing, bounded reassembly, TLS extraction and Linux capture adapter; inspector/tests/ for synthetic fixtures; systemd/ for a hardened service; docs/engineering/ for contracts and deployment instructions.

## Code style
Use descriptive snake_case names, explicit Result errors, rustfmt defaults and no unsafe application code. Example: `fn parse_client_hello(bytes: &[u8]) -> Result<Option<TlsObservation>, ParseError>`. Never panic on packet contents. Reject malformed hostnames rather than exposing control characters in logs/UI.

## Testing strategy
Synthetic offline cases cover fragmented ClientHello across records/segments, duplicates, retransmissions, out-of-order segments, sequence wrap, connection reuse, IPv4/IPv6, invalid lengths, truncated frames, ECH and absent SNI. Resource tests verify deterministic eviction and bounded buffers. Linux integration tests verify capture/interface failure, socket permissions, dropped-output behavior and forwarding independence. Run the existing Python suite after integration.

## Boundaries
Always: bound memory, pending flows, ClientHello length, fragment count and flow lifetime; publish counters for dropped/expired/unsupported observations; fail closed for attribution, not network forwarding. Starting limits: 4096 pending connections, 64 KiB per connection, 64 MiB aggregate reassembly, 15 seconds idle, 30 seconds absolute lifetime, bounded output queue of 1024 observations. Evict oldest incomplete work under pressure and expose drops.
Ask first: new public ports, payload retention, TLS interception, automatic resets or changes to these approved privacy boundaries.
Never: commit secrets; grant broad privileges to the web app; install compilers on production as part of normal updates; store packet captures; infer byte ownership from a shared IP alone.

## Success criteria
Offline tests prove extraction and safe rejection for the cases above. Memory and queues remain bounded under adversarial input. Linux service starts without Suricata and without a network listener; failure does not interrupt bridge/DNS. Only connection metadata crosses IPC. Deployment remains blocked until a Linux executable and service integration are verified.

## Open questions
Linux build route on this Windows development PC must be established without a compiler workload on production. Do not pretend native Windows compilation validates Linux capture.
