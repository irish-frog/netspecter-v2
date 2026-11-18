# Spec: flow-attribution

Status: approved by the operator on 2026-11-18. Module: flow-attribution. Depends on tls-metadata.

## Objective
Combine device identity, client-aware AdGuard DNS, exact TLS connection metadata and independently measured flows. Replace shared-destination guesses with evidence that explains both known applications and remaining unknown traffic. Preserve edited device names and custom classification rules.

## Stack and commands
Existing Python/SQLite collector and classification services; no new public listener or external enrichment API. Rust sensor JSONL schema v1 is the input contract. Run `python -m pytest -q` and focused `python -m pytest -q tests/test_flow_attribution.py tests/test_tls_metadata_receiver.py tests/test_netflow_measurements.py` from repository root. Rust checks remain those in SPEC-tls-metadata.md.

## Structure and contracts
- services/tls_metadata_service.py validates a bounded JSON line and writes connection metadata to a dedicated traffic-database table, independent of ids_events.
- A root-owned systemd UNIX socket (0750 parent, 0660 socket) passes its listening descriptor to the existing unprivileged collector. Dedicated sensor group grants socket access. Do not run the collector as root to create this path.
- services/flow_attribution_service.py correlates source/destination address, both ports, TCP protocol and connection time. Flow observations carry export identity, start/end timestamps, direction, measured bytes/packets and a stable deduplication key.
- Refactor NetFlow parsing into a testable service. Decode exporter uptime/first/last switched timestamps, sequence/session information, IPv4/IPv6 where exported, bounded templates and exact record identity. Bind NetFlow only to loopback; validate the exporter source and packet size. Truncated/malformed or unsupported measurements remain unclassified rather than fabricated.
- Store measured directional flow rows and their attribution as the authoritative application evidence. Preserve bridge counters as the independent internet-usage source. Never add a flow export to bridge totals. Duplicate exports must not add bytes twice. Active-timeout exports representing successive intervals are distinct, not duplicates.
- Application precedence: explicit operator rules, exact connection SNI, client/time/TTL-scoped DNS with unambiguous application, otherwise unknown. ECH outer names cannot supply SNI classification. Conflicting DNS candidates remain ambiguous unless they all identify the same application. Do not select the newest DNS name arbitrarily on a shared IP. An unrecognized exact hostname remains visible as a known hostname with unknown application.
- Sensor observations contribute no bytes themselves. An SNI match cannot label other connections to a CDN IP. Missing/ambiguous connection times, tuple reuse, exporter gaps and unsupported encryption retain explicit unknown reasons.
- Apply internet scope consistently to flow measurements, all attribution numerators and denominators: exclude configured LAN/VPN/internal transfers, non-global destinations and local service traffic. The client's VPN pool is configured on that client only. Routed VPN internet use can count where visible; VPN/server transfers cannot. Never guess individual VPN users from an outer encrypted tunnel or a router MAC.
- Coverage presents eligible bridge bytes, measured-flow bytes and attributed-flow bytes separately. Use comparable settled time windows and show lag/mismatch. Never improve the headline merely by shrinking its denominator, double-counting exports or hiding unobserved bridge traffic. If measured byte totals disagree, show the discrepancy rather than silently claiming complete coverage.

## Code style
Use small typed/validated data objects, parameterized SQL and explicit unknown reasons. Example: `Attribution(application=None, evidence="none", reason="ambiguous_dns")`. Reuse existing transaction and split-database helpers. Do not retain an IP-only classification cache as if it were exact connection evidence.

## Testing
Synthetic v5/v9 export fixtures cover timestamps/uptime wrap, duplicates, active intervals, template bounds, malformed input, IPv6 and exporter restart. Correlation tests cover same CDN with different applications, reversed download direction, tuple reuse, late metadata/export, unique versus conflicting client DNS, ECH, manual overrides and internal/VPN transfers. Socket tests cover oversized/control-character input, unauthorized peer, unavailable sensor, malformed JSON, descriptor validation and bounded buffering. Existing suite must pass.

## Boundaries and acceptance
Always validate IPC independently of the sensor, enforce bounded readers/batches/retention and preserve forwarding/DNS on failure. Keep learned data out of settings. Never store packet payload or reactivate IDS. No remote DNS enrichment that alters AdGuard behavior. Success: exact measured connections can be attributed end to end, duplicate exports do not change totals, internal transfers add zero internet/application bytes, ambiguous traffic remains explicit, and the two appliances can update without a compiler.
