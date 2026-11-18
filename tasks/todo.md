# Attribution rebuild tasks

## tls-metadata (specification approved)

- [ ] 1. Establish portable metadata parsing.
  - Acceptance: versioned observation contract; validated DNS hostnames; malformed/ECH/absent-SNI input never becomes confident application evidence.
  - Verify: cargo test --locked, cargo fmt --check, cargo clippy --locked --all-targets -- -D warnings.
  - Dependencies: none. Files: inspector/Cargo.toml, Cargo.lock, src/lib.rs, src/tls.rs, tests/tls.rs.
- [ ] 2. Add bounded TCP reconstruction.
  - Acceptance: valid segmented hellos produce one observation; retransmits/out-of-order segments are handled; conflicting overlaps, midstream/reused sessions and expiry are rejected safely; global/per-flow limits enforced.
  - Verify: synthetic segment, resource-pressure, sequence-wrap and reuse tests via cargo test --locked.
  - Dependencies: 1. Files: src/reassembly.rs, src/lib.rs, tests/reassembly.rs.
- [ ] Checkpoint: review portable parsing and resource-limit results.
- [ ] 3. Add packet adapter and capture loop.
  - Acceptance: Ethernet/VLAN/IPv4/IPv6/TCP inputs yield exact tuple metadata; unsupported fragments/QUIC count as unsupported; Linux capture errors leave network forwarding untouched.
  - Verify: packet fixture tests plus Linux capture smoke test on an isolated interface.
  - Dependencies: 2. Files: Cargo.toml, Cargo.lock, src/packet.rs, src/main.rs, tests/packet.rs.
- [ ] 4. Add local metadata delivery.
  - Acceptance: restrictive UNIX socket contract; bounded output and drop counters; missing consumer cannot cause unbounded memory growth.
  - Verify: Linux socket fixture tests, disconnect/slow-consumer tests.
  - Dependencies: 3. Files: src/output.rs, src/main.rs, tests/output.rs.
- [ ] 5. Package and validate Linux service.
  - Acceptance: reproducible pinned Linux binary; dedicated user and scoped capture capability; no public listener; service limits and failure recovery verified.
  - Verify: Linux build/tests; systemd-analyze verify; integration status and socket permission checks before live activation.
  - Dependencies: 4. Files: systemd/netspecter-tls-inspector.service, scripts/install-tls-inspector.sh, inspector/README.md, rust-toolchain.toml, docs/engineering/SPEC-tls-metadata.md.
- [ ] Checkpoint: review Linux integration before live deployment or further module integration.

## Remaining capability gates
- [ ] Specify and review flow-attribution, then plan its focused tasks.
- [ ] Specify and review device-timeline, then plan its focused tasks.
- [ ] Specify and review history-reset, including preservation/reimport/recovery checks.
- [ ] Pass the combined Rust/Python suite and security/privilege checks.
- [ ] Deploy and validate on the two authorized reachable appliances.
- [ ] Explicitly reset collected history on those two only; verify edited names/settings survive and fresh collection resumes.
