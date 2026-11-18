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

## Remaining module implementation tasks (specifications and task plan approved)

- [ ] 6. Add bounded metadata intake and dedicated schema.
  - Acceptance: root-owned socket activation; peer/schema validation; bounded JSON and transactional batches; no IDS table dependency.
  - Verify: receiver/schema malformed input, disconnect, permissions and descriptor tests.
  - Dependencies: 1-4. Files: services/tls_metadata_service.py, tests/test_tls_metadata_receiver.py, netspecter_db.py, systemd/netspecter-tls-metadata.socket, live_packet_collector.py.
- [ ] 7. Decode measured flow timestamps and identities.
  - Acceptance: bounded v5/v9 templates; correct start/end/sequence identity and IPv4/IPv6; malformed exports rejected.
  - Verify: tests/test_netflow_measurements.py synthetic exporter fixtures.
  - Dependencies: 6. Files: services/netflow_measurement_service.py, tests/test_netflow_measurements.py, live_packet_collector.py.
- [ ] 8. Persist deduplicated eligible measurements.
  - Acceptance: loopback exporter only; successive active intervals count once each; internal/VPN bytes excluded; bridge totals unchanged.
  - Verify: export replay, active intervals, scope and byte conservation tests.
  - Dependencies: 7. Files: services/flow_attribution_service.py, tests/test_flow_attribution.py, netspecter_db.py, live_packet_collector.py.
- [ ] Checkpoint: validate measured byte conservation and socket/flow intake.
- [ ] 9. Resolve exact connection and client DNS evidence.
  - Acceptance: precedence and unknown reasons match spec; same CDN/different apps cannot leak evidence; late metadata safely reconciled.
  - Verify: attribution tests covering reused tuples, TTL, ambiguity, ECH, manual rules and export gaps.
  - Dependencies: 8. Files: services/flow_attribution_service.py, services/classification_resolver_service.py, tests/test_flow_attribution.py, live_packet_collector.py.
- [ ] 10. Stage verified sensor and exporter service integration.
  - Acceptance: checksummed binary, dedicated identity, hardened units, safe updater integration; no appliance compiler or public port.
  - Verify: shell syntax, systemd unit validation, isolated Linux service tests and failure/recovery checks.
  - Dependencies: 5,9. Files: scripts/install-tls-inspector.sh, install.sh, scripts/post-update-maintenance.sh, systemd/netspecter-collector.service, inspector/README.md.
- [ ] 11. Query device timelines and honest coverage.
  - Acceptance: bounded/paginated identity-aware query; directional bytes and explicit evidence; comparable bridge/flow windows and discrepancies visible.
  - Verify: tests/test_device_timeline.py with identity changes, duplicates, unknowns and empty data.
  - Dependencies: 9. Files: services/device_timeline_service.py, tests/test_device_timeline.py, services/report_context_service.py.
- [ ] 12. Render authenticated device activity.
  - Acceptance: escaped names/domains, clear unknown/metadata-only state, existing navigation/security headers preserved.
  - Verify: route/partial-navigation tests and representative page smoke checks.
  - Dependencies: 11. Files: app.py, services/device_timeline_service.py, tests/test_device_timeline.py.
- [ ] Checkpoint: validate end-to-end timeline and coverage without live reset.
- [ ] 13. Inventory reset and preview preservation.
  - Acceptance: every schema table classified; unknown schema fails closed; explicit retained names/settings/custom rules inventory.
  - Verify: preview and preservation fixtures; no DB mutation in default mode.
  - Dependencies: 9,12. Files: services/history_reset_service.py, scripts/reset-collected-history.py, tests/test_collected_history_reset.py.
- [ ] 14. Implement writer-safe reset and recovery.
  - Acceptance: exclusive lock, writer/timer state capture, protected snapshots, disk/integrity checks, cross-database recovery and service restoration.
  - Verify: interrupted/failed reset, insufficient space, unknown table, active writer and idempotence tests.
  - Dependencies: 13. Files: services/history_reset_service.py, scripts/reset-collected-history.py, tests/test_collected_history_reset.py.
- [ ] 15. Prevent old DNS reimport and verify fresh state.
  - Acceptance: cutoff precedes device updates, DNS resolutions and target caches; restart clears learned in-memory state; new observations resume.
  - Verify: old/new DNS import fixture and post-reset fresh flow tests.
  - Dependencies: 14. Files: live_packet_collector.py, tests/test_collected_history_reset.py, docs/engineering/SPEC-history-reset.md.
- [ ] Checkpoint: full suite, Linux integration, privilege/update/reset recovery review.
- [ ] 16. Deploy, verify, then reset only two authorized units.
  - Acceptance: coherent main revision and matching binary installed; AdGuard/forwarding/collector healthy; history fresh and retained state verified; third untouched.
  - Verify: root-assisted deploy/reset reports, before/after preservation checks and fresh traffic timeline on both units.
  - Dependencies: 10,12,15. Files: operational verification report only; no appliance-only source patches.
