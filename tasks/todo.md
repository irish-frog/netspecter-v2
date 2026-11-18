# Attribution rebuild tasks

Updated 2026-11-19. All specifications and integration plans were approved. Tasks marked complete below mean implementation and focused tests are complete; the final combined Linux bridge/reset gate and deployment remain separate. Client deployment is ON HOLD; the third appliance is package-only.

## tls-metadata (specification approved)

- [x] 1. Establish portable metadata parsing.
  - Acceptance: versioned observation contract; validated DNS hostnames; malformed/ECH/absent-SNI input never becomes confident application evidence.
  - Verify: cargo test --locked, cargo fmt --check, cargo clippy --locked --all-targets -- -D warnings.
  - Dependencies: none. Files: inspector/Cargo.toml, Cargo.lock, src/lib.rs, src/tls.rs, tests/tls.rs.
- [x] 2. Add bounded TCP reconstruction.
  - Acceptance: valid segmented hellos produce one observation; retransmits/out-of-order segments are handled; conflicting overlaps, midstream/reused sessions and expiry are rejected safely; global/per-flow limits enforced.
  - Verify: synthetic segment, resource-pressure, sequence-wrap and reuse tests via cargo test --locked.
  - Dependencies: 1. Files: src/reassembly.rs, src/lib.rs, tests/reassembly.rs.
- [x] Checkpoint: review portable parsing and resource-limit results.
- [x] 3. Add packet adapter and capture loop.
  - Acceptance: Ethernet/VLAN/IPv4/IPv6/TCP inputs yield exact tuple metadata; unsupported fragments/QUIC count as unsupported; Linux capture errors leave network forwarding untouched.
  - Verify: packet fixture tests plus Linux capture smoke test on an isolated interface.
  - Dependencies: 2. Files: Cargo.toml, Cargo.lock, src/packet.rs, src/main.rs, tests/packet.rs.
- [x] 4. Add local metadata delivery.
  - Acceptance: restrictive UNIX socket contract; bounded output and drop counters; missing consumer cannot cause unbounded memory growth.
  - Verify: Linux socket fixture tests, disconnect/slow-consumer tests.
  - Dependencies: 3. Files: src/output.rs, src/main.rs, tests/output.rs.
- [x] 5. Package and validate Linux service.
  - Acceptance: reproducible pinned Linux binary; dedicated user and scoped capture capability; no public listener; service limits and failure recovery verified.
  - Verify: Linux build/tests; systemd-analyze verify; integration status and socket permission checks before live activation.
  - Dependencies: 4. Files: systemd/netspecter-tls-inspector.service, scripts/install-tls-inspector.sh, inspector/README.md, rust-toolchain.toml, docs/engineering/SPEC-tls-metadata.md.
- [x] Checkpoint: review Linux integration before live deployment or further module integration.

## Remaining capability gates
- [x] Specify and review flow-attribution, then plan its focused tasks.
- [x] Specify and review device-timeline, then plan its focused tasks.
- [x] Specify and review history-reset, including preservation/reimport/recovery checks.
- [x] Pass the combined Rust/Python suite and security/privilege checks.
- [ ] Deploy/validate the owner appliance with root access; client ON HOLD.
- [ ] Owner live history reset pending root execution; held client and inaccessible third stay untouched.

## Remaining module implementation tasks (specifications and task plan approved)

- [x] 6. Add bounded metadata intake and dedicated schema.
  - Acceptance: root-owned socket activation; peer/schema validation; bounded JSON and transactional batches; no IDS table dependency.
  - Verify: receiver/schema malformed input, disconnect, permissions and descriptor tests.
  - Dependencies: 1-4. Files: services/tls_metadata_service.py, tests/test_tls_metadata_receiver.py, netspecter_db.py, systemd/netspecter-tls-metadata.socket, live_packet_collector.py.
- [x] 7. Decode measured flow timestamps and identities.
  - Acceptance: bounded v5/v9 templates; correct start/end/sequence identity and IPv4/IPv6; malformed exports rejected.
  - Verify: tests/test_netflow_measurements.py synthetic exporter fixtures.
  - Dependencies: 6. Files: services/netflow_measurement_service.py, tests/test_netflow_measurements.py, live_packet_collector.py.
- [x] 8. Persist deduplicated eligible measurements.
  - Acceptance: loopback exporter only; successive active intervals count once each; internal/VPN bytes excluded; bridge totals unchanged.
  - Verify: export replay, active intervals, scope and byte conservation tests.
  - Dependencies: 7. Files: services/flow_attribution_service.py, tests/test_flow_attribution.py, netspecter_db.py, live_packet_collector.py.
- [x] Checkpoint: validate measured byte conservation and socket/flow intake.
- [x] 9. Resolve exact connection and client DNS evidence.
  - Acceptance: precedence and unknown reasons match spec; same CDN/different apps cannot leak evidence; late metadata safely reconciled.
  - Verify: attribution tests covering reused tuples, TTL, ambiguity, ECH, manual rules and export gaps.
  - Dependencies: 8. Files: services/flow_attribution_service.py, services/classification_resolver_service.py, tests/test_flow_attribution.py, live_packet_collector.py.
- [x] 10. Stage verified sensor and exporter service integration.
  - Acceptance: checksummed binary, dedicated identity, hardened units, safe updater integration; no appliance compiler or public port.
  - Verify: shell syntax, systemd unit validation, isolated Linux service tests and failure/recovery checks.
  - Dependencies: 5,9. Files: scripts/install-tls-inspector.sh, install.sh, scripts/post-update-maintenance.sh, systemd/netspecter-collector.service, inspector/README.md.
- [x] 11. Query device timelines and honest coverage.
  - Acceptance: bounded/paginated identity-aware query; directional bytes and explicit evidence; comparable bridge/flow windows and discrepancies visible.
  - Verify: tests/test_device_timeline.py with identity changes, duplicates, unknowns and empty data.
  - Dependencies: 9. Files: services/device_timeline_service.py, tests/test_device_timeline.py, services/report_context_service.py.
- [x] 12. Render authenticated device activity.
  - Acceptance: escaped names/domains, clear unknown/metadata-only state, existing navigation/security headers preserved.
  - Verify: route/partial-navigation tests and representative page smoke checks.
  - Dependencies: 11. Files: app.py, services/device_timeline_service.py, tests/test_device_timeline.py.
- [x] Checkpoint: validate end-to-end timeline and coverage without live reset.
- [x] 13. Inventory reset and preview preservation.
  - Acceptance: every schema table classified; unknown schema fails closed; explicit retained names/settings/custom rules inventory.
  - Verify: preview and preservation fixtures; no DB mutation in default mode.
  - Dependencies: 9,12. Files: services/history_reset_service.py, scripts/reset-collected-history.py, tests/test_collected_history_reset.py.
- [x] 14. Implement writer-safe reset and recovery.
  - Acceptance: exclusive lock, writer/timer state capture, protected snapshots, disk/integrity checks, cross-database recovery and service restoration.
  - Verify: interrupted/failed reset, insufficient space, unknown table, active writer and idempotence tests.
  - Dependencies: 13. Files: services/history_reset_service.py, scripts/reset-collected-history.py, tests/test_collected_history_reset.py.
- [x] 15. Prevent old DNS reimport and verify fresh state.
  - Acceptance: cutoff precedes device updates, DNS resolutions and target caches; restart clears learned in-memory state; new observations resume.
  - Verify: old/new DNS import fixture and post-reset fresh flow tests.
  - Dependencies: 14. Files: live_packet_collector.py, tests/test_collected_history_reset.py, docs/engineering/SPEC-history-reset.md.
- [x] Checkpoint: full suite, Linux integration, privilege/update/reset recovery review.
- [ ] 16. Validate the owner appliance; hold the client and prepare the third.
  - Acceptance: coherent main revision and matching binary prepared; owner install/reset only with root access; AdGuard/forwarding/collector healthy; client and third untouched.
  - Verify: root-assisted owner deploy/reset report, preservation checks and fresh timeline; prepared commands for the held client and offline third.
  - Dependencies: 10,12,15. Files: operational verification report only; no appliance-only source patches.

Linux gate passed on ac60ce6 (run 44413300905): 382 Python and 23 Rust tests, offline bootstrap, real bridge attribution/internal exclusion and root reset/fresh restart. Final package verification uses the shipped binaries, not a substitute build.
