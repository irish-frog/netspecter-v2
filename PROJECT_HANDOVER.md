# NetSpecter v2 handover

Updated 19 November 2026. This is the rolling project handover; deployment evidence is recorded separately from implementation status.

## Current objective

Finish the passive Rust TLS metadata / client DNS / measured-flow attribution pipeline, validate it on Linux, and prepare explicit deployment and history cleanup for three appliances. The client appliance is on hold: do not deploy, reset, restart or change its configuration without a later instruction. The inaccessible third appliance is package-only. The owner's appliance is authorized for live validation, subject to available root access.

## Implemented on the feature branch

- Bounded passive Rust ClientHello/SNI inspector; no decryption, packet archive or public listener. ECH outer SNI is suppressed.
- Exact connection/time matching, client-aware DNS fallback, measured bytes with export deduplication, and explicit unknown reasons. Shared CDN/provider addresses do not prove an application.
- Internet-only scope, internal routed/VPN exclusions, appliance self-traffic exclusion, identity-at-time mapping and device application timeline. Bridge totals and flow/application coverage remain separate.
- Separate unprivileged sensor/exporter identities; root-owned restricted UNIX socket with authenticated intake; loopback NetFlow only.
- Explicit fresh-database history reset with schema allow-list, stopped writers, crash recovery, preserved settings/logins/licences/edited names/rules, and temporary rollback copy discarded after successful checks.
- Deployment preflight, binary/source provenance verification, optional restricted Suricata purge, portable Git bundle bootstrap and read-only DNS continuity checks.

## Published versus pending

The complete Linux validation passed on feature commit ac60ce6f65f33325c256f2bf7076253cebeb790b: workflow run 44413300905, job 135186866896. It passed 382 Python tests and 23 Rust tests, formatting/lint, Linux capture/IPC smoke, offline bootstrap protections and the full bridge/systemd/reset pipeline. The passing sensor/exporter binaries and provenance are now included in `inspector/prebuilt/linux-x86_64`; the packaging revision 2bcba9d7f64907928342f09bbf05a491343c14ce also passed the full pipeline using those shipped binaries (run 44414118372, job 135189753598). This tested release is ready for explicit deployment; it is not installed on production appliances.

The bridge test proved distinct applications on one remote IP, actual measured flow bytes, unchanged TCP payload, no internal flow/SNI/internet-counter attribution, no legacy byte guesses, and dedicated identities/private socket/loopback receiver. The real root reset preserved edited names and raw settings, cleared history, discarded the temporary rollback copy and collected fresh attributed traffic afterward.

The test exposed and fixed: upstream infinite quiet-traffic capture buffering (pinned 100 ms exporter patch), a pre-read sensor timestamp causing stale first-connection times, and SQLite WAL snapshot companions preventing temporary-copy disposal. Exact correlation stayed strict. Thirteen focused cleanup tests cover WAL snapshots, recovery, schema refusal, retained state and unexpected files.

No production deployment/reset has been performed by this work. Both checked binaries also loaded successfully on the owner Debian appliance in a temporary unprivileged compatibility check; temporary files were removed. Owner DNS was checked successfully over UDP and TCP; AdGuard and the three core NetSpecter services were active on the previously installed revision. A separate SSH session remains unprivileged even if the operator's terminal is already in `su -`. The client remains on hold and the third untouched.

## DNS and deployment boundaries

AdGuard is independent of the inspector. The explicit deployment path must not install optional AdGuard/Gatus/Beszel components. Check existing AdGuard configuration hashes and local UDP/TCP resolution before deployment, before history cleanup and afterward. Neither cleanup nor the sensor changes routing, decrypts TLS or resets AdGuard filtering. DNS health checks cannot guarantee all upstream/provider conditions.

Root via `su -` is required to install services/reset history. An existing operator root terminal does not grant a new SSH session root access. Never automate a terminal UI to bypass this. Do not request or store root passwords in documentation.

## Important files

- `inspector/`: Rust source, pinned dependencies/toolchain, Linux tests, build provenance and tested prebuilt bundle when published.
- `services/flow_attribution_service.py`, `netflow_measurement_service.py`, `tls_metadata_service.py`, `device_timeline_service.py`.
- `services/history_reset_service.py`, `history_reset_runtime.py`, `config/history-reset-schema-v1.json`.
- `scripts/deploy-attribution.sh`, `install-tls-inspector.sh`, `verify-passive-attribution.py`, `reset-collected-history.py`.
- `scripts/build-deployment-bundle.py`, `deploy-from-bundle.sh`, `check-dns-continuity.py`.
- `docs/engineering/PASSIVE-DEPLOYMENT.md`, `HISTORY-RESET.md` and the approved `SPEC-*.md` files.

## Known limits / next work

Runtime implementation and Linux validation are complete. The published release includes checked binaries and explicit deployment/history-cleanup tooling. The portable deployment archive and site-specific operator handover are generated outside the public repo. Remaining live work requires an operator root shell: install/verify/reset the owner appliance, leave the held client unchanged, and deploy the third only when access returns. IPv4 is the primary headline accounting scope; encrypted QUIC/ECH and unseen VPN inner traffic can remain unknown. Never inflate coverage to hide this.

Keep the client on hold and the third appliance untouched. Record installed revision, test evidence and remaining root actions explicitly when finishing. Settings are outside Git at `/etc/netspecter/config.json`; split SQLite data is under `/var/lib/netspecter`. Never use broad `rm` globs against those databases to clear history.


## Attribution catalogue follow-up

Owner review identified 99 distinct unrecognized hostnames. Product-specific rules and imported-allowlist precedence fixes resolve most of the reviewed unknown-hostname bytes offline, without guessing shared providers. A bounded preview/apply command relabels only existing exact-SNI unknowns and preserves measurements. See `docs/engineering/DOMAIN-CATALOGUE-UPDATE.md`. Full local suite: 383 passed, five Linux-only skipped. Linux CI remains the publication gate; the test fixture now matches production config ownership. No client or third-appliance action is authorized.
