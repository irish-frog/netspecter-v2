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

Main currently contains the standalone safe cleanup and prior maintenance fixes at 1bfbaca3e70fd7aa9879758900113ed64ca92bb0. The integrated rebuild remains on feature/passive-attribution-rebuild until the full Linux bridge and reset integration passes. Do not claim the rebuild is deployed or ready solely because portable unit tests pass.

The Linux suite has passed 377 Python regression/socket tests and Rust tests, lint, release build and loopback capture. The real bridge/systemd/reset test is still being debugged. It exposed two production issues: upstream softflowd buffers quiet traffic indefinitely with a zero capture timeout, and the sensor timestamp was sampled before a blocking packet read. The exporter now has a pinned 100 ms timeout patch; sensor timing is sampled after reads. The two-second exact-correlation window was not widened to hide the error. CI fixture fixes also preserve the root safety environment flag, copy the virtual environment into the service-visible filesystem, and keep readiness polls read-only. No production settings were changed during those fixes.

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

Complete the real Linux bridge + exporter + exact SNI + internal exclusion + root reset integration, vendor its passing binary/provenance, publish the coherent revision to main, validate the portable deployment bundle and create a site-specific operator handover outside the public repo. IPv4 is the primary headline accounting scope; encrypted QUIC/ECH and unseen VPN inner traffic can remain unknown. Never inflate coverage to hide this.

Keep the client on hold and the third appliance untouched. Record installed revision, test evidence and remaining root actions explicitly when finishing. Settings are outside Git at `/etc/netspecter/config.json`; split SQLite data is under `/var/lib/netspecter`. Never use broad `rm` globs against those databases to clear history.
