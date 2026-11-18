# NetSpecter v2 Project Map

Concise architecture map for future coding agents with limited context. Facts below were verified from the repository unless marked not verified.

## Current attribution rebuild

Read `PROJECT_HANDOVER.md` first for current release/testing/deployment state. The new primary path is passive Rust SNI metadata + client DNS + measured NetFlow, with per-device timelines. Suricata runtime/automatic blocking is retired. Legacy IDS/classification source can remain for compatibility; its existence does not mean it runs. Use `docs/engineering/PASSIVE-DEPLOYMENT.md` for explicit deployment and cleanup.

## Project Purpose

NetSpecter v2 is an inline Debian-based LAN visibility and security appliance. It runs on a bridged host, counts client traffic, imports AdGuard DNS data, classifies traffic/application usage, displays health and monitoring data in a Flask web UI, and manages IDS, backups, internet-quality checks, incidents, and appliance status.

## Top-Level Folders

- `adguard/` - AdGuard-related assets/templates; exact runtime use not fully verified.
- `api_v1/` - contains only `__pycache__` files in this checkout; no source API module verified.
- `config/` - classification/category config, including `application_categories.json`.
- `docs/` - deployment, network, integration, engineering, business, and history documentation.
- `hardware/` - physical appliance/STL documentation.
- `lcd/` - LCD display docs/firmware.
- `licenses/` - third-party licence files.
- `netspecter_vault/` - backup/vault archive, restore, retention, scheduler, USB/SMB, and CLI code.
- `scripts/` - maintenance/update/reset/IDS helper scripts.
- `services/` - classification, reporting, PDF/export, device presence, Microsoft 365 endpoints, DNS rollups, AI attribution, Suricata classification services.
- `static/` - web UI static assets.
- `systemd/` - service and timer unit files.
- `tests/` - pytest coverage for security, DB split, classification, IDS, incidents, LCD, vault, internet quality, device identity/presence.
- `tools/` - helper scripts such as UI screenshot capture.
- `wiki/` - supplemental docs.

## Main Entry Points

- `app.py` - Flask web UI and API. Routes, auth, dashboard, devices, traffic/history, AdGuard controls, reports, speed tests, system health, LCD API, updates, vault flows.
- `wsgi.py` - exposes `app` for Gunicorn.
- `live_packet_collector.py` - long-running collector for nftables counters, AdGuard import, device discovery, IDS import, quality checks, threat intel, anomaly baseline, retention.
- `scheduled_speedtest.py` - scheduled internet speed-test runner.
- `monitor_sweeper.py` - monitor alert sweeper used by `netspecter-monitor.service`.
- `netspecter_https_proxy.py` - HTTPS LAN proxy in front of web UI.
- `install.sh` - Debian appliance installer.

## Important Services and Workers

Verified systemd units:

- `netspecter-web.service` - Gunicorn web UI, working dir `/opt/netspecter`, runs `wsgi:application`.
- `netspecter-https.service` - HTTPS proxy, runs `netspecter_https_proxy.py`.
- `netspecter-collector.service` - collector, runs `live_packet_collector.py`.
- `netspecter-monitor.timer/service` - monitor alert sweeper.
- `gatus.service` - Gatus status dashboard using `/etc/netspecter/gatus/config.yaml`.
- `netspecter-speedtest.timer/service` - scheduled speed tests.
- `netspecter-vault.timer/service` - scheduled backups.
- `netspecter-db-maintenance.timer/service` - SQLite maintenance; stops/starts collector around maintenance.
- `netspecter-watchdog.timer/service` - collector watchdog.
- `netspecter-update.service/path` - UI-triggered update.
- `netspecter-nic-offload.service` - IDS capture interface preparation.

`live_packet_collector.py` starts multiple daemon threads: `flush_loop`, `adguard_querylog_loop`, optional SNMP/MQTT loops, `internet_quality_loop`, `config_change_monitor_loop`, `threat_intel_loop`, `anomaly_baseline_loop`, and `retention_cleanup_loop`.

## Device Discovery Flow

- Traffic discovery starts in `flush_loop()` by reading nftables per-host counters from `read_nft_counters()`.
- MAC addresses come from `/proc/net/arp` via `read_arp_macs()`.
- Names can come from AdGuard client names (`refresh_adguard_client_names()`, `adguard_name_for_ip()`), UniFi (`refresh_unifi_clients()`), NetBIOS (`discover_netbios_name()`), mDNS (`discover_mdns_name()`), SNMP (`discover_snmp_name()`), SSDP (`discover_ssdp_name()`), and vendor fallback (`vendor_fallback_name()`).
- Identity handling is centralized in `apply_device_identity()` with `device_identities` and related tables.
- Device rows are written to `devices` from traffic, AdGuard, and UniFi/device-import sources.

## Online/Offline Status Logic

- `services/device_presence_service.py` defines `PresenceState`, `PRESENCE_TIMEOUT_SECONDS=900`, and `REACHABILITY_CHECK_INTERVAL_SECONDS=900`.
- Traffic writes call `mark_presence_many(..., "traffic")`.
- `resolve_presence_states()` marks a device online if recent `last_presence_seen` is within timeout.
- If stale/unknown, it checks neighbor tables (`ip neigh` or `arp -an`) and then limited pings (`MAX_REACHABILITY_CHECKS=8`).
- Device presence columns are added lazily to `devices`: `last_presence_seen`, `last_presence_source`, `last_presence_check`.

## DNS/AdGuard Integration

- Web UI uses `ag_get()`, `ag_post()`, and `ag_control()` in `app.py` against configured `adguard_url`.
- Collector imports `/control/querylog` in `import_adguard_querylog()`.
- Imported DNS rows go to `dns_querylog`.
- DNS answers are converted by `dns_answer_rows()` into `dns_resolution_events` with `client_ip`, `domain`, `resolved_ip`, `ttl`, `expires_at`, and `source='adguard'`.
- `remember_estimated_app_targets()` builds in-memory monitored app attribution targets from DNS answers for known monitored domains.
- `request_dns_classification_target_refresh()` asks the nft counter loop to refresh destination counters after DNS evidence changes.
- Internal DNS forwarding/apply logic is in `app.py` functions `internal_dns_upstream_entries()`, `adguard_internal_dns_apply()`, and `internal_dns_test()`.

## Traffic Capture, Classification, Attribution Flow

Verified live path:

1. `lan_network()` converts `lan_prefix` to an IPv4 network.
2. `install_nft_counters()` creates private nftables `bridge` table/chain rules for each LAN host and selected destination targets.
3. Per-device rules count external `tx` and `rx` bytes into comments like `netspecter:tx:<ip>` and `netspecter:rx:<ip>`.
4. Monitored app target rules use comments like `netspecter:estimated:<category>:tx:<client>:<destination>`.
5. Classification target rules use comments like `netspecter:classify:tx:<client>:<destination>`.
6. `read_nft_counters()` parses nft JSON counters into device totals, estimated counters, and classification counters.
7. `flush_loop()` calculates deltas.
8. Device totals write `live_device_speed`, `devices`, and `traffic_intervals`; live values also update `live_snapshot.json`.
9. Monitored app deltas write `estimated_app_traffic` directly and also `remote_traffic_intervals` through `write_destination_delta()`.
10. Classification destination deltas call `classify_flow()` and then write `remote_traffic_intervals`; if classified with default category `Unknown`, they also write `estimated_app_traffic`.
11. `classify_flow()` checks operator signatures, client-aware DNS resolution (`dns_resolution_events`), TLS SNI, HTTP host, static site mapping, ASN/provider, destination signatures, and port/protocol.
12. Classified facts write `classified_flow_facts`; unknown flows upsert `unknown_traffic_queue`.

Important limit: `traffic_intervals` stores device totals but no remote IP/domain/port. Destination-aware attribution depends on nft destination target rules being installed while traffic flows.

## Databases and Tables

Paths from `netspecter_paths.py`:

- Config: `/etc/netspecter/config.json`
- Data root: `/var/lib/netspecter`
- Core DB: `netspecter.db`
- DNS DB: `netspecter_dns.db`
- Traffic DB: `netspecter_traffic.db`
- Security DB: `netspecter_security.db` exists as a path; docs say future split target, not actively routed yet.
- Live snapshot: `live_snapshot.json`

Key tables from `netspecter_db.py`:

- Core: `devices`, `device_overrides`, `device_override_unlocks`, `device_identities`, `device_ip_history`, `user_labels`, `user_device_assignments`, application category/mapping tables, telemetry, monitor events, config snapshots/change events, threat intel tables, IDS events/notifications/state, processing checkpoints, investigation cases/notes.
- DNS: `dns_querylog`, `dns_daily_rollups`, `dns_resolved_ips`, `dns_resolution_events`, `dns_import_state`.
- Traffic: `traffic_samples`, `traffic_intervals`, `traffic_hourly_rollups`, `estimated_app_traffic`, `estimated_app_hourly_rollups`, `remote_traffic_intervals`, `remote_traffic_hourly_rollups`, `application_signatures`, `classification_cache`, `classified_flow_rollups`, `classified_flow_facts`, `unknown_traffic_review`, `unknown_traffic_queue`, `remote_ip_locations`, `live_device_speed`, `collector_heartbeat`, `speed_tests`, `internet_quality`.

`connect_db()` attaches split history DBs so some old SQL names still work through attached aliases.

## API/Web UI Flow

- Flask app is monolithic in `app.py`.
- Auth/session/CSRF/security headers are enforced by `require_login()`, `require_csrf_token()`, and `set_security_headers()`.
- Live UI polling uses `/api/live`.
- LCD endpoint uses `/api/lcd/summary` and token/display logic.
- Health endpoints include `/api/health/web`, `/api/health/collector`, `/api/health/bridge`, `/api/health/database`.
- Dashboard JSON endpoints include `/api/dashboard-summary`, `/api/dashboard-quality`, `/api/dashboard-apps`, `/api/dashboard-health`.
- Major UI route functions include `dashboard()`, `devices()`, `traffic/history/application/report routes` (exact full list not exhaustively mapped), `speed_tests()`, `system()`, AdGuard routes, monitor routes, vault/update routes.
- Reports use services in `services/report_*`.

## Configuration Files

- `netspecter_config.py` defines `DEFAULT_CONFIG`, sensitive keys, `cfg()`, and `save_cfg()`.
- `config.example.json` is example config.
- Runtime config is `/etc/netspecter/config.json` on appliances, with local fallback to repo root if `/etc/netspecter` does not exist.
- Sensitive config keys are encrypted when saved if `cryptography` is available: AdGuard, UniFi, SMTP, SNMP community, MQTT, Telegram, NetLic secrets.
- Important runtime config includes `packet_iface`, `lan_prefix`, `gateway_ip`, `ignore_ips`, AdGuard URL/credentials, classification limits, speed-test path, IDS settings, monitoring, vault, integrations, and retention.

## Important Files/Functions to Inspect First

- `app.py`: route/HTML/API behavior. Start with the target route and helper functions named by `rg`.
- `live_packet_collector.py`: `flush_loop()`, `install_nft_counters()`, `read_nft_counters()`, `import_adguard_querylog()`, `active_classification_targets()`, `remember_estimated_app_targets()`.
- `netspecter_db.py`: `init_db()`, `init_dns_db()`, `init_traffic_db()`, `connect_db()`, `attach_history_dbs()`.
- `netspecter_config.py`: `DEFAULT_CONFIG`, `cfg()`, `save_cfg()`, sensitive-key handling.
- `services/classification_resolver_service.py`: `Flow`, `Classification`, `classify_flow()`, `match_dns_resolution()`, `write_classified_flow_fact()`, `upsert_unknown_traffic()`.
- `services/application_classification_service.py`: `classify_application()`, `categories()`, domain/IP matching helpers.
- `services/device_presence_service.py`: online/offline resolution and presence writes.
- `netspecter_live_snapshot.py`: snapshot update/read helpers for fast live UI values.
- `systemd/*.service` and `install.sh`: deployment/runtime assumptions.

## Fragile or High-Risk Areas

- nftables bridge rules in `install_nft_counters()` affect traffic counting and IDS auto-ban drops; changing them can break attribution or networking visibility.
- `classification_nft_target_limit` controls destination classification target creation; zero disables classification targets.
- SQLite write contention is managed with busy timeouts and contention backoff; high-write collector paths are sensitive.
- Split DB attachment means SQL may work against attached aliases; verify actual table location before changing queries.
- Runtime config is preserved outside Git; code updates do not overwrite `/etc/netspecter/config.json`.
- AdGuard import must preserve client-specific DNS resolution evidence; do not replace it with external DNS/PTR/RDAP lookup unless explicitly required.
- `traffic_intervals` lacks remote IP information; do not expect historical total traffic rows to be reclassified by destination without other evidence.
- Device identity/private MAC logic can affect names and historical identity continuity.
- Suricata/IDS import and auto-ban can write config/firewall-related state; avoid unrelated changes.
- Installer touches system packages, services, permissions, AdGuard, Gatus, Beszel, Suricata, and logrotate; test cautiously.
- Do not expose web/AdGuard/Gatus/LCD/SSH publicly; docs state LAN/VPN-only security boundary.

