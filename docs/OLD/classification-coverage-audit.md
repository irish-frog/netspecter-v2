# Classification Coverage Audit

## Current Pipeline

NetSpecter currently records total device traffic from bridge nftables counters in `traffic_intervals`. Those rows are per local device and contain bytes, timestamps, and device identity, but they do not contain destination domain, TLS SNI, HTTP host, port, protocol, or classification evidence.

Application byte attribution is a separate best-effort path in `live_packet_collector.py`. AdGuard DNS querylog rows are imported into `dns_querylog`, `app_from_domain()` assigns a friendly DNS category, and `remember_estimated_app_targets()` only creates nftables application counters for domains matching the fixed `MONITORED_APP_DOMAIN_KEYS` allowlist. Matching client/destination pairs are counted into `estimated_app_traffic` and `remote_traffic_intervals`.

The reporting category summary in `services/application_classification_service.py` reads `estimated_app_traffic.category`, maps those app names into functional categories using `config/application_categories.json`, and compares that classified traffic total to total monitored traffic. Traffic that never passed through the monitored DNS-to-counter path remains `Unclassified / Other Network Traffic`.

## Signals Already Stored

- Device traffic totals: `traffic_intervals` stores source/local IP, bytes, day, and timestamp.
- DNS querylog: `dns_querylog` stores client IP, domain, blocked flag, category, day, and timestamp.
- DNS resolved IP cache: `dns_resolved_ips` stores domain, resolved IP, and resolved timestamp, but not client IP or TTL.
- Estimated application traffic: `estimated_app_traffic` stores local IP, application/category label, bytes, day, and timestamp.
- Remote destination application traffic: `remote_traffic_intervals` stores local IP, remote IP, category label, bytes, day, and timestamp.
- Suricata structured events: `ids_events` stores DNS query values, HTTP host/url/user-agent, TLS SNI/version/cert fields, app protocol, ports, flow ID, source/destination IPs, timestamps, and event type.
- Device context: `devices` and `device_overrides` store device names, owners, types, vendors, and ignored status.
- Classification config: `config/application_categories.json` stores functional category mappings by application name, domain pattern, and destination IP.

## Signals Collected But Not Yet Used For Reporting Classification

- TLS SNI is parsed from Suricata `tls` events into `ids_events.tls_sni`, but it is not joined to `traffic_intervals`, `estimated_app_traffic`, or reporting category summaries.
- HTTP host is parsed from Suricata `http` events into `ids_events.hostname`, but it is not used for application traffic classification.
- Suricata app protocol, source/destination ports, and flow IDs are stored in `ids_events`, but they are not used in the report classification pipeline.
- `dns_resolved_ips` is maintained for domain-to-IP enrichment, but it is global rather than client-specific and is not used to classify historical flows in reports.
- Device names and overrides can provide useful context, but the report classification pipeline currently uses them only for display, not as classification evidence.

## Gaps In Current Traffic Records

- `traffic_intervals` has no remote IP, domain, SNI, HTTP host, port, protocol, application, evidence source, or confidence fields.
- `estimated_app_traffic` has no destination IP, domain, SNI, HTTP host, matched rule, evidence source, confidence, or classified timestamp.
- `remote_traffic_intervals` has destination IP and category, but no domain, SNI, HTTP host, matched rule, evidence source, confidence, or classified timestamp.
- `dns_querylog` has domains and clients, but it does not store DNS answer IPs per client with TTL and expiry.

## DNS Correlation Status

Client-specific DNS correlation partially exists only in memory. `remember_estimated_app_targets()` receives AdGuard DNS answers and stores `(client, destination_ip) -> category` in `estimated_app_targets`. The collector then installs nftables counters for those specific pairs.

Limitations:

- Only domains in `MONITORED_APP_DOMAIN_KEYS` are eligible.
- The mapping is not persisted as client-specific DNS correlation data.
- Historical flows cannot be reclassified from this mapping.
- Multiple possible domains for a shared CDN IP are not retained with confidence.
- If a service is not in `MONITORED_APP_DOMAIN_KEYS`, DNS rows may show the app while byte traffic remains unclassified.

## TLS SNI And HTTP Host Availability

TLS SNI and HTTP host values are available when Suricata emits them and `ingest_eve_incremental()` imports `eve.json`. They are stored in `ids_events.tls_sni` and `ids_events.hostname`. They are currently useful in IDS/event views, but not used by the reporting application usage summary.

## Local Traffic Status

Total monitored traffic includes local device traffic counted by bridge nftables rules where the source or destination is inside the configured LAN network. Current application byte attribution intentionally ignores DNS answers that resolve to internal LAN IPs. That means internal services such as a local Nextcloud server can create legitimate file-sharing traffic that remains outside `estimated_app_traffic`.

## Why Coverage Is Low

The executive report compares all monitored traffic against only the subset that has an `estimated_app_traffic` row. That subset is narrow because it depends on DNS answer visibility, a small monitored-domain allowlist, external destination IPs, and active nftables estimated counters. Large local services, direct-IP connections, encrypted traffic without usable host evidence, unsupported domains, and traffic collected before a DNS mapping was active remain unclassified.

## Immediate Nextcloud Finding

This site has a known Nextcloud server at `192.168.99.4`. Nextcloud domains are present in the functional category config, but Nextcloud is not in the collector's monitored app DNS allowlist, and local LAN destinations are currently skipped by `remember_estimated_app_targets()`. A targeted site mapping for `192.168.99.4` can improve current reporting without claiming the full DNS/SNI correlation system is complete.
