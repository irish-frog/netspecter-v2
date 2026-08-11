# AdGuard Classification Audit

## Summary

NetSpecter already uses AdGuard DNS querylog data to improve application reporting, but the current implementation is intentionally narrow. It imports DNS query rows into `dns_querylog`, uses an in-memory DNS-answer map for selected domains, installs nftables counters for those selected client/destination pairs, and writes the resulting byte deltas into `estimated_app_traffic` and `remote_traffic_intervals`.

The current design is lightweight for the appliance because expensive correlation is not performed during report rendering. The main limitation is that client-specific DNS response events are not persisted, so historical correlation and broader classification cannot happen safely yet.

## Current AdGuard DNS Data

Source: `live_packet_collector.import_adguard_querylog()`

AdGuard is queried through `/control/querylog`. The importer reads each row and currently uses:

- Query timestamp: `item["time"]`, normalised by `parse_adguard_time()`
- Client IP: `item["client"]`
- Requested domain: `item["question"]["name"]`
- Block status/reason: `item["reason"]`, converted by `is_blocked_reason()`
- DNS answers: `item["answer"]`, passed to `remember_estimated_app_targets()`

Stored table: `dns_querylog`

Stored fields:

- `day`
- `ts`
- `client`
- `domain`
- `blocked`
- `category`

Not stored today:

- Query type
- AdGuard client name
- DNS response status
- Returned IP addresses per client
- TTL per answer
- Expiry time per answer
- Original AdGuard reason text

Important note: response IPs and TTLs are available to the importer when AdGuard includes them in `item["answer"]`, but they are only used in memory for selected app attribution. They are not persisted as client-specific DNS resolution events.

## Current Traffic Data

Primary traffic table: `traffic_intervals`

Stored fields:

- Local device IP: `ip`
- Device name and MAC: `name`, `mac`
- Download/upload/total MB: `downloaded_mb`, `uploaded_mb`, `total_mb`
- Live bits per second: `live_bps`
- `day`
- `ts`

Missing for correlation:

- Remote IP
- Source/destination port
- Protocol
- Flow ID
- Application
- Classification source/confidence

Application-estimated byte table: `estimated_app_traffic`

Stored fields:

- Local device IP: `ip`
- Existing app label in `category`
- Download/upload/total MB
- `day`
- `ts`

Remote app destination table: `remote_traffic_intervals`

Stored fields:

- Local device IP: `ip`
- Remote IP: `remote_ip`
- Existing app label in `category`
- Download/upload/total MB
- `day`
- `ts`

This table is the closest current source for DNS-to-traffic classification by remote IP, but it only contains rows for traffic that was already selected by the in-memory monitored-app attribution path.

## Current Application Detection

Collector-side DNS label detection:

- `live_packet_collector.app_from_domain(domain)` assigns a friendly DNS category for `dns_querylog`.
- `live_packet_collector.monitored_app_for_domain(domain)` checks `MONITORED_APP_DOMAIN_KEYS`.
- `remember_estimated_app_targets()` creates a temporary `(client_ip, destination_ip) -> app` mapping only for monitored domains with DNS A answers.

Report-side functional category mapping:

- `services.application_classification_service.classify_application()` maps an app/domain/IP into a functional category using `config/application_categories.json`.
- `category_summary()` groups `estimated_app_traffic` rows into functional report categories.

Existing database-backed application tables:

- `application_categories`
- `application_subcategories`
- `application_mappings`
- `application_aliases`
- `application_domain_patterns`
- `application_tags`
- `site_category_overrides`
- `classification_audit`

These tables exist in schema, but the current report classifier primarily uses the JSON config file plus current traffic tables.

## Current DNS-to-Traffic Correlation

Current correlation is in-memory and live only:

1. AdGuard querylog row is imported.
2. `remember_estimated_app_targets()` receives client IP, domain, DNS answers, timestamp, and blocked flag.
3. If the domain matches `MONITORED_APP_DOMAIN_KEYS`, it stores `(client_ip, resolved_ip) -> app` in `estimated_app_targets`.
4. `install_nft_counters()` creates nftables rules for those active app targets.
5. `read_nft_counters()` reads byte deltas from the app-specific nft counters.
6. The collector writes app byte deltas to `estimated_app_traffic` and `remote_traffic_intervals`.

This is efficient because nftables does the live byte counting. It also avoids heavy SQL joins during page rendering.

Limitations:

- Only allowlisted domains get app byte counters.
- Client-specific DNS answers are not stored for future use.
- Expired DNS mappings disappear from memory.
- Historical traffic cannot be reclassified from past DNS answers.
- `traffic_intervals` does not include remote IPs, so broad post-hoc correlation against total traffic is not possible from that table alone.

## TLS SNI And HTTP Host Data

Suricata `eve.json` events are imported by `netspecter_ids.ingest_eve_incremental()`.

Stored in `ids_events`:

- TLS SNI: `tls_sni`
- TLS version and certificate fields
- HTTP host: `hostname`
- HTTP URL path and user agent
- Source/destination IP
- Source/destination port
- Protocol/app protocol
- Flow ID
- Timestamp and day

These signals are already stored, but current reporting classification does not use them for application byte totals.

## Existing Indexes Relevant To Performance

Traffic:

- `idx_intervals_day_ip`
- `idx_intervals_ip_ts`
- `idx_intervals_ts`
- `idx_intervals_day_totals`
- `idx_intervals_ip_day_totals`
- `idx_intervals_day_ip_totals`

Estimated app traffic:

- `idx_estimated_app_day_ip`
- `idx_estimated_app_day_category`

Remote traffic:

- `idx_remote_traffic_day_ip`
- `idx_remote_traffic_ts_ip`

DNS:

- `idx_dns_day`
- `idx_dns_client`
- `idx_dns_day_category`
- `idx_dns_day_domain`
- `idx_dns_day_blocked_domain`
- `idx_dns_day_category_client_domain`
- `idx_dns_ts_client`
- unique index on `(ts, client, domain)`

Suricata:

- `idx_ids_events_ts`
- `idx_ids_events_src_ip`
- `idx_ids_events_dest_ip`
- `idx_ids_events_type`
- `idx_ids_events_signature`
- `idx_ids_events_day_type`

## Coverage Source

The current report traffic coverage percentage is calculated by comparing `estimated_app_traffic` bytes against total `traffic_intervals` bytes for the reporting period. This means coverage is low when most traffic is not part of the monitored DNS app target path.

## Local Traffic And Nextcloud

Total traffic includes local LAN traffic counted by bridge nftables rules. The live DNS app attribution path normally skips internal LAN destinations, with a narrow current exception for the known Nextcloud server at `192.168.99.4`.

That exception is low-cost but should be treated as a temporary site mapping. The longer-term plan should represent it as a site override or classification rule with constraints such as destination IP, expected port, and direction.

## Performance Notes

The plan is compatible with current changes if implementation keeps the existing performance shape:

- Continue doing correlation in the collector/background path, not in report routes.
- Persist DNS response IPs in a bounded, indexed table.
- Use client IP + resolved IP + timestamp indexes.
- Keep batch sizes small.
- Retain and prune DNS resolution events.
- Avoid reverse DNS or external lookups during page rendering.
- Avoid full-history reclassification during normal requests.

Potential speed risks:

- Joining all `traffic_intervals` rows to DNS rows at report time.
- Reclassifying all history on every mapping change.
- Running reverse DNS from Flask route handlers.
- Adding many per-destination nftables rules without caps.
- Persisting duplicate DNS answer rows without retention.

## Recommended Next Step

Add a dedicated `dns_resolution_events` table and import AdGuard response IPs/TTL per client. This is the safest next change because it preserves the existing live counter path while creating a reliable, indexed evidence source for later background classification.
