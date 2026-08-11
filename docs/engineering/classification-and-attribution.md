# Classification and Attribution

## Main Discovery

Report GB attribution comes mostly from `estimated_app_traffic`, produced by the collector's monitored DNS answer counters. It is not driven only by `config/application_categories.json`.

Changing JSON signatures improves classification lookup, but old unknown GB will not magically change unless matching bytes were already recorded in `estimated_app_traffic`.

## Current Pipeline

1. Bridge nftables counters produce total device traffic in `traffic_intervals`.
2. AdGuard querylog rows are imported into `dns_querylog`.
3. DNS answers for monitored domains are used in memory to create `(client_ip, destination_ip) -> app` mappings.
4. Collector installs nftables counters for those selected pairs.
5. Byte deltas are written to `estimated_app_traffic` and `remote_traffic_intervals`.
6. Reporting maps estimated app labels into functional categories using `config/application_categories.json`.

## Why Coverage Is Low

The report compares all monitored traffic against only traffic with `estimated_app_traffic` rows. Traffic remains unclassified when it never passed through the monitored DNS-to-counter path.

Common causes:

- service not in monitored domain allowlist
- missing DNS answer visibility
- direct IP connections
- encrypted traffic without usable host evidence
- local LAN services intentionally skipped
- traffic captured before a DNS mapping was active
- broad CDN/shared-IP ambiguity

## Current Stored Signals

- `traffic_intervals`: local device IP, bytes, day, timestamp, but no remote IP/domain/SNI/HTTP host/ports/protocol.
- `dns_querylog`: client IP, domain, blocked flag, category, day and timestamp.
- `dns_resolved_ips`: domain, resolved IP and timestamp, but not client-specific with TTL.
- `estimated_app_traffic`: local IP, application/category label, bytes, day and timestamp.
- `remote_traffic_intervals`: local IP, remote IP, category label, bytes, day and timestamp.
- `ids_events`: Suricata DNS, TLS SNI, HTTP host/url/user-agent, app protocol, ports, flow ID, source/destination IPs and timestamps.

## Important Local Classifications

- `e7a37f2d.hvcdn.to` is Plex/HVCDN and should classify as video/streaming.
- BitTorrent DHT on `moms` device is expected.
- AnyDesk use is expected.
- `*.in-addr.arpa` and `*.ip6.arpa` are reverse DNS housekeeping and should be infrastructure, not user browsing.

## Reverse DNS / PTR Handling

Reverse DNS PTR domains should:

- classify as DNS Reverse Lookup / Network Infrastructure
- usage group Infrastructure
- tag System Services
- be excluded from top apps, device domain lists, application detail, blocked-domain views and report domain summaries
- be skipped for estimated app target attribution

## Classification Cache Refresh

After major classification changes:

```bash
sqlite3 /var/lib/netspecter/netspecter_traffic.db "delete from classification_cache;"
systemctl restart netspecter-web
systemctl restart netspecter-collector
```

Then wait for new DNS answers and traffic.

## Verify New Attribution

```bash
sqlite3 /var/lib/netspecter/netspecter_traffic.db "
select category, round(sum(total_mb),2)
from estimated_app_traffic
where day >= date('now','localtime')
group by category
order by sum(total_mb) desc
limit 30;
"
```

## Recommended Next Change

Add a dedicated client-specific DNS resolution table that persists:

- client IP
- domain
- answer IP
- TTL
- expiry
- timestamp
- response status where available

This preserves the current lightweight live counter path while creating indexed evidence for later background classification.
