# Data Architecture

## Design Goal

Reduce SQLite lock contention and keep UI/LCD live values responsive by separating high-write/history data from core state.

## Live Snapshot System

Live UI/LCD values should prefer:

```text
/var/lib/netspecter/live_snapshot.json
```

Collector writes the snapshot. Web/API reads it first for live values such as:

- current Mbps
- device count
- service health
- ping/internet quality
- LCD summary
- dashboard live values

This avoids making UI/LCD live values wait on SQLite.

## Split Database Layout

```text
/var/lib/netspecter/netspecter.db
/var/lib/netspecter/netspecter_dns.db
/var/lib/netspecter/netspecter_traffic.db
/var/lib/netspecter/netspecter_security.db
```

### Core DB: netspecter.db

Contains core state and lower-write tables:

- devices
- labels
- application state
- security/incidents/anomaly/threat tables for now

### DNS DB: netspecter_dns.db

Contains DNS import/history tables:

- `dns_import_state`
- `dns_querylog`
- `dns_resolved_ips`

### Traffic DB: netspecter_traffic.db

Contains traffic/history/high-write tables:

- `collector_heartbeat`
- `live_device_speed`
- `speed_tests`
- `estimated_app_traffic`
- `remote_ip_locations`
- `traffic_intervals`
- `internet_quality`
- `remote_traffic_intervals`
- `traffic_samples`

### Security DB: netspecter_security.db

Created by installer as a future split target. Not actively routed yet.

## Compatibility

Old SQL names can still work because database connection helpers attach split databases automatically.

## Reset Workflow

`scripts/reset-history.sh` should:

- stop NetSpecter services
- move old DB/cache/live snapshot files into a timestamped backup folder
- keep `/etc/netspecter/config.json`
- create fresh split DB files
- clear history/runtime data

## Verify DB Split

```bash
sqlite3 /var/lib/netspecter/netspecter.db ".tables" | grep -E "dns|traffic|speed_tests|internet_quality|live_device_speed|collector_heartbeat" || echo "main DB has no DNS/traffic history tables"
sqlite3 /var/lib/netspecter/netspecter_dns.db ".tables"
sqlite3 /var/lib/netspecter/netspecter_traffic.db ".tables"
```

Expected:

```text
main DB has no DNS/traffic history tables
```

## Future Work

- Route IDS/security high-growth tables into `netspecter_security.db` if they become large.
- Add retention strategy per database.
- Keep report routes bounded and indexed.
