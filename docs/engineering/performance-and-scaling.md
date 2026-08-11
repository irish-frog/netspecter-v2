# Performance and Scaling

## Target

Support roughly:

- 50 users
- 50 mobiles
- 50 desk phones
- 150-250 active endpoints
- 30-90 days of running data

without CPU/HDD degradation.

## Core Decisions

- No expensive reverse DNS during UI/API/report rendering.
- Classification/correlation happens during ingestion or scheduled background processing.
- Keep RAM acceptable, but prioritize low CPU and low disk churn.
- Avoid changing traffic collection semantics without understanding accuracy impact.

## Important Performance Fixes

### Incident Builder

- Incident builder uses checkpoints.
- Added incident indexes and timing logs.
- Avoids walking old IDS history repeatedly.

### Collector Timing

Traffic counter batch timing includes:

- `prepare`
- `live_speed_write`
- `device_write`
- `traffic_fact_write`
- `estimated_write`
- `destination_write`

Incident builder timing includes:

- rows selected
- incidents created/updated/closed
- checkpoint start/end
- SQL time
- transaction time
- commit time

### Device Inventory Write Throttling

Device writes are throttled to once per IP per 60 seconds unless metadata changes. Live speed and traffic facts remain continuous.

## Observed Improvements

Before optimizations:

- Threat intel: around 115s+
- Anomaly: around 152s+
- Destination classification: around 122s
- Suricata metadata classification: 8-9s
- Incident builder: 17-18s
- Traffic batch: 12-15s

After fixes observed:

- Threat correlation: around 2-3s
- Anomaly batch: around 2s
- Destination classification: milliseconds
- Suricata metadata classification with cache: around 0.5-1.2s per 500 rows
- DNS split improved AdGuard/import loop from roughly 46-90s to around 7s in one observed run

## Validate

```bash
journalctl -u netspecter-collector -n 220 -l --no-pager | grep -E "Incident build detail|Incident correlation detail|Traffic counter batch detail|traffic_counter_batch|Suricata metadata classification|database is locked"
```

Expected after throttling:

- `device_writes` often `0`
- `device_write` near `0.000s`
- `traffic_counter_batch` generally under 1s
- no recent `database is locked` errors

## Scaling Rules

- Keep collector writes batched.
- Keep retention bounded.
- Add indexes before heavy history reports.
- Use live snapshot for live UI/LCD instead of direct SQLite when possible.
- Avoid full-history classification in normal routes.
