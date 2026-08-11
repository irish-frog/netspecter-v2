# IDS and Incidents

## Severity Philosophy

NetSpecter should reduce IDS noise without hiding evidence. Informational/default-suppressed alerts should remain searchable in expanded/raw IDS history but should not inflate High/Critical totals or notify by default.

## Important Severity Decisions

- ET INFO external-IP lookup alerts are Informational.
- External-IP lookup alerts are labeled External IP discovery.
- `.biz` and `.management` DNS observations are Low, not High/Critical.
- Truncated packet decoder alerts are Diagnostic/hidden by default.
- ET USER_AGENTS Steam HTTP Client User-Agent is Informational.
- Steam override stores `application=Steam`, `category=Gaming`.
- `ET USER_AGENTS*` defaults to Informational unless explicit malicious override exists.
- Suricata policy/privacy categories no longer drive Critical classification on their own.

## ids_events Schema Additions

`ids_events` includes:

- `first_seen`
- `last_seen`
- `alert_count`
- `application`

## Duplicate Alert Aggregation

Duplicate alert aggregation uses:

- signature/signature ID
- source
- destination/domain
- protocol
- configurable time bucket

## Migration / Maintenance

Existing alerts are reclassified by collector import/retention and by:

```bash
cd /opt/netspecter
./scripts/post-update-maintenance.sh
systemctl restart netspecter-web netspecter-collector
```

## Validation

Useful checks:

```bash
python -m pytest tests/test_ids_eve.py tests/test_ids_notifications.py -q
python -m py_compile netspecter_ids.py netspecter_db.py live_packet_collector.py app.py tests/test_ids_eve.py tests/test_ids_notifications.py
```

## Incident Statuses

- Open: needs attention and can notify
- Acknowledged: seen by admin; should not repeat as open
- Investigating: being reviewed
- Closed: resolved; should not notify as open
- Ignored: intentionally ignored
- Banned: source or endpoint banned by NetSpecter action

## Notification Rules

- Open P1/P2 alerts can notify.
- Non-open alerts should not continue to notify.
- Cooldown prevents repeated messages for the same alert key.
- Auto-banning should remain disabled unless explicitly configured.
