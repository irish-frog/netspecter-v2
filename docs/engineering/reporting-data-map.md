# Reporting Data Map

Reporting should stay focused on network, DNS, application, destination, traffic, IDS, incident, internet-quality, configuration-change, device and user/device-correlation data.

## Main Tables

| Table | Purpose | Known limitations |
|---|---|---|
| `devices` | Device inventory and context | Owner is free text, not reliable logged-in-user evidence |
| `device_overrides` | Friendly names and ignored/hidden devices | No historical override snapshots |
| `traffic_intervals` | Device traffic usage over time | No domain/remote IP/application evidence |
| `traffic_samples` | Historical chart samples | May duplicate interval concepts; prefer intervals for reporting |
| `estimated_app_traffic` | Application byte attribution | Estimated and category-based, not exact process/user attribution |
| `remote_traffic_intervals` | Remote IP traffic by app/category | Domain names not always available |
| `dns_querylog` | DNS activity and blocked domains | DNS rows do not contain byte counts |
| `dns_resolved_ips` | Domain-to-IP enrichment | Not client-specific and timing may not match flows |
| `ids_events` | IDS/security event evidence | Severity is Suricata-style and not every event is an alert |
| `security_incidents` | Grouped security incidents | Does not preserve full report snapshots yet |
| `security_incident_events` | Incident evidence mapping | Generic source references require careful rendering |
| `security_incident_notes` | Technician notes | Incident-specific notes only |
| `anomaly_events` | Anomaly findings | Exact fields are owned by anomaly module |
| `internet_quality` | Site-level WAN quality | Not tied to individual devices |
| `speed_tests` | Site-level speed history | Sparse if scheduled tests disabled |
| `config_change_events` | Configuration timeline | Values may contain sensitive data and must be sanitized |
| `monitor_events` | Service monitor events | Timestamp format differs from most tables |

## Audit Notes

- Timestamp formats are not fully uniform.
- Current user identity is limited.
- DNS, app and traffic activity can usually be tied to device IP, not always to a person.
- PDF/CSV exports must use bounded, filtered datasets.
- Timeline views should aggregate and paginate rather than load all raw rows.

## Candidate Indexes

```sql
CREATE INDEX IF NOT EXISTS idx_dns_ts_client ON dns_querylog(ts, client);
CREATE INDEX IF NOT EXISTS idx_remote_traffic_ts_ip ON remote_traffic_intervals(ts, ip);
CREATE INDEX IF NOT EXISTS idx_incidents_last_event ON security_incidents(last_event_ts);
CREATE INDEX IF NOT EXISTS idx_incident_notes_incident_ts ON security_incident_notes(incident_id, ts);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
```
