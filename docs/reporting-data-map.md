# Reporting Data Map

This map documents the existing NetSpecter v2 data available for reporting and investigations. Reporting should stay focused on network, DNS, application, destination, traffic, IDS, incident, internet-quality, configuration-change, device, and user/device-correlation data.

| Table | Important fields | Relationships | Report sections | Known limitations | Required indexes |
| --- | --- | --- | --- | --- | --- |
| `devices` | `ip`, `name`, `mac`, `vendor`, `device_type`, `status`, `first_seen`, `last_seen`, `owner`, `location` | `ip` links to traffic, DNS client IPs, IDS source/destination IPs, incidents | Device inventory, selected devices, new devices, assignment candidates | `owner` is a free-text label, not assignment history. Hostname and username are not guaranteed. | Primary key on `ip`; add `idx_devices_last_seen` if reports frequently filter by recent devices. |
| `device_overrides` | `ip`, `name`, `vendor`, `device_type`, `status`, `ignored`, `updated_at` | Overrides display fields for `devices` and traffic rows | Friendly names, hidden/ignored devices, technician labeling | No historical override snapshots. Historical reports may show current friendly name. | Primary key on `ip` is sufficient. |
| `traffic_intervals` | `ip`, `name`, `mac`, `downloaded_mb`, `uploaded_mb`, `total_mb`, `live_bps`, `day`, `ts` | `ip` joins to `devices`; `day` and `ts` define report period | Traffic usage, upload/download totals, top devices, timeline highlights | Does not identify domains by byte count unless correlated externally. | Existing `idx_intervals_ts`, `idx_intervals_day_ip`, `idx_intervals_ip_ts`, and total indexes are suitable. |
| `traffic_samples` | Same shape as `traffic_intervals` | Same as traffic intervals | Historical charts where samples are still used | Similar data may duplicate intervals; prefer intervals for reporting. | Existing day/IP indexes are suitable. |
| `estimated_app_traffic` | `ip`, `category`, `downloaded_mb`, `uploaded_mb`, `total_mb`, `day`, `ts` | `ip` joins to `devices`; `category` maps to application labels | Application activity, top applications, per-device usage | Application attribution is estimated by category and may not map to exact process/user. | Existing day/category indexes are suitable; add `idx_estimated_app_ts_category` if long custom time ranges are slow. |
| `remote_traffic_intervals` | `ip`, `remote_ip`, `category`, `downloaded_mb`, `uploaded_mb`, `total_mb`, `day`, `ts` | `ip` joins devices | Destinations, remote IPs, traffic by destination | Domain names are not always available for remote IPs. | Add `idx_remote_traffic_ts_ip` for timestamp/device filters. |
| `dns_querylog` | `day`, `ts`, `client`, `domain`, `blocked`, `category` | `client` is normally device IP; `domain` joins `dns_resolved_ips` | DNS summary, blocked DNS, top domains, timeline | User identity is not stored. DNS rows do not contain byte counts. | Existing day/category/domain indexes are useful; add `idx_dns_ts_client` for custom date/time investigations. |
| `dns_resolved_ips` | `domain`, `remote_ip`, `resolved_ts` | Links DNS domains to remote IPs | Domain-to-destination correlation | Resolution timing may not match the exact flow time. | Existing domain and remote-IP indexes are suitable. |
| `ids_events` | `event_type`, `ts`, `day`, `src_ip`, `dest_ip`, `protocol`, `app_proto`, `signature`, `category`, `severity`, `query`, `tls_sni`, `alert_status` | `src_ip`/`dest_ip` can link to devices and destinations; incident events link by source id | IDS alerts, security timeline, risk rating, incident reports | Severity is numeric Suricata-style; not every event is an alert. | Existing timestamp, source, destination, type, signature, day/type, and status indexes are suitable. |
| `security_incidents` | `id`, `severity`, `device_ip`, `device_mac`, `device_name`, `first_event_ts`, `last_event_ts`, `status`, `assigned_to`, `title`, `summary` | `device_ip` links devices; child tables hold event and note history | Incidents, open incident counts, findings | Incidents preserve their own summary, but not full report snapshots yet. | Existing status, severity, and first-event indexes are useful; add `idx_incidents_last_event` for report ranges. |
| `security_incident_events` | `incident_id`, `source_table`, `source_id`, `event_ts`, `event_type`, `summary`, `reason` | `incident_id` joins incidents; source table/id links IDS events | Incident detail, case evidence | Generic source references require careful rendering. | Existing incident/source indexes are suitable. |
| `security_incident_notes` | `incident_id`, `ts`, `author`, `note` | `incident_id` joins incidents | Technician notes | Existing incident notes are incident-specific, not case-management notes. | Add `idx_incident_notes_incident_ts` if notes are used in reports. |
| `anomaly_events` | Anomaly details from anomaly module | Usually relates to device and traffic baselines | New/unusual activity, timeline, risk rules | Exact fields are owned by anomaly module and need cautious query use. | Existing anomaly schema indexes should be reviewed before heavy timelines. |
| `internet_quality` | `ts`, `status`, `diagnosis`, `gateway_latency_ms`, `gateway_loss_pct`, `internet_latency_ms`, `internet_loss_pct`, `jitter_ms`, `dns_ms`, `external_dns_ms`, `wan_up` | Standalone site-level measurements | Internet quality, outages, DNS performance, recommendations | Not tied to individual devices. | Existing `idx_internet_quality_ts` and status index are suitable. |
| `speed_tests` | `ts`, `source`, `latency_ms`, `download_mbps`, `upload_mbps`, `result_text`, `success` | Standalone site-level measurements | Speed-test summary, internet quality report | Scheduled tests may be disabled or sparse. | Existing `idx_speed_tests_ts` is suitable. |
| `config_change_events` | `ts`, `component`, `field`, `severity`, `previous_value`, `new_value`, `snapshot_id`, `status` | `snapshot_id` links `config_snapshots` | Configuration changes, timeline | Values may contain sensitive operational configuration and must be sanitised. | Existing timestamp, component, severity, and status indexes are suitable. |
| `monitor_events` | `monitor_key`, `name`, `url`, `state`, `ts` | Monitor key maps to configured service monitors | Service/internet outage timeline | `ts` is integer epoch while most tables use text timestamps. Convert carefully in reports. | Existing key/timestamp index is suitable. |

## Audit Notes

- Timestamp formats are not fully uniform. Most reporting tables use text timestamps, while `monitor_events.ts` uses an integer epoch.
- Current user identity is limited. Device `owner` is a free-text field and should not be treated as reliable logged-in-user evidence.
- DNS activity, application activity, and traffic usage can usually be tied to a device IP, but not always to a person.
- PDF and CSV exports must use bounded, filtered datasets. Timeline views should aggregate and paginate rather than load all raw rows.
- Slow custom date/time reports are most likely on DNS, remote destination traffic, incidents by last event time, and notes.

## Indexes To Add

```sql
CREATE INDEX IF NOT EXISTS idx_dns_ts_client ON dns_querylog(ts, client);
CREATE INDEX IF NOT EXISTS idx_remote_traffic_ts_ip ON remote_traffic_intervals(ts, ip);
CREATE INDEX IF NOT EXISTS idx_incidents_last_event ON security_incidents(last_event_ts);
CREATE INDEX IF NOT EXISTS idx_incident_notes_incident_ts ON security_incident_notes(incident_id, ts);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
```
