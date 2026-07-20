# Suricata IDS

This guide covers Suricata alert import, IDS notifications, and safe testing.

[<- Back to README](../README.md)

Suricata is optional but recommended for IDS visibility when the appliance hardware can handle it.

## Actual Alert Sources

Current code supports two paths:

| Source | Role |
|---|---|
| `/var/log/suricata/eve.json` | Imported by `netspecter-collector.service` into structured `ids_events` rows |
| `/var/log/suricata/fast.log` | Bounded fallback used by the web UI when structured events are not available |

Structured EVE JSON is the richer source. It can include source/destination IPs and ports, protocol, app protocol, flow ID, signature ID, signature, category, severity, DNS fields, TLS fields, HTTP fields, file fields, and hashes where Suricata provides them.

Do not assume `fast.log` alone is the main data source on current builds.

## Services Involved

| Service | Purpose |
|---|---|
| `netspecter-collector.service` | Imports Suricata `eve.json` incrementally |
| `netspecter-monitor.timer` | Runs monitor sync and alert processing |
| `netspecter-monitor.service` | Sends eligible IDS notifications when triggered |
| `netspecter-web.service` | Displays IDS alerts, incidents, and actions |

## Notification Behaviour

NetSpecter Telegram IDS alerts require:

- Telegram enabled globally.
- IDS Telegram alerts enabled.
- Alert status is `open`.
- Priority is P1 or P2.
- Cooldown has expired.

P3 alerts are ignored for Telegram by default.

Closed, acknowledged, investigating, ignored, or banned alerts should not repeatedly notify as open alerts.

## Incident Deduplication

At a high level, NetSpecter groups related IDS alerts into incidents using normalized alert details such as signature and source context. Repeated matching events can update the same active incident instead of creating a new separate incident every time.

The exact grouping is controlled by incident settings such as:

- `incident_trigger_severities`
- `incident_window_minutes`
- `incident_dedupe_minutes`
- `incident_max_per_device_per_day`

## Safe Testing

For live production, prefer controlled test alerts and avoid overwriting real Suricata logs.

Create the log path if needed:

```bash
mkdir -p /var/log/suricata
touch /var/log/suricata/fast.log
```

P1 test fallback alert:

```bash
bash -c 'echo "07/10/2026-23:01:00.000000 [**] [1:999001:1] NETSPECTER TEST P1 IDS ALERT [**] [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 192.168.1.50:4444 -> 8.8.8.8:443" >> /var/log/suricata/fast.log'
systemctl start netspecter-monitor.service
journalctl -u netspecter-monitor.service -n 80 --no-pager
```

P2 test fallback alert:

```bash
bash -c 'echo "07/10/2026-23:02:00.000000 [**] [1:999002:1] NETSPECTER TEST P2 IDS ALERT [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.51:5555 -> 1.1.1.1:443" >> /var/log/suricata/fast.log'
systemctl start netspecter-monitor.service
journalctl -u netspecter-monitor.service -n 80 --no-pager
```

P3 should not send Telegram by default:

```bash
bash -c 'echo "07/10/2026-23:03:00.000000 [**] [1:999003:1] NETSPECTER TEST P3 IDS ALERT SHOULD NOT SEND [**] [Classification: Misc activity] [Priority: 3] {TCP} 192.168.1.52:1234 -> 9.9.9.9:443" >> /var/log/suricata/fast.log'
systemctl start netspecter-monitor.service
```

## Troubleshooting

```bash
systemctl status netspecter-collector netspecter-monitor.timer --no-pager -l
journalctl -u netspecter-collector -n 120 --no-pager
journalctl -u netspecter-monitor.service -n 120 --no-pager
ls -l /var/log/suricata/eve.json /var/log/suricata/fast.log
```

If CPU is high and `top` shows `Suricata-Main` at or near 100% on one core, check for a restart loop:

```bash
systemctl status suricata --no-pager -l
systemctl show suricata -p NRestarts -p RestartUSec -p CPUQuotaPerSecUSec
journalctl -u suricata -n 120 --no-pager
```

A common cause is Suricata still listening on Debian's default interface, `eth0`, while the appliance uses the NetSpecter bridge interface such as `br0`. The Suricata log will show:

```text
af-packet: eth0: failed to find interface: No such device
```

NetSpecter installer and post-update maintenance sync Suricata's AF_PACKET interface from `/etc/netspecter/config.json` `packet_iface`, or from `NETSPECTER_SURICATA_IFACE` when that environment variable is set.

NetSpecter installs a Suricata systemd safety override at:

```text
/etc/systemd/system/suricata.service.d/netspecter-safety.conf
```

It slows restarts, limits restart bursts, and caps Suricata CPU so a broken IDS service does not keep the appliance busy. If Suricata is repeatedly exiting with `status=1`, NetSpecter post-update maintenance disables it to protect the appliance. The web UI and collector still run, but new IDS alerts will not be captured until Suricata is repaired and started again:

```bash
suricata -T -c /etc/suricata/suricata.yaml
systemctl reset-failed suricata
systemctl enable --now suricata
```

Expected result:

- EVE JSON imports appear in collector logs when new structured rows are inserted.
- IDS Alerts page shows structured rows when available.
- `fast.log` fallback alerts show only when structured rows are unavailable.

---

Next:

- [Understand incidents](INCIDENTS.md)
- [Configure Telegram](TELEGRAM.md)
- [Return to README](../README.md)
