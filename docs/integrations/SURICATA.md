# Suricata IDS

Suricata is optional but recommended for IDS visibility when appliance hardware can handle it.

## Actual Alert Sources

| Source | Role |
|---|---|
| `/var/log/suricata/eve.json` | Imported by `netspecter-collector.service` into structured `ids_events` rows |
| `/var/log/suricata/fast.log` | Bounded fallback used by the web UI when structured events are unavailable |

Structured EVE JSON is the richer source. It can include source/destination IPs and ports, protocol, app protocol, flow ID, signature details, DNS fields, TLS fields, HTTP fields, file fields and hashes where Suricata provides them.

## Services Involved

| Service | Purpose |
|---|---|
| `netspecter-collector.service` | Imports Suricata EVE JSON incrementally |
| `netspecter-monitor.timer` | Runs monitor sync and alert processing |
| `netspecter-monitor.service` | Sends eligible IDS notifications when triggered |
| `netspecter-web.service` | Displays IDS alerts, incidents and actions |

## Notification Behaviour

NetSpecter Telegram IDS alerts require:

- Telegram enabled globally
- IDS Telegram alerts enabled
- Alert status is open
- Priority is P1 or P2
- Cooldown has expired

P3 alerts are ignored for Telegram by default. Closed, acknowledged, investigating, ignored or banned alerts should not repeatedly notify as open alerts.

## Suricata Interface Safety

A common failure is Suricata listening on Debian's default interface while the appliance uses the bridge interface such as `br0`.

Check:

```bash
systemctl status suricata --no-pager -l
journalctl -u suricata -n 120 --no-pager
```

NetSpecter post-update maintenance syncs Suricata AF_PACKET interface from `/etc/netspecter/config.json` `packet_iface`, or `NETSPECTER_SURICATA_IFACE` when set.

## NIC Offload Service

For bridge deployments, NetSpecter installs `netspecter-nic-offload.service`. It disables GRO, GSO and TSO on physical bridge members to improve IDS packet fidelity.

Verify:

```bash
bridge link
/opt/netspecter/scripts/configure-ids-interfaces.sh br0 --verify
systemctl status netspecter-nic-offload.service --no-pager
systemctl status suricata --no-pager
```

Expected offloads on physical bridge members:

```text
tcp-segmentation-offload: off
generic-segmentation-offload: off
generic-receive-offload: off
```
