# Architecture

This guide explains how the main NetSpecter components interact.

[<- Back to README](../README.md)

## Security Boundary

NetSpecter is designed to run inside the customer's LAN. The web UI, API, LCD endpoint, AdGuard Home, Gatus, SSH, and all appliance management ports must not be exposed directly to the public internet.

Remote access should be through a private VPN only.

## Component Flow

```mermaid
flowchart LR
  Router["Router / Gateway"] --> Bridge["NetSpecter bridge br0"]
  Bridge --> Switch["Switch / LAN"]
  Bridge --> Collector["netspecter-collector"]
  AdGuard["AdGuard Home"] --> Collector
  Suricata["Suricata eve.json / fast.log"] --> Collector
  Gatus["Gatus monitors"] --> Sweeper["netspecter-monitor"]
  Collector --> SQLite["SQLite /var/lib/netspecter/netspecter.db"]
  Sweeper --> SQLite
  SQLite --> Flask["Flask / Gunicorn web UI"]
  Telegram["Telegram bot"] <-- Alerts["Monitor and IDS alerts"]
  Sweeper --> Alerts
  Flask --> Alerts
```

## Main Runtime Paths

| Path | Purpose |
|---|---|
| `/opt/netspecter` | Installed application runtime |
| `/etc/netspecter` | Local configuration and secrets |
| `/var/lib/netspecter` | SQLite database and local state |
| `/etc/netspecter/gatus/config.yaml` | Generated Gatus monitor configuration |

## Main Services

| Service | Purpose |
|---|---|
| `netspecter-web.service` | Flask/Gunicorn web UI and API |
| `netspecter-collector.service` | Bridge traffic collector, AdGuard importers, and Suricata EVE import |
| `netspecter-monitor.timer` | Monitor sync and alert sweeper |
| `gatus.service` | Service monitor engine |

---

Next:

- [Development](DEVELOPMENT.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Return to README](../README.md)
