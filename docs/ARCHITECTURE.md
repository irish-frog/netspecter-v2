# Architecture

## Security Boundary

NetSpecter is designed to run inside a customer LAN. The web UI, API, LCD endpoint, AdGuard Home, Gatus, SSH and management ports must not be exposed directly to the public internet. Remote access should be through a private VPN.

## Main Runtime Paths

| Path | Purpose |
|---|---|
| `/opt/netspecter` | Installed application runtime |
| `/etc/netspecter` | Local configuration and secrets |
| `/var/lib/netspecter` | SQLite databases, live snapshot and local state |
| `/etc/netspecter/gatus/config.yaml` | Generated monitor configuration |

## Main Services

| Service | Purpose |
|---|---|
| `netspecter-web.service` | Flask/Gunicorn web UI and API, internally bound to 127.0.0.1:5050 by default |
| `netspecter-https.service` | HTTPS LAN entry point on port 9443 |
| `netspecter-collector.service` | Bridge traffic collector, AdGuard importer, Suricata EVE import and live snapshot writer |
| `netspecter-monitor.timer` | Monitor sync and alert sweeper |
| `gatus.service` | Service monitor engine |
| `netspecter-vault.timer` | Backup/vault scheduling |
| `netspecter-speedtest.timer` | Scheduled speed tests when enabled |

## Component Flow

```mermaid
flowchart LR
  Router[Router / Gateway] --> Bridge[NetSpecter bridge br0]
  Bridge --> Switch[Switch / LAN]
  Bridge --> Collector[netspecter-collector]
  AdGuard[AdGuard Home] --> Collector
  Suricata[Suricata eve.json / fast.log] --> Collector
  Collector --> Snapshot[live_snapshot.json]
  Collector --> DBs[Split SQLite databases]
  Gatus[Gatus monitors] --> Sweeper[netspecter-monitor]
  Sweeper --> DBs
  Snapshot --> Web[Flask / Gunicorn]
  DBs --> Web
  Web --> HTTPS[netspecter-https :9443]
  Telegram[Telegram bot] <-- Alerts[Monitor and IDS alerts]
```

## Design Rules

- Do not perform expensive reverse DNS, external lookups or full-history joins during report rendering.
- Collector/background jobs should do correlation and classification work.
- UI/LCD live values should prefer `live_snapshot.json` over direct SQLite queries when available.
- Keep high-write/history data separate from core state to reduce SQLite lock contention.
