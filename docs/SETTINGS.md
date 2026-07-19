# Settings Reference

This guide summarizes important NetSpecter settings.

[<- Back to README](../README.md)

## Network

| Setting | Purpose |
|---|---|
| LAN prefix | Used to identify local devices |
| Gateway IP | Router IP; excluded from some device usage totals |
| Packet interface | Bridge capture interface, normally `br0` |
| Ignored IPs | Devices to hide or reduce noise for |

## AdGuard

| Setting | Purpose |
|---|---|
| AdGuard URL | AdGuard Home admin URL |
| Username/password | Used to import DNS logs and manage DNS rules |
| Query log interval | How often NetSpecter imports query log data |

## Telegram

| Setting | Purpose |
|---|---|
| Enable Telegram Alerts | Enables Telegram sending globally |
| Bot Token | Telegram bot token |
| Chat ID | Private or group chat ID |

Use [Telegram Alerts](TELEGRAM.md) for setup details.

## IDS And Incidents

Relevant settings include:

- IDS Telegram enabled
- IDS email enabled
- cooldown minutes
- retention days
- incident trigger severities
- incident dedupe window
- banned IPs

## Retention

Use retention settings to keep the database from growing forever. Shorter retention improves query speed and lowers disk usage.

## Authentication

Keep authentication enabled for normal deployments. Session secrets are stored locally under NetSpecter configuration.

---

Next:

- [Telegram Alerts](TELEGRAM.md)
- [Backups and Restore](BACKUPS.md)
