# Repositories and Positioning

## Repositories

Main repos under:

```text
C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website
```

| Repo | Purpose |
|---|---|
| `netspecter-v2` | Current feature-rich appliance branch |
| `netspecter` | Original NetSpecter for simpler/older hardware deployments |

## NetSpecter v2 Positioning

v2 is positioned for:

- better hardware
- expanded monitoring
- IDS incident workflows
- MaxMind GeoLite2 support
- backup/restore tooling
- telemetry
- broader health views

## Original NetSpecter Positioning

Original NetSpecter is positioned for:

- home networks
- very small networks
- older hardware
- simpler deployments

## Documentation Rule

Do not oversell features. Avoid claiming a feature unless code confirms it or Gavin confirms it.

Known correction:

- Original NetSpecter README should not claim Gatus, Beszel, Telegram or backup unless verified as real supported features for v1.
- v1 README feature claims were reduced to UniFi, SNMP, MQTT and Suricata.

## Repository Hygiene

- Do not commit `nul`.
- Do not commit local `examples/` unless explicitly requested.
- Do not push the NetLic PHP service repo to GitHub.
- Use GitHub-pushed changes as the source of truth for shared work.
