# Migration Map

## Keep at docs root

| New file | Purpose |
|---|---|
| `CURRENT_STATE.md` | Short active handoff for Codex/new chats. Keep under 1-2 pages. |
| `ARCHITECTURE.md` | High-level architecture and component map. |
| `ROADMAP.md` | Planned work and priorities. |
| `TECHNICAL_DEBT.md` | Known issues and cleanup items. |

## Move into deployment/

| Old file | New path |
|---|---|
| `INSTALL.md` | `deployment/INSTALL.md` |
| `FIRST-SETUP.md` | `deployment/FIRST-SETUP.md` |
| `UPDATES.md` | `deployment/UPDATES.md` |
| `TROUBLESHOOTING.md` | `deployment/TROUBLESHOOTING.md` |
| `SETTINGS.md` | `deployment/SETTINGS.md` |
| `BACKUPS.md` | `deployment/BACKUPS.md` |
| `2026-07-install-hardening-and-appliance-recovery.md` | merge into `deployment/INSTALL.md`, `deployment/UPDATES.md`, and `engineering/platform-security-and-installer-notes.md` if created later |

## Move into network/

| Old file | New path |
|---|---|
| `NETWORK-BRIDGE.md` | `network/NETWORK-BRIDGE.md` |

## Move into integrations/

| Old file | New path |
|---|---|
| `ADGUARD.md` | `integrations/ADGUARD.md` |
| `SURICATA.md` | `integrations/SURICATA.md` |
| `UNIFI.md` | `integrations/UNIFI.md` |
| `TELEGRAM.md` | `integrations/TELEGRAM.md` |
| LCD handoff content | `integrations/LCD.md` |

## Move into engineering/

| Old file | New path |
|---|---|
| `02-performance-and-scaling.md` | split into `engineering/data-architecture.md` and `engineering/performance-and-scaling.md` |
| `03-classification-and-traffic-analysis.md` | `engineering/classification-and-attribution.md` |
| `04-ids-and-incidents.md` | `engineering/ids-and-incidents.md` |
| `reporting-data-map.md` | `engineering/reporting-data-map.md` |
| `adguard-classification-audit.md` | merge into `engineering/classification-and-attribution.md` |
| `classification-coverage-audit.md` | merge into `engineering/classification-and-attribution.md` |
| `2026-07-performance-and-classification.md` | split between `engineering/performance-and-scaling.md` and `engineering/classification-and-attribution.md` |
| `2026-07-lcd-api-and-bridge-investigation.md` | split between `integrations/LCD.md`, `engineering/monitoring-and-health.md`, and `network/NETWORK-BRIDGE.md` |

## Move into business/

| Old file | New path |
|---|---|
| `2026-07-licensing-legal-and-hardware.md` | split into `business/licensing-and-compliance.md` and `business/hardware-and-appliance-builds.md` |
| `2026-07-repositories-and-documentation.md` | `business/repositories-and-positioning.md` |

## Move into history/

After merging useful detail into the structured files, keep original handoffs in:

```text
history/archive/
```

Do not keep one new handoff file per chat forever. Merge future handoffs into the correct category and only keep very large source handoffs in archive.
