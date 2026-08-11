# Technical Debt

## Installer / Platform

- Add a proper `install-check.sh` covering services, bridge, DNS, HTTPS, Suricata, AdGuard, retention and update state.
- Improve AdGuard reinstall path when stale `/etc/systemd/system/AdGuardHome.service` exists but installation files are missing.
- Keep 5050 internal-only by default while retaining emergency recovery via `allow_lan_http_5050`.
- Watch for local mode changes such as `100644 => 100755` on scripts that can block `git pull`.

## Classification

- Historical unknown GB cannot be fixed purely through JSON signatures.
- `traffic_intervals` lacks remote IP/domain/SNI/HTTP host/port/protocol fields.
- `dns_querylog` does not store client-specific answer IPs, TTL or expiry.
- `estimated_app_traffic` lacks evidence source, confidence and matched rule details.

## Data / Performance

- `netspecter_security.db` exists as a future split target but is not actively routed yet.
- Review retention and pruning policies for long-running appliances.
- Keep correlation out of report routes; do it in collector/background jobs.

## IDS

- Keep informational and diagnostic rules searchable but suppressed by default.
- Continue validating Suricata severity mapping to avoid false High/Critical noise.

## UI / Monitoring

- Monitor page/card layout needs polish on ultrawide/square displays.
- Gatus checks may need redirect tolerance or stable endpoint guidance.
