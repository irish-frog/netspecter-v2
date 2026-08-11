# Roadmap

## Near Term

- Validate clean Debian 13 install flow from a fresh clone.
- Add or improve `install-check.sh` for DNS, bridge, web, HTTPS, collector, Suricata, AdGuard, disk/log retention and update checks.
- Improve AdGuard reinstall cleanup when stale service files remain but `/opt/AdGuardHome` is missing.
- Continue classification coverage improvements through persistent DNS answer evidence and safe collector-side correlation.
- Build ESP32/KNOMI LCD firmware/client for `/api/lcd/summary`.
- Improve monitor card layout on ultrawide displays.

## Medium Term

- Add persistent `dns_resolution_events` or equivalent client-specific DNS answer table.
- Add bounded background classification using DNS answer IPs, Suricata TLS SNI/HTTP host and remote destination rows.
- Review retention strategy for DNS, traffic, remote traffic, IDS and incident tables.
- Consider moving IDS/security high-growth tables into `netspecter_security.db` when needed.
- Convert more local/site-specific mappings into explicit site override rules.

## Long Term

- Validate 30-90 day appliance operation under 150-250 active endpoints.
- Produce reliable executive reporting with clear confidence/evidence indicators.
- Keep the appliance suitable for SMB hardware without heavy DPI or packet-capture storage.
