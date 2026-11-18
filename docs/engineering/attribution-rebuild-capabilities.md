# Attribution rebuild capability map

Status: structure approved by the operator on 2026-11-18. Existing application remains operational until a tested replacement is ready.

| Module id | Responsibility | Depends on |
| --- | --- | --- |
| tls-metadata | Bounded passive ClientHello/SNI inspection in a separate Rust process; emit connection-scoped metadata without storing packet payloads | Existing bridge capture interface |
| flow-attribution | Correlate device identity, client-aware DNS and exact connection metadata with measured traffic; preserve confidence and unknown reasons | tls-metadata, existing AdGuard import and bridge counters |
| device-timeline | Display application/domain observations, measured bytes, evidence source and confidence for a device | flow-attribution |
| history-reset | Explicit reset of collected history while retaining settings, authentication, licences, backups and edited device identities | Validated replacement schema and coordinated collector stop/start |

Build order: tls-metadata -> flow-attribution -> device-timeline -> validated deployment with history-reset.

## Agreed constraints

- Retire Suricata IDS collection, rule management and IDS alerts.
- Keep AdGuard DNS filtering, existing web UI, service checks and device names.
- No TLS decryption, interception certificates, persistent packet captures or additional public listening ports.
- Exclude LAN/server transfers and configured VPN/internal networks from internet usage. VPN users are visible only where traffic crosses the bridge.
- A hostname observed on one connection must not label all traffic to a shared CDN address. Attribution requires a matching connection/time window; otherwise record an observation without claiming its bytes.
- ECH, QUIC and unavailable evidence remain explicit coverage limitations.
- Reset scope approved for two reachable appliances: all collected history while retaining edited device names/settings, login, licences and backups. No deployment or reset on the inaccessible third unit merely because it shares the repository.
- Reset is explicit, never a normal update side effect. Do not erase history before the replacement is validated and ready.

## Operational constraints

- Both reachable appliances are Debian 13 x86_64 with glibc 2.41.
- Rust/Cargo 1.100.0 are installed in the local development workspace; native compilation and execution passed. No compiler was installed on an appliance.
- Native Windows tests and Linux cross-target checks do not replace Linux linking and runtime validation.
- Existing SSH access is unprivileged; installation, package removal and live data resets require the operator's root shell.

## Later operator instruction

Prepare the same explicit cleanup/deployment procedure and source/binary package for the inaccessible third appliance. Do not contact or reset it now. When access returns, the operator supplies its exact hostname and runs preflight followed by explicit deployment/reset. Preserve settings, login credentials, licences, edited names and custom rules. Do not retain an extra history backup after verified reset success.
