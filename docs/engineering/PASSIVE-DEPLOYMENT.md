# Passive attribution deployment and explicit cleanup

## Supported appliances

Linux x86_64, glibc 2.39 or later; tested with the Debian 13 appliances. The configured capture interface must already be a Linux bridge. The bundled sensor and flow exporter, their pinned build identity, source fingerprint and checksums are checked before installation. The exporter has a tested 100 ms capture timeout so quiet traffic does not remain in an infinite packet-buffer wait. No Rust compiler, interception certificate, packet archive or new public listening port is installed.

The sensor and softflowd run under separate locked service identities with only CAP_NET_RAW. Metadata uses a root-owned group-restricted UNIX socket passed to the unprivileged collector. Flow export is local UDP on 127.0.0.1 only. Bridge capture uses temporary promiscuous packet membership so forwarded frames are visible; it does not change routing, DNS, bridge membership or firewall policy. Legacy IDS automatic blocking is disabled; only counting rules remain in NetSpecter's private table. System and kernel logs are not cleared.

## Update and preflight

Run in a root shell on the appliance. Source edits are never discarded. Permission-only Git differences caused by installed executable scripts can be ignored for the update:

```bash
cd /opt/netspecter
git -c safe.directory=/opt/netspecter -c core.filemode=false pull --ff-only origin main
bash scripts/deploy-attribution.sh --preflight --expected-hostname ACTUAL_HOSTNAME
```

Check the hostname with `hostname`; replace ACTUAL_HOSTNAME literally. Preflight checks the binary/source checksum, architecture, glibc, current configuration and existing bridge without changing settings/services/history. A failed preflight must be resolved before applying. A pending interrupted history reset must be recovered first.

## Deployment hold

The client appliance is currently on hold: prepare its commands only. Do not deploy, clean up, restart or change it without a later operator instruction. The owner appliance is the live validation target; the third appliance is inaccessible and stays untouched.

## Deploy the known appliances when authorized

On the personal appliance:

```bash
bash /opt/netspecter/scripts/deploy-attribution.sh --apply --expected-hostname Netspecter --reset-history --purge-retired-ids
```

On the client appliance, with its VPN client network:

```bash
bash /opt/netspecter/scripts/deploy-attribution.sh --apply --expected-hostname Wslunifi --internal-network CLIENT_VPN_CIDR --reset-history --purge-retired-ids
```

Replace CLIENT_VPN_CIDR with the actual client pool (for example 10.20.30.0/24). Do not add that site's VPN configuration to other appliances. Existing internal-network exclusions are retained. Transfers between LANs/VPN clients/internal servers are excluded. The server's internet traffic still counts. Only VPN traffic visible after decryption on the monitored bridge can be attributed to an individual client; encrypted outer tunnels do not reveal their inner applications.

The explicit deployment wrapper skips optional AdGuard/Gatus/Beszel installation. It checks active AdGuard UDP/TCP resolution and hashes existing AdGuard configuration before installation, before history cleanup and afterward; failure stops further cleanup. It does not restart AdGuard.

`--apply` installs/enables the tested pipeline and verifies dedicated identities, checksums, private socket permissions and loopback export. `--reset-history` separately requests the tested fresh-database cleanup. Settings, logins, licences, edited names, custom classifications and existing backups remain. A temporary rollback copy is removed after successful restart/verification. No normal update resets history.

`--purge-retired-ids` removes only installed suricata/suricata-update packages, after simulating removal and refusing any additional package removals. It never runs apt autoremove. Existing AdGuard settings and filtering are preserved.

## Third appliance when access returns

The third appliance is not contacted or changed now. Use the same online preflight/apply procedure with its actual hostname. Preserve its own subnets; add `--internal-network` only for its actual VPN/routed network configuration. Do not copy the client's subnet blindly.

Alternatively, transfer/extract the prepared deployment archive onto that appliance. It contains the tested public Git revision and prebuilt binary, not any working-tree databases, credentials, licence files or private settings. From the extracted package:

```bash
bash deploy-from-bundle.sh ACTUAL_HOSTNAME --preflight
bash deploy-from-bundle.sh ACTUAL_HOSTNAME --apply --reset-history --purge-retired-ids
```

The bundle verifies its checksum and Git revision, refuses real local source edits, and fast-forwards the existing checkout. It needs no GitHub connection; apt and pip network access are still needed for any missing normal appliance dependencies/libpcap/Python packages. This is an offline Git/source bundle, not a fully air-gapped dependency installer. Both the Rust sensor and patched flow exporter are included in the bundle. No compiler is required. The preflight bootstrap updates the checkout but does not enable services, change configuration or clear history. Settings live outside the source bundle and remain on the appliance.

## Verification and limits

Run `python3 /opt/netspecter/scripts/verify-passive-attribution.py` after deployment. Confirm the collector, TLS inspector, local flow exporter and private socket are active. Fresh activity should populate the device's Application timeline. New connections supply SNI; cached DNS/long-lived connections can need time to rebuild evidence after reset.

The pipeline does not decrypt TLS, ECH or QUIC. It requires exact connection/time matching for SNI bytes, otherwise uses unambiguous client-aware DNS or reports an unknown reason. Providers/shared CDN addresses alone do not prove an application. Bridge totals, measured flow visibility and attributed bytes remain separate; coverage excludes the newest two minutes while exports settle and is unavailable when counters disagree. SNI is an unauthenticated client claim, never a security or authorization decision.

Primary bridge coverage is currently IPv4. IPv6 packets/exports are decoded, but IPv6 global-prefix accounting needs site configuration and is not included in that IPv4 headline. Configured client subnets up to 1024 addresses each are counted, with a 4096-client cap; larger routed prefixes remain destination exclusions rather than enormous counter rule sets.

If deployment fails, no explicit history reset is attempted. If a reset fails, use its printed recovery command; interrupted-reset guards keep writers stopped until recovery. Do not use broad database/WAL deletion commands or delete system logs to repair a deployment.
