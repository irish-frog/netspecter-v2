# NetSpecter v2 handover

Updated 19 November 2026. Read this before deployment or further attribution work.

## Current live state and authorization

The owner completed the root installation/activation and history cleanup at c3bbf85. A shared web-config bug that removed the new passive flag was fixed by adding supported defaults; the operator applied that correction. Independent checks confirmed all six services active, zero restarts, collector/bridge/database health online, and working DNS. The owner supplied measured records showing real TLS SNI/client-DNS application attribution. The activation verifier's history_reset_performed=false field is static and does not describe a previous reset.

The client's appliance remains ON HOLD: do not update, restart, reset or change it without a later instruction. The inaccessible third appliance remains untouched; prepare a current deployment bundle only. Do not copy the client's VPN settings to any other site.

Owner disk cleanup was root-assisted. About 3.7 GB of old system journals was reclaimed, leaving about 46 GB free (14% used). A journal policy caps persistent logging at 300 MB. Databases, settings, licence material and backups were not deleted by that log cleanup.

## Current attribution update

Product-domain rules now cover Instagram, Facebook, TikTok, OneDrive/SharePoint, Teams, Outlook, Microsoft 365/authentication, OpenAI static assets, Autodesk Fusion and Life360. Imported Microsoft endpoint allowlists provide category context and cannot suppress a stronger product signature. Explicit operator domain mappings retain their named application and precedence.

Shared Meta CDN addresses, generic Google APIs/content, opaque cloud tenants and general iCloud/shared Autodesk endpoints remain unknown without stronger evidence. ASN/provider labels must stay separate from primary applications. SNI is an unauthenticated client claim, not an authorization verdict or proof of a foreground app.

The bounded reclassify-unrecognized CLI previews by default and updates only existing exact-SNI unknown labels when explicitly applied. It rechecks current internet scope and preserves measured bytes, packet counts, connection times, device identities, hostname and evidence. The CLI drops root to the existing service user before opening SQLite; each write transaction covers at most 200 rows. No history reset or DNS change is part of this update.

The owner review snapshot is stored outside the public repo. Offline replay resolves 90.69% of that snapshot's unrecognized-hostname bytes; that is not overall application coverage. The owner-reported headline baseline was 25.2%, which must be measured again after the catalogue update is installed. Catalogue installation/relabeling is currently awaiting the operator's root command.

## Validation

Runtime revision e9a87619fea919039d896bb2f66f601a1218502a passed Linux workflow 44456213365, job 135331732718: 388 Python tests, 23 Rust tests, formatting/clippy/release build, shipped-binary verification, Linux loopback capture, offline third-box bootstrap, and the real bridge/systemd/reset/relabel integration. Local suite: 383 passed and five Linux-only skipped.

The real integration verifies separate apps on one remote IP, actual measured bytes, unchanged TCP delivery, zero internal internet/SNI attribution, no legacy byte guesses, dedicated capture users/private socket/loopback export, retained edited names/raw settings through reset, discarded temporary rollback copy and fresh collection after restart. It also exercises root CLI preview/apply on a real stored-SNI row under the service identity and verifies immutable byte counts/evidence.

The failed workflow 44452978588 came from root-owned CI config permissions after web normalization. The fixture now matches the installer: root:netspecter directory 0750/config 0660. Both corrected bridge runs passed. Earlier development failures also caught real timing/buffering bugs before deployment; GitHub emailed failures automatically. Do not disable notifications to conceal failures.

## Architecture and release files

- Passive Rust sensor: bounded initial ClientHello reconstruction, exact tuple/time metadata, no TLS decryption, payload archive or public listener. ECH outer SNI is suppressed. Memory/CPU/output limits remain enforced.
- Pinned softflowd exporter: upstream 1.1.0 with a checked 100 ms packet-buffer timeout patch; quiet-traffic exports are tested. No compiler or preload hook on appliances.
- Shipped binaries/provenance: inspector/prebuilt/linux-x86_64; source fingerprint/checksums verified before install. Runtime compatibility was checked on the owner Debian 13 host.
- Services: flow_attribution_service, netflow_measurement_service, tls_metadata_service and device_timeline_service. Bridge totals and flow/application coverage stay separate.
- Explicit fresh-database reset: schema allow-list, stopped writers, crash recovery, preserved settings/logins/licences/edited names/rules. Temporary rollback copies are discarded only after successful verification; existing backups remain.
- The full installer now stops old web/proxy workers before activating new keys, preventing stale in-memory defaults from deleting those keys. On failure, previously active core services are resumed. AdGuard is not stopped.
- Deployment and reset commands: docs/engineering/PASSIVE-DEPLOYMENT.md, HISTORY-RESET.md and DOMAIN-CATALOGUE-UPDATE.md. Public third-party notices and build recipe are included.

## Remaining limits and next actions

Install the catalogue on the owner, preview/apply its relabeling, then verify the live result and refreshed settled coverage. Preserve the client hold and leave the third untouched until access returns. Refresh any old exported archive before deployment; revision 3606a28 predates the shared-config fix and is superseded.

Primary headline accounting is IPv4. Unseen VPN inner traffic, ECH, QUIC and missing/long-lived handshake evidence can remain unknown. Raw measured-flow retention defaults to 14 days and TLS metadata to two days; retention pruning is bounded per pass. Current history still grows with flow volume, so do not promise a fixed disk-growth rate or speed improvement without measurements.

A separate SSH session remains unprivileged even when the operator's terminal is already in su -. Never automate terminal UI or request/store root passwords. Appliance settings are outside Git at /etc/netspecter/config.json; SQLite data is under /var/lib/netspecter. Never repair attribution by deleting database/WAL files or backup directories with wildcards.
