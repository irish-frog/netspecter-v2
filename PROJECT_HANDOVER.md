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

The owner review snapshot is stored outside the public repo. Offline replay resolves 90.69% of that snapshot's unrecognized-hostname bytes; that is not overall application coverage. The owner-reported headline baseline was 25.2%, which must be measured again after the catalogue update is installed. The owner has now installed runtime revision 7f199af and completed historical exact-SNI relabeling; see the final live verification below.

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

Owner installation and bounded historical relabeling are complete. Monitor settled coverage using the same reporting window; the old 25.2% screenshot and the later whole-history snapshot are not directly comparable. Preserve the client hold and leave the third untouched until access returns. Refresh any old exported archive before deployment; revision 3606a28 predates the shared-config fix and is superseded.

Primary headline accounting is IPv4. Unseen VPN inner traffic, ECH, QUIC and missing/long-lived handshake evidence can remain unknown. Raw measured-flow retention defaults to 14 days and TLS metadata to two days; retention pruning is bounded per pass. Current history still grows with flow volume, so do not promise a fixed disk-growth rate or speed improvement without measurements.

A separate SSH session remains unprivileged even when the operator's terminal is already in su -. Never automate terminal UI or request/store root passwords. Appliance settings are outside Git at /etc/netspecter/config.json; SQLite data is under /var/lib/netspecter. Never repair attribution by deleting database/WAL files or backup directories with wildcards.

## Owner maintenance follow-up (19 November)

Main workflow 44456720679 also completed successfully. Owner follow-up changes replace the web updater's writing git fetch with read-only ls-remote, move public-IP lookup off page requests, and queue manual speed tests with a shared scheduled/manual exclusion lock. Existing installs skip optional DNS/Gatus/Beszel provisioning unless explicitly requested, preserving those configurations during updates.

The retired device drawer Alerts tab and IDS empty-state text are removed. Attribution Review reads current measured unknown flows rather than the legacy queue; it remains a view, not a background collector. Exact TLS hostname rules require an operator-supplied verified application; no provider/IP inference is added. Historical relabeling remains a separate preview-first command.

Local regression before publication: 390 passed, five Linux-only skipped; only existing UTC deprecation warnings. Runtime revision 45f915a6c6348117e332c7f4f114df36c484684d passed Linux workflow 44459231555, including real bridge/systemd/TLS/flow validation. Temporary hostname-restricted maintenance access was installed and used only for the fixed verification, update, profiling and relabeling actions. It provided no DNS restart, arbitrary command, database reset or root shell. The temporary sudo policy was revoked after verification. Client and third appliance remain untouched.

Owner deployment is complete at runtime revision 7f199af83759aa6d5e1fb12659a5922f77cc528f. Its feature Linux workflow 44502074949 and main Linux workflow 44502472845 passed; the prior main history-reset regression 44459620884 also passed. The cache-only follow-up changes no schema, measurement or DNS behavior.

Final independent owner checks: all six appliance services active, collector/bridge/database health online, passive verifier ready with loopback flow intake and hardened metadata socket, and Suricata inactive. AdGuard retained PID 830 and its original activation timestamp throughout both updater runs; local DNS continued answering. The source checkout remains root-owned, and git ls-remote succeeds without writing FETCH_HEAD. The unauthenticated speed-test status endpoint returned 401. No production speed test was triggered by these checks.

Direct service-user handler timings: dashboard 104/64 ms (first/repeat), reporting 59/26 ms. These exclude browser/network overhead and are not a controlled before/after benchmark against the earlier request logs. Attribution Review passed isolated render, byte-total, escaping and rule-evidence checks.

The final root-preview identified 3,916 eligible exact-SNI unknown flows. Applying their labels updated those 3,916 records covering 105,551,232 bytes (100.66 MiB), preserving measurements and settings. The preview took 7.277 s and apply 12.601 s after adding a bounded 2,048-host cache scoped to one invocation. A repeat preview found zero remaining eligible improvements. The live flow total grew from 130,987 records / 17,537,169,399 bytes to 135,083 / 18,031,611,754; TLS observations grew from 8,972 to 9,401. This demonstrates ongoing intake, not a promise that all internet traffic can be attributed. Shared providers, ECH, QUIC and missing handshake/DNS evidence remain explicit unknowns.

No history reset was performed in this follow-up. Login/licence/settings and edited names were retained. Disk remains about 7.4 GB used with 46 GB free. The client hold remains in effect; the third appliance package must be transferred and validated when access returns.

## Requested hostname/DNS follow-up

The operator supplied a fresh Attribution Review paste and requested shared catalogue/DNS matching improvements, GitHub publication and deployment only on the owner, preserving DNS and the client hold. New changes add narrow dedicated-service rules, correct noncacheable/CNAME DNS lifetimes, reject blocked-response evidence, and revalidate historical DNS-backed unknowns rather than refreshing only SNI. The DNS database is attached read-only; conflicting/expired/other-client evidence cannot qualify. No resolver settings or primary coverage denominator are changed. Local suite: 410 passed, five Linux-only skipped; Linux integration and owner rollout are pending. Offline hostname-only replay matches about 1,471 MiB of the supplied list, but this is an upper bound before per-flow DNS revalidation, not a projected coverage percentage. See docs/engineering/DNS-ATTRIBUTION-REFRESH.md.
