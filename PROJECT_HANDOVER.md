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

The operator supplied a fresh Attribution Review paste and requested shared catalogue/DNS matching improvements, GitHub publication and deployment only on the owner, preserving DNS and the client hold. New changes add narrow dedicated-service rules, correct noncacheable/CNAME DNS lifetimes, reject blocked-response evidence, and revalidate historical DNS-backed unknowns rather than refreshing only SNI. The DNS database is attached read-only; conflicting/expired/other-client evidence cannot qualify. No resolver settings or primary coverage denominator are changed. Local suite: 410 passed, five Linux-only skipped. Runtime 8c5c6dfae28e18b0ca9e8a651a2fefa32dfef09e passed Linux feature workflow 44510980649 and main workflow 44511407001 (415 Python and 23 Rust tests). Main history-reset safety workflow 44511407056 also passed. Offline hostname-only replay matches about 1,471 MiB of the supplied list, but this is an upper bound before per-flow DNS revalidation, not a projected coverage percentage. See docs/engineering/DNS-ATTRIBUTION-REFRESH.md.

### Completed owner DNS rollout

Owner runtime 8c5c6df is installed. Historical apply revalidated 35,865 rows and updated 4,384 labels covering 1,607,248,988 bytes: 3,960 client-DNS records / 1,359,187,788 bytes at medium confidence, and 424 TLS records / 248,061,200 bytes. Apply took 26.658 seconds; preview took 14.697 seconds. The repeat preview checked 31,821 remaining records, found zero candidates, and did not hit its scan cap. No measurement, settings, login, licence or edited names were deleted or reset.

A fixed settled window (start_ms 1794999591000, end_ms 1795085991000) preserved exactly 19,377,732,892 measured bytes before/after. Attributed bytes rose from 1,460,755,423 to 3,023,542,352: measured-flow classification increased 7.5% to 15.6%. This is not the dashboard bridge-based headline. The audit's raw bridge-only total was 18,946,440,037 bytes, below measured flows; its bridge coverage was correctly unavailable. Do not turn that audit into a bridge-coverage claim or alter the denominator. The selected UI period and merged bridge source require separate comparison.

Independent owner checks passed: all six services active, no automatic service restarts, passive socket/loopback/binary verifier ready, and collector/bridge/database health online. AdGuard retained PID 830 and the original activation timestamp; local DNS answered during and after installation. Fresh flow/TLS data continued arriving. The web updater check under the actual service identity returned ok=true, available=false, current=latest=8c5c6df; Attribution Review rendered HTTP 200 in about 0.9 seconds. Temporary sudo access was revoked again after verification. Client and third appliance remain untouched.

## Management report counter mismatch follow-up

The operator supplied a report with unavailable primary bridge coverage, duplicated application/category names and a retired Security Events option. A bridge compaction defect was reproduced: successive partial-hour batches overwrite the previous hourly total before raw deletion. Fixes use additive transaction-bound compaction, frozen raw/retention cutoffs and a shared disjoint rollup/raw reader. NULL byte counters cannot erase known values, and missing live-rate samples keep the combined mean unknown. Historical bytes already lost cannot be safely reconstructed; bridge coverage must remain unavailable where mismatched. Reports show a separate measured-flow percentage and real primary categories, remove retired security sections, and keep passive device attribution evidence-based.

Local suite: 430 passed / five Linux-only skipped before the final small Excel-section guard; focused tests including that guard passed. Fresh adversarial review and the requested read-only Codex CLI review completed. The initial findings were reproduced/corrected; the CLI re-review found no material issues. See docs/engineering/BRIDGE-ROLLUP-REPORT-FIX.md. Changes are not yet installed on the owner; DNS and the held client remain untouched in this follow-up.

The full regression suite additionally passed435tests in an isolated unprivileged temporary checkout on the owner (runtime revision20dcb09), using only temporary test databases/configuration. Hosted CI44521874765 failed twice at Ubuntu dependency downloads with503 before tests. An HTTPS mirror/retry adjustment is included only in the hosted workflow, with signed APT verification retained; production APT/DNS settings are unchanged. Owner production has not yet been updated with this bridge fix.


## Owner verification — 19 November 2026, 14:43 SAST

Installed runtime 5efeb0c4 on 192.168.99.6. Feature Linux CI 44524117121 passed all 435 Python and 23 Rust tests, real bridge/systemd/TLS/flow integration, binary provenance and offline bootstrap. The final SQLite-row compatibility correction passed its targeted regression including actual sqlite3.Row inputs, then the actual owner generated report returned HTTP 200 in 4.325 seconds: TikTok/Social Media, ChatGPT/AI Services, Instagram/Social Media, YouTube/Video Streaming and Windows Update/Software Updates. Security Events is absent and the separate measured-flow explanation is present. Final runtime main Linux CI 44526269797 passed, including the complete 435 Python / 23 Rust suite and real integration; main history-reset safety 44526270050 passed too.

The fixed historical window was unchanged before/after: bridge 19,177,715,446 bytes; measured 19,377,732,892; attributed 3,023,542,352. Primary bridge coverage correctly remains unavailable; separate measured-flow classification is 15.6%. Previously deleted history was not fabricated. Collection continued (199,027 measured flows and 14,039 TLS observations at verification); all six services were active and updater check under the service user returned current=latest=5efeb0c, available=false. AdGuard PID830/NRestarts0 remained unchanged; UDP loopback and TCP LAN DNS succeeded. No history reset. Settings/secrets retained. Client and third appliance untouched.

Temporary fixed-action owner maintenance access remains enabled only until its existing 18:23 SAST expiry. QUIC inspection is not implemented by this release.


## Verified rollout — 19 November 2026, 15:18 SAST

Owner runtime92accaa5 installed via normal updater; no reset. Local full suite436passed/5Linux-onlyskipped; final focused82passed after removing the overbroad N-central pattern. Linux feature44531138857 passed441Python/23Rust tests and real bridge/systemd/TLS/measured-flow integration, binary provenance and offline bootstrap. Main history-reset safety44531804891 passed. Duplicate main Linux44531804922 was still running at this observation.

Live bounded preview scanned1464unknown-hostname rows, found81eligible labels/221,690bytes; apply scanned1474and updated exactly81/221,690bytes. Breakdown:24TLS-SNI flows/136,733bytes;57client-DNS flows/84,957bytes. Service labels cover Firebase Remote Config, WeatherKit, Home Assistant Connectivity, N-able software distribution/Take Control, Safe Browsing and AnyDesk. Repeat full bounded preview scanned1410rows with0candidates and no cap hit. No measurements deleted or settings changed; byte/time preservation is covered by actual SQL regressions. Do not claim a before/after coverage percentage from moving windows.

All six services active, passive verifierready, fresh collector heartbeatOK, measured flows6297and TLS/flow collection continuing. Live generated reportHTTP200in0.384s with76.2%primary coverage at that instant. Updater check under actual service usercurrent=latest=92accaa, available=false before final docs-only recording. AdGuardPID830/NRestarts0unchanged; loopbackUDP/LANTCP DNS succeeded. Client and third unit untouched. Temporary fixed-action owner maintenance access retains its existing18:23SASTexpiry. Generic/shared hosts, missing evidence, encrypted/QUIC unknowns and ambiguous DNS remain unknown rather than guessed.


## Settings maintenance controls — verified on owner

Settings → Maintenance provides preview/confirmation for traffic-only/all collected-history reset and optional retired IDS purge. Requires admin sign-in, CSRF, current password, exact hostname and acknowledgement. Fixed root worker, protected bounded per-job status, whole-operation lock inherited by reset and shared with update/manual recovery, fixed dpkg purge with dependency checks/no autoremove. No production cleanup is part of installation. See docs/engineering/SETTINGS-MAINTENANCE.md.


## Verified owner rollout — 19 November 2026

Runtime15395db9c3f6bee38732fba3a0c44f606a6da1cc is installed on the owner. Feature Linux44537604155 and main Linux44538200892 passed474Python tests,23Rust tests, binary provenance/offline bootstrap and the actual systemd maintenance worker integration. Main history-reset safety44538200975 passed. The integration proved preview, refusal while another operation holds the lock, inherited-lock traffic reset, configuration/name retention, watcher restart and fresh attribution after restart. An earlier run completed the worker but exhausted its four-transfer fixture server; the fixture now supports the fifth post-maintenance transfer and the rerun passed.

Live installation: updater Result=success/inactive; maintenance.path active; worker inactive with empty ExecMainStartTimestamp (no job triggered during feature installation). State directoryroot:netspecter0750. Unauthenticated statusAPI401 and page302to login. Existing six services active; passive verifierready. AdGuardPID830/NRestarts0unchanged, UDP loopback and TCP LAN DNS succeeded. No production reset, purge, settings deletion or client contact was performed. The owner UI is /settings?section=maintenance; installation of the feature itself never performs cleanup. Held client and inaccessible third unit remain untouched. Temporary fixed-action owner helper retains its existing18:23SASTexpiry.

Portable package netspecter-deploy-15395db9.tar.gz includes this runtime; SHA256d1582f903d3bfda9dfb2a7815e291d7e0ceb01db678a046a0c1d75b2799da983. Archive paths, Git bundle and inner checksum verified. Third-unit cleanup is still an explicit future action.


## Confirmation flow correction verified — 19 November 2026

Installed owner runtimefc194b15f665290c0a26455f427dc74d6eeabef8. Feature Linux44541364590 and main Linux44541852230 passed478Python/23Rust tests and actual root/systemd worker integration. Main history-reset safety44541852155 passed. New regression tests reproduced the direct-page/status setup gate inconsistency, verified confirmation-first ordering, sticky all-history selection, manual/non-JavaScript progress, and bounded unresolved-job refresh. Fresh adversarial review accepted auth/scope boundaries and found an unbounded refresh loop; carrying wait_started now bounds missing jobs to30seconds and known jobs to45minutes, with manual recovery links. Re-review found no further material issue.

The owner's supplied protected status showed kind=preview/status=ready, scope=traffic and purge_ids=true, not an apply. At that observation old traffic and installed Suricata packages remained. No all-history cleanup was claimed complete, and no reset/purge was triggered by the assistant. The new screen explicitly distinguishes preview from apply and traffic-only from all collected history. Units still containing Suricata receive the same explicit controls when updated; normal update alone never clears histories or purges packages. Retained settings/login/licence/names/custom rules and native AdGuard preservation are unchanged. Held client and third unit were not contacted.

Live update Result=success/inactive, installedfc194b1, maintenance.pathactive. AdGuardPID830/NRestarts0unchanged and UDP/TCP DNS succeeded. Temporary fixed-action helper still expires at18:23SAST. For the owner's intended cleanup, select Reset all collected history plus purge, preview, then complete the password/hostname/acknowledgement confirmation; do not mistake the previous traffic-only preview for completion.

Updated portable package netspecter-deploy-fc194b15.tar.gz, SHA2563cd2a8c511d32776f54e46185ba017a3ef81d95c1dfa6e6a18f0ce7b016a8183; archive paths and inner Git-bundle checksum verified. No new package dependencies, DNS settings, byte attribution rules or reset backend semantics changed in this UI correction.


## LAN-bound DNS continuity fix verified — 19 November 2026

Runtimea47cabe673535bf158d41679319cbb365535ee42 passed Linux feature44581611836, including real ss PID ownership and real UDP/TCP DNS on a non-default loopback-bound native-listener fixture, the full Python/Rust suite and real reset/systemd integration. Native AdGuard service identity alone was substituted in the dedicated fixture; actual socket discovery and dig responses were used. No test or remote cleanup was run on client192.168.1.4 or owner. The client operator's own output proved LAN-only AdGuard listening with working LAN UDP DNS and no loopback listener. Earlier script stopped in DNS snapshot after source staging but before installer/purge/reset. Do not rebind AdGuard or bypass the check.

Guard now records an address jointly served on UDP/TCP by structured ss process records matching native AdGuard MainPID, validates same-address ownership again and probes both transports without UDP-to-TCP retry. Config hashes/active checks retained. Updated SSH script pins this tested runtime. The root operator can retry the checksum-verified script with actual hostnameWslunifi; it still requires explicit--apply and preserves saved settings/credentials/licence/names/rules. No direct SSH session or changes on1.4 were performed by the assistant; only its repository/test-environment fix was made.
