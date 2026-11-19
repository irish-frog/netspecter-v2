# Traffic-only counter reset

Explicit operator command: `python3 /opt/netspecter/scripts/reset-collected-history.py --traffic-only --apply --expected-hostname Netspecter`.

Without `--apply`, this is a read-only preview. The hostname guard prevents application to the wrong host. Do not use the legacy web Clear Traffic button for passive-flow validation: it does not clear all modern measurements/rollups.

The traffic scope clears bridge raw/hourly counters, measured internet flows, TLS observations, legacy traffic/app aggregates, live speed and traffic classification queues/caches. It copies all other database tables unchanged, including DNS queries, resolution evidence/import cutoff, identity timestamps and edited names, custom classifications, monitoring, quality and speed-test history. Configurations, credentials, licences and native AdGuard data remain outside the reset. Derived snapshot caches are rebuilt; IDS mail deduplication cache is retained.

The existing coordinated reset pauses NetSpecter writers and exporters, locks collection, snapshots databases, prepares replacements, verifies SQLite integrity/foreign keys/row counts, then swaps and restarts original active services. It restores snapshots if post-swap verification fails and records a recovery journal. Successful CLI execution removes its temporary rollback copy. DNS filtering and bridge forwarding are left running. No update invokes reset automatically. Old traffic is irreversibly removed after success; counters may begin increasing immediately as collection restarts.

Compare fresh bridge and flow counters after several minutes, excluding the newest two minutes while exports settle. A reset does not guarantee 100% application coverage; unknown encrypted/shared-host traffic remains unknown. Client Wslunifi is on hold and is not authorized for this operation.
