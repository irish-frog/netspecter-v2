# Spec: history-reset

Status: approved by the operator on 2026-11-18. Module: history-reset. Depends on validated replacement schemas and collection pipeline.

## Objective
Explicitly start the two reachable authorized appliances afresh after replacement validation. Clear collected activity while preserving settings, edited device names, custom classifications, user assignments, credentials, licences and existing backups. The inaccessible third appliance is untouched and must never reset through a normal update.

## Stack and commands
Python standard library, existing SQLite helpers and a narrowly scoped root systemd orchestration wrapper. Proposed CLI: `python3 scripts/reset-collected-history.py` previews affected tables/counts and preserved categories; `python3 scripts/reset-collected-history.py --apply` performs an explicit reset after writer-stop and health checks. Run `python -m pytest -q tests/test_collected_history_reset.py` before any live apply. Do not use the existing reset-history.sh which moves whole databases and loses edited state.

## Structure and preservation contract
services/history_reset_service.py owns an explicit reviewed table/field inventory. scripts/reset-collected-history.py handles preview/apply, exclusive reset lock and service coordination. Existing databases are opened deliberately, never created accidentally by a misspelled path. Settings/auth/licence/backup directories are outside deletion scope. Preserve device_overrides, necessary stable identity-to-edited-name mappings, user_labels, user_device_assignments, manual signatures/categories/mappings/aliases/domain patterns/tags/site overrides and their settings. Clear learned activity fields without losing the links required for kept names.

Clear traffic samples/intervals/rollups, application usage and flow facts, DNS query/resolution/rollup history, quality/speed-test history, telemetry/monitor/config-change activity, IDS/security activity, learned destination/classification caches, unknown queues, TLS metadata and new measured flow history. Classify every existing table explicitly; an unexpected table or an unrecognized preservation schema stops apply for review. Keep necessary schema/version state. Report retained state separately from cleared activity; do not claim collection-derived timestamps were cleared when they were preserved.

Stop collection and other database writers before apply, including relevant timers/services, preserve their original enabled/active state, and restore running services on both success and failure. Do not stop AdGuard filtering or alter bridge/firewall configuration. Set one reset cutoff before restarting; prevent old AdGuard query log data from re-entering DNS resolution caches, device updates or application target caches as well as query history. Clear relevant in-process caches through controlled restart. Make operation rerunnable with a clear result report.

Create a consistent protected temporary recovery snapshot before destructive operations. Per the operator's later instruction, discard this new snapshot after successful verification; do not retain an extra copy of collected history. Existing backup directories are outside this reset's deletion scope. Preflight disk space and integrity. Use transactions and a recovery journal across databases; do not imply separate SQLite commits are globally atomic. On partial failure, restore coherent pre-reset state before restarting writers; otherwise remain clearly failed with recovery instructions. Never delete database files, WAL files or arbitrary glob matches while writers may be active.

## Style and verification
Use parameterized SQL and a fixed allowlist; refuse symlinks/path escapes and unsupported schemas. Example result: `cleared: traffic_intervals=123; preserved: device_overrides=8`. Tests use synthetic copies with edited names, stable identities, custom rules, secrets/licences and backups; compare kept state before/after. Cover preview idempotence, apply idempotence, rollback/failure recovery, missing DB, unknown tables, insufficient disk, active writers and old-DNS reimport cutoff. Verify fresh DNS/flows populate after reset and internal transfers remain excluded.

## Boundaries and acceptance
Always preview, validate preservation, keep a recovery snapshot, stop writers safely and validate the replacement before live apply. Never reset on ordinary update or on the third unit. No broad filesystem deletion or changes to login/security controls. Success: both authorized appliances show fresh history, edited names/settings/custom mappings match pre-reset values, fresh collection works and DNS/forwarding remain healthy.
