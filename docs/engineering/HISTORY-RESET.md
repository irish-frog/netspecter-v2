# Clear collected history while preserving edited names

This is an explicit maintenance command, never an automatic update step. Run it only on the appliance you intend to reset. Install the repository update first, then use a root shell (`su -` after SSH as your normal user).

Preview: `python3 /opt/netspecter/scripts/reset-collected-history.py`

Apply: `python3 /opt/netspecter/scripts/reset-collected-history.py --apply --expected-hostname YOUR_APPLIANCE_HOSTNAME`

The hostname must match exactly. This requirement helps prevent running a copied command on the wrong appliance. The command has no fleet discovery or remote reset behavior.

## Result

Fresh databases contain no collected traffic, DNS, speed tests, internet quality, telemetry, incident/investigation, identity activity or classification-cache history. They retain edited device names, stable identity inventory/mappings, custom application definitions, user labels/assignments and monitor notification deduplication state. Learned presence/user activity timestamps are cleared. Manual user labels remain settings. Settings, passwords, licences and existing backup directories are outside the deletion scope.

The command stops known writers/timers and takes an exclusive collector lock. Persistent systemd conditions prevent writers starting during an interrupted reset. It stages fresh databases, verifies retained rows and integrity, atomically replaces individual files with a cross-database recovery journal, then restores the previously active services. It confirms a fresh collector heartbeat before success. AdGuard filtering and bridge forwarding are not stopped. A DNS import cutoff is enforced before device updates, domain classification and resolution/target caches, so old native AdGuard query logs cannot refill the application history.

A protected **temporary** rollback copy is used during the operation. Following the operator's preference, it is removed after successful service verification; no extra history backup from this reset is retained. Existing backup directories are not removed. Ordinary system logs, native AdGuard query logs, `.gunicorn`, settings and unrelated files are not deleted. This is an application history reset, not a forensic disk wipe.

If the operation fails, it restores the old databases before restarting writers where recovery is possible. If recovery cannot finish, it leaves the inhibit marker and writers stopped; the printed recovery command uses the exact protected journal directory. Resolve the failure and run that command as root. If reset succeeded but temporary-copy deletion failed, use `--discard-completed RECOVERY_DIRECTORY --expected-hostname YOUR_APPLIANCE_HOSTNAME`.

Unknown tables, unrecognized fields in retained state, unsafe links, insufficient disk space or an in-progress updater stop the operation before replacement. Disable retired IDS collection before applying; the reset does not silently change saved settings. Fresh history starts collecting immediately after restart, so small nonzero counts afterward are expected.

Do not use broad `rm netspecter*.db*` commands: edited names and custom state also live in those databases. Do not delete WAL files while writers run. Do not delete reset/backups directories by wildcard.
