# Backups and Restore

NetSpecter includes vault backup and restore tooling for configuration and history.

## Backup Service

```bash
systemctl status netspecter-vault.timer --no-pager -l
journalctl -u netspecter-vault.service -n 80 --no-pager
```

## Preserved Runtime Data

Important runtime data lives under:

```text
/etc/netspecter
/var/lib/netspecter
```

The repository should not include local runtime state such as config files, databases, logs, session keys or backup archives.

## Restore Notes

Use restore actions carefully. A full restore may restart NetSpecter web and collector services.

Expected result:

- Configuration restore updates settings and keys.
- Full restore can also restore database history.
- NetSpecter services may briefly restart.
