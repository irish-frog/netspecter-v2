# Backups and Restore

This guide covers NetSpecter backup and restore tooling.

[<- Back to README](../README.md)

NetSpecter includes vault backup and restore tooling for configuration and history.

## Backup Service

Main service:

```text
netspecter-vault.timer
```

Check it:

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

The repository should not include local runtime state such as config files, databases, logs, session keys, or backup archives.

## Restore Notes

Use restore actions carefully. A full restore may restart NetSpecter web and collector services.

Expected result:

- Configuration restore updates settings and keys.
- Full restore can also restore database history.
- NetSpecter services may briefly restart.

---

Next:

- [Updating](UPDATES.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Return to README](../README.md)

