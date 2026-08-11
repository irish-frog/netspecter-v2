# Updating

This guide covers updating an existing appliance safely.

[<- Back to README](../README.md)

The production branch is `main`.

## Correct Update Path

Use the installed runtime path:

```text
/opt/netspecter
```

Do not use `/root/netspecter-v2` for routine appliance updates unless you intentionally run from that clone.

## Update Commands

Run as `root`:

```bash
cd /opt/netspecter
git fetch origin
git checkout main
git pull --ff-only origin main
python3 -m unittest discover tests
systemctl restart netspecter-web
systemctl restart netspecter-collector
```

If the monitor logic changed, also restart or run:

```bash
systemctl restart netspecter-monitor.timer
systemctl start netspecter-monitor.service
```

## What Is Preserved

Updates preserve runtime state such as:

```text
/etc/netspecter/config.json
/var/lib/netspecter
```

## Troubleshooting

If `git pull --ff-only origin main` fails, stop and inspect local changes:

```bash
git status --short --branch
```

Do not run destructive git reset commands unless you know you are discarding local edits.

---

Next:

- [Troubleshooting](TROUBLESHOOTING.md)
- [Development](DEVELOPMENT.md)
- [Return to README](../README.md)

