# Development

This guide covers local checks for contributors.

[<- Back to README](../README.md)

## Unit Tests

Run:

```bash
python3 -m unittest discover tests
```

On Windows development machines, use:

```bash
python -m unittest discover tests
```

## Compile Checks

```bash
python3 -m py_compile app.py live_packet_collector.py monitor_sweeper.py netspecter_config.py netspecter_ids.py netspecter_ui_helpers.py
```

## Documentation Checks

```bash
find . -name "*.md" -type f -print
grep -Rni "old-production-branch-name" README.md docs FAQ.md
grep -Rni "/root/netspecter-v2\|/opt/netspecter" README.md docs FAQ.md
grep -Rni "fast.log\|eve.json" README.md docs
```

## Runtime Services

Main services:

```text
netspecter-web.service
netspecter-collector.service
netspecter-monitor.timer
netspecter-speedtest.timer
netspecter-vault.timer
netspecter-watchdog.timer
gatus.service
```

## Repository Hygiene

Do not commit:

- `/etc/netspecter` runtime config
- `/var/lib/netspecter` runtime data
- local SQLite databases
- session keys
- logs
- backup archives
- fake screenshots or generated browser artifacts

---

Next:

- [Architecture](ARCHITECTURE.md)
- [Updating](UPDATES.md)
- [Return to README](../README.md)
