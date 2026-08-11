# Updating

Use the installed runtime path:

```text
/opt/netspecter
```

Do not use `/root/netspecter-v2` for routine updates unless intentionally running from that clone.

## Normal Update

```bash
cd /opt/netspecter
git fetch origin
git checkout main
git pull --ff-only origin main
bash ./install.sh
systemctl restart netspecter-web netspecter-https netspecter-collector
```

If monitor logic changed:

```bash
systemctl restart netspecter-monitor.timer
systemctl start netspecter-monitor.service
```

## What Is Preserved

Updates preserve:

```text
/etc/netspecter/config.json
/var/lib/netspecter
```

## Force Align To GitHub Main

Only use this when deliberately discarding local code changes:

```bash
cd /opt/netspecter
git fetch origin
git reset --hard origin/main
bash ./install.sh
systemctl restart netspecter-web netspecter-https netspecter-collector
```

## Check Current State

```bash
git log -1 --oneline
git rev-parse --short origin/main
git status --short --branch
```

If `git pull --ff-only` fails, inspect local changes first. Do not run destructive resets unless you know what is being discarded.
