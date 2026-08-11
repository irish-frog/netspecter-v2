# Current State

## Project

- Project: NetSpecter v2
- Local development path: `C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2`
- Appliance path: `/opt/netspecter`
- Branch: `main`
- GitHub remote: `https://github.com/irish-frog/netspecter-v2.git`

## Current Priorities

1. Keep fresh Debian 13 appliance installation reliable for non-expert users.
2. Keep HTTPS access on port `9443` working, with the internal Flask/Gunicorn service on `127.0.0.1:5050`.
3. Improve application classification coverage without expensive UI/API/report lookups.
4. Preserve appliance performance for roughly 150-250 active endpoints.
5. Continue reducing SQLite lock contention and collector loop delays.
6. Keep IDS/incident alerts useful by suppressing informational noise.
7. Finish LCD/KNOMI display client work against the existing `/api/lcd/summary` backend.

## Current Watch Items

- Unknown/unclassified traffic remains high until new DNS-to-traffic attribution paths collect enough evidence.
- `estimated_app_traffic` is the main source for application GB attribution in reports.
- New JSON signatures do not reclassify old unknown GB unless matching byte attribution already exists.
- Live snapshot and split database design should be preserved because it reduces UI/LCD dependency on SQLite.
- Do not stage or remove local `nul` or unrelated dirty files unless explicitly confirmed.
- Do not push the NetLic PHP service repo to GitHub.

## Standard Appliance Update

```bash
cd /opt/netspecter
git fetch origin
git checkout main
git pull --ff-only origin main
bash ./install.sh
systemctl restart netspecter-web netspecter-https netspecter-collector
```

## Fast Health Check

```bash
systemctl --no-pager --failed
systemctl status netspecter-web netspecter-https netspecter-collector --no-pager -l
ss -ltnp | grep -E '5050|9443'
journalctl -u netspecter-web -n 80 --no-pager -l
journalctl -u netspecter-collector -n 80 --no-pager -l
```
