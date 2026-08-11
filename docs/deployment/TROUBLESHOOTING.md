# Troubleshooting

## Services

```bash
systemctl status netspecter-web netspecter-https netspecter-collector gatus netspecter-monitor.timer --no-pager -l
systemctl --no-pager --failed
```

## Logs

```bash
journalctl -u netspecter-web -n 80 --no-pager -l
journalctl -u netspecter-https -n 80 --no-pager -l
journalctl -u netspecter-collector -n 80 --no-pager -l
journalctl -u gatus -n 80 --no-pager -l
journalctl -u netspecter-monitor.service -n 80 --no-pager -l
```

## Ports

```bash
ss -ltnup | grep -E ':53|:80|:5050|:8090|:9443|:18080'
```

Expected ports:

- `9443/tcp` - NetSpecter HTTPS LAN entry point
- `5050/tcp` - internal web service, normally bound to `127.0.0.1`
- `53/tcp` and `53/udp` - AdGuard Home DNS
- `80/tcp` - AdGuard Home admin UI
- `18080/tcp` - Gatus, normally local/internal
- `8090/tcp` - Beszel, normally local/internal

## HTTPS Dead After Locking Down 5050

First check:

```bash
systemctl status netspecter-web netspecter-https --no-pager
journalctl -u netspecter-web -n 80 --no-pager
journalctl -u netspecter-https -n 80 --no-pager
ss -ltnp | grep -E '5050|9443'
```

Emergency reopen 5050:

```bash
python3 -c 'import json; p="/etc/netspecter/config.json"; c=json.load(open(p)); c["allow_lan_http_5050"]=True; c["web_host"]="0.0.0.0"; json.dump(c, open(p,"w"), indent=2)'
systemctl restart netspecter-web
```

## Database Integrity

```bash
sqlite3 /var/lib/netspecter/netspecter.db 'PRAGMA integrity_check;'
sqlite3 /var/lib/netspecter/netspecter_dns.db 'PRAGMA integrity_check;'
sqlite3 /var/lib/netspecter/netspecter_traffic.db 'PRAGMA integrity_check;'
```

Expected result: `ok`.

## Route Smoke Test

Unauthenticated routes may return 302 to login; that is normal.

```bash
for path in / /devices /traffic /history /applications /blocked /ids-alerts /health /adguard /monitor /speed-tests; do
  curl -k -o /dev/null -s -w "$path %{http_code} %{time_total}s\n" https://127.0.0.1:9443$path
done
```
