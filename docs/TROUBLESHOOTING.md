# Troubleshooting

This guide covers common service, DNS, bridge, and database checks.

[<- Back to README](../README.md)

## Services

```bash
systemctl status netspecter-web netspecter-collector gatus netspecter-monitor.timer --no-pager -l
```

## Logs

```bash
journalctl -u netspecter-web -n 80 --no-pager
journalctl -u netspecter-collector -n 80 --no-pager
journalctl -u gatus -n 80 --no-pager
journalctl -u netspecter-monitor.service -n 80 --no-pager
```

## Ports

```bash
ss -ltnup | grep -E ':53|:80|:5050|:18080|:8090'
```

Expected ports:

- `5050` for NetSpecter web
- `53` for DNS
- `80` for AdGuard Home
- `18080` for Gatus

## DNS

```bash
nslookup google.com YOUR-NETSPECTER-IP
dig @YOUR-NETSPECTER-IP google.com A
```

Expected result:

- DNS answers from the NetSpecter appliance.
- AdGuard query log shows the client query.

## Bridge

```bash
ip -br addr show br0
bridge link
ip route
```

Expected result:

- `br0` has the management IP.
- Physical NICs are bridge ports.
- Default route uses the router.

## Database

```bash
sqlite3 /var/lib/netspecter/netspecter.db "PRAGMA integrity_check;"
```

Expected result:

```text
ok
```

## Monitor Config

```bash
sed -n '1,260p' /etc/netspecter/gatus/config.yaml
```

---

Next:

- [Installation](INSTALL.md)
- [Updating](UPDATES.md)
- [Return to README](../README.md)
