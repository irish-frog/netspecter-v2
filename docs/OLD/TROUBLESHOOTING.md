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
ss -ltnup | grep -E ':53|:80|:5050|:8090|:9443|:18080'
```

Expected ports:

- `9443/tcp` for the NetSpecter HTTPS LAN entry point
- `5050/tcp` for the NetSpecter internal web service, normally bound to `127.0.0.1`
- `53/tcp` and `53/udp` for AdGuard Home DNS
- `80/tcp` for AdGuard Home admin UI
- `18080/tcp` for Gatus, normally bound to `127.0.0.1`
- `8090/tcp` for Beszel, normally bound to `127.0.0.1`

Optional or temporary ports:

- `3000/tcp` for the first AdGuard Home setup wizard only
- `161/udp` for outbound SNMP polling targets when SNMP telemetry is enabled
- `1883/tcp` or `8883/tcp` for outbound MQTT broker connections when MQTT telemetry is enabled
- `587/tcp` or the configured SMTP port for outbound email alerts

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
