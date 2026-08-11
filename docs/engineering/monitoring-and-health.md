# Monitoring and Health

## Monitoring Stack

NetSpecter uses Gatus for monitor cards and warning messages.

Main services:

```bash
systemctl status gatus netspecter-monitor.timer --no-pager -l
sed -n '1,260p' /etc/netspecter/gatus/config.yaml
journalctl -u gatus -n 80 --no-pager
```

## Monitor Types

Supported monitor concepts include:

- HTTP
- HTTPS
- TCP port
- UDP port
- Ping
- DNS
- TLS
- STARTTLS
- WebSocket
- Secure WebSocket
- SSH

For TCP, enter only `host:port`; the dropdown adds the scheme.

## Internet Quality

NetSpecter records WAN quality signals:

- latency
- packet loss
- jitter
- DNS response time
- scheduled speed-test history when enabled

Scheduled speed tests consume internet data; keep disabled unless regular WAN testing is wanted.

NetSpecter can run either:

- Ookla Speedtest: `/usr/bin/speedtest`
- Debian/Python speedtest-cli: `speedtest-cli`

If a box already has Ookla Speedtest installed, keep it and set **Speedtest CLI path** to `/usr/bin/speedtest`. Do not force-install Debian `speedtest-cli` over it if apt reports a `/usr/bin/speedtest` file conflict.

## Checks

```bash
systemctl status netspecter-collector netspecter-speedtest.timer --no-pager -l
journalctl -u netspecter-collector -n 80 --no-pager
```

## Nextcloud Monitor Note

For a stable Nextcloud monitor endpoint, use:

```text
https://192.168.99.4/status.php
```

The observed response included `installed true`, `maintenance false`, `needsDbUpgrade false` and version info.

## UI Notes

- Main dashboard should adapt between ultrawide and square screens.
- IDS page layout was improved.
- Monitor page/card layout may still need polish.
- Red monitor cards are service checks, not necessarily offline LAN devices.
