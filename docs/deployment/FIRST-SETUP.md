# First Setup

This guide covers the first login and minimum settings after install.

## Create The Admin User

Open:

```text
https://YOUR-NETSPECTER-IP:9443
```

If no admin exists, NetSpecter redirects to `/setup-admin`.

## Minimum Settings

Open `Settings` and review:

| Setting | What to enter |
|---|---|
| LAN prefix | Your LAN prefix, for example `192.168.1.` |
| Gateway IP | Router IP, for example `192.168.1.1` |
| Packet interface | Bridge interface, normally `br0` |
| AdGuard URL | Usually `http://YOUR-NETSPECTER-IP` |
| Authentication | Keep enabled for normal deployments |

## Recommended Setup Order

1. Configure the bridge.
2. Configure AdGuard Home.
3. Add Telegram if alerts are wanted.
4. Enable Suricata IDS if available.
5. Add monitors.

Expected result: dashboard loads and service cards stop showing setup warnings as each integration is configured.
