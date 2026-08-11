# Installation

This guide covers preparing a fresh Debian appliance and installing NetSpecter.

## Supported Operating System

Primary supported OS:

- Debian 13 Trixie

Run installer commands as `root`. Do not use `sudo` in the appliance instructions.

## Paths Used By NetSpecter

| Path | Purpose |
|---|---|
| `/root/netspecter-v2` | Typical clone path during fresh install |
| `/opt/netspecter` | Installed runtime path used by systemd services and updates |
| `/etc/netspecter` | Configuration and secrets |
| `/var/lib/netspecter` | Databases, cache, backup state and live snapshot |

## Fresh Debian Preparation

```bash
apt update
apt install -y git curl nano
cat /etc/os-release
ip -br link
ip -br addr
ip route
```

Write down:

- NetSpecter management IP
- Router/gateway IP
- LAN subnet
- Router-facing NIC
- LAN-facing NIC

Bridge changes can disconnect SSH. Use a local keyboard/monitor or out-of-band console where possible.

## Install NetSpecter

```bash
cd /root
git clone https://github.com/irish-frog/netspecter-v2.git
cd netspecter-v2
bash ./install.sh
```

Installer expectations:

- NetSpecter HTTPS entry point on `9443`
- Internal web service on `127.0.0.1:5050`
- Collector service
- AdGuard Home unless skipped/already installed
- Gatus monitor engine
- Beszel appliance metrics hub unless skipped
- Suricata where packages are available
- Required tools such as nftables, tcpdump, vnstat, dnsutils and Python runtime packages

Open:

```text
https://YOUR-NETSPECTER-IP:9443
```

If no admin exists, NetSpecter redirects to `/setup-admin`.

## Expected Result

```bash
systemctl status netspecter-web netspecter-https netspecter-collector --no-pager -l
ss -ltnup | grep -E ':53|:80|:5050|:8090|:9443|:18080'
```

Expected:

- `netspecter-web.service` exists and listens internally on `127.0.0.1:5050`
- `netspecter-https.service` exists and listens on `0.0.0.0:9443`
- `netspecter-collector.service` is active
- Settings can be completed from the browser

## Known Installer Concerns

- A stale `/etc/systemd/system/AdGuardHome.service` can block AdGuard reinstall if `/opt/AdGuardHome` is missing.
- Installer must work both from `/opt/netspecter` and from a separate source clone.
- A future `install-check.sh` should validate DNS, bridge, web, HTTPS, collector, Suricata, AdGuard, disk/log retention and update checks.

Next:

- `deployment/FIRST-SETUP.md`
- `network/NETWORK-BRIDGE.md`
- `integrations/ADGUARD.md`
- `integrations/SURICATA.md`
