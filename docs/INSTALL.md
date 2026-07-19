# Installation

This guide covers preparing a fresh Debian appliance and installing NetSpecter.

[<- Back to README](../README.md)

## Supported Operating System

Primary supported OS:

- Debian 13 Trixie

Run the installer as `root`.

Debian 12 may still work, but NetSpecter v2 is built around Debian 13.

## Paths Used By NetSpecter

There are two paths to understand:

| Path | Purpose |
|---|---|
| `/root/netspecter-v2` | Typical clone path used during a fresh install |
| `/opt/netspecter` | Installed runtime path used by systemd services and updates |

The installer copies or installs the runtime into `/opt/netspecter`. Use `/opt/netspecter` for future updates on an installed appliance.

## Fresh Debian Preparation

Log in as `root`.

```bash
apt update
apt install -y git curl nano
```

Check the appliance network:

```bash
cat /etc/os-release
ip -br link
ip -br addr
ip route
```

Write down:

- NetSpecter management IP
- Router or gateway IP
- LAN subnet, for example `192.168.1.0/24`
- NIC that faces the router
- NIC that faces the LAN switch

Warning: bridge changes can disconnect SSH. Do bridge work from a local keyboard/monitor or out-of-band console when possible.

## Install NetSpecter

```bash
cd /root
git clone https://github.com/irish-frog/netspecter-v2.git
cd netspecter-v2
bash ./install.sh
```

The installer installs:

- NetSpecter web UI on port `5050`
- NetSpecter collector service
- AdGuard Home, unless already installed or skipped
- Gatus monitor engine
- Suricata when Debian packages are available
- Required tools such as `nftables`, `tcpdump`, `vnstat`, `dnsutils`, and Python runtime packages

Open NetSpecter:

```text
http://YOUR-NETSPECTER-IP:5050
```

If no admin exists yet, NetSpecter redirects to:

```text
/setup-admin
```

## Expected Result

After installation:

- `netspecter-web.service` is available.
- `netspecter-collector.service` is available.
- The web UI answers on port `5050`.
- Settings can be completed from the browser.

## Useful Checks

```bash
systemctl status netspecter-web netspecter-collector --no-pager -l
ss -ltnp | grep -E ':5050|:53|:80|:18080'
```

---

Next:

- [Complete first setup](FIRST-SETUP.md)
- [Configure the network bridge](NETWORK-BRIDGE.md)
- [Set up AdGuard Home](ADGUARD.md)
- [Configure Telegram](TELEGRAM.md)
- [Configure Suricata IDS](SURICATA.md)
