# AdGuard DNS

AdGuard Home is the DNS engine. NetSpecter imports query logs, client names, blocked domains and blocked service data from it.

## Third-Party Licence Notice

AdGuard Home is separate third-party software licensed under GNU GPLv3. NetSpecter does not own, modify, relicense, endorse or partner with AdGuard Home. Current installer behaviour downloads/runs the official upstream installer and does not bundle AdGuard binaries in GitHub.

## First AdGuard Wizard

On a new install, AdGuard opens its setup wizard on:

```text
http://YOUR-NETSPECTER-IP:3000
```

Recommended wizard choices:

- Web/admin interface: port `80`
- DNS server: port `53`
- Create an AdGuard username and password

After the wizard, AdGuard should open at:

```text
http://YOUR-NETSPECTER-IP
```

## NetSpecter AdGuard Settings

In NetSpecter: `Services -> AdGuard`

```text
AdGuard URL:      http://YOUR-NETSPECTER-IP
AdGuard username: your AdGuard username
AdGuard password: your AdGuard password
```

Save and test.

## Router DNS

For DNS analytics to work, clients must use NetSpecter/AdGuard as DNS.

```text
Router DHCP DNS: YOUR-NETSPECTER-IP
```

Test from a LAN client:

```bash
nslookup google.com YOUR-NETSPECTER-IP
```

## DNS Blocking Is A Soft Block

DNS blocking may be bypassed by cached DNS, hardcoded DNS, DNS-over-HTTPS, VPNs or direct IP connections. Use firewall/router rules when a hard network block is required.
