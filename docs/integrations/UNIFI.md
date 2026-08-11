# UniFi Integration

UniFi is optional. NetSpecter can run without it.

With UniFi enabled, NetSpecter can import client names, MAC addresses and device details. This makes Devices and traffic history easier to read.

Without UniFi, NetSpecter can still discover devices from traffic, DNS logs, ARP, vendors and manual edits.

## Configure UniFi

Open `Services -> UniFi`.

Recommended local gateway URL:

```text
https://YOUR-GATEWAY-IP/proxy/network/integration
```

Example:

```text
https://192.168.1.1/proxy/network/integration
```

Settings:

```text
Enable UniFi Device Discovery: on
UniFi Network API URL:         https://YOUR-GATEWAY-IP/proxy/network/integration
Local UniFi Username:          your local UniFi user
Local UniFi Password:          your local UniFi password
Allow self-signed certificate: on if your gateway uses its built-in cert
```

Click `Find Site Automatically`. If auto-detect fails, enter the site ID manually. Many home deployments use `default`.
