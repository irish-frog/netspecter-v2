# NetSpecter LCD Display Firmware

This folder contains the tested NetLCD firmware upload for a KNOMI-style
NetSpecter status display.

## Tested Hardware

| Firmware | Hardware |
|---|---|
| `firmware/netlcd_knomi_gc9a01/netlcd.bin` | BIGTREETECH/KNOMI-style ESP32 display board with a 1.28 inch 240x240 GC9A01 round TFT |

Other ESP32 displays are not confirmed.

## User Update Process

1. Download or copy:

   ```text
   lcd/firmware/netlcd_knomi_gc9a01/netlcd.bin
   ```

2. Open the KNOMI/BIGTREETECH display's existing web interface.
3. Open the firmware update page.
4. Upload `netlcd.bin`.
5. Wait for the display to restart.

## First Setup

After flashing, connect to the setup access point:

```text
SSID: NetSpecter-LCD
Password: blank by default
```

Then enter:

```text
Wi-Fi SSID/password
NetSpecter URL, for example https://192.168.99.6:9443/api/lcd/summary
LCD token from NetSpecter Settings -> LCD Displays
Refresh interval
Brightness
Optional TLS CA certificate
```

## Where To Get Setup Values

Open NetSpecter from a browser on the same LAN:

```text
https://NETSPECTER-IP:9443
```

Use the appliance IP shown on NetSpecter, for example:

```text
https://192.168.99.6:9443
```

The LCD setup fields should be filled like this:

| LCD setup field | Value to enter |
|---|---|
| NetSpecter URL | `https://NETSPECTER-IP:9443/api/lcd/summary` |
| LCD bearer token | Token created in NetSpecter under `Settings -> LCD Displays -> Add LCD display` |
| Trusted TLS certificate (PEM) | Copy the full local CA certificate from NetSpecter, including `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` |
| Trusted TLS SHA-256 fingerprint | Optional. Leave blank unless you are pinning a specific certificate fingerprint. |
| Refresh interval | `5` to `30` seconds is recommended. Use `5` for fastest updates. |

Generate the LCD bearer token in NetSpecter:

```text
Settings -> LCD Displays -> Add LCD display
```

The token is read-only and only allows the display to call:

```text
GET /api/lcd/summary
```

Copy the trusted TLS certificate from NetSpecter:

```text
Settings -> LCD Displays -> TLS certificate
```

Paste the complete PEM block. It must start and end like this:

```text
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

## Firmware Notes

This binary is based on the tested KNOMI NetSpecter LCD build:

```text
Version: NetSpecter LCD M1
Built: 2026-07-16 23:56:28
```
