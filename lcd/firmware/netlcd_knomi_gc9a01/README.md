# NetLCD KNOMI Firmware

Tested firmware binary for BIGTREETECH/KNOMI-style ESP32 display boards using
a 1.28 inch 240x240 GC9A01 round TFT.

## File

```text
netlcd.bin
```

## Upload

1. Connect to the KNOMI/BIGTREETECH display's existing web interface.
2. Open its firmware update page.
3. Upload `netlcd.bin`.
4. Wait for the display to restart.

## First Setup

After flashing, connect to the display setup access point:

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

## Setup Values

In NetSpecter, open:

```text
Settings -> LCD Displays
```

Use:

| LCD setup field | Value |
|---|---|
| NetSpecter URL | `https://NETSPECTER-IP:9443/api/lcd/summary` |
| LCD bearer token | Create one with `Add LCD display` |
| Trusted TLS certificate (PEM) | Copy the full NetSpecter local CA certificate, including the begin/end certificate lines |
| Trusted TLS SHA-256 fingerprint | Optional. Leave blank unless required. |
| Refresh interval | Recommended: `5` to `30` seconds |

The LCD token is read-only and only permits access to `/api/lcd/summary`.
