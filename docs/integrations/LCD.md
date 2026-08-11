# LCD / KNOMI Integration

## Backend Status

Backend foundation exists for:

```text
GET /api/lcd/summary
```

Served through HTTPS:

```text
https://<netspecter-host>:9443/api/lcd/summary
```

Authentication:

```text
Authorization: Bearer <lcd_token>
```

Important: the header must include `Bearer`.

## LCD Token Model

- Tokens are created in `Settings -> LCD Displays`.
- One token per named display.
- Token hash is stored only.
- Full token is shown only once.
- Token suffix is shown after creation.
- Tokens can be regenerated, revoked or removed.
- Token does not grant admin/session/control access.

## Endpoint Summary Fields

The endpoint returns compact JSON including:

- generated timestamp
- overall status
- internet status
- devices online
- active alerts
- live download/upload Mbps
- traffic history
- total traffic today GB
- ping, jitter, loss and DNS stats
- service states: DNS, IDS, collector, database and bridge
- system CPU/RAM/disk/uptime
- top talker
- top application
- devices known/online/new
- latest completed speed test

## Display Status Rules

Badge priority:

1. Grey `CONNECTING` if no successful response yet.
2. Amber `STALE` if cached/old data is shown because NetSpecter cannot be reached.
3. Red `INTERNET OFFLINE` if `internet_status = offline`.
4. Red `SERVICE DOWN` if DNS, IDS, collector, database or bridge is down.
5. Amber `WATCH` if degraded/warning/watch.
6. Red `ALERT` if status alert or active critical IDS incident.
7. Green `ONLINE` only when internet is online, services are healthy and there are no active alerts.

Service colours:

- `healthy` = green
- `warning` = amber
- `down` = red
- `unknown` = grey

## Load Assessment

LCD polling every 6-7 seconds is expected to be lightweight. The endpoint uses cached/collector data and should not run speed tests or heavy reports.

## Outstanding

- ESP32/KNOMI firmware/client still needs to be built.
- Firmware must poll `/api/lcd/summary`, use Bearer auth, apply the fixed status rules and display service states independently.
