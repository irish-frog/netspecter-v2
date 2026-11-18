# Spec: device-timeline

Status: approved by the operator on 2026-11-18. Module: device-timeline. Depends on flow-attribution.

## Objective
Show each device's internet application activity with understandable evidence, measured bytes and honest uncertainty. Keep operator-edited names authoritative.

## Stack and commands
Existing Python web UI, SQLite and existing authentication. Run `python -m pytest -q tests/test_device_timeline.py` and `python -m pytest -q`. Smoke-check the existing partial-navigation response and device page.

## Structure and interface
A services/device_timeline_service.py query layer reads measured flow attribution, TLS observations and stable device identity. Existing device routes render a bounded, paginated time range. Reuse current page layout and authenticated navigation; add no public endpoint. Display time, application (or unknown), hostname, download/upload bytes, evidence and confidence/unknown reason. Metadata without measured bytes must read as an observation, never estimated usage. Link evidence to a connection/time internally without exposing raw packets.

Coverage displays bridge usage, measured flow visibility and primary application attribution with clearly stated comparable periods. Separate known hostname from known application. Explain that ECH, QUIC, missed handshakes and traffic outside the bridge limit visibility. Never present a provider such as a shared CDN as a proven application.

## Style and tests
Use existing escape/render helpers and parameterized SQL. Example: render an unknown flow as `Unknown application - ambiguous DNS`, with its real measured bytes. Tests verify stable device identity across an address change, preserved edited names, reverse-direction bytes, pagination/time filters, empty state, unavailable sensor and hostile domain/name strings. Rendered hostname and labels must be escaped.

## Boundaries and acceptance
Always preserve authentication and existing security headers; bound query periods/rows; do not infer device ownership from VPN outer endpoints. Never multiply or allocate bytes by DNS query frequency. Success: a known test connection appears once under the correct device with measured directional bytes and evidence; ambiguous/shared-CDN and unsupported traffic remain visibly unknown; the existing device and dashboard navigation still work.
