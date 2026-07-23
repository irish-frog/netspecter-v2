# NetSpecter AI Integration API

NetSpecter v2 exposes a read-only API for local AI agents, automation platforms, reporting systems, and custom scripts. The API is designed for self-hosted SMB appliance deployments where the appliance normally stays on the LAN and third-party tools connect over the local network.

## Architecture

- Flask blueprint: `api_v1/blueprint.py` registers all `/api/v1/` routes.
- API authentication: `api_v1/auth.py` validates API keys, enforces read-only methods, rate-limits callers, and writes request audit rows.
- Query layer: `api_v1/data.py` builds JSON payloads from the existing SQLite helper and reporting services.
- Versioning: all integration endpoints live under `/api/v1/`; future breaking changes should use `/api/v2/`.
- Documentation: `GET /api/v1/openapi.json` returns an OpenAPI 3.0 document.

## Authentication

Send either:

```text
X-API-Key: <key>
```

or:

```text
Authorization: Bearer <key>
```

API keys are never stored in plaintext. Store SHA-256 hashes in `config.json`:

```json
{
  "api_keys": [
    {
      "id": "ollama-local",
      "name": "Ollama local reporting",
      "enabled": true,
      "key_hash": "sha256-hex-value",
      "roles": ["reader"],
      "scopes": ["read"],
      "rate_limit_per_minute": 60
    }
  ]
}
```

For testing only, `NETSPECTER_API_KEY` can be set in the service environment. That key is treated as a read-only local integration key.

## Security Model

- HTTPS is required for non-local requests by the existing NetSpecter HTTPS redirect.
- API routes are read-only and reject non-GET methods.
- API keys require the `read` scope.
- Rate limiting defaults to 60 requests per minute per key.
- Requests are audited in `api_audit_log`.
- LAN-only deployment is recommended; Internet exposure is not required.
- Reverse proxies should preserve `X-Forwarded-Proto: https`.

## Endpoints

### `GET /api/v1/dashboard`

```json
{
  "device_count": 24,
  "internet_status": "ok",
  "active_alerts": 3,
  "threat_count": 1,
  "dns_health": {
    "query_volume_7d": 18420,
    "blocked_7d": 311,
    "latest_dns_response_ms": 14.2
  },
  "recent_incidents": [],
  "period": {"start": "2026-07-16 12:00:00", "end": "2026-07-23 12:00:00"}
}
```

### `GET /api/v1/devices`

```json
{
  "items": [
    {
      "id": "192.168.1.25",
      "hostname": "reception-pc",
      "ip": "192.168.1.25",
      "mac": "00:11:22:33:44:55",
      "vendor": "Dell",
      "status": "online",
      "last_seen": "2026-07-23 11:59:21",
      "traffic_statistics": {
        "period": "last_7_days",
        "downloaded_mb": 1400.3,
        "uploaded_mb": 210.7,
        "total_mb": 1611.0
      }
    }
  ]
}
```

### `GET /api/v1/devices/{id}`

Returns one device using the same object shape as `/devices`. `{id}` may be an IP address or MAC address.

### `GET /api/v1/internet`

```json
{
  "availability": 99.7,
  "latency_ms": 18.4,
  "jitter_ms": 2.1,
  "packet_loss_pct": 0,
  "dns_response_time_ms": 14.2,
  "last_outage": null,
  "period_rollup": {"samples": 10080, "issue_samples": 30}
}
```

### `GET /api/v1/dns`

```json
{
  "top_domains": [{"domain": "example.com", "queries": 520}],
  "top_clients": [{"client": "192.168.1.25", "queries": 840, "blocked": 12}],
  "blocked_domains": [{"domain": "bad.example", "blocked_queries": 44}],
  "query_volume": 18420,
  "dns_latency_ms": 14.2
}
```

### `GET /api/v1/alerts`

```json
{
  "items": [
    {
      "id": 991,
      "severity": "High",
      "source_ip": "192.168.1.25",
      "destination_ip": "203.0.113.10",
      "signature": "ET MALWARE Suspicious TLS",
      "timestamp": "2026-07-23 10:14:00",
      "status": "new"
    }
  ]
}
```

### `GET /api/v1/threats`

```json
{
  "threat_matches": [],
  "risk_scores": [{"risk_score": 90, "matches": 2}],
  "known_malicious_hosts": [{"indicator_value": "203.0.113.10", "indicator_type": "ip", "source": "spamhaus_drop"}],
  "historical_detections": 2,
  "feeds": []
}
```

### `GET /api/v1/incidents`

Returns a unified timeline from IDS alerts, DNS events, Internet outages, config changes, and threat data where available.

```json
{
  "items": [
    {
      "ts": "2026-07-23 10:14:00",
      "category": "IDS Alert",
      "device": "192.168.1.25",
      "destination": "203.0.113.10",
      "description": "ET MALWARE Suspicious TLS",
      "severity": "high"
    }
  ]
}
```

### Reports

- `GET /api/v1/reports/daily`
- `GET /api/v1/reports/weekly`
- `GET /api/v1/reports/monthly`

Reports return structured JSON with overview metrics, top DNS domains, application usage, Internet quality, and incidents.

### AI-Optimized Summaries

- `GET /api/v1/ai/network-summary`
- `GET /api/v1/ai/executive-summary`
- `GET /api/v1/ai/security-summary`

These endpoints return condensed datasets for AI report generation. They intentionally avoid dumping thousands of raw events.

```json
{
  "summary_type": "executive-summary",
  "overview": {"devices": 24, "dns_total": 18420, "ids_alerts": 3},
  "findings": {
    "rating": "Normal",
    "score": 0,
    "findings": ["No major usage or internet-quality concerns were detected in the selected period."]
  },
  "top_devices": [],
  "top_applications": [],
  "top_dns": [],
  "security": {"alerts": [], "incidents": [], "threats": []}
}
```

## Future FastAPI Migration

The current split deliberately keeps HTTP routing, auth, and data access separate. A future FastAPI migration can:

- Move `api_v1/data.py` unchanged at first.
- Replace Flask blueprints with `APIRouter`.
- Convert response shapes into Pydantic models.
- Generate richer OpenAPI schemas automatically.
- Add async support later only for external integrations; SQLite reads should remain bounded and synchronous unless the storage layer changes.

## Risks And Mitigations

- Exposed API keys: store only hashes, rotate keys, and keep the appliance LAN-scoped.
- Internet exposure: avoid public NAT; use VPN if remote AI/reporting systems need access.
- Over-broad AI access: issue separate keys per tool with read-only scope and audit all requests.
- Prompt data leakage: prefer AI summary endpoints over raw alert/event endpoints.
- High query load: rate-limit keys and keep endpoint defaults capped.
- Weak TLS deployment: use the existing HTTPS proxy certificate settings and monitor redirects.
