import fnmatch
import ipaddress
import json
import hashlib
from datetime import datetime, timedelta

from netspecter_db import query, run_sql


BUILTIN_PROVIDER_SIGNATURES = [
    ("Microsoft / Azure", "Cloud Infrastructure", ["microsoft", "azure", "msft"], ["Microsoft", "Azure"], 58, 18),
    ("Google / YouTube", "Cloud Infrastructure", ["google", "google llc", "youtube"], ["Google", "YouTube"], 58, 18),
    ("Meta", "Social Media", ["meta", "facebook", "instagram", "whatsapp"], ["Meta", "Facebook"], 58, 18),
    ("Cloudflare", "Cloud Infrastructure", ["cloudflare"], ["Cloudflare", "CDN"], 55, 16),
    ("Akamai", "Cloud Infrastructure", ["akamai"], ["Akamai", "CDN"], 55, 16),
    ("Amazon AWS", "Cloud Infrastructure", ["amazon", "aws", "cloudfront"], ["AWS", "CloudFront"], 55, 16),
    ("Fastly", "Cloud Infrastructure", ["fastly"], ["Fastly", "CDN"], 55, 16),
    ("Apple", "Software Updates", ["apple"], ["Apple"], 55, 16),
    ("Netflix", "Video Streaming", ["netflix", "nflx"], ["Netflix"], 60, 20),
    ("Valve / Steam", "Gaming", ["valve", "steam"], ["Steam"], 60, 20),
    ("Discord", "Communication & Collaboration", ["discord"], ["Discord"], 60, 20),
    ("AnyDesk", "Remote Access", ["anydesk"], ["Remote Access"], 62, 22),
]


def load_signatures(category_rows):
    signatures = _signatures_from_categories(category_rows)
    signatures.extend(_builtin_provider_signatures(category_rows))
    rows = query(
        """
        SELECT id, app, category, domains_json, asn_json, destination_ips_json,
               ports_json, protocols_json, tags_json, confidence, priority, enabled
        FROM application_signatures
        WHERE enabled=1
        ORDER BY priority DESC, confidence DESC, app COLLATE NOCASE
        """
    )
    if rows:
        signatures.extend(_normalise_signature(row) for row in rows)
    return sorted(signatures, key=lambda item: (-int(item["priority"]), -int(item["confidence"]), item["app"].lower()))


def classify_metadata(signatures, app_name="", domain="", sni="", destination_ip="", asn="", provider="", protocol="", port=None):
    candidates = []
    for signature in signatures:
        score = _match_score(signature, app_name, domain, sni, destination_ip, asn, provider, protocol, port)
        if score <= 0:
            continue
        candidates.append((score + int(signature["priority"]), signature))
    if not candidates:
        return None
    _score, signature = sorted(candidates, key=lambda item: (-item[0], -int(item[1]["confidence"]), item[1]["app"].lower()))[0]
    return {
        "app": signature["app"],
        "category": signature["category"],
        "confidence": int(signature["confidence"]),
        "priority": int(signature["priority"]),
        "tags": list(signature["tags"]),
        "source": "Signature",
        "signature_id": signature.get("id"),
    }


def classify_metadata_cached(signatures, app_name="", domain="", sni="", destination_ip="", asn="", provider="", protocol="", port=None, ttl_hours=168):
    cache_key = _cache_key(app_name, domain, sni, destination_ip, asn, provider, protocol, port, signatures)
    cached = _cached_classification(cache_key)
    if cached:
        return cached
    result = classify_metadata(signatures, app_name, domain, sni, destination_ip, asn, provider, protocol, port)
    if result:
        _store_classification(cache_key, result, domain, sni, destination_ip, asn, provider, protocol, port, ttl_hours)
    return result


def upsert_unknown_review(domain="", sni="", destination_ip="", asn="", provider="", protocol="", port=None, traffic_mb=0.0, devices_seen=0, first_seen="", last_seen=""):
    review_key = _cache_key("", domain, sni, destination_ip, asn, provider, protocol, port)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    run_sql(
        """
        INSERT INTO unknown_traffic_review (
            review_key, domain, sni, destination_ip, asn, provider, protocol, port,
            traffic_mb, devices_seen, first_seen, last_seen, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(review_key) DO UPDATE SET
            traffic_mb=traffic_mb + excluded.traffic_mb,
            devices_seen=MAX(devices_seen, excluded.devices_seen),
            first_seen=COALESCE(MIN(first_seen, excluded.first_seen), excluded.first_seen),
            last_seen=COALESCE(MAX(last_seen, excluded.last_seen), excluded.last_seen),
            updated_at=excluded.updated_at
        """,
        (
            review_key,
            _normalise_host(domain),
            _normalise_host(sni),
            str(destination_ip or "").strip(),
            str(asn or "").strip(),
            str(provider or "").strip(),
            str(protocol or "").strip().lower(),
            _int_or_none(port),
            float(traffic_mb or 0),
            int(devices_seen or 0),
            first_seen or now,
            last_seen or now,
            now,
            now,
        ),
    )
    return review_key


def create_application_signature(app, category, domains=None, asn=None, destination_ips=None, ports=None, protocols=None, tags=None, confidence=85, priority=70, source="operator"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    run_sql(
        """
        INSERT INTO application_signatures (
            app, category, domains_json, asn_json, destination_ips_json,
            ports_json, protocols_json, tags_json, confidence, priority, enabled,
            source, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        """,
        (
            str(app or "").strip(),
            str(category or "").strip(),
            json.dumps(_clean_list(domains)),
            json.dumps(_clean_list(asn)),
            json.dumps(_clean_list(destination_ips)),
            json.dumps([str(value).strip().lower() for value in _clean_list(ports)]),
            json.dumps([str(value).strip().lower() for value in _clean_list(protocols)]),
            json.dumps(_clean_list(tags)),
            int(confidence or 85),
            int(priority or 70),
            str(source or "operator").strip(),
            now,
            now,
        ),
    )


def _clean_list(values):
    if values is None:
        return []
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",")]
    return [str(item).strip() for item in values if str(item or "").strip()]


def unknown_review_rows(limit=25):
    return query(
        """
        SELECT domain, sni, destination_ip, asn, provider, protocol, port,
               traffic_mb, devices_seen, first_seen, last_seen, status
        FROM unknown_traffic_review
        WHERE status IN ('new', 'review')
        ORDER BY traffic_mb DESC, last_seen DESC
        LIMIT ?
        """,
        (max(1, min(100, int(limit or 25))),),
    )


def _normalise_signature(row):
    return {
        "id": _row_value(row, "id"),
        "app": str(_row_value(row, "app", "") or "").strip(),
        "category": str(_row_value(row, "category", "") or "").strip(),
        "domains": _json_list(_row_value(row, "domains_json", "[]")),
        "asn": _json_list(_row_value(row, "asn_json", "[]")),
        "destination_ips": _json_list(_row_value(row, "destination_ips_json", "[]")),
        "ports": _json_list(_row_value(row, "ports_json", "[]")),
        "protocols": [value.lower() for value in _json_list(_row_value(row, "protocols_json", "[]"))],
        "tags": _json_list(_row_value(row, "tags_json", "[]")),
        "confidence": int(_row_value(row, "confidence", 70) or 70),
        "priority": int(_row_value(row, "priority", 50) or 50),
    }


def _signatures_from_categories(category_rows):
    signatures = []
    for category in category_rows:
        category_name = category.get("name", "Unknown")
        base = {
            "id": None,
            "category": category_name,
            "asn": [],
            "ports": [],
            "protocols": [],
            "tags": category.get("tags", []),
            "confidence": 75,
            "priority": max(1, 1000 - int(category.get("display_order") or 999)),
        }
        for app in category.get("applications", []):
            signatures.append({
                **base,
                "app": app,
                "domains": category.get("domains", []),
                "destination_ips": category.get("destination_ips", []),
            })
    return signatures


def _builtin_provider_signatures(category_rows):
    valid_categories = {str(row.get("name") or "") for row in category_rows}
    signatures = []
    for app, category, provider_needles, tags, confidence, priority in BUILTIN_PROVIDER_SIGNATURES:
        if category not in valid_categories:
            continue
        signatures.append({
            "id": None,
            "app": app,
            "category": category,
            "domains": [],
            "asn": provider_needles,
            "destination_ips": [],
            "ports": [],
            "protocols": [],
            "tags": tags,
            "confidence": confidence,
            "priority": priority,
        })
    return signatures


def _match_score(signature, app_name, domain, sni, destination_ip, asn, provider, protocol, port):
    score = 0
    app_text = str(app_name or "").strip().lower()
    if app_text and app_text == signature["app"].lower():
        score += 100
    elif app_text and len(signature["app"]) >= 3 and signature["app"].lower() in app_text:
        score += 70

    for host in (domain, sni):
        host = _normalise_host(host)
        if host and any(_domain_matches(pattern, host) for pattern in signature["domains"]):
            score += 90
            break

    if destination_ip and any(_ip_matches(pattern, destination_ip) for pattern in signature["destination_ips"]):
        score += 80

    provider_text = " ".join([str(asn or ""), str(provider or "")]).lower()
    if provider_text and any(value.lower() in provider_text for value in signature["asn"]):
        score += 35

    protocol_text = str(protocol or "").strip().lower()
    if protocol_text and protocol_text in signature["protocols"]:
        score += 10

    try:
        port_number = int(port)
    except (TypeError, ValueError):
        port_number = None
    if port_number is not None and str(port_number) in {str(value) for value in signature["ports"]}:
        score += 10
    return score


def _cached_classification(cache_key):
    rows = query(
        """
        SELECT primary_app, primary_category, confidence, priority, matched_signature_id,
               optional_tags_json, expires_at
        FROM classification_cache
        WHERE cache_key=?
        """,
        (cache_key,),
    )
    if not rows:
        return None
    row = rows[0]
    expires_at = str(_row_value(row, "expires_at") or "")
    if expires_at and expires_at < datetime.now().strftime("%Y-%m-%d %H:%M:%S"):
        return None
    return {
        "app": _row_value(row, "primary_app", "Unknown"),
        "category": _row_value(row, "primary_category", "Unknown"),
        "confidence": int(_row_value(row, "confidence", 0) or 0),
        "priority": int(_row_value(row, "priority", 0) or 0),
        "tags": _json_list(_row_value(row, "optional_tags_json", "[]")),
        "source": "Classification cache",
        "signature_id": _row_value(row, "matched_signature_id"),
    }


def _store_classification(cache_key, result, domain, sni, destination_ip, asn, provider, protocol, port, ttl_hours):
    now = datetime.now()
    expires = now + timedelta(hours=max(1, int(ttl_hours or 168)))
    run_sql(
        """
        INSERT OR REPLACE INTO classification_cache (
            cache_key, domain, sni, destination_ip, asn, provider, protocol, port,
            primary_app, primary_category, confidence, priority, matched_signature_id,
            optional_tags_json, classified_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cache_key,
            _normalise_host(domain),
            _normalise_host(sni),
            str(destination_ip or "").strip(),
            str(asn or "").strip(),
            str(provider or "").strip(),
            str(protocol or "").strip().lower(),
            _int_or_none(port),
            result["app"],
            result["category"],
            int(result["confidence"]),
            int(result["priority"]),
            result.get("signature_id"),
            json.dumps(result.get("tags") or []),
            now.strftime("%Y-%m-%d %H:%M:%S"),
            expires.strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )


def _cache_key(app_name, domain, sni, destination_ip, asn, provider, protocol, port, signatures=None):
    parts = [
        str(app_name or "").strip().lower(),
        _normalise_host(domain),
        _normalise_host(sni),
        str(destination_ip or "").strip(),
        str(asn or "").strip().lower(),
        str(provider or "").strip().lower(),
        str(protocol or "").strip().lower(),
        str(_int_or_none(port) or ""),
    ]
    if signatures is not None:
        parts.append(_signature_fingerprint(signatures))
    return "|".join(parts)


def _signature_fingerprint(signatures):
    payload = [
        {
            "app": item.get("app"),
            "category": item.get("category"),
            "domains": item.get("domains"),
            "asn": item.get("asn"),
            "destination_ips": item.get("destination_ips"),
            "ports": item.get("ports"),
            "protocols": item.get("protocols"),
            "priority": item.get("priority"),
            "confidence": item.get("confidence"),
        }
        for item in signatures
    ]
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:12]


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _domain_matches(pattern, domain):
    pattern = _normalise_host(pattern)
    if not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain == suffix or domain.endswith("." + suffix)
    return fnmatch.fnmatch(domain, pattern) or domain == pattern


def _ip_matches(pattern, destination_ip):
    try:
        ip = ipaddress.ip_address(str(destination_ip or "").strip())
        text = str(pattern or "").strip()
        return ip in ipaddress.ip_network(text, strict=False) if "/" in text else ip == ipaddress.ip_address(text)
    except ValueError:
        return False


def _normalise_host(value):
    return str(value or "").strip().lower().rstrip(".")


def _json_list(value):
    try:
        parsed = json.loads(value or "[]")
    except Exception:
        parsed = []
    return [str(item).strip() for item in parsed if str(item or "").strip()] if isinstance(parsed, list) else []


def _row_value(row, key, default=None):
    if hasattr(row, "get"):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return default
