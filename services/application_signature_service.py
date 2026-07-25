import fnmatch
import ipaddress
import json

from netspecter_db import query


def load_signatures(category_rows):
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
        return [_normalise_signature(row) for row in rows]
    return _signatures_from_categories(category_rows)


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
