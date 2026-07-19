from netspecter_db import query
from services.application_classification_service import classify_application

AI_CATEGORY = "AI Services"


AI_SERVICE_DOMAINS = {
    "ChatGPT": ("chatgpt.com", "chat.openai.com"),
    "OpenAI API": ("api.openai.com", "platform.openai.com"),
    "OpenAI Authentication": ("auth.openai.com",),
    "OpenAI Static Assets": ("oaistatic.com",),
    "OpenAI Uploaded Content": ("oaiusercontent.com",),
    "Sora": ("sora.com",),
    "Microsoft Copilot": ("copilot.microsoft.com",),
    "GitHub Copilot": ("githubcopilot.com",),
    "Azure OpenAI": ("openai.azure.com", "services.ai.azure.com"),
    "Claude": ("claude.ai", "anthropic.com"),
    "Gemini": ("gemini.google.com", "generativelanguage.googleapis.com"),
    "Google AI Studio": ("aistudio.google.com",),
    "Vertex AI": ("vertexai.googleapis.com",),
    "Perplexity": ("perplexity.ai",),
    "DeepSeek": ("deepseek.com",),
    "Grok": ("grok.com", "x.ai"),
    "Mistral": ("mistral.ai", "chat.mistral.ai"),
    "Meta AI": ("meta.ai",),
    "Hugging Face": ("huggingface.co", "hf.co", "api-inference.huggingface.co"),
    "Cursor AI": ("cursor.com", "cursor.sh"),
    "Windsurf": ("windsurf.com",),
    "Amazon Q": ("amazonq.aws", "qbusiness.aws.dev"),
}


def ai_service_for_domain(domain):
    text = str(domain or "").lower().strip(".")
    if not text:
        return ""
    for service, suffixes in AI_SERVICE_DOMAINS.items():
        if any(text == suffix or text.endswith("." + suffix) for suffix in suffixes):
            return service
    return ""


def ai_attribution_summary(filters, start_time, end_time, include_dns_correlation=False):
    filters = filters or {}
    device_ids = _clean_list(filters.get("device_ids"))
    dns_where = ["ts BETWEEN ? AND ?"]
    dns_params = [start_time, end_time]
    if device_ids:
        placeholders = ",".join(["?"] * len(device_ids))
        dns_where.append(f"client IN ({placeholders})")
        dns_params.extend(device_ids)

    dns_rows = query(
        f"""
        SELECT domain, client, COUNT(*) AS requests, MIN(ts) AS first_seen, MAX(ts) AS last_seen
        FROM dns_querylog
        WHERE {' AND '.join(dns_where)}
        GROUP BY domain, client
        """,
        tuple(dns_params),
    )
    services = {}
    for row in dns_rows:
        service = ai_service_for_domain(row["domain"])
        if not service:
            continue
        item = services.setdefault(service, _empty_service(service))
        item["service_detected"] = True
        item["dns_requests"] += int(row["requests"] or 0)
        item["devices"].add(str(row["client"] or ""))
        item["domains"].add(str(row["domain"] or ""))
        item["classification_sources"].add("DNS")
        item["first_seen"] = _min_time(item["first_seen"], row["first_seen"])
        item["last_seen"] = _max_time(item["last_seen"], row["last_seen"])

    app_where = ["ts BETWEEN ? AND ?"]
    app_params = [start_time, end_time]
    if device_ids:
        placeholders = ",".join(["?"] * len(device_ids))
        app_where.append(f"ip IN ({placeholders})")
        app_params.extend(device_ids)
    app_rows = query(
        f"""
        SELECT category, ip, SUM(downloaded_mb) AS downloaded_mb, SUM(uploaded_mb) AS uploaded_mb,
               SUM(total_mb) AS total_mb, MIN(ts) AS first_seen, MAX(ts) AS last_seen
        FROM estimated_app_traffic
        WHERE {' AND '.join(app_where)}
        GROUP BY category, ip
        """,
        tuple(app_params),
    )
    for row in app_rows:
        classified = classify_application(row["category"])
        if classified["category"] != AI_CATEGORY:
            continue
        service = str(row["category"] or AI_CATEGORY)
        item = services.setdefault(service, _empty_service(service))
        item["service_detected"] = True
        item["devices"].add(str(row["ip"] or ""))
        item["downloaded_mb"] += float(row["downloaded_mb"] or 0)
        item["uploaded_mb"] += float(row["uploaded_mb"] or 0)
        item["attributed_mb"] += float(row["total_mb"] or 0)
        item["classification_sources"].add("Attributed traffic")
        item["first_seen"] = _min_time(item["first_seen"], row["first_seen"])
        item["last_seen"] = _max_time(item["last_seen"], row["last_seen"])

    if include_dns_correlation:
        for row in dns_time_window_correlations(filters, start_time, end_time):
            service = row["service"]
            item = services.setdefault(service, _empty_service(service))
            item["service_detected"] = True
            item["devices"].add(str(row["ip"] or ""))
            item["domains"].add(str(row["domain"] or ""))
            item["dns_correlated_mb"] += float(row["total_mb"] or 0)
            item["classification_sources"].add("DNS time-window correlation")
            item["first_seen"] = _min_time(item["first_seen"], row["first_seen"])
            item["last_seen"] = _max_time(item["last_seen"], row["last_seen"])

    service_rows = []
    for item in services.values():
        item["devices"] = sorted(value for value in item["devices"] if value)
        item["domains"] = sorted(value for value in item["domains"] if value)
        item["classification_sources"] = sorted(item["classification_sources"])
        item["service_detection_confidence"] = "High" if item["dns_requests"] or item["attributed_mb"] else "Unknown"
        item["traffic_attribution_status"] = _attribution_status(item)
        item["traffic_attribution_confidence"] = _attribution_confidence(item)
        item["evidence_summary"] = ", ".join(item["classification_sources"]) or "No evidence"
        service_rows.append(item)
    service_rows.sort(key=lambda row: (-row["attributed_mb"], row["service"].lower()))

    detected = [row for row in service_rows if row["service_detected"]]
    with_traffic = [row for row in detected if row["attributed_mb"] > 0]
    dns_only = [row for row in detected if row["dns_requests"] and row["attributed_mb"] <= 0]
    return {
        "services": service_rows,
        "services_detected": len(detected),
        "services_with_attributed_traffic": len(with_traffic),
        "services_detected_by_dns_only": len(dns_only),
        "services_detected_by_tls_sni": 0,
        "services_detected_by_http_host": 0,
        "services_with_partial_attribution": len([row for row in detected if row["traffic_attribution_status"] in {"Partial", "Minimal"}]),
        "attributed_mb": sum(row["attributed_mb"] for row in service_rows),
        "downloaded_mb": sum(row["downloaded_mb"] for row in service_rows),
        "uploaded_mb": sum(row["uploaded_mb"] for row in service_rows),
        "devices": sorted({device for row in service_rows for device in row["devices"]}),
        "assigned_users": [],
        "attribution_coverage": _coverage_label(service_rows),
    }


def _empty_service(service):
    return {
        "service": service,
        "category": AI_CATEGORY,
        "service_detected": False,
        "service_detection_confidence": "Unknown",
        "attributed_mb": 0.0,
        "dns_correlated_mb": 0.0,
        "downloaded_mb": 0.0,
        "uploaded_mb": 0.0,
        "traffic_attribution_confidence": "Unknown",
        "traffic_attribution_status": "Unavailable",
        "classification_sources": set(),
        "evidence_summary": "",
        "dns_requests": 0,
        "devices": set(),
        "domains": set(),
        "first_seen": "",
        "last_seen": "",
        "policy_status": "Monitor",
    }


def _attribution_status(item):
    if item["attributed_mb"] > 0 and item["dns_requests"]:
        return "Partial"
    if item["attributed_mb"] > 0:
        return "Partial"
    if item.get("dns_correlated_mb", 0) > 0:
        return "Partial"
    if item["dns_requests"]:
        return "Minimal"
    return "Unavailable"


def _attribution_confidence(item):
    if item["attributed_mb"] > 0 and item["dns_requests"]:
        return "Partial"
    if item["attributed_mb"] > 0:
        return "Low"
    if item.get("dns_correlated_mb", 0) > 0:
        return "Partial"
    if item["dns_requests"]:
        return "Low"
    return "Unknown"


def _coverage_label(service_rows):
    if not service_rows:
        return "Unknown"
    if any(row["traffic_attribution_status"] in {"Partial", "Minimal"} for row in service_rows):
        return "Partial"
    return "Unknown"


def dns_time_window_correlations(filters, start_time, end_time, window_minutes=30):
    filters = filters or {}
    device_ids = _clean_list(filters.get("device_ids"))
    where = ["r.ts BETWEEN ? AND ?"]
    params = [start_time, end_time]
    if device_ids:
        placeholders = ",".join(["?"] * len(device_ids))
        where.append(f"r.ip IN ({placeholders})")
        params.extend(device_ids)
    window_value = f"+{max(1, int(window_minutes))} minutes"
    rows = query(
        f"""
        SELECT
            r.ip,
            r.remote_ip,
            dr.domain,
            SUM(r.downloaded_mb) AS downloaded_mb,
            SUM(r.uploaded_mb) AS uploaded_mb,
            SUM(r.total_mb) AS total_mb,
            MIN(r.ts) AS first_seen,
            MAX(r.ts) AS last_seen
        FROM remote_traffic_intervals r
        JOIN dns_resolved_ips dr ON dr.remote_ip = r.remote_ip
        WHERE {' AND '.join(where)}
          AND EXISTS (
              SELECT 1
              FROM dns_querylog q
              WHERE q.client = r.ip
                AND q.domain = dr.domain
                AND r.ts >= q.ts
                AND r.ts <= datetime(q.ts, ?)
          )
        GROUP BY r.ip, r.remote_ip, dr.domain
        """,
        tuple(params + [window_value]),
    )
    output = []
    for row in rows:
        service = ai_service_for_domain(row["domain"])
        if not service:
            continue
        output.append({
            "service": service,
            "ip": row["ip"],
            "remote_ip": row["remote_ip"],
            "domain": row["domain"],
            "downloaded_mb": float(row["downloaded_mb"] or 0),
            "uploaded_mb": float(row["uploaded_mb"] or 0),
            "total_mb": float(row["total_mb"] or 0),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        })
    return output


def _min_time(current, candidate):
    if not current:
        return str(candidate or "")
    if not candidate:
        return current
    return min(str(current), str(candidate))


def _max_time(current, candidate):
    if not current:
        return str(candidate or "")
    if not candidate:
        return current
    return max(str(current), str(candidate))


def _clean_list(values):
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    return [str(value).strip() for value in values if str(value or "").strip()]
