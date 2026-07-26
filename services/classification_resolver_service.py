from dataclasses import dataclass
from datetime import datetime, timedelta

from services.application_classification_service import classify_application, site_application_mappings


DEFAULT_DNS_TTL_SECONDS = 900


@dataclass
class Flow:
    ts: str
    local_ip: str
    remote_ip: str
    bytes: int = 0
    port: int | None = None
    protocol: str = ""
    tls_sni: str = ""
    http_host: str = ""
    app_proto: str = ""
    asn: str = ""
    provider: str = ""
    flow_id: str = ""


@dataclass
class Classification:
    category: str
    application: str
    evidence_source: str
    confidence: str


def dns_answer_rows(client_ip, domain, answers, observed_at, default_ttl=DEFAULT_DNS_TTL_SECONDS):
    rows = []
    for answer in answers if isinstance(answers, list) else []:
        if not isinstance(answer, dict):
            continue
        if str(answer.get("type") or "").upper() not in {"A", "AAAA"}:
            continue
        resolved_ip = str(answer.get("value") or "").strip()
        if not resolved_ip:
            continue
        ttl = _positive_int(answer.get("ttl"), default_ttl)
        rows.append((
            observed_at,
            str(client_ip or "").strip(),
            str(domain or "").strip(".").lower(),
            resolved_ip,
            ttl,
            _expires_at(observed_at, ttl),
            "adguard",
        ))
    return rows


def match_dns_resolution(con, client_ip, remote_ip, timestamp):
    return con.execute(
        """
        SELECT domain
        FROM dns_resolution_events
        WHERE client_ip=?
          AND resolved_ip=?
          AND ts <= ?
          AND (expires_at IS NULL OR expires_at >= ?)
        ORDER BY ts DESC
        LIMIT 1
        """,
        (str(client_ip or "").strip(), str(remote_ip or "").strip(), timestamp, timestamp),
    ).fetchone()


def classify_flow(con, flow):
    dns_result = match_dns_resolution(con, flow.local_ip, flow.remote_ip, flow.ts)
    if dns_result:
        return _classification_for_domain(dns_result["domain"], "dns_resolution", "high")

    if flow.tls_sni:
        return _classification_for_domain(flow.tls_sni, "tls_sni", "high")

    if flow.http_host:
        return _classification_for_domain(flow.http_host, "http_host", "high")

    static_result = match_static_site_mapping(flow.remote_ip, flow.port)
    if static_result:
        return Classification(
            category=static_result["category"],
            application=static_result["application"],
            evidence_source="static_site_mapping",
            confidence="high",
        )

    asn_result = match_asn_provider(flow.remote_ip, flow.asn, flow.provider)
    if asn_result:
        return asn_result

    protocol_result = classify_by_port_protocol(flow.port, flow.protocol or flow.app_proto)
    if protocol_result:
        return protocol_result

    return None


def write_classified_flow_fact(con, flow, classification):
    bytes_value = int(flow.bytes or 0)
    evidence_key = flow.flow_id or f"{flow.ts}|{flow.local_ip}|{flow.remote_ip}|{flow.port}|{flow.protocol}|{classification.evidence_source}"
    existing = con.execute(
        """
        SELECT id
        FROM classified_flow_facts
        WHERE flow_id=? AND evidence_source=? AND local_ip=? AND remote_ip=?
        LIMIT 1
        """,
        (evidence_key, classification.evidence_source, flow.local_ip, flow.remote_ip),
    ).fetchone()
    if existing:
        return
    con.execute(
        """
        INSERT INTO classified_flow_facts (
            ts, day, local_ip, remote_ip, port, protocol, bytes,
            category, application, evidence_source, confidence, flow_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            flow.ts,
            flow.ts[:10],
            flow.local_ip,
            flow.remote_ip,
            flow.port,
            flow.protocol or flow.app_proto,
            bytes_value,
            classification.category,
            classification.application,
            classification.evidence_source,
            classification.confidence,
            evidence_key,
        ),
    )


def upsert_unknown_traffic(con, flow):
    con.execute(
        """
        INSERT INTO unknown_traffic_queue (
            first_seen, last_seen, local_ip, remote_ip, port, protocol, total_bytes,
            flow_count, asn, provider, sample_sni, sample_http_host, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 'new')
        ON CONFLICT(local_ip, remote_ip, port, protocol) DO UPDATE SET
            first_seen=MIN(first_seen, excluded.first_seen),
            last_seen=MAX(last_seen, excluded.last_seen),
            total_bytes=total_bytes + excluded.total_bytes,
            flow_count=flow_count + 1,
            asn=COALESCE(NULLIF(excluded.asn, ''), asn),
            provider=COALESCE(NULLIF(excluded.provider, ''), provider),
            sample_sni=COALESCE(NULLIF(excluded.sample_sni, ''), sample_sni),
            sample_http_host=COALESCE(NULLIF(excluded.sample_http_host, ''), sample_http_host)
        """,
        (
            flow.ts,
            flow.ts,
            flow.local_ip,
            flow.remote_ip,
            flow.port,
            flow.protocol or flow.app_proto,
            int(flow.bytes or 0),
            flow.asn,
            flow.provider,
            flow.tls_sni,
            flow.http_host,
        ),
    )


def _classification_for_domain(domain, evidence_source, confidence):
    domain = str(domain or "").strip(".").lower()
    classified = classify_application(domain=domain)
    return Classification(
        category=classified.get("primary_category") or classified.get("category") or "Unknown",
        application=domain,
        evidence_source=evidence_source,
        confidence=confidence,
    )


def match_static_site_mapping(remote_ip, port=None):
    for mapping in site_application_mappings():
        if mapping.get("ip") == str(remote_ip or "").strip():
            return mapping
    return None


def match_asn_provider(remote_ip="", asn="", provider=""):
    if not (asn or provider):
        return None
    classified = classify_application(destination_ip=remote_ip, asn=asn, provider=provider)
    if classified.get("primary_category") == "Unknown":
        return None
    return Classification(
        category=classified["primary_category"],
        application=classified.get("primary_app") or provider or asn,
        evidence_source="asn_provider",
        confidence="medium",
    )


def classify_by_port_protocol(port, protocol=""):
    protocol = str(protocol or "").strip().lower()
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = None
    if port in {80, 8080}:
        return Classification("Web Browsing", "HTTP", "port_protocol", "low")
    if port == 443 or protocol in {"tls", "https"}:
        return Classification("Web Browsing", "HTTPS", "port_protocol", "low")
    if port == 53 or protocol == "dns":
        return Classification("Local Services", "DNS", "port_protocol", "low")
    return None


def _positive_int(value, default):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return int(default)
    return parsed if parsed > 0 else int(default)


def _expires_at(observed_at, ttl):
    try:
        ts = datetime.strptime(str(observed_at), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        ts = datetime.now()
    return (ts + timedelta(seconds=int(ttl))).strftime("%Y-%m-%d %H:%M:%S")
