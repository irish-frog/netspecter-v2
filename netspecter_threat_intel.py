import csv
import hashlib
import ipaddress
import json
import shutil
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from netspecter_paths import DATA_ROOT


FEED_STATUS = {
    "spamhaus_drop": {
        "enabled": True,
        "url": "https://www.spamhaus.org/drop/drop_v4.json",
        "type": "spamhaus_drop_json",
        "category": "malicious_network",
        "confidence": 95,
        "licence": "Permitted: Spamhaus DROP page says free/no-cost access for use, with credit/date/copyright retained and no more than hourly fetching.",
    },
    "urlhaus": {
        "enabled": False,
        "url": "",
        "type": "urlhaus_csv",
        "category": "malware_url",
        "confidence": 85,
        "licence": "Disabled: URLhaus community feeds require auth and fair-use/commercial-use review before enabling.",
    },
    "tor_exit": {
        "enabled": False,
        "url": "https://check.torproject.org/torbulkexitlist",
        "type": "tor_exit_list",
        "category": "tor_exit",
        "confidence": 60,
        "licence": "Disabled: public list found, but explicit feed reuse/licence terms were not clear enough to enable by default.",
    },
    "emerging_threats": {
        "enabled": False,
        "url": "",
        "type": "emerging_threats_rules",
        "category": "emerging_threats",
        "confidence": 80,
        "licence": "Disabled: reachable open directory did not provide clear redistribution/feed terms.",
    },
}


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_schema(con):
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            source TEXT NOT NULL,
            category TEXT,
            confidence INTEGER DEFAULT 50,
            reason TEXT,
            first_seen TEXT,
            last_seen TEXT,
            expires_at TEXT,
            active INTEGER DEFAULT 1,
            UNIQUE(indicator, indicator_type, source)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_feed_state (
            source TEXT PRIMARY KEY,
            url TEXT,
            status TEXT,
            licence_status TEXT,
            fetched_at TEXT,
            indicator_count INTEGER DEFAULT 0,
            error TEXT,
            content_hash TEXT
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            ts TEXT NOT NULL,
            reputation TEXT NOT NULL,
            indicator TEXT,
            indicator_type TEXT,
            source TEXT,
            category TEXT,
            confidence INTEGER DEFAULT 0,
            reason TEXT,
            src_ip TEXT,
            dest_ip TEXT,
            domain TEXT,
            device_ip TEXT,
            country TEXT,
            asn TEXT,
            provider TEXT,
            first_seen TEXT,
            last_seen TEXT,
            total_mb REAL DEFAULT 0
        )
        """
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicators_indicator ON threat_indicators(indicator, indicator_type)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicators_active ON threat_indicators(active, expires_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_threat_corr_ts ON threat_correlations(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_threat_corr_reputation ON threat_correlations(reputation)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_threat_corr_indicator ON threat_correlations(indicator)")


def enabled_sources(config):
    requested = config.get("threat_intel_sources")
    if isinstance(requested, list):
        names = set(str(item) for item in requested)
    else:
        names = {name for name, info in FEED_STATUS.items() if info["enabled"]}
    return {name: info for name, info in FEED_STATUS.items() if name in names and info["enabled"]}


def download_text(url, timeout=15, max_bytes=2_000_000):
    req = Request(url, headers={"User-Agent": "NetSpecter-ThreatIntel/1.0"})
    with urlopen(req, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("feed too large")
    return data.decode("utf-8", errors="replace")


def parse_indicator(value):
    text = str(value or "").strip().strip('"').strip("'")
    if not text or text.startswith("#") or text.startswith(";"):
        return None
    try:
        network = ipaddress.ip_network(text, strict=False)
        return (str(network), "cidr" if "/" in text else "ip")
    except ValueError:
        pass
    if "://" in text:
        host = urlparse(text).hostname or ""
        text = host
    text = text.lower().strip(".")
    if not text or "/" in text or " " in text:
        return None
    if "." in text:
        return (text[:253], "domain")
    return None


def parse_json_documents(text):
    body = str(text or "").strip()
    if not body:
        return []
    try:
        return [json.loads(body)]
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    values = []
    idx = 0
    while idx < len(body):
        while idx < len(body) and body[idx].isspace():
            idx += 1
        if idx >= len(body):
            break
        value, end = decoder.raw_decode(body, idx)
        values.append(value)
        idx = end
    return values


def parse_spamhaus_drop(text):
    payloads = parse_json_documents(text)
    rows = []
    items = []
    for payload in payloads:
        if isinstance(payload, list):
            items.extend(payload)
        elif isinstance(payload, dict):
            nested = payload.get("data") or payload.get("drop") or payload.get("items") or payload.get("networks")
            if isinstance(nested, list):
                items.extend(nested)
            else:
                items.append(payload)
    for item in items:
        if isinstance(item, dict):
            value = item.get("cidr") or item.get("network") or item.get("ip") or item.get("netblock")
            reason = item.get("sblid") or item.get("description") or "Spamhaus DROP"
        else:
            value, reason = item, "Spamhaus DROP"
        parsed = parse_indicator(value)
        if parsed:
            rows.append((*parsed, str(reason)[:300]))
    return rows


def parse_urlhaus_csv(text):
    rows = []
    for row in csv.reader(line for line in text.splitlines() if line and not line.startswith("#")):
        if not row:
            continue
        parsed = parse_indicator(row[0])
        if parsed:
            rows.append((*parsed, "URLhaus malware URL"))
    return rows


def parse_tor_exit_list(text):
    rows = []
    for line in text.splitlines():
        parsed = parse_indicator(line)
        if parsed and parsed[1] == "ip":
            rows.append((*parsed, "Tor exit node"))
    return rows


def parse_emerging_threats_rules(text):
    rows = []
    for line in text.splitlines():
        for token in line.replace("[", " ").replace("]", " ").replace(",", " ").split():
            parsed = parse_indicator(token)
            if parsed:
                rows.append((*parsed, "Emerging Threats rule indicator"))
    return rows


PARSERS = {
    "spamhaus_drop_json": parse_spamhaus_drop,
    "urlhaus_csv": parse_urlhaus_csv,
    "tor_exit_list": parse_tor_exit_list,
    "emerging_threats_rules": parse_emerging_threats_rules,
}


def upsert_indicators(con, source, feed, indicators, ttl_days=7):
    now = now_text()
    expires = (datetime.now() + timedelta(days=ttl_days)).strftime("%Y-%m-%d %H:%M:%S")
    seen = set()
    count = 0
    for indicator, indicator_type, reason in indicators:
        key = (indicator, indicator_type)
        if key in seen:
            continue
        seen.add(key)
        con.execute(
            """
            INSERT INTO threat_indicators
                (indicator, indicator_type, source, category, confidence, reason, first_seen, last_seen, expires_at, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(indicator, indicator_type, source) DO UPDATE SET
                category=excluded.category,
                confidence=excluded.confidence,
                reason=excluded.reason,
                last_seen=excluded.last_seen,
                expires_at=excluded.expires_at,
                active=1
            """,
            (indicator, indicator_type, source, feed["category"], int(feed["confidence"]), reason[:300], now, now, expires),
        )
        count += 1
    con.execute("UPDATE threat_indicators SET active=0 WHERE source=? AND last_seen<>?", (source, now))
    return count


def refresh_feeds(connect_db, config):
    con = connect_db()
    ensure_schema(con)
    results = {}
    max_bytes = int(config.get("threat_intel_max_feed_bytes", 2_000_000) or 2_000_000)
    timeout = int(config.get("threat_intel_download_timeout_seconds", 15) or 15)
    for source, feed in enabled_sources(config).items():
        url = feed.get("url")
        try:
            text = download_text(url, timeout=timeout, max_bytes=max_bytes)
            digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
            indicators = PARSERS[feed["type"]](text)
            if not indicators:
                raise ValueError("no valid indicators")
            count = upsert_indicators(con, source, feed, indicators)
            con.execute(
                """
                INSERT INTO threat_feed_state (source, url, status, licence_status, fetched_at, indicator_count, error, content_hash)
                VALUES (?, ?, 'ok', ?, ?, ?, '', ?)
                ON CONFLICT(source) DO UPDATE SET
                    url=excluded.url, status=excluded.status, licence_status=excluded.licence_status,
                    fetched_at=excluded.fetched_at, indicator_count=excluded.indicator_count,
                    error='', content_hash=excluded.content_hash
                """,
                (source, url, feed["licence"], now_text(), count, digest),
            )
            results[source] = {"ok": True, "count": count}
        except Exception as error:
            con.execute(
                """
                INSERT INTO threat_feed_state (source, url, status, licence_status, fetched_at, indicator_count, error, content_hash)
                VALUES (?, ?, 'failed', ?, ?, 0, ?, '')
                ON CONFLICT(source) DO UPDATE SET
                    status='failed', licence_status=excluded.licence_status, fetched_at=excluded.fetched_at, error=excluded.error
                """,
                (source, url, feed["licence"], now_text(), str(error)[:300]),
            )
            results[source] = {"ok": False, "error": str(error)}
    for source, feed in FEED_STATUS.items():
        if not feed["enabled"]:
            con.execute(
                """
                INSERT INTO threat_feed_state (source, url, status, licence_status, fetched_at, indicator_count, error, content_hash)
                VALUES (?, ?, 'disabled', ?, '', 0, '', '')
                ON CONFLICT(source) DO UPDATE SET status='disabled', licence_status=excluded.licence_status
                """,
                (source, feed.get("url", ""), feed["licence"]),
            )
    con.commit()
    con.close()
    return results


def load_active_indicators(con):
    now = now_text()
    rows = con.execute(
        """
        SELECT indicator, indicator_type, source, category, confidence, reason, first_seen, last_seen
        FROM threat_indicators
        WHERE active=1 AND (expires_at IS NULL OR expires_at='' OR expires_at>?)
        """,
        (now,),
    ).fetchall()
    return rows


def match_ip(ip, indicators):
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    for row in indicators:
        indicator, indicator_type = row[0], row[1]
        if indicator_type == "ip" and indicator == str(address):
            return row
        if indicator_type == "cidr":
            try:
                if address in ipaddress.ip_network(indicator, strict=False):
                    return row
            except ValueError:
                continue
    return None


def match_domain(domain, indicators):
    text = str(domain or "").lower().strip(".")
    if not text:
        return None
    for row in indicators:
        indicator, indicator_type = row[0], row[1]
        if indicator_type == "domain" and (text == indicator or text.endswith("." + indicator)):
            return row
    return None


def reputation_for(dest_ip="", domain="", indicators=()):
    match = match_ip(dest_ip, indicators) if dest_ip else None
    if not match and domain:
        match = match_domain(domain, indicators)
    if not match:
        return {"reputation": "Unknown"}
    category = str(match[3] or "")
    if category in ("tor_exit",):
        reputation = "Suspicious"
    else:
        reputation = "Malicious"
    return {
        "reputation": reputation,
        "indicator": match[0],
        "indicator_type": match[1],
        "source": match[2],
        "category": match[3],
        "confidence": int(match[4] or 0),
        "reason": match[5],
        "first_seen": match[6],
        "last_seen": match[7],
    }


def safe_event_key(prefix, *parts):
    return prefix + ":" + hashlib.sha256("|".join(str(part or "") for part in parts).encode()).hexdigest()


def correlate_once(connect_db, config):
    con = connect_db()
    ensure_schema(con)
    indicators = load_active_indicators(con)
    inserted = 0
    since_days = int(config.get("threat_intel_correlation_days", 14) or 14)
    cutoff = (datetime.now() - timedelta(days=since_days)).strftime("%Y-%m-%d %H:%M:%S")

    ids_rows = con.execute(
        """
        SELECT id, ts, src_ip, dest_ip, query, hostname, signature
        FROM ids_events
        WHERE ts>=?
        ORDER BY id DESC
        LIMIT 2000
        """,
        (cutoff,),
    ).fetchall()
    for row in ids_rows:
        domain = row[4] or row[5] or ""
        rep = reputation_for(row[3], domain, indicators)
        if rep["reputation"] == "Unknown":
            continue
        key = safe_event_key("ids", row[0], rep.get("indicator"))
        inserted += insert_correlation(con, key, row[1], rep, src_ip=row[2], dest_ip=row[3], domain=domain, reason=row[6])

    dns_rows = con.execute(
        """
        SELECT id, ts, client, domain
        FROM dns_querylog
        WHERE ts>=?
        ORDER BY id DESC
        LIMIT 3000
        """,
        (cutoff,),
    ).fetchall()
    for row in dns_rows:
        rep = reputation_for("", row[3], indicators)
        if rep["reputation"] == "Unknown":
            continue
        key = safe_event_key("dns", row[0], rep.get("indicator"))
        inserted += insert_correlation(con, key, row[1], rep, src_ip=row[2], domain=row[3], device_ip=row[2])

    remote_rows = con.execute(
        """
        SELECT r.remote_ip, MAX(r.ts), SUM(r.total_mb), l.country, l.country_code
        FROM remote_traffic_intervals r
        LEFT JOIN remote_ip_locations l ON l.remote_ip=r.remote_ip
        WHERE r.ts>=?
        GROUP BY r.remote_ip
        LIMIT 3000
        """,
        (cutoff,),
    ).fetchall()
    for row in remote_rows:
        rep = reputation_for(row[0], "", indicators)
        if rep["reputation"] == "Unknown":
            continue
        key = safe_event_key("remote", row[0], rep.get("indicator"))
        inserted += insert_correlation(con, key, row[1], rep, dest_ip=row[0], total_mb=row[2] or 0, country=row[3] or row[4] or "")

    con.commit()
    con.close()
    return inserted


def insert_correlation(con, key, ts, rep, src_ip="", dest_ip="", domain="", device_ip="", reason="", total_mb=0, country="", asn="", provider=""):
    try:
        con.execute(
            """
            INSERT INTO threat_correlations
                (event_key, ts, reputation, indicator, indicator_type, source, category, confidence, reason,
                 src_ip, dest_ip, domain, device_ip, country, asn, provider, first_seen, last_seen, total_mb)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key, ts or now_text(), rep["reputation"], rep.get("indicator"), rep.get("indicator_type"),
                rep.get("source"), rep.get("category"), rep.get("confidence", 0), (reason or rep.get("reason", ""))[:300],
                src_ip or "", dest_ip or "", domain or "", device_ip or src_ip or "", country or "", asn or "", provider or "",
                rep.get("first_seen", ""), rep.get("last_seen", ""), float(total_mb or 0),
            ),
        )
        return 1
    except sqlite3.IntegrityError:
        return 0


def prune_threat_intel(connect_db, config):
    days = int(config.get("threat_intel_retention_days", 30) or 30)
    max_corr = int(config.get("threat_intel_max_correlations", 100000) or 100000)
    min_free_mb = int(config.get("threat_intel_min_free_mb", 512) or 512)
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    con = connect_db()
    ensure_schema(con)
    con.execute("UPDATE threat_indicators SET active=0 WHERE expires_at IS NOT NULL AND expires_at<>'' AND expires_at<?", (now_text(),))
    con.execute("DELETE FROM threat_correlations WHERE ts<?", (cutoff,))
    count = con.execute("SELECT COUNT(*) FROM threat_correlations").fetchone()[0]
    if count > max_corr:
        con.execute("DELETE FROM threat_correlations WHERE id IN (SELECT id FROM threat_correlations ORDER BY ts ASC LIMIT ?)", (count - max_corr,))
    try:
        free_mb = shutil.disk_usage(str(DATA_ROOT)).free / 1024 / 1024
    except Exception:
        free_mb = min_free_mb + 1
    if free_mb < min_free_mb:
        con.execute("DELETE FROM threat_correlations WHERE id IN (SELECT id FROM threat_correlations ORDER BY ts ASC LIMIT 1000)")
    con.commit()
    con.close()


def latest_reputation_for_event(connect_db, event_id, dest_ip="", domain=""):
    con = connect_db()
    ensure_schema(con)
    row = con.execute(
        """
        SELECT reputation, indicator, source, category, confidence, reason, country, asn, provider, first_seen, last_seen, total_mb
        FROM threat_correlations
        WHERE dest_ip=? OR domain=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (dest_ip or "", domain or ""),
    ).fetchone()
    con.close()
    if not row:
        return {"reputation": "Unknown"}
    return {
        "reputation": row[0], "indicator": row[1], "source": row[2], "category": row[3],
        "confidence": row[4], "reason": row[5], "country": row[6], "asn": row[7],
        "provider": row[8], "first_seen": row[9], "last_seen": row[10], "total_mb": row[11],
    }


def feed_states(connect_db):
    con = connect_db()
    ensure_schema(con)
    rows = con.execute("SELECT source, status, licence_status, fetched_at, indicator_count, error FROM threat_feed_state ORDER BY source").fetchall()
    con.close()
    return rows
