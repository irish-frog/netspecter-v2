import fnmatch
import ipaddress
import json
import time
from pathlib import Path

from netspecter_paths import ROOT
from netspecter_config import CONFIG_PATH, cfg
from netspecter_db import query
from services.microsoft365_endpoints_service import CACHE_PATH as M365_ENDPOINT_CACHE_PATH
from services.microsoft365_endpoints_service import cached_microsoft365_domain_mappings


CATEGORY_CONFIG_PATH = ROOT / "config" / "application_categories.json"
UNKNOWN_CATEGORY = "Unknown"
ALWAYS_SHOW_CATEGORIES = {"AI Services", "Social Media"}
_CONFIG_CACHE = {"mtime": None, "data": None}
_SITE_MAPPING_CACHE_TTL_SECONDS = 60
_SITE_MAPPING_CACHE = {
    "expires_at": 0,
    "config_mtime": None,
    "m365_mtime": None,
    "application_mappings": None,
    "domain_mappings": None,
}
DEFAULT_SITE_APPLICATION_MAPPINGS = [
    {"application": "Nextcloud", "category": "File Sharing & Storage", "ip": "192.168.99.4"},
]


def load_category_config():
    try:
        mtime = CATEGORY_CONFIG_PATH.stat().st_mtime
    except OSError:
        mtime = None
    if _CONFIG_CACHE["data"] is not None and _CONFIG_CACHE["mtime"] == mtime:
        return _CONFIG_CACHE["data"]
    try:
        data = json.loads(CATEGORY_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as error:
        print(f"Application category config load failed: {error}")
        data = {"categories": []}
    categories = [normalise_category(row) for row in data.get("categories", []) if row.get("name")]
    data = {"categories": categories}
    _CONFIG_CACHE.update({"mtime": mtime, "data": data})
    return data


def normalise_category(row):
    name = str(row.get("name") or UNKNOWN_CATEGORY).strip()
    return {
        "name": name,
        "slug": slugify(name),
        "usage_group": str(row.get("usage_group") or "System and Background").strip(),
        "description": str(row.get("description") or "").strip(),
        "icon": str(row.get("icon") or "circle").strip(),
        "display_order": int(row.get("display_order") or 999),
        "color": str(row.get("color") or "#5ba8ff").strip(),
        "applications": [str(value).strip() for value in row.get("applications", []) if str(value or "").strip()],
        "domains": [str(value).strip().lower() for value in row.get("domains", []) if str(value or "").strip()],
        "destination_ips": [str(value).strip() for value in row.get("destination_ips", []) if str(value or "").strip()],
        "services": normalise_services(row.get("services", [])),
        "tags": [str(value).strip() for value in row.get("tags", []) if str(value or "").strip()],
        "enabled": bool(row.get("enabled", True)),
    }


def normalise_services(rows):
    services = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        vendor = str(row.get("vendor") or "").strip()
        service = str(row.get("service") or "").strip()
        if not vendor or not service:
            continue
        services.append({
            "vendor": vendor,
            "service": service,
            "policy": str(row.get("policy") or "Monitor").strip(),
            "tags": [str(value).strip() for value in row.get("tags", []) if str(value or "").strip()],
        })
    return services


def categories():
    return [row for row in load_category_config().get("categories", []) if row.get("enabled", True)]


def classify_application(application_name="", domain="", destination_ip=""):
    app_text = str(application_name or "").strip().lower()
    domain_text = normalise_domain(domain)
    destination_text = str(destination_ip or "").strip()

    if app_text:
        for category in categories():
            for app in category.get("applications", []):
                candidate = app.lower()
                if app_text == candidate or (len(candidate) >= 3 and candidate in app_text):
                    return classification(category, "Application match")

    if domain_text:
        mapped = classify_site_domain(domain_text)
        if mapped:
            return mapped
        domain_match = best_domain_category(domain_text)
        if domain_match:
            return classification(domain_match, "Domain pattern")

    if destination_text:
        for category in categories():
            if ip_matches(category, destination_text):
                return classification(category, "Destination IP")

    unknown = next((row for row in categories() if row["name"] == UNKNOWN_CATEGORY), None)
    return classification(unknown or {"name": UNKNOWN_CATEGORY, "usage_group": "System and Background", "color": "#94a3b8"}, "Unknown")


def category_summary(start_time, end_time, filters=None, limit=8, total_network_mb=None):
    filters = filters or {}
    started = time.perf_counter()
    where = ["ts BETWEEN ? AND ?"]
    params = [start_time, end_time]
    device_ids = _clean_list(filters.get("device_ids"))
    if device_ids:
        placeholders = ",".join(["?"] * len(device_ids))
        where.append(f"ip IN ({placeholders})")
        params.extend(device_ids)
    application = str(filters.get("application") or "").strip()
    if application:
        where.append("category=?")
        params.append(application)
    rows = query(
        f"""
        SELECT category AS application_name,
               SUM(downloaded_mb) AS downloaded_mb,
               SUM(uploaded_mb) AS uploaded_mb,
               SUM(total_mb) AS total_mb,
               COUNT(DISTINCT ip) AS devices
        FROM estimated_app_traffic
        WHERE {' AND '.join(where)}
        GROUP BY category
        ORDER BY total_mb DESC
        """,
        tuple(params),
    )
    buckets = {}
    classified_total = 0.0
    for row in rows:
        classified = classify_application(row["application_name"])
        name = classified["category"]
        total_mb = float(row["total_mb"] or 0)
        classified_total += total_mb
        bucket = buckets.setdefault(name, {
            "category": name,
            "usage_group": classified["usage_group"],
            "classification_source": classified["source"],
            "color": classified["color"],
            "downloaded_mb": 0.0,
            "uploaded_mb": 0.0,
            "total_mb": 0.0,
            "devices": 0,
            "applications": {},
        })
        bucket["downloaded_mb"] += float(row["downloaded_mb"] or 0)
        bucket["uploaded_mb"] += float(row["uploaded_mb"] or 0)
        bucket["total_mb"] += total_mb
        bucket["devices"] += int(row["devices"] or 0)
        if row["application_name"]:
            app_name = display_application_name(row["application_name"])
            bucket["applications"][app_name] = bucket["applications"].get(app_name, 0.0) + total_mb

    classified_total += add_site_device_mappings(
        buckets,
        start_time,
        end_time,
        device_ids=device_ids,
        application_filter=application,
    )

    output = []
    network_total = float(total_network_mb or 0)
    if network_total <= 0:
        network_total = classified_total
    for bucket in buckets.values():
        application_names = [
            name for name, _total in sorted(
                bucket["applications"].items(),
                key=lambda item: (-item[1], item[0].lower()),
            )
        ]
        output.append({
            **bucket,
            "devices": bucket["devices"],
            "applications": len(application_names),
            "application_names": application_names,
            "share_classified_pct": round((bucket["total_mb"] / classified_total * 100), 1) if classified_total else 0,
            "share_total_pct": round((bucket["total_mb"] / network_total * 100), 1) if network_total else 0,
            "share_pct": round((bucket["total_mb"] / network_total * 100), 1) if network_total else 0,
        })
    output.sort(key=lambda row: row["total_mb"], reverse=True)
    max_rows = max(1, int(limit or 8))
    top = output[:max_rows]
    other = output[max_rows:]
    protected = [row for row in other if row["category"] in ALWAYS_SHOW_CATEGORIES]
    if protected:
        protected_names = {row["category"] for row in protected}
        top.extend(protected)
        other = [row for row in other if row["category"] not in protected_names]
    if other:
        other_total = sum(row["total_mb"] for row in other)
        top.append({
            "category": "Other",
            "usage_group": "Mixed",
            "classification_source": "Grouped",
            "color": "#94a3b8",
            "downloaded_mb": sum(row["downloaded_mb"] for row in other),
            "uploaded_mb": sum(row["uploaded_mb"] for row in other),
            "total_mb": other_total,
            "devices": sum(row["devices"] for row in other),
            "applications": sum(row["applications"] for row in other),
            "application_names": sorted(
                {name for row in other for name in row.get("application_names", [])},
                key=str.lower,
            ),
            "share_classified_pct": round((other_total / classified_total * 100), 1) if classified_total else 0,
            "share_total_pct": round((other_total / network_total * 100), 1) if network_total else 0,
            "share_pct": round((other_total / network_total * 100), 1) if network_total else 0,
        })
    unclassified_mb = max(0.0, network_total - classified_total)
    if unclassified_mb > 0:
        top.append({
            "category": "Unclassified / Other Network Traffic",
            "usage_group": "Unclassified",
            "classification_source": "Outside application classification",
            "color": "#64748b",
            "downloaded_mb": 0.0,
            "uploaded_mb": 0.0,
            "total_mb": unclassified_mb,
            "devices": 0,
            "applications": 0,
            "application_names": [],
            "share_classified_pct": 0,
            "share_total_pct": round((unclassified_mb / network_total * 100), 1) if network_total else 0,
            "share_pct": round((unclassified_mb / network_total * 100), 1) if network_total else 0,
        })
    elapsed_ms = (time.perf_counter() - started) * 1000
    if elapsed_ms > 500:
        print(f"Category summary query slow: {elapsed_ms:.1f} ms")
    return {
        "rows": top,
        "total_network_mb": network_total,
        "classified_application_mb": classified_total,
        "unclassified_application_mb": unclassified_mb,
        "classification_coverage_pct": round((classified_total / network_total * 100), 1) if network_total else 0,
    }


def add_site_device_mappings(buckets, start_time, end_time, device_ids=None, application_filter=""):
    device_ids = set(device_ids or [])
    added_total = 0.0
    for mapping in site_application_mappings():
        ip = mapping["ip"]
        app_name = mapping["application"]
        if device_ids and ip not in device_ids:
            continue
        if application_filter and application_filter.lower() != app_name.lower():
            continue
        traffic = _first_row(query(
            """
            SELECT SUM(downloaded_mb) AS downloaded_mb,
                   SUM(uploaded_mb) AS uploaded_mb,
                   SUM(total_mb) AS total_mb,
                   COUNT(DISTINCT ip) AS devices
            FROM traffic_intervals
            WHERE ts BETWEEN ? AND ? AND ip=?
            """,
            (start_time, end_time, ip),
        ))
        total_mb = float(_row_value(traffic, "total_mb", 0) or 0)
        if total_mb <= 0:
            continue
        existing = _first_row(query(
            """
            SELECT SUM(downloaded_mb) AS downloaded_mb,
                   SUM(uploaded_mb) AS uploaded_mb,
                   SUM(total_mb) AS total_mb
            FROM estimated_app_traffic
            WHERE ts BETWEEN ? AND ? AND ip=?
            """,
            (start_time, end_time, ip),
        ))
        downloaded_mb = max(0.0, float(_row_value(traffic, "downloaded_mb", 0) or 0) - float(_row_value(existing, "downloaded_mb", 0) or 0))
        uploaded_mb = max(0.0, float(_row_value(traffic, "uploaded_mb", 0) or 0) - float(_row_value(existing, "uploaded_mb", 0) or 0))
        mapped_total = max(0.0, total_mb - float(_row_value(existing, "total_mb", 0) or 0))
        if mapped_total <= 0:
            continue
        classified = classify_category_name(mapping.get("category")) or classify_application(app_name, destination_ip=ip)
        name = classified["category"]
        bucket = buckets.setdefault(name, {
            "category": name,
            "usage_group": classified["usage_group"],
            "classification_source": "Site device mapping",
            "color": classified["color"],
            "downloaded_mb": 0.0,
            "uploaded_mb": 0.0,
            "total_mb": 0.0,
            "devices": 0,
            "applications": {},
        })
        bucket["classification_source"] = "Site device mapping"
        bucket["downloaded_mb"] += downloaded_mb
        bucket["uploaded_mb"] += uploaded_mb
        bucket["total_mb"] += mapped_total
        bucket["devices"] += int(_row_value(traffic, "devices", 1) or 1)
        bucket["applications"][app_name] = bucket["applications"].get(app_name, 0.0) + mapped_total
        added_total += mapped_total
    return added_total


def display_application_name(application_name):
    name = str(application_name or "").strip()
    if name == "Microsoft Services - Unresolved":
        return "Microsoft Services (General)"
    return name


def site_application_mappings(config=None):
    if config is None:
        cached = _cached_site_mappings()
        if cached["application_mappings"] is not None:
            return cached["application_mappings"]
        config = cfg()
    config = config or cfg()
    output = normalised_site_application_mappings(config.get("site_application_mappings"))
    if config is not None:
        return output
    return output


def normalised_site_application_mappings(mappings):
    if not isinstance(mappings, list):
        mappings = DEFAULT_SITE_APPLICATION_MAPPINGS
    output = []
    seen = set()
    for row in mappings:
        if not isinstance(row, dict):
            continue
        app_name = str(row.get("application") or "").strip()
        ip = str(row.get("ip") or "").strip()
        category = str(row.get("category") or "").strip()
        if not app_name or not ip or not ip_matches({"destination_ips": [ip]}, ip):
            continue
        key = (app_name.lower(), ip)
        if key in seen:
            continue
        seen.add(key)
        output.append({"application": app_name, "category": category, "ip": ip})
    return output


def site_domain_mappings(config=None):
    if config is None:
        cached = _cached_site_mappings()
        if cached["domain_mappings"] is not None:
            return cached["domain_mappings"]
        config = cfg()
    config = config or cfg()
    output = normalised_site_domain_mappings(config)
    if config is not None:
        return output
    return output


def normalised_site_domain_mappings(config):
    mappings = config.get("site_domain_mappings")
    if not isinstance(mappings, list):
        mappings = []
    if config.get("microsoft365_endpoint_import_enabled"):
        mappings = list(mappings) + cached_microsoft365_domain_mappings(config.get("microsoft365_endpoint_cache_hours", 168))
    output = []
    seen = set()
    for row in mappings:
        if not isinstance(row, dict):
            continue
        app_name = str(row.get("application") or "").strip()
        category = str(row.get("category") or "").strip()
        pattern = normalise_domain_pattern(row.get("domain") or row.get("pattern") or "")
        if not app_name or not category or not valid_domain_pattern(pattern):
            continue
        key = (app_name.lower(), category.lower(), pattern)
        if key in seen:
            continue
        seen.add(key)
        output.append({"application": app_name, "category": category, "domain": pattern})
    return output


def _cached_site_mappings():
    now = time.monotonic()
    config_mtime = _path_mtime(CONFIG_PATH)
    m365_mtime = _path_mtime(M365_ENDPOINT_CACHE_PATH)
    if (
        _SITE_MAPPING_CACHE["application_mappings"] is not None
        and _SITE_MAPPING_CACHE["domain_mappings"] is not None
        and _SITE_MAPPING_CACHE["config_mtime"] == config_mtime
        and _SITE_MAPPING_CACHE["m365_mtime"] == m365_mtime
        and now < _SITE_MAPPING_CACHE["expires_at"]
    ):
        return _SITE_MAPPING_CACHE

    config = cfg()
    _SITE_MAPPING_CACHE.update({
        "expires_at": now + _SITE_MAPPING_CACHE_TTL_SECONDS,
        "config_mtime": config_mtime,
        "m365_mtime": m365_mtime,
        "application_mappings": normalised_site_application_mappings(config.get("site_application_mappings")),
        "domain_mappings": normalised_site_domain_mappings(config),
    })
    return _SITE_MAPPING_CACHE


def _path_mtime(path):
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def classify_site_domain(domain):
    for mapping in site_domain_mappings():
        if domain_matches({"domains": [mapping["domain"]]}, domain):
            return classify_category_name(mapping.get("category")) or classification(
                {"name": mapping["category"], "usage_group": "Site Mapping", "color": "#5ba8ff"},
                "Site domain mapping",
            )
    return None


def category_for_existing_application(application_name):
    return classify_application(application_name)


def classify_category_name(category_name):
    name = str(category_name or "").strip().lower()
    if not name:
        return None
    for category in categories():
        if category["name"].lower() == name:
            return classification(category, "Site category mapping")
    return None


def best_domain_category(domain):
    best = None
    best_score = -1
    for category in categories():
        score = domain_match_score(category, domain)
        if score > best_score:
            best = category
            best_score = score
    return best if best_score >= 0 else None


def classification(category, source):
    category = category or {}
    return {
        "category": category.get("name", UNKNOWN_CATEGORY),
        "usage_group": category.get("usage_group", "System and Background"),
        "color": category.get("color", "#94a3b8"),
        "source": source,
    }


def domain_matches(category, domain):
    return domain_match_score(category, domain) >= 0


def domain_match_score(category, domain):
    for pattern in category.get("domains", []):
        pattern = normalise_domain_pattern(pattern)
        if not pattern:
            continue
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if domain == suffix or domain.endswith("." + suffix):
                return len(suffix)
        elif fnmatch.fnmatch(domain, pattern) or domain == pattern:
            return len(pattern.replace("*", ""))
    return -1


def ip_matches(category, destination_ip):
    try:
        ip = ipaddress.ip_address(destination_ip)
    except ValueError:
        return False
    for value in category.get("destination_ips", []):
        try:
            if "/" in value and ip in ipaddress.ip_network(value, strict=False):
                return True
            if ip == ipaddress.ip_address(value):
                return True
        except ValueError:
            continue
    return False


def normalise_domain(value):
    text = str(value or "").strip().lower().rstrip(".")
    return text[2:] if text.startswith("*.") else text


def normalise_domain_pattern(value):
    return str(value or "").strip().lower().rstrip(".")


def valid_domain_pattern(value):
    text = str(value or "").strip().lower()
    if not text or " " in text or "/" in text:
        return False
    if text.startswith("*."):
        text = text[2:]
    return "." in text and all(part for part in text.split("."))


def slugify(value):
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value)).strip("-")


def _clean_list(values):
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    return [str(value).strip() for value in values if str(value or "").strip()]


def _first_row(rows):
    return rows[0] if rows else {}


def _row_value(row, key, default=0):
    if row is None:
        return default
    if hasattr(row, "get"):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return default
