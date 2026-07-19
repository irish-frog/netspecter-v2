import json
import time
import uuid
from pathlib import Path
from urllib.request import urlopen

from netspecter_paths import DATA_ROOT


ENDPOINT_URL = "https://endpoints.office.com/endpoints/{instance}?clientrequestid={client_id}"
CACHE_PATH = DATA_ROOT / "microsoft365_endpoints.json"
DEFAULT_INSTANCE = "worldwide"

SERVICE_MAP = {
    "exchange": ("Outlook", "Email"),
    "sharepoint": ("SharePoint Documents", "File Sharing & Storage"),
    "skype": ("Microsoft Teams", "Communication & Collaboration"),
    "common": ("Microsoft 365", "Office & Productivity"),
}


def refresh_microsoft365_endpoints(instance=DEFAULT_INSTANCE, timeout=20):
    instance = str(instance or DEFAULT_INSTANCE).strip().lower()
    if instance not in {"worldwide", "china", "germany", "usgovdod", "usgovgcchigh"}:
        instance = DEFAULT_INSTANCE
    url = ENDPOINT_URL.format(instance=instance, client_id=str(uuid.uuid4()))
    with urlopen(url, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    mappings = endpoint_domain_mappings(payload)
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps({
        "refreshed_at": int(time.time()),
        "instance": instance,
        "source": url.split("clientrequestid=", 1)[0] + "clientrequestid=<generated>",
        "domain_mappings": mappings,
    }, indent=2), encoding="utf-8")
    return {"ok": True, "count": len(mappings), "instance": instance}


def cached_microsoft365_domain_mappings(max_age_hours=168):
    try:
        data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    refreshed_at = int(data.get("refreshed_at") or 0)
    max_age_seconds = max(1, int(max_age_hours or 168)) * 3600
    if refreshed_at and time.time() - refreshed_at > max_age_seconds:
        return []
    mappings = data.get("domain_mappings")
    return mappings if isinstance(mappings, list) else []


def microsoft365_endpoint_cache_status(max_age_hours=168):
    try:
        data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"exists": False, "fresh": False, "count": 0, "age_seconds": None}
    refreshed_at = int(data.get("refreshed_at") or 0)
    age_seconds = max(0, int(time.time() - refreshed_at)) if refreshed_at else None
    max_age_seconds = max(1, int(max_age_hours or 168)) * 3600
    mappings = data.get("domain_mappings")
    count = len(mappings) if isinstance(mappings, list) else 0
    return {
        "exists": True,
        "fresh": bool(refreshed_at and age_seconds is not None and age_seconds <= max_age_seconds and count),
        "count": count,
        "age_seconds": age_seconds,
    }


def endpoint_domain_mappings(payload):
    output = []
    seen = set()
    for row in payload if isinstance(payload, list) else []:
        service_area = str(row.get("serviceArea") or "").strip().lower()
        app_name, category = SERVICE_MAP.get(service_area, ("Microsoft Cloud Services", "Microsoft Cloud Services"))
        for domain in row.get("urls") or []:
            domain = normalise_endpoint_domain(domain)
            if not domain:
                continue
            key = (app_name.lower(), category.lower(), domain)
            if key in seen:
                continue
            seen.add(key)
            output.append({"application": app_name, "category": category, "domain": domain, "source": "Microsoft 365 endpoints"})
    return sorted(output, key=lambda item: (item["category"], item["application"], item["domain"]))


def normalise_endpoint_domain(value):
    text = str(value or "").strip().lower().rstrip(".")
    if not text or "/" in text or " " in text:
        return ""
    if text.startswith("http://") or text.startswith("https://"):
        text = text.split("://", 1)[1].split("/", 1)[0]
    return text
