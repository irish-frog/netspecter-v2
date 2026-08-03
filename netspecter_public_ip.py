import ipaddress
import json
import urllib.request


IPIFY_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)
IPINFO_URL = "https://ipinfo.io/json"
IPAPI_URL = "https://ipapi.co/json/"
IPWHO_URL = "https://ipwho.is/"


def valid_public_ip(value):
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    if ip.version != 4 or not ip.is_global:
        return ""
    return str(ip)


def fetch_text(url, timeout=4):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "NetSpecter/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(4096).decode("utf-8", errors="replace").strip()


def detect_public_ip(timeout=4):
    for url in IPIFY_URLS:
        try:
            ip = valid_public_ip(fetch_text(url, timeout=timeout))
            if ip:
                return ip
        except Exception:
            continue
    return ""


def clean_asn(value):
    text = str(value or "").strip().upper()
    if not text:
        return ""
    if text.startswith("AS"):
        suffix = text[2:].strip()
        return f"AS{suffix}" if suffix.isdigit() else text
    return f"AS{text}" if text.isdigit() else text


def split_org(value):
    org = str(value or "").strip()
    if not org:
        return "", "", ""
    parts = org.split(None, 1)
    if parts and parts[0].upper().startswith("AS"):
        asn = clean_asn(parts[0])
        isp = parts[1].strip() if len(parts) > 1 else org
        return isp, asn, org
    return org, "", org


def provider_name_from_payload(payload):
    for key in ("isp", "org", "organization", "connection", "asn"):
        value = payload.get(key)
        if isinstance(value, dict):
            for nested_key in ("isp", "org", "organization"):
                nested = str(value.get(nested_key) or "").strip()
                if nested:
                    return nested
        elif str(value or "").strip():
            return str(value).strip()
    return ""


def lookup_ipinfo(timeout=4):
    payload = json.loads(fetch_text(IPINFO_URL, timeout=timeout))
    ip = valid_public_ip(payload.get("ip"))
    isp, asn, org = split_org(payload.get("org"))
    return {"public_ip": ip, "isp_name": isp, "asn": asn, "org": org, "source": "ipinfo"}


def lookup_ipapi(timeout=4):
    payload = json.loads(fetch_text(IPAPI_URL, timeout=timeout))
    ip = valid_public_ip(payload.get("ip"))
    asn = clean_asn(payload.get("asn"))
    org = str(payload.get("org") or "").strip()
    isp = str(payload.get("network") or org).strip()
    return {"public_ip": ip, "isp_name": isp, "asn": asn, "org": org, "source": "ipapi"}


def lookup_ipwho(timeout=4):
    payload = json.loads(fetch_text(IPWHO_URL, timeout=timeout))
    ip = valid_public_ip(payload.get("ip"))
    connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    asn = clean_asn(connection.get("asn") or payload.get("asn"))
    org = str(connection.get("org") or payload.get("org") or "").strip()
    isp = str(connection.get("isp") or provider_name_from_payload(payload) or org).strip()
    return {"public_ip": ip, "isp_name": isp, "asn": asn, "org": org, "source": "ipwho"}


def best_public_ip_info(results):
    usable = [item for item in results if item.get("public_ip")]
    if not usable:
        return {}
    ip_counts = {}
    for item in usable:
        ip_counts[item["public_ip"]] = ip_counts.get(item["public_ip"], 0) + 1
    public_ip = sorted(ip_counts.items(), key=lambda pair: (-pair[1], pair[0]))[0][0]
    matching = [item for item in usable if item["public_ip"] == public_ip] or usable
    isp = max((item.get("isp_name", "") for item in matching), key=len, default="")
    asn = max((item.get("asn", "") for item in matching), key=len, default="")
    org = max((item.get("org", "") for item in matching), key=len, default="")
    sources = ",".join(item.get("source", "") for item in matching if item.get("source"))
    return {"public_ip": public_ip, "isp_name": isp, "asn": asn, "org": org, "source": sources}


def lookup_public_ip_info(timeout=4):
    results = []
    for lookup in (lookup_ipinfo, lookup_ipapi, lookup_ipwho):
        try:
            result = lookup(timeout=timeout)
            if result.get("public_ip"):
                results.append(result)
        except Exception:
            continue

    best = best_public_ip_info(results)
    if best:
        return best

    ip = detect_public_ip(timeout=timeout)
    return {
        "public_ip": ip,
        "isp_name": "",
        "asn": "",
        "org": "",
        "source": "ipify" if ip else "",
    }
