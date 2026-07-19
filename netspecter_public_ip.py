import ipaddress
import json
import urllib.request


IPIFY_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)
IPINFO_URL = "https://ipinfo.io/json"


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


def lookup_public_ip_info(timeout=4):
    ip = ""
    isp = ""
    asn = ""
    org = ""
    source = ""

    try:
        payload = json.loads(fetch_text(IPINFO_URL, timeout=timeout))
        ip = valid_public_ip(payload.get("ip"))
        org = str(payload.get("org") or "").strip()
        if org:
            parts = org.split(None, 1)
            if parts and parts[0].upper().startswith("AS"):
                asn = parts[0].upper()
                isp = parts[1].strip() if len(parts) > 1 else org
            else:
                isp = org
        if ip:
            source = "ipinfo"
    except Exception:
        pass

    if not ip:
        ip = detect_public_ip(timeout=timeout)
        source = "ipify" if ip else ""

    return {
        "public_ip": ip,
        "isp_name": isp,
        "asn": asn,
        "org": org,
        "source": source,
    }
