import json
import re
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

from netspecter_config import save_cfg
from netspecter_db import connect_db, init_db
from netspecter_paths import CONFIG_ROOT, DATA_ROOT, DB_PATH

try:
    import psutil
except Exception:
    psutil = None


def service_url(config, key):
    return str(config.get(key, "") or "").strip().rstrip("/")


_GATUS_URL_CACHE = {"url": "", "ts": 0}


def internal_gatus_url(config=None):
    now = time.time()
    cached_url = str(_GATUS_URL_CACHE.get("url") or "")
    if cached_url and now - float(_GATUS_URL_CACHE.get("ts") or 0) < 300:
        return cached_url

    if config is None:
        config = {}
    candidates = []
    configured = service_url(config, "gatus_url")
    if configured:
        candidates.append(configured)
    candidates.extend(["http://127.0.0.1:18080", "http://127.0.0.1:8080"])

    seen = set()
    for candidate in candidates:
        candidate = str(candidate or "").strip().rstrip("/")
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if _gatus_api_ok(candidate):
            _GATUS_URL_CACHE.update({"url": candidate, "ts": now})
            if config is not None and config.get("gatus_url") != candidate:
                try:
                    config["gatus_url"] = candidate
                    save_cfg(config)
                except Exception:
                    pass
            return candidate

    fallback = configured or "http://127.0.0.1:18080"
    _GATUS_URL_CACHE.update({"url": fallback, "ts": now})
    return fallback


def _gatus_api_ok(base_url):
    try:
        response = requests.get(f"{str(base_url).rstrip('/')}/api/v1/endpoints/statuses", timeout=1.5)
        if response.status_code != 200:
            return False
        return bool(_gatus_endpoint_items(response.json()))
    except Exception:
        return False


def yaml_quote(value):
    return json.dumps(str(value or ""))


def built_in_gatus_monitors():
    return [
        {"name": "NetSpecter Health", "url": "http://127.0.0.1:5050/api/health/web", "interval": "60s", "email": False, "telegram": False},
        {"name": "Traffic Collector", "url": "http://127.0.0.1:5050/api/health/collector", "interval": "60s", "email": False, "telegram": False},
        {"name": "Bridge Interface", "url": "http://127.0.0.1:5050/api/health/bridge", "interval": "60s", "email": False, "telegram": False},
        {"name": "History Database", "url": "http://127.0.0.1:5050/api/health/database", "interval": "60s", "email": False, "telegram": False},
        {"name": "Service Watch", "url": "http://127.0.0.1:18080", "interval": "60s", "email": False, "telegram": False},
        {"name": "Metrics Engine", "url": "http://127.0.0.1:8090", "interval": "60s", "email": False, "telegram": False},
    ]


def normalise_gatus_monitors(config):
    monitors = config.get("gatus_monitors")
    if not isinstance(monitors, list):
        monitors = []
    deprecated_defaults = {
        ("adguard web", "http://127.0.0.1/"),
        ("netspecter health", "http://127.0.0.1:5050/health"),
    }
    custom_monitors = []
    for item in monitors:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip().lower()
        url = str(item.get("url", "") or "").strip().rstrip("/")
        if (name, url) in deprecated_defaults:
            continue
        custom_monitors.append(dict(item))
    known = {str(item.get("name", "") or "").strip().lower() for item in custom_monitors}
    monitors = [built_in for built_in in built_in_gatus_monitors() if built_in["name"].lower() not in known] + custom_monitors
    clean = []
    for item in monitors:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()[:80]
        url = str(item.get("url", "") or "").strip()[:300]
        dns_query_type = str(item.get("dns_query_type", "") or "").strip().upper()
        dns_query_name = str(item.get("dns_query_name", "") or "").strip()[:253]
        interval = str(item.get("interval", "60s") or "60s").strip().lower()
        if not name or not url:
            continue
        if not re.match(r"^\d+[smh]$", interval):
            interval = "60s"
        monitor_type = str(item.get("type") or monitor_url_scheme(url)).strip().lower()
        if monitor_type not in MONITOR_TYPE_INFO:
            monitor_type = monitor_type_for_url(url)
        if monitor_type == "dns":
            dns_query_type = dns_query_type if dns_query_type in DNS_QUERY_TYPES else "A"
            if not dns_query_name:
                continue
        elif not urlsplit(url).scheme:
            url = f"https://{url}"
        clean.append({
            "name": name,
            "url": url,
            "type": monitor_type,
            "dns_query_type": dns_query_type,
            "dns_query_name": dns_query_name,
            "interval": interval,
            "email": bool(item.get("email")),
            "telegram": bool(item.get("telegram")),
            "verify_tls": item.get("verify_tls") is not False,
        })
    return clean


MONITOR_TYPE_INFO = {
    "http": {
        "label": "HTTP",
        "placeholder": "example.com/health",
        "help": "Checks a normal web endpoint and expects HTTP 200.",
    },
    "https": {
        "label": "HTTPS",
        "placeholder": "example.com/health",
        "help": "Checks an encrypted web endpoint and expects HTTP 200.",
    },
    "tcp": {
        "label": "TCP port",
        "placeholder": "example.com:443",
        "help": "Checks that something accepts a TCP connection on that host and port.",
    },
    "icmp": {
        "label": "Ping",
        "placeholder": "192.168.99.1 or example.com",
        "help": "Checks whether the host answers ICMP ping.",
    },
    "udp": {
        "label": "UDP port",
        "placeholder": "example.com:1194",
        "help": "Checks a UDP target using Gatus. Some UDP services only prove reachability when they answer.",
    },
    "dns": {
        "label": "DNS",
        "placeholder": "8.8.8.8 or 192.168.99.216",
        "help": "Queries a DNS server for A, AAAA, CNAME, MX, NS, PTR, or SRV records.",
    },
    "tls": {
        "label": "TLS port",
        "placeholder": "mail.example.com:993",
        "help": "Checks that a TLS service accepts a secure connection.",
    },
    "starttls": {
        "label": "STARTTLS",
        "placeholder": "smtp.example.com:587",
        "help": "Checks services such as SMTP that upgrade to TLS after connecting.",
    },
    "ssh": {
        "label": "SSH",
        "placeholder": "server.example.com:22",
        "help": "Checks that an SSH service accepts a connection.",
    },
    "ws": {
        "label": "WebSocket",
        "placeholder": "example.com/socket",
        "help": "Checks that a plain WebSocket endpoint accepts a connection.",
    },
    "wss": {
        "label": "Secure WebSocket",
        "placeholder": "example.com/socket",
        "help": "Checks that an encrypted WebSocket endpoint accepts a connection.",
    },
}


DNS_QUERY_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV")


CONNECTED_GATUS_SCHEMES = {
    "tcp",
    "udp",
    "sctp",
    "icmp",
    "ws",
    "wss",
    "grpc",
    "grpcs",
    "ssh",
    "starttls",
    "tls",
}


TCP_CONNECT_SCHEMES = {
    "tcp",
    "tls",
    "starttls",
    "ssh",
    "grpc",
    "grpcs",
    "ws",
    "wss",
}


def monitor_url_scheme(url):
    scheme = urlsplit(str(url or "").strip()).scheme.lower()
    return scheme or "http"


def monitor_type_for_url(url):
    scheme = monitor_url_scheme(url)
    return scheme if scheme in MONITOR_TYPE_INFO else "http"


def monitor_target_from_url(url):
    url = str(url or "").strip()
    parsed = urlsplit(url)
    if parsed.scheme and "://" in url:
        return url[len(parsed.scheme) + 3:]
    return url


def build_monitor_url(monitor_type, target):
    monitor_type = str(monitor_type or "http").strip().lower()
    if monitor_type not in MONITOR_TYPE_INFO:
        monitor_type = "http"
    target = str(target or "").strip()
    parsed = urlsplit(target)
    if parsed.scheme and "://" in target:
        target = target[len(parsed.scheme) + 3:]
    if not target:
        return ""
    if monitor_type == "dns":
        return target
    return f"{monitor_type}://{target}"


def monitor_scheme_label(url):
    scheme = monitor_url_scheme(url)
    labels = {
        "http": "http",
        "https": "https",
        "tcp": "tcp",
        "udp": "udp",
        "sctp": "sctp",
        "icmp": "icmp",
        "ws": "websocket",
        "wss": "websocket",
        "grpc": "grpc",
        "grpcs": "grpc",
        "ssh": "ssh",
        "starttls": "starttls",
        "tls": "tls",
    }
    return labels.get(scheme, scheme or "target")


def monitor_type_label(monitor):
    monitor_type = str(monitor.get("type") or monitor_type_for_url(monitor.get("url", ""))).lower()
    return monitor_scheme_label(f"{monitor_type}://placeholder") if monitor_type != "dns" else "dns"


def monitor_icon_name(monitor):
    monitor_type = str(monitor.get("type") or monitor_type_for_url(monitor.get("url", ""))).lower()
    if monitor_type in ("http", "https", "ws", "wss"):
        return "monitor-web"
    if monitor_type == "dns":
        return "monitor-dns"
    if monitor_type == "icmp":
        return "traffic"
    if monitor_type in ("tcp", "udp", "tls", "starttls", "ssh"):
        return "services"
    return "monitor"


def monitor_display_target(monitor):
    if monitor.get("type") == "dns":
        query_name = str(monitor.get("dns_query_name") or "").strip()
        query_type = str(monitor.get("dns_query_type") or "A").strip().upper()
        server = str(monitor.get("url") or "").strip()
        if query_name:
            return f"{server} -> {query_type} {query_name}"
    return str(monitor.get("url") or "")


def gatus_conditions_for_url(url):
    scheme = monitor_url_scheme(url)
    if scheme in ("http", "https"):
        return ['"[STATUS] < 500"']
    if scheme in CONNECTED_GATUS_SCHEMES:
        return ['"[CONNECTED] == true"']
    return ['"[CONNECTED] == true"']


def gatus_conditions_for_monitor(monitor):
    if monitor.get("type") == "dns":
        return ['"[DNS_RCODE] == NOERROR"']
    return gatus_conditions_for_url(monitor.get("url", ""))


def check_dns_monitor(monitor, timeout=2, brief=False):
    server = str(monitor.get("url") or "").strip()
    query_name = str(monitor.get("dns_query_name") or "").strip()
    query_type = str(monitor.get("dns_query_type") or "A").strip().upper()
    label = str(monitor.get("name") or "DNS").strip()
    if not server or not query_name:
        return False, f"{label} DNS target not configured"
    try:
        result = subprocess.run(
            ["dig", f"@{server}", query_name, query_type, "+time=2", "+tries=1", "+short"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(3, float(timeout) + 1),
            check=False,
        )
        if result.returncode == 0 and (result.stdout or "").strip():
            return True, f"DNS {query_type} {query_name} answered by {server}"
        if brief:
            return False, f"{label} DNS failed"
        detail = (result.stderr or result.stdout or "no answer").strip()
        return False, f"{label} DNS check failed: {detail[:160]}"
    except FileNotFoundError:
        return False, "dig is not installed"
    except Exception as error:
        return False, f"{label} DNS check failed: {error}"


def check_monitor_service(monitor, timeout=2.0, brief=False):
    if monitor.get("type") == "dns":
        return check_dns_monitor(monitor, timeout=timeout, brief=brief)
    return check_http_service(
        monitor.get("url", ""),
        monitor.get("name", "Monitor"),
        timeout=timeout,
        brief=brief,
        verify_tls=monitor.get("verify_tls") is not False,
    )


def render_gatus_config(config):
    monitors = normalise_gatus_monitors(config)
    lines = [
        "ui:",
        "  title: NetSpecter Monitor",
        "web:",
        "  address: 127.0.0.1",
        "  port: 18080",
    ]
    if config.get("ids_email_enabled") and config.get("smtp_host") and config.get("smtp_to"):
        lines.extend([
            "alerting:",
            "  email:",
            f"    from: {yaml_quote(config.get('smtp_from') or config.get('smtp_username') or config.get('smtp_to'))}",
            f"    username: {yaml_quote(config.get('smtp_username', ''))}",
            f"    password: {yaml_quote(config.get('smtp_password', ''))}",
            f"    host: {yaml_quote(config.get('smtp_host', ''))}",
            f"    port: {int(config.get('smtp_port', 587) or 587)}",
            f"    to: {yaml_quote(config.get('smtp_to', ''))}",
        ])
    if config.get("telegram_enabled") and config.get("telegram_bot_token") and config.get("telegram_chat_id"):
        if "alerting:" not in lines:
            lines.append("alerting:")
        lines.extend([
            "  custom:",
            "    url: \"http://127.0.0.1:5050/api/monitor-alert\"",
            "    method: POST",
            "    headers:",
            "      Content-Type: application/json",
            "    body: |",
            "      {",
            "        \"state\": \"[ALERT_TRIGGERED_OR_RESOLVED]\",",
            "        \"name\": \"[ENDPOINT_NAME]\",",
            "        \"group\": \"[ENDPOINT_GROUP]\",",
            "        \"url\": \"[ENDPOINT_URL]\",",
            "        \"description\": \"[ALERT_DESCRIPTION]\"",
            "      }",
        ])
    lines.append("endpoints:")
    for monitor in monitors:
        lines.extend([
            f"  - name: {yaml_quote(monitor['name'])}",
            "    group: NetSpecter",
            f"    url: {yaml_quote(monitor['url'])}",
            f"    interval: {monitor['interval']}",
        ])
        if monitor.get("type") == "dns":
            lines.extend([
                "    dns:",
                f"      query-name: {yaml_quote(monitor.get('dns_query_name', ''))}",
                f"      query-type: {yaml_quote(monitor.get('dns_query_type', 'A'))}",
            ])
        lines.append("    conditions:")
        for condition in gatus_conditions_for_monitor(monitor):
            lines.append(f"      - {condition}")
        alerts = []
        if monitor.get("email"):
            alerts.append("email")
        if monitor.get("telegram"):
            alerts.append("custom")
        if alerts:
            lines.append("    alerts:")
            description = yaml_quote(f"{monitor['name']} offline")
            for alert_type in alerts:
                lines.append(f"      - type: {alert_type}")
                lines.append("        enabled: true")
                lines.append(f"        description: {description}")
                lines.append("        failure-threshold: 2")
                lines.append("        success-threshold: 2")
                lines.append("        send-on-resolved: true")
    return "\n".join(lines) + "\n"


def write_gatus_config(config):
    path = Path("/etc/netspecter/gatus/config.yaml")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_gatus_config(config))
        subprocess.run(["chmod", "600", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
        result = subprocess.run(
            ["systemctl", "restart", "gatus"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
            check=False,
        )
        if result.returncode == 0:
            return True, "Monitor settings saved."
        active, state = systemd_active("gatus")
        if active:
            return True, "Monitor settings saved. Gatus restarted with a warning."
        detail = (result.stderr or result.stdout or state or "unknown error").strip()
        return False, f"Monitor config saved, but Gatus did not restart: {detail[:180]}"
    except subprocess.TimeoutExpired:
        active, state = systemd_active("gatus")
        if active:
            return True, "Monitor settings saved. Gatus restart is still settling."
        return False, f"Monitor config saved, but Gatus restart timed out; service state is {state}."
    except Exception as error:
        return False, f"Monitor config could not be written: {error}"


def apply_gatus_monitor_config(config, previous_monitors):
    save_cfg(config)
    ok, notice = write_gatus_config(config)
    if ok:
        return True, notice
    config["gatus_monitors"] = previous_monitors
    save_cfg(config)
    write_gatus_config(config)
    return False, notice


def systemd_active(service):
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        state = (result.stdout or "").strip() or "unknown"
        return state == "active", state
    except Exception:
        return False, "unknown"


def process_summary(names):
    if not psutil:
        return []
    rows = []
    wanted = tuple(names)
    for proc in psutil.process_iter(["pid", "name", "cmdline", "memory_info", "cpu_percent"]):
        try:
            cmdline = " ".join(proc.info.get("cmdline") or [])
            name = proc.info.get("name") or ""
            if not any(token in name or token in cmdline for token in wanted):
                continue
            memory_mb = round((proc.info.get("memory_info").rss or 0) / 1024 / 1024, 1)
            rows.append({
                "pid": proc.info.get("pid"),
                "name": name,
                "memory": memory_mb,
                "cmd": cmdline[:120],
            })
        except Exception:
            continue
    return rows


def friendly_process_name(row):
    cmd = row.get("cmd", "")
    name = row.get("name", "")
    if "AdGuardHome" in name or "AdGuardHome" in cmd:
        return "AdGuardHome"
    if "gatus" in name or "gatus" in cmd:
        return "Service Watch"
    if "beszel" in name or "beszel" in cmd:
        return "Metrics Engine"
    if "gunicorn" in name or "gunicorn" in cmd:
        return "Web Worker"
    if "live_packet_collector.py" in cmd:
        return "Traffic Collector"
    return "Appliance Process"


def disk_usage_rows():
    candidates = [
        ("History Database", DB_PATH),
        ("NetSpecter App", Path("/opt/netspecter")),
        ("NetSpecter Data", DATA_ROOT),
        ("NetSpecter Config", CONFIG_ROOT),
        ("AdGuard", Path("/opt/AdGuardHome")),
        ("Metrics Store", Path("/opt/beszel")),
        ("System Logs", Path("/var/log")),
        ("Package Cache", Path("/var/cache/apt")),
        ("Root Home", Path("/root")),
    ]
    rows = []
    for label, path in candidates:
        if not path.exists():
            continue
        try:
            if path.is_file():
                size = round(path.stat().st_size / 1024 / 1024, 2)
            else:
                result = subprocess.run(
                    ["du", "-sm", str(path)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                    check=False,
                )
                size = int((result.stdout or "0").split()[0])
            rows.append((label, size))
        except Exception:
            continue
    return sorted(rows, key=lambda item: item[1], reverse=True)


def check_http_service(url, label, timeout=2, brief=False, verify_tls=True):
    if not url:
        return False, f"{label} URL not configured"
    try:
        parsed = urlsplit(url)
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname
        port = parsed.port or (443 if scheme in ("https", "tls", "grpcs", "wss") else 80)
        if scheme == "icmp":
            target = host or parsed.path
            if not target:
                return False, f"{label} target not configured"
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(max(1, int(float(timeout)))), target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(2, float(timeout) + 1),
                check=False,
            )
            if result.returncode == 0:
                return True, f"Reachable at {url}"
            return False, f"{label} unreachable" if brief else f"{label} ping failed"
        if scheme in TCP_CONNECT_SCHEMES:
            if not host:
                return False, f"{label} target not configured"
            try:
                with socket.create_connection((host, port), timeout=min(float(timeout), 2.0)):
                    pass
            except Exception:
                return False, f"{label} unreachable" if brief else f"{label} is not reachable at {host}:{port}"
            return True, f"Connected to {host}:{port}"
        if scheme in CONNECTED_GATUS_SCHEMES:
            return True, f"{monitor_scheme_label(url).upper()} check delegated to Gatus"
        if host:
            try:
                with socket.create_connection((host, port), timeout=min(float(timeout), 0.4)):
                    pass
            except Exception:
                return False, f"{label} unreachable" if brief else f"{label} is not reachable at {host}:{port}"
        res = requests.get(url, timeout=timeout, verify=verify_tls)
        if 200 <= res.status_code < 400:
            return True, f"Online at {url}"
        return False, f"HTTP {res.status_code} from {url}"
    except Exception as error:
        if brief:
            return False, f"{label} unreachable"
        return False, f"{label} check failed: {error}"


def check_telegram_config(config):
    if not config.get("telegram_enabled"):
        return False, "Telegram disabled"
    if not str(config.get("telegram_bot_token", "") or "").strip():
        return False, "Bot token missing"
    if not str(config.get("telegram_chat_id", "") or "").strip():
        return False, "Chat ID missing"
    return True, "Configured"


def send_telegram_message(config, text):
    ok, detail = check_telegram_config(config)
    if not ok:
        return False, detail
    token = str(config.get("telegram_bot_token", "") or "").strip()
    chat_id = str(config.get("telegram_chat_id", "") or "").strip()
    try:
        res = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=10,
        )
        if res.status_code == 200:
            return True, "Telegram test message sent."
        return False, f"Telegram returned HTTP {res.status_code}: {res.text[:160]}"
    except Exception as error:
        return False, f"Telegram test failed: {error}"


def monitor_key(name, url):
    return f"{str(name or '').strip().lower()}|{str(url or '').strip().rstrip('/')}"


def monitor_state_percent(segments, wanted_state):
    total = len(segments)
    if not total:
        return 0
    return round(sum(1 for state in segments if state == wanted_state) / total * 100, 2)


def record_monitor_event(name, url, state):
    try:
        init_db()
        key = monitor_key(name, url)
        now = int(time.time())
        con = connect_db()
        con.row_factory = sqlite3.Row
        last = con.execute(
            "SELECT state FROM monitor_events WHERE monitor_key=? ORDER BY ts DESC LIMIT 1",
            (key,),
        ).fetchone()
        con.execute(
            "INSERT INTO monitor_events (monitor_key, name, url, state, ts) VALUES (?, ?, ?, ?, ?)",
            (key, name, url, state, now),
        )
        con.commit()
        con.close()
    except Exception as error:
        print(f"Monitor event record failed: {error}")


def monitor_history_segments(name, url, current_state, hours=8, buckets=32):
    start = int(time.time()) - hours * 3600
    key = monitor_key(name, url)
    events = []
    try:
        init_db()
        con = connect_db()
        con.row_factory = sqlite3.Row
        previous = con.execute(
            "SELECT state FROM monitor_events WHERE monitor_key=? AND ts<? ORDER BY ts DESC LIMIT 1",
            (key, start),
        ).fetchone()
        events = con.execute(
            "SELECT state, ts FROM monitor_events WHERE monitor_key=? AND ts>=? ORDER BY ts",
            (key, start),
        ).fetchall()
        con.close()
    except Exception:
        previous = None

    if not events and not previous:
        return [current_state] * buckets

    segments = []
    state = str(previous["state"]) if previous else current_state
    event_index = 0
    bucket_seconds = (hours * 3600) / buckets
    for bucket in range(buckets):
        bucket_start = start + int(bucket * bucket_seconds)
        while event_index < len(events) and int(events[event_index]["ts"]) <= bucket_start:
            state = str(events[event_index]["state"])
            event_index += 1
        segments.append(state)
    return segments


def monitor_latest_states():
    """Return the most recent recorded state for each monitor key."""
    try:
        init_db()
        con = connect_db()
        con.row_factory = sqlite3.Row
        rows = con.execute(
            """
            SELECT e.monitor_key, e.name, e.url, e.state, e.ts
            FROM monitor_events e
            JOIN (
                SELECT monitor_key, MAX(ts) AS ts
                FROM monitor_events
                GROUP BY monitor_key
            ) latest
              ON latest.monitor_key = e.monitor_key
             AND latest.ts = e.ts
            """
        ).fetchall()
        con.close()
        return {str(row["monitor_key"]): dict(row) for row in rows}
    except Exception:
        return {}


def gatus_latest_states(gatus_url):
    """Return current monitor states from Gatus by endpoint key and endpoint name."""
    base = internal_gatus_url({"gatus_url": gatus_url})
    if not base:
        return {}
    try:
        response = requests.get(f"{base}/api/v1/endpoints/statuses", timeout=2)
        if response.status_code != 200:
            return {}
        payload = response.json()
    except Exception:
        return {}
    states = {}
    endpoints = _gatus_endpoint_items(payload)
    if not endpoints:
        return states
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        name = str(endpoint.get("name") or "").strip()
        results = endpoint.get("results") or []
        if not name or not isinstance(results, list) or not results:
            continue
        latest = results[-1] if isinstance(results[-1], dict) else {}
        state = "up" if latest.get("success") else "down"
        ts = int(time.time())
        timestamp = str(latest.get("timestamp") or "")
        try:
            ts = int(time.mktime(time.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S")))
        except Exception:
            pass
        url = ""
        error_text = " ".join(str(error) for error in latest.get("errors") or [])
        match = re.search(r'"(https?://[^"]+)"', error_text)
        if match:
            url = match.group(1)
        key = str(endpoint.get("key") or "").strip()
        row = {"monitor_key": key, "name": name, "url": url, "state": state, "ts": ts, "source": "gatus"}
        if key:
            states[key] = row
        states[f"name:{name.lower()}"] = row
    return states


def _gatus_endpoint_items(payload):
    if isinstance(payload, list):
        if all(isinstance(item, dict) and ("results" in item or "name" in item) for item in payload):
            return payload
        output = []
        for item in payload:
            output.extend(_gatus_endpoint_items(item))
        return output
    if not isinstance(payload, dict):
        return []
    for key in ("endpoints", "statuses", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return _gatus_endpoint_items(value)
    output = []
    for value in payload.values():
        if isinstance(value, (list, dict)):
            output.extend(_gatus_endpoint_items(value))
    return output
