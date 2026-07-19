
#!/usr/bin/env python3
import json
import os
import sqlite3
import time
import socket
import subprocess
import csv
import io
import math
import secrets
import re
import ipaddress
import hashlib
import smtplib
import ssl
import shlex
import zipfile
import threading
from functools import wraps
from collections import Counter
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

try:
    import requests
except Exception:
    requests = None
from flask import Flask, request, redirect, Response, session, g, jsonify, send_file
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import psutil
except Exception:
    psutil = None

from netspecter_vault.archive import VaultError
from netspecter_vault.config import load_vault_config, save_vault_config
from netspecter_vault.history import recent_events, record_event
from netspecter_vault.paths import backup_dir as vault_backup_dir
from netspecter_vault.retention import apply_retention
from netspecter_vault.restore import inspect_backup
from netspecter_vault.usb import copy_latest_backup_to_usb, eject_usb, removable_partitions
from netspecter_vault.verify import valid_backup_archive_name, verify_backup
from netspecter_paths import (
    BASE_DIR,
    CONFIG_ROOT,
    CONFIG_PATH,
    DATA_ROOT,
    DB_PATH,
    REQUEST_TIMING_PATH,
    ROOT,
    SURICATA_EVE_LOG,
    SURICATA_FAST_LOG,
    UPDATE_LOG_PATH,
    UPDATE_STATE_PATH,
    VAULT_BACKUP_LOG_PATH,
    VAULT_BACKUP_STATE_PATH,
    VAULT_RESTORE_LOG_PATH,
    VAULT_RESTORE_STATE_PATH,
)
from netspecter_config import (
    DEFAULT_CONFIG,
    INTEGRATION_SETTINGS_KEYS,
    SENSITIVE_CONFIG_KEYS,
    cfg,
    cfg_list,
    default_gateway_from_prefix,
    get_or_create_session_secret,
    ignored_ips,
    appliance_ip_from_host,
    apply_appliance_ip_urls,
    save_cfg,
)
from netspecter_anomaly import anomaly_detail, baseline_summary, list_anomalies, mark_expected
from netspecter_db import cache_delete_prefix, cache_get, cache_set, cache_value, cached_query as db_cached_query, connect_db, init_db, load_json, query, run_sql, save_json
from netspecter_incidents import incident_detail, list_incidents, severity_label, update_incident
from netspecter_ids import delete_alert, fast_log_alerts_from_text, ids_endpoint_ip, recent_structured_alerts, recent_structured_event_summaries, update_alert_status
from netspecter_internet_quality import latest_quality, recent_quality
import netspecter_live_snapshot as live_snapshot
from netspecter_public_ip import lookup_public_ip_info
from netspecter_threat_intel import feed_states, latest_reputation_for_event
from netspecter_monitoring import (
    CONNECTED_GATUS_SCHEMES,
    DNS_QUERY_TYPES,
    MONITOR_TYPE_INFO,
    TCP_CONNECT_SCHEMES,
    apply_gatus_monitor_config,
    build_monitor_url,
    check_http_service,
    check_monitor_service,
    check_telegram_config,
    disk_usage_rows,
    friendly_process_name,
    gatus_conditions_for_monitor,
    gatus_conditions_for_url,
    gatus_latest_states,
    internal_gatus_url,
    monitor_display_target,
    monitor_history_segments,
    monitor_icon_name,
    monitor_latest_states,
    monitor_key,
    monitor_scheme_label,
    monitor_state_percent,
    monitor_target_from_url,
    monitor_type_for_url,
    monitor_type_label,
    monitor_url_scheme,
    normalise_gatus_monitors,
    process_summary,
    record_monitor_event,
    render_gatus_config,
    send_telegram_message,
    service_url,
    systemd_active,
    write_gatus_config,
    yaml_quote,
)
from services.report_export_service import structured_report_text
from services.report_context_service import build_reporting_context_from_request
from services.report_pdf_service import reporting_pdf_response
from services.ai_attribution_service import ai_attribution_summary
from services.application_classification_service import categories as application_categories, valid_domain_pattern
from services.microsoft365_endpoints_service import microsoft365_endpoint_cache_status, refresh_microsoft365_endpoints
from netspecter_ui_helpers import (
    device_age_seconds,
    device_lifecycle_badges,
    env_minutes,
    fmt_bits_as_bytes,
    fmt_bps,
    fmt_bytes_per_sec,
    fmt_mb,
    h,
    parse_local_dt,
    public_ipv4,
    valid_ipv4_ip,
    valid_lan_ip,
)
from netspecter_netlic import NETLIC_PRIVACY, activate as netlic_activate, check_in as netlic_check_in

UPDATE_STATUS_CACHE = {"ts": 0, "data": None}
UNIFI_SESSION_TTL_SECONDS = 900
UNIFI_RATE_LIMIT_COOLDOWN_SECONDS = 60
unifi_session_cache = {}
LCD_LAST_SEEN = {}
LCD_TRAFFIC_HISTORY = {"download_mbps": [], "upload_mbps": []}
LCD_RATE_LIMIT_SECONDS = 2.0
NETLIC_CHECKIN_LOCK = threading.Lock()

app = Flask(__name__, static_folder=str(ROOT / "static"), static_url_path="/static")

NOISE_DOMAINS = [
    "msftconnecttest.com",
    "connectivitycheck.gstatic.com",
    "ping.ui.com",
    "cloudflare-dns.com",
    "dns.msftncsi.com",
    "detectportal.firefox.com",
]

APP_ICONS = {
    "YouTube": '<i class="fa-brands fa-youtube app-yt"></i>',
    "Netflix": '<i class="fa-solid fa-film app-netflix"></i>',
    "Microsoft": '<i class="fa-brands fa-microsoft app-ms"></i>',
    "Google": '<i class="fa-brands fa-google app-google"></i>',
    "WhatsApp": '<i class="fa-brands fa-whatsapp app-wa"></i>',
    "Facebook": '<i class="fa-brands fa-facebook app-fb"></i>',
    "Instagram": '<i class="fa-brands fa-instagram app-ig"></i>',
    "TikTok": '<i class="fa-brands fa-tiktok app-tiktok"></i>',
    "Twitter / X": '<i class="fa-brands fa-x-twitter app-other"></i>',
    "Snapchat": '<i class="fa-brands fa-snapchat app-other"></i>',
    "Discord": '<i class="fa-brands fa-discord app-other"></i>',
    "Twitch": '<i class="fa-brands fa-twitch app-other"></i>',
    "Disney+": '<i class="fa-solid fa-film app-other"></i>',
    "Prime Video": '<i class="fa-solid fa-circle-play app-other"></i>',
    "Gaming": '<i class="fa-solid fa-gamepad app-game"></i>',
    "Apple": '<i class="fa-brands fa-apple app-apple"></i>',
    "Cloud": '<i class="fa-solid fa-cloud app-cloud"></i>',
    "Security": '<i class="fa-solid fa-shield-halved app-sec"></i>',
    "Other": '<i class="fa-solid fa-globe app-other"></i>',
}
MONITORED_APP_CATEGORIES = {
    "YouTube",
    "Netflix",
    "TikTok",
    "Facebook",
    "Instagram",
    "WhatsApp",
    "Microsoft",
    "Spotify",
    "Steam",
    "Twitter / X",
    "Snapchat",
    "Discord",
    "Twitch",
    "Disney+",
    "Prime Video",
}

DEVICE_ICONS = {
    "PC": '<i class="fa-solid fa-desktop"></i>',
    "Phone": '<i class="fa-solid fa-mobile-screen"></i>',
    "TV": '<i class="fa-solid fa-tv"></i>',
    "Camera": '<i class="fa-solid fa-video"></i>',
    "Server": '<i class="fa-solid fa-server"></i>',
    "IoT": '<i class="fa-solid fa-microchip"></i>',
    "Gateway": '<i class="fa-solid fa-network-wired"></i>',
    "Printer": '<i class="fa-solid fa-print"></i>',
    "Unknown": '<i class="fa-solid fa-circle-question"></i>',
}


app.secret_key = get_or_create_session_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("NETSPECTER_SESSION_COOKIE_SECURE", "1").strip().lower() not in ("0", "false", "no", "off"),
)

LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 5 * 60
LOGIN_MAX_FAILURES = 5
LOGIN_FAILURES = {}
HEAVY_PAGE_CACHE_SECONDS = 60
ADGUARD_STATUS_CACHE_SECONDS = 30
UPDATE_STATUS_CACHE_SECONDS = 300


SESSION_IDLE_TIMEOUT_SECONDS = int(env_minutes("NETSPECTER_SESSION_IDLE_MINUTES", 30) * 60)


def today():
    return datetime.now().strftime("%Y-%m-%d")


def range_days():
    value = request.args.get("range", "1d")
    return {"1d": 1, "7d": 7, "30d": 30, "60d": 60, "90d": 90}.get(value, 1)


def range_key():
    days = range_days()
    return "90d" if days == 90 else "60d" if days == 60 else "30d" if days == 30 else "7d" if days == 7 else "1d"


def range_label():
    return {
        "1d": "Today",
        "7d": "Last 7 Days",
        "30d": "Last 30 Days",
        "60d": "Last 60 Days",
        "90d": "Last 90 Days",
    }.get(range_key(), "Today")


def range_start_day():
    seconds = (range_days() - 1) * 86400
    return datetime.fromtimestamp(time.time() - seconds).strftime("%Y-%m-%d")


def range_query_suffix(extra=""):
    suffix = f"?range={range_key()}"
    if extra:
        suffix += "&" + extra.lstrip("&")
    return suffix


def time_picker():
    options = [("1d", "Today"), ("7d", "7 Days"), ("30d", "30 Days"), ("60d", "60 Days"), ("90d", "90 Days")]
    current = range_key()
    links = ""
    path = h(request.path)
    for key, label in options:
        cls = "active" if key == current else ""
        links += f'<a class="{cls}" href="{path}?range={key}">{label}</a>'
    return f'<div class="time-picker">{links}</div>'


def auth_required():
    c = cfg()
    return bool(c.get("auth_enabled", True))


def admin_password_set():
    return bool(cfg().get("admin_password_hash"))


def product_version():
    return "2.0.0"


def netlic_metrics():
    metrics = {}
    try:
        rows = query("SELECT COUNT(*) AS total FROM devices WHERE ignored=0")
        metrics["active_devices"] = int(rows[0]["total"] or 0) if rows else 0
    except Exception:
        pass
    try:
        rows = query("SELECT COUNT(*) AS total FROM dns_querylog")
        metrics["dns_requests"] = int(rows[0]["total"] or 0) if rows else 0
    except Exception:
        pass
    return metrics


def maybe_start_netlic_checkin():
    c = cfg()
    if not c.get("netlic_enabled", True) or not c.get("netlic_setup_complete") or not c.get("netlic_licence_key"):
        return
    if int(c.get("netlic_next_check_after") or 0) > int(time.time()):
        return
    if not NETLIC_CHECKIN_LOCK.acquire(blocking=False):
        return

    def worker():
        try:
            current = cfg()
            ok, message, updates = netlic_check_in(current, product_version(), netlic_metrics())
            if ok and updates:
                current.update(updates)
                save_cfg(current)
            elif message:
                print(f"NetLic check-in skipped: {message}")
        except Exception as error:
            print(f"NetLic check-in failed: {error}")
        finally:
            NETLIC_CHECKIN_LOCK.release()

    threading.Thread(target=worker, daemon=True).start()


def login_client_key():
    forwarded = request.headers.get("X-Forwarded-For", "")
    ip = forwarded.split(",", 1)[0].strip() if forwarded else request.remote_addr
    return ip or "unknown"


def login_lockout_seconds(key):
    now = time.time()
    failures = [ts for ts in LOGIN_FAILURES.get(key, []) if now - ts < LOGIN_FAILURE_WINDOW_SECONDS]
    LOGIN_FAILURES[key] = failures
    if len(failures) < LOGIN_MAX_FAILURES:
        return 0
    return max(0, int(LOGIN_LOCKOUT_SECONDS - (now - failures[-1])))


def record_login_failure(key):
    now = time.time()
    failures = [ts for ts in LOGIN_FAILURES.get(key, []) if now - ts < LOGIN_FAILURE_WINDOW_SECONDS]
    failures.append(now)
    LOGIN_FAILURES[key] = failures


def clear_login_failures(key):
    LOGIN_FAILURES.pop(key, None)


def mark_session_active():
    if SESSION_IDLE_TIMEOUT_SECONDS > 0:
        session["_last_activity"] = int(time.time())


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def csrf_input():
    return f'<input type="hidden" name="_csrf_token" value="{h(csrf_token())}">'


def safe_local_redirect(target, fallback="/"):
    target = str(target or "").strip()[:500].replace("\\", "/").replace("\r", "").replace("\n", "")
    parsed = urlsplit(target)
    if target.startswith("/") and not target.startswith("//") and not parsed.scheme and not parsed.netloc:
        return target
    return fallback


def local_redirect(path):
    target = safe_local_redirect(path, "/")
    response = Response("", status=302)
    response.headers["Location"] = target
    return response


def device_page_url(ip, **params):
    if not valid_lan_ip(ip):
        return "/devices"
    query_parts = []
    for key, value in params.items():
        if value:
            query_parts.append(f"{quote(str(key), safe='')}={quote(str(value), safe='')}")
    suffix = "?" + "&".join(query_parts) if query_parts else ""
    return f"/device/{quote(ip, safe='')}{suffix}"


def devices_page_url(**params):
    query_parts = []
    for key, value in params.items():
        if value:
            query_parts.append(f"{quote(str(key), safe='')}={quote(str(value), safe='')}")
    suffix = "?" + "&".join(query_parts) if query_parts else ""
    return f"/devices{suffix}"


def configured_https_host():
    configured = str(cfg().get("appliance_ip") or "").strip()
    try:
        ipaddress.ip_address(configured)
        return configured
    except ValueError:
        return "127.0.0.1"


def valid_setup_email(value):
    email = str(value or "").strip()
    if len(email) > 254 or email.count("@") != 1:
        return False
    local, domain = email.rsplit("@", 1)
    if not local or not domain or "." not in domain:
        return False
    if any(ch.isspace() or ord(ch) < 32 for ch in email):
        return False
    return all(label for label in domain.split("."))


def operation_failed_message(action):
    return f"{action} could not complete. Check the NetSpecter service log for details."


def setup_missing_items(config=None):
    c = config or cfg()
    missing = []

    if not str(c.get("lan_prefix", "") or "").strip():
        missing.append("LAN Prefix")

    if not str(c.get("packet_iface", "") or "").strip():
        missing.append("Live Traffic Interface")

    if not str(c.get("gateway_ip", "") or "").strip() and not default_gateway_from_prefix(c.get("lan_prefix")):
        missing.append("Gateway IP")

    if not str(c.get("adguard_url", "") or "").strip():
        missing.append("AdGuard URL")

    if str(c.get("adguard_url", "")).strip() == DEFAULT_CONFIG["adguard_url"]:
        missing.append("Confirm AdGuard URL")

    return missing


def setup_banner():
    missing = setup_missing_items()
    if not missing and request.args.get("setup"):
        return '<div class="setup-ok">Setup looks complete. You can continue to the dashboard.</div>'
    if not missing:
        return ""
    items = "".join(f"<li>{h(item)}</li>" for item in missing)
    return f"""
<div class="setup-warning">
  <h2>Finish NetSpecter Setup</h2>
  <p>These deployment settings still need attention before the dashboard opens normally:</p>
  <ul>{items}</ul>
  <p>Save this page after updating them.</p>
</div>
"""


def login_template(title, body):
    return f"""<!DOCTYPE html>
<html>
<head>
<title>{h(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/static/favicon.png">
<link rel="stylesheet" href="/static/ui-tokens.css?v=20260711a">
<link rel="stylesheet" href="/static/ui-icons.css?v=20260711c">
<link rel="stylesheet" href="/static/ui-components.css?v=20260711a">
<link rel="stylesheet" href="/static/theme.css?v=20260718a">
</head>
<body class="login-body">
  <div class="login-card">
    <img src="/static/brand/logo-login.png?v=20260711-ui5" class="login-logo">
    {body}
  </div>
</body>
</html>"""


def cached_query(key, max_age, sql, params=()):
    return db_cached_query(key, max_age, sql, params)


@app.before_request
def start_request_timer():
    g.request_started_at = time.perf_counter()
    return None


def request_host_without_port():
    host = str(request.host or "").strip()
    if host.startswith("[") and "]" in host:
        return host[1:].split("]", 1)[0]
    return host.split(":", 1)[0]


def local_request_host():
    host = request_host_without_port().lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def request_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        parts = [part.strip() for part in forwarded.split(",") if part.strip()]
        if parts:
            return parts[-1]
    return str(request.remote_addr or "").strip()


def request_from_lan(config=None):
    ip_text = request_client_ip()
    if ip_text in {"127.0.0.1", "::1"}:
        return True
    c = config or cfg()
    prefix = str(c.get("lan_prefix", "") or "").strip()
    candidates = []
    if prefix.endswith("."):
        candidates.append(f"{prefix}0/24")
    elif prefix:
        candidates.append(prefix if "/" in prefix else f"{prefix}/24")
    appliance = str(c.get("appliance_ip", "") or "").strip()
    if appliance:
        try:
            candidates.append(str(ipaddress.ip_network(f"{appliance}/24", strict=False)))
        except Exception:
            pass
    try:
        ip = ipaddress.ip_address(ip_text)
    except Exception:
        return False
    for candidate in candidates:
        try:
            if ip in ipaddress.ip_network(candidate, strict=False):
                return True
        except Exception:
            continue
    return False


@app.before_request
def redirect_plain_http_to_https():
    if request.headers.get("X-Forwarded-Proto", "").lower() == "https":
        return None
    if request.scheme == "https" or local_request_host():
        return None
    if (request.path.startswith("/api/health/") or request.path == "/api/monitor-alert") and request.remote_addr in ("127.0.0.1", "::1"):
        return None
    c = cfg()
    https_port = int(c.get("https_proxy_port") or DEFAULT_CONFIG["https_proxy_port"])
    return redirect(f"https://{configured_https_host()}:{https_port}/", code=308)


def record_request_timing(response):
    started = getattr(g, "request_started_at", None)
    if started is None:
        return response
    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    response.headers["X-NetSpecter-Render-Ms"] = str(elapsed_ms)
    if elapsed_ms < 750:
        return response
    try:
        REQUEST_TIMING_PATH.parent.mkdir(parents=True, exist_ok=True)
        with REQUEST_TIMING_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ms": elapsed_ms,
                "method": request.method,
                "path": request.full_path.rstrip("?"),
                "endpoint": request.endpoint or "",
                "status": response.status_code,
            }) + "\n")
    except Exception as error:
        print(f"Request timing log failed: {error}")
    return response


def recent_request_timings(limit=20):
    if not REQUEST_TIMING_PATH.exists():
        return []
    try:
        lines = REQUEST_TIMING_PATH.read_text(errors="replace").splitlines()[-limit:]
        rows = []
        for line in reversed(lines):
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
        return rows
    except Exception:
        return []


@app.before_request
def require_csrf_token():
    if request.path == "/api/monitor-alert" and request.remote_addr in ("127.0.0.1", "::1"):
        return None
    if request.method == "POST":
        expected = session.get("_csrf_token", "")
        submitted = request.form.get("_csrf_token", "")
        if not expected or not secrets.compare_digest(str(expected), str(submitted)):
            return Response("Invalid CSRF token.", status=400, mimetype="text/plain")
    return None


@app.before_request
def require_login():
    if request.endpoint not in ["static", "login", "logout", "setup_admin"]:
        maybe_start_netlic_checkin()
    if request.endpoint in ["static", "login", "logout", "setup_admin"]:
        return None
    if request.path == "/api/lcd/summary":
        return None
    if (request.path.startswith("/api/health/") or request.path == "/api/monitor-alert") and request.remote_addr in ("127.0.0.1", "::1"):
        return None

    if not auth_required():
        return None

    if not admin_password_set():
        if request.path.startswith("/api/"):
            return jsonify({"error": "setup_required"}), 409
        return redirect("/setup-admin")

    if session.get("authenticated"):
        if SESSION_IDLE_TIMEOUT_SECONDS > 0:
            last_activity = int(session.get("_last_activity") or 0)
            now = int(time.time())
            if last_activity and now - last_activity > SESSION_IDLE_TIMEOUT_SECONDS:
                session.clear()
                if request.path.startswith("/api/"):
                    return jsonify({"error": "session_expired"}), 401
                return redirect("/login?next=" + quote(request.full_path.rstrip("?") or "/"))
            mark_session_active()
        if request.endpoint not in ["settings", "logout"] and setup_missing_items():
            if request.path.startswith("/api/"):
                return jsonify({"error": "setup_required"}), 409
            return redirect("/settings?setup=1")
        return None

    if request.path.startswith("/api/"):
        return jsonify({"error": "login_required"}), 401

    return redirect("/login")


@app.after_request
def set_security_headers(response):
    response = record_request_timing(response)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com; "
        "font-src 'self' data: https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https://*.basemaps.cartocdn.com; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'",
    )
    return response


@app.route("/setup-admin", methods=["GET", "POST"])
def setup_admin():
    if admin_password_set():
        return redirect("/login")

    error = ""
    form = {
        "company_name": request.form.get("company_name", ""),
        "administrator_name": request.form.get("administrator_name", ""),
        "administrator_email": request.form.get("administrator_email", ""),
        "appliance_name": request.form.get("appliance_name", "NetSpecter"),
        "licence_key": request.form.get("licence_key", "FREE"),
        "username": request.form.get("username", "admin"),
    }
    if request.method == "POST":
        company_name = request.form.get("company_name", "").strip()
        administrator_name = request.form.get("administrator_name", "").strip()
        administrator_email = request.form.get("administrator_email", "").strip()
        appliance_name = request.form.get("appliance_name", "").strip()
        licence_key = request.form.get("licence_key", "").strip() or cfg().get("netlic_free_registration_key", "FREE")
        username = request.form.get("username", "admin").strip() or "admin"
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not company_name:
            error = "Enter your company name."
        elif not administrator_name:
            error = "Enter the administrator full name."
        elif not valid_setup_email(administrator_email):
            error = "Enter a valid administrator email address."
        elif not appliance_name:
            error = "Enter an appliance name."
        elif len(password) < 12 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"\d", password):
            error = "Use a stronger password with at least 12 characters, upper and lower case letters, and a number."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            c = cfg()
            ok, activation_error, updates = netlic_activate(
                c,
                company_name,
                administrator_name,
                administrator_email,
                appliance_name,
                licence_key,
                product_version(),
            )
            if not ok:
                error = activation_error or "NetLic activation failed. Check internet access and try again."
            else:
                c.update(updates or {})
                c["admin_user"] = username
                c["admin_password_hash"] = generate_password_hash(password)
                c["auth_enabled"] = True
                save_cfg(c)
                session["authenticated"] = True
                session["admin_user"] = username
                mark_session_active()
                return redirect("/")

    body = f"""
<h1>Register your NetSpecter appliance</h1>
<p>Complete first-time setup before opening the dashboard.</p>
{f'<div class="login-error">{h(error)}</div>' if error else ''}
<form method="post">
  {csrf_input()}
  <label>Customer / Company Name</label>
  <input name="company_name" value="{h(form['company_name'])}" required>
  <label>Administrator Full Name</label>
  <input name="administrator_name" value="{h(form['administrator_name'])}" required>
  <label>Administrator Email Address</label>
  <input name="administrator_email" type="email" value="{h(form['administrator_email'])}" required>
  <label>Appliance / Display Name</label>
  <input name="appliance_name" value="{h(form['appliance_name'])}" required>
  <label>Licence Key</label>
  <input name="licence_key" value="{h(form['licence_key'])}" placeholder="FREE">
  <label>Username</label>
  <input name="username" value="{h(form['username'])}">
  <label>Local NetSpecter Administrator Password</label>
  <input name="password" type="password" autofocus>
  <label>Confirm Local Password</label>
  <input name="confirm" type="password">
  <p class="sub">{h(NETLIC_PRIVACY)}</p>
  <button type="submit">Register and Create Login</button>
</form>
"""
    return login_template("Register NetSpecter", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not admin_password_set():
        return redirect("/setup-admin")

    error = ""
    if request.method == "POST":
        key = login_client_key()
        wait_seconds = login_lockout_seconds(key)
        if wait_seconds > 0:
            error = f"Too many failed login attempts. Try again in {max(1, math.ceil(wait_seconds / 60))} minute(s)."
        else:
            c = cfg()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if username == c.get("admin_user", "admin") and check_password_hash(c.get("admin_password_hash", ""), password):
                clear_login_failures(key)
                session["authenticated"] = True
                session["admin_user"] = username
                mark_session_active()
                return redirect("/")
            record_login_failure(key)
            error = "Invalid username or password."

    body = f"""
<h1>Sign In</h1>
<p>Enter your NetSpecter admin credentials.</p>
{f'<div class="login-error">{h(error)}</div>' if error else ''}
<form method="post">
  {csrf_input()}
  <label>Username</label>
  <input name="username" value="{h(cfg().get('admin_user', 'admin'))}">
  <label>Password</label>
  <input name="password" type="password" autofocus>
  <button type="submit">Sign In</button>
</form>
"""
    return login_template("NetSpecter Login", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


def ensure_device_overrides_table():
    if not DB_PATH.exists():
        return

    con = connect_db()
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS device_overrides (
            ip TEXT PRIMARY KEY,
            name TEXT,
            vendor TEXT,
            device_type TEXT,
            status TEXT,
            ignored INTEGER DEFAULT 0,
            updated_at TEXT
        )
        """
    )
    try:
        con.execute("ALTER TABLE device_overrides ADD COLUMN ignored INTEGER DEFAULT 0")
    except sqlite3.OperationalError as error:
        if "duplicate column name" not in str(error).lower():
            raise
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS device_override_unlocks (
            ip TEXT PRIMARY KEY,
            updated_at TEXT
        )
        """
    )
    con.commit()
    con.close()


def has_real_vendor(vendor):
    text = str(vendor or "").strip().lower()
    return bool(text and text not in ["unknown", "unknown vendor", "private / random mac", "n/a", "none", "-"])


def private_mac_address(mac):
    """Detect locally administered addresses used by Private Wi-Fi/Randomized MAC."""
    text = str(mac or "").strip().replace(":", "").replace("-", "")
    try:
        return len(text) >= 2 and bool(int(text[:2], 16) & 0x02)
    except ValueError:
        return False


def auto_lock_known_vendors():
    """Lock collector-discovered vendors so later collector passes do not erase good metadata."""
    ensure_device_overrides_table()
    rows = query(
        """
        SELECT d.ip, d.name, d.vendor, d.device_type, d.status
        FROM devices d
        LEFT JOIN device_overrides o ON o.ip=d.ip
        LEFT JOIN device_override_unlocks u ON u.ip=d.ip
        WHERE o.ip IS NULL AND u.ip IS NULL
        """
    )
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for r in rows:
        vendor = r["vendor"] or ""
        if not has_real_vendor(vendor):
            continue
        name = r["name"] or r["ip"]
        dtype = r["device_type"] or classify_device("", vendor, "")
        status = r["status"] or "Active"
        run_sql(
            """
            INSERT OR IGNORE INTO device_overrides
                (ip, name, vendor, device_type, status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (r["ip"], name, vendor, dtype, status, now),
        )


def public_ip(refresh=True):
    c = cfg()
    cached = cache_get("public_ip", int(c.get("public_ip_cache_seconds", 1800)))

    if cached:
        return cached

    stale = cache_value("public_ip")
    if not refresh:
        return stale or "Unknown"

    try:
        info = lookup_public_ip_info(timeout=5)
        ip = str(info.get("public_ip") or "").strip()
        if ip:
            cache_set("public_ip", ip)
            cache_set("public_ip_info", info)
            return ip
    except Exception:
        pass

    return stale or "Unknown"




def live_sample_max_age():
    """Keep a collector sample live until the next configured write can arrive."""
    try:
        interval = max(1, int(cfg().get("collect_interval_seconds", 2) or 2))
    except Exception:
        interval = 2
    return max(20, interval * 2 + 5)


def live_packet_speed(ip):
    """Read live per-device speed from the lightweight packet collector.

    live_device_speed stores bytes/sec. The existing UI formatter expects bits/sec
    and converts to KB/s/MB/s, so we multiply by 8 here to keep all existing
    dashboard/device/traffic displays working safely.
    """
    key = str(ip or "").strip()
    if not key:
        return {}

    row = live_snapshot.speeds().get(key)
    if row:
        return {
            "rx_bps": float(row.get("rx_bps") or 0) * 8,
            "tx_bps": float(row.get("tx_bps") or 0) * 8,
            "total_bps": float(row.get("total_bps") or 0) * 8,
            "source": "memory",
        }

    try:
        con = connect_db()
        con.row_factory = sqlite3.Row
        row = con.execute(
            """
            SELECT rx_bps, tx_bps, total_bps, updated_at
            FROM live_device_speed
            WHERE ip=?
            """,
            (key,),
        ).fetchone()
        con.close()
    except Exception:
        return {}

    if not row:
        return {}

    # Ignore samples only after enough time for the configured next flush.
    try:
        updated = datetime.strptime(str(row["updated_at"])[:19], "%Y-%m-%d %H:%M:%S")
        if (datetime.now() - updated).total_seconds() > live_sample_max_age():
            return {}
    except Exception:
        pass

    return {
        "rx_bps": float(row["rx_bps"] or 0) * 8,
        "tx_bps": float(row["tx_bps"] or 0) * 8,
        "total_bps": float(row["total_bps"] or 0) * 8,
        "source": "packet",
    }


def live_host_speed(ip_or_name):
    """Live speed comes ONLY from the NetSpecter packet collector.

    Source table: live_device_speed
    Stored values are bytes/sec; live_packet_speed converts to bits/sec
    so the existing formatter can display KB/s, MB/s and GB/s correctly.
    No external traffic-analyser fallback is used for speed values.
    """
    key = str(ip_or_name or "").strip()
    packet = live_packet_speed(key)
    if packet:
        return packet

    return {"rx_bps": 0.0, "tx_bps": 0.0, "total_bps": 0.0, "source": "collector"}


def live_all_host_speeds():
    """Read live speed for all devices in one query for table rendering."""
    snapshot = live_snapshot.speeds()
    if snapshot:
        return {
            str(ip): {
                "rx_bps": float(row.get("rx_bps") or 0) * 8,
                "tx_bps": float(row.get("tx_bps") or 0) * 8,
                "total_bps": float(row.get("total_bps") or 0) * 8,
                "source": "memory",
            }
            for ip, row in snapshot.items()
        }

    freshness = f"-{live_sample_max_age()} seconds"
    rows = query(
        """
        SELECT ip, rx_bps, tx_bps, total_bps
        FROM live_device_speed
        WHERE updated_at >= datetime('now', 'localtime', ?)
        """,
        (freshness,),
    )
    return {
        str(row["ip"]): {
            "rx_bps": float(row["rx_bps"] or 0) * 8,
            "tx_bps": float(row["tx_bps"] or 0) * 8,
            "total_bps": float(row["total_bps"] or 0) * 8,
            "source": "packet",
        }
        for row in rows
    }


def live_network_speed():
    """Sum current live throughput from the packet collector table only."""
    snapshot_rows = live_snapshot.speeds()
    if snapshot_rows:
        rx = sum(float(row.get("rx_bps") or 0) for row in snapshot_rows.values())
        tx = sum(float(row.get("tx_bps") or 0) for row in snapshot_rows.values())
        return {
            "rx_bps": rx * 8,
            "tx_bps": tx * 8,
            "total_bps": (rx + tx) * 8,
            "source": "memory",
        }

    try:
        freshness = f"-{live_sample_max_age()} seconds"
        rows = query(
            """
            SELECT
                SUM(rx_bps) AS rx,
                SUM(tx_bps) AS tx,
                SUM(total_bps) AS total
            FROM live_device_speed
            WHERE updated_at >= datetime('now', 'localtime', ?)
            """,
            (freshness,),
        )
    except Exception:
        rows = []

    if not rows:
        return {"rx_bps": 0.0, "tx_bps": 0.0, "total_bps": 0.0, "source": "collector"}

    r = rows[0]
    # Table stores bytes/sec; convert to bits/sec for the display formatter.
    return {
        "rx_bps": float(r["rx"] or 0) * 8,
        "tx_bps": float(r["tx"] or 0) * 8,
        "total_bps": float(r["total"] or 0) * 8,
        "source": "collector",
    }


def collector_service_action(action):
    try:
        result = subprocess.run(
            ["systemctl", action, "netspecter-collector"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Collector {action} failed: {e}")
        return False


def restart_collector_service():
    return collector_service_action("restart")


@app.route("/collector/restart", methods=["POST"])
def restart_collector():
    ok = restart_collector_service()
    return_to = safe_local_redirect(request.form.get("return_to"), "/system")
    separator = "&" if "?" in return_to else "?"
    status = "restarted" if ok else "restart_failed"
    return local_redirect(f"{return_to}{separator}collector={status}")


def source_checkout_root():
    candidates = [
        os.environ.get("NETSPECTER_SOURCE_ROOT"),
        str(Path.home() / "netspecter-v2"),
        str(Path.home() / "netspecter"),
        str(BASE_DIR),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if (path / ".git").exists():
            return path
    return None


def git_command(source_root, *args, timeout=20):
    result = subprocess.run(
        ["git", "-C", str(source_root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    return result.returncode, (result.stdout or "").strip(), (result.stderr or "").strip()


def git_upstream_ref(source_root):
    rc, upstream, _err = git_command(source_root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if rc == 0 and upstream:
        return upstream
    for fallback in ("origin/main", "v2/main"):
        rc, _sha, _err = git_command(source_root, "rev-parse", "--verify", fallback)
        if rc == 0:
            return fallback
    return ""


def update_status(force=False, fetch_remote=False):
    now = time.time()
    cached = UPDATE_STATUS_CACHE.get("data")
    if cached and not force and now - float(UPDATE_STATUS_CACHE.get("ts", 0) or 0) < UPDATE_STATUS_CACHE_SECONDS:
        return cached

    source = source_checkout_root()
    if not source:
        data = {"ok": False, "available": False, "detail": "Source checkout not found."}
        UPDATE_STATUS_CACHE.update({"ts": now, "data": data})
        return data

    upstream = git_upstream_ref(source)
    if not upstream:
        data = {"ok": False, "available": False, "detail": "Git upstream not configured."}
        UPDATE_STATUS_CACHE.update({"ts": now, "data": data})
        return data

    remote_name = upstream.split("/", 1)[0] if "/" in upstream else "origin"
    if fetch_remote:
        git_command(source, "fetch", "--quiet", remote_name, timeout=10)
    _rc, current, _err = git_command(source, "rev-parse", "--short", "HEAD")
    rc, latest, err = git_command(source, "rev-parse", "--short", upstream)
    if rc != 0:
        data = {"ok": False, "available": False, "detail": err or f"Could not read {upstream}."}
        UPDATE_STATUS_CACHE.update({"ts": now, "data": data})
        return data

    rc, behind, _err = git_command(source, "rev-list", "--count", f"HEAD..{upstream}")
    available = rc == 0 and str(behind or "0").isdigit() and int(behind) > 0
    data = {
        "ok": True,
        "available": available,
        "current": current,
        "latest": latest,
        "behind": int(behind or 0) if str(behind or "0").isdigit() else 0,
        "source": str(source),
        "upstream": upstream,
    }
    UPDATE_STATUS_CACHE.update({"ts": now, "data": data})
    return data


def start_background_update():
    source = source_checkout_root()
    if not source:
        return False, "Source checkout not found."

    UPDATE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    state_path = shlex.quote(str(UPDATE_STATE_PATH))
    script = (
        f"cd {shlex.quote(str(source))} && "
        "printf '\\n=== NetSpecter update started %s ===\\n' \"$(date)\" && "
        f"printf 'running %s\\n' \"$(date +%s)\" > {state_path} && "
        "if git pull --ff-only && bash ./install.sh; then "
        "printf 'Restarting NetSpecter services in readiness order...\\n'; "
        "systemctl restart netspecter-collector || true; "
        "systemctl restart netspecter-web || true; "
        "sleep 8; "
        "systemctl restart netspecter-https || true; "
        "sleep 2; "
        "printf '=== NetSpecter update finished %s ===\\n' \"$(date)\"; "
        f"printf 'finished %s\\n' \"$(date +%s)\" > {state_path}; "
        "else rc=$?; "
        "printf '=== NetSpecter update failed %s ===\\n' \"$(date)\"; "
        f"printf 'failed %s\\n' \"$(date +%s)\" > {state_path}; "
        "exit $rc; "
        "fi"
    )
    log_file = open(UPDATE_LOG_PATH, "ab")
    try:
        subprocess.Popen(
            ["bash", "-lc", script],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        log_file.close()
        UPDATE_STATUS_CACHE.update({"ts": 0, "data": None})
        return True, "Update started."
    except Exception as error:
        log_file.close()
        print(f"Update start failed: {error}")
        return False, operation_failed_message("Update")


def update_run_state():
    if not UPDATE_STATE_PATH.exists():
        return None, None
    try:
        parts = UPDATE_STATE_PATH.read_text(errors="replace").strip().split()
        state = parts[0] if parts else ""
        marker_ts = float(parts[1]) if len(parts) > 1 else UPDATE_STATE_PATH.stat().st_mtime
        age = time.time() - marker_ts
        return state, age
    except Exception:
        return None, None


def vault_backup_run_state():
    if not VAULT_BACKUP_STATE_PATH.exists():
        return None, None
    try:
        parts = VAULT_BACKUP_STATE_PATH.read_text(errors="replace").strip().split()
        state = parts[0] if parts else ""
        marker_ts = float(parts[1]) if len(parts) > 1 else VAULT_BACKUP_STATE_PATH.stat().st_mtime
        age = time.time() - marker_ts
        return state, age
    except Exception:
        return None, None


def start_background_vault_backup():
    state, age = vault_backup_run_state()
    if state == "running" and age is not None and age < 3600:
        return False, "Vault backup is already running."

    VAULT_BACKUP_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    state_path = shlex.quote(str(VAULT_BACKUP_STATE_PATH))
    config = load_vault_config()
    min_free_mb = shlex.quote(str(config.get("min_free_mb", 2048)))
    max_archive_mb = shlex.quote(str(config.get("max_archive_mb", 2048)))
    script = (
        "printf '\\n=== NetSpecter Vault backup started %s ===\\n' \"$(date)\" && "
        f"printf 'running %s\\n' \"$(date +%s)\" > {state_path} && "
        f"if /usr/local/bin/netspecter-vault backup --allow-unencrypted --min-free-mb {min_free_mb} --max-archive-mb {max_archive_mb}; then "
        "printf '=== NetSpecter Vault backup finished %s ===\\n' \"$(date)\"; "
        f"printf 'finished %s\\n' \"$(date +%s)\" > {state_path}; "
        "else rc=$?; "
        "printf '=== NetSpecter Vault backup failed %s ===\\n' \"$(date)\"; "
        f"printf 'failed %s\\n' \"$(date +%s)\" > {state_path}; "
        "exit $rc; "
        "fi"
    )
    log_file = open(VAULT_BACKUP_LOG_PATH, "ab")
    try:
        subprocess.Popen(
            ["bash", "-lc", script],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        log_file.close()
        return True, "Vault backup started. Refresh Vault History in a moment to see the result."
    except Exception as error:
        log_file.close()
        print(f"Vault backup start failed: {error}")
        return False, operation_failed_message("Vault backup")


def vault_restore_run_state():
    if not VAULT_RESTORE_STATE_PATH.exists():
        return None, None
    try:
        parts = VAULT_RESTORE_STATE_PATH.read_text(errors="replace").strip().split()
        state = parts[0] if parts else ""
        marker_ts = float(parts[1]) if len(parts) > 1 else VAULT_RESTORE_STATE_PATH.stat().st_mtime
        age = time.time() - marker_ts
        return state, age
    except Exception:
        return None, None


def start_background_restore_config(archive_path, confirmation):
    if str(confirmation or "").strip() != "RESTORE CONFIG":
        return False, "Confirmation must be RESTORE CONFIG."
    state, age = vault_restore_run_state()
    if state == "running" and age is not None and age < 1800:
        return False, "Vault restore is already running."

    VAULT_RESTORE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    state_path = shlex.quote(str(VAULT_RESTORE_STATE_PATH))
    script = (
        "printf '\\n=== NetSpecter Vault config restore started %s ===\\n' \"$(date)\" && "
        f"printf 'running %s\\n' \"$(date +%s)\" > {state_path} && "
        f"if /usr/local/bin/netspecter-vault restore-config {shlex.quote(str(archive_path))} --confirm {shlex.quote('RESTORE CONFIG')}; then "
        "printf '=== NetSpecter Vault config restore finished %s ===\\n' \"$(date)\"; "
        f"printf 'finished %s\\n' \"$(date +%s)\" > {state_path}; "
        "else rc=$?; "
        "printf '=== NetSpecter Vault config restore failed %s ===\\n' \"$(date)\"; "
        f"printf 'failed %s\\n' \"$(date +%s)\" > {state_path}; "
        "exit $rc; "
        "fi"
    )
    log_file = open(VAULT_RESTORE_LOG_PATH, "ab")
    try:
        subprocess.Popen(
            ["bash", "-lc", script],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        log_file.close()
        return True, "Config restore started. NetSpecter services may restart briefly."
    except Exception as error:
        log_file.close()
        print(f"Vault config restore start failed: {error}")
        return False, operation_failed_message("Config restore")


def start_background_restore_full(archive_path, confirmation):
    if str(confirmation or "").strip() != "RESTORE FULL":
        return False, "Confirmation must be RESTORE FULL."
    state, age = vault_restore_run_state()
    if state == "running" and age is not None and age < 1800:
        return False, "Vault restore is already running."

    VAULT_RESTORE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    state_path = shlex.quote(str(VAULT_RESTORE_STATE_PATH))
    inner_script = (
        "printf '\\n=== NetSpecter Vault full restore started %s ===\\n' \"$(date)\" && "
        f"printf 'running %s\\n' \"$(date +%s)\" > {state_path} && "
        f"if /usr/local/bin/netspecter-vault restore-full {shlex.quote(str(archive_path))} --confirm {shlex.quote('RESTORE FULL')}; then "
        "printf '=== NetSpecter Vault full restore finished %s ===\\n' \"$(date)\"; "
        f"printf 'finished %s\\n' \"$(date +%s)\" > {state_path}; "
        "else rc=$?; "
        "printf '=== NetSpecter Vault full restore failed %s ===\\n' \"$(date)\"; "
        f"printf 'failed %s\\n' \"$(date +%s)\" > {state_path}; "
        "exit $rc; "
        "fi"
    )
    systemd_script = f"{inner_script} >> {shlex.quote(str(VAULT_RESTORE_LOG_PATH))} 2>&1"
    script = (
        f"if command -v systemd-run >/dev/null 2>&1; then "
        f"systemd-run --unit=netspecter-vault-restore --collect --quiet bash -lc {shlex.quote(systemd_script)}; "
        f"else bash -lc {shlex.quote(inner_script)}; "
        "fi"
    )
    log_file = open(VAULT_RESTORE_LOG_PATH, "ab")
    try:
        subprocess.Popen(
            ["bash", "-lc", script],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        log_file.close()
        return True, "Full restore started. NetSpecter web and collector will restart."
    except Exception as error:
        log_file.close()
        print(f"Vault full restore start failed: {error}")
        return False, operation_failed_message("Full restore")


def latest_hosts(limit=100):
    ensure_device_overrides_table()
    ignore = ignored_ips()
    ignore_clause = ""
    params = [today()]
    if ignore:
        placeholders = ",".join(["?"] * len(ignore))
        ignore_clause = f"AND t.ip NOT IN ({placeholders})"
        params.extend(ignore)
    params.append(limit)

    return cached_query(
        f"latest_hosts:{today()}:{limit}:{','.join(ignore)}",
        10,
        f"""
        WITH usage AS (
            SELECT
                ip,
                MAX(id) AS max_id,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb
            FROM traffic_intervals
            WHERE day = ?
            GROUP BY ip
        )
        SELECT
            COALESCE(o.name, d.name, t.name, t.ip) AS name,
            COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS vendor,
            COALESCE(o.device_type, d.device_type, 'Unknown') AS device_type,
            COALESCE(o.status, d.status, 'Active') AS status,
            d.first_seen,
            d.last_seen,
            d.owner,
            d.location,
            CASE WHEN o.ip IS NOT NULL THEN 1 ELSE 0 END AS manual_locked,
            t.id,
            t.ip,
            t.mac,
            u.downloaded_mb,
            u.uploaded_mb,
            u.total_mb,
            t.live_bps,
            t.day,
            t.ts
        FROM usage u
        JOIN traffic_intervals t
            ON t.id = u.max_id
        LEFT JOIN devices d
            ON d.ip = t.ip
        LEFT JOIN device_overrides o
            ON o.ip = t.ip
        WHERE 1=1 {ignore_clause}
        ORDER BY u.total_mb DESC
        LIMIT ?
        """,
        tuple(params),
    )


def classify_device(name="", vendor="", mac=""):
    text = f"{name or ''} {vendor or ''} {mac or ''}".lower()

    if any(x in text for x in ["ubiquiti", "unifi"]):
        return "Network Device"

    if any(x in text for x in ["hp", "epson", "canon", "brother", "printer"]):
        return "Printer"

    if any(x in text for x in ["hikvision", "dahua", "ezviz", "camera"]):
        return "Camera"

    if any(x in text for x in ["iphone", "ipad", "apple"]):
        return "Apple Device"

    if any(x in text for x in ["samsung", "galaxy", "xiaomi", "huawei", "oppo"]):
        return "Mobile Device"

    if any(x in text for x in ["intel", "asustek", "gigabyte", "dell", "lenovo", "hp inc"]):
        return "Computer"

    if any(x in text for x in ["debian", "ubuntu", "proxmox", "server"]):
        return "Server"

    if any(x in text for x in ["google", "chromecast", "roku", "tv", "media"]):
        return "Media Device"

    return "Unknown"


def totals():
    start_day = range_start_day()
    ignore = ignored_ips()
    ignore_clause = ""
    params = [start_day]
    if ignore:
        placeholders = ",".join(["?"] * len(ignore))
        ignore_clause = f"AND t.ip NOT IN ({placeholders})"
        params.extend(ignore)
    rows = cached_query(
        f"totals_usage:{start_day}:{','.join(ignore)}",
        10,
        f"""
        WITH usage AS (
            SELECT
                ip,
                MAX(name) AS name,
                MAX(mac) AS mac,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb
            FROM traffic_intervals
            WHERE day >= ?
            GROUP BY ip
        )
        SELECT
            COALESCE(o.name, d.name, u.name, u.ip) AS name,
            u.ip,
            u.mac,
            u.downloaded_mb,
            u.uploaded_mb,
            u.total_mb
        FROM usage u
        LEFT JOIN devices d ON d.ip=u.ip
        LEFT JOIN device_overrides o ON o.ip=u.ip
        WHERE 1=1 {ignore_clause.replace("t.ip", "u.ip")}
        ORDER BY u.total_mb DESC
        LIMIT 500
        """,
        tuple(params),
    )

    down = round(sum(float(r["downloaded_mb"] or 0) for r in rows), 2)
    up = round(sum(float(r["uploaded_mb"] or 0) for r in rows), 2)
    total = round(sum(float(r["total_mb"] or 0) for r in rows), 2)

    blocked = cached_query(
        f"totals_blocked:{start_day}",
        10,
        """
        SELECT COUNT(*) AS total
        FROM dns_querylog
        WHERE day>=? AND blocked=1
        """,
        (start_day,),
    )

    blocked_total = int(blocked[0]["total"] or 0) if blocked else 0

    topcat = cached_query(
        f"totals_topcat:{start_day}",
        10,
        """
        SELECT category, COUNT(*) AS q
        FROM dns_querylog
        WHERE day>=?
        GROUP BY category
        ORDER BY q DESC
        LIMIT 1
        """,
        (start_day,),
    )

    top_category = topcat[0]["category"] if topcat else "None"

    return down, up, total, len(rows), blocked_total, top_category

def system_health():
    db_size = round(DB_PATH.stat().st_size / 1024 / 1024, 2) if DB_PATH.exists() else 0

    if psutil:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage("/")
        disk = disk_usage.percent
        disk_free_gb = round(disk_usage.free / 1024 / 1024 / 1024, 1)
        uptime_seconds = int(time.time() - psutil.boot_time())
    else:
        cpu = mem = disk = 0
        disk_free_gb = 0
        uptime_seconds = 0

    uptime = f"{uptime_seconds // 86400}d {(uptime_seconds % 86400) // 3600}h"

    heartbeat = live_snapshot.heartbeat()
    last_seen = heartbeat.get("updated_at") or "No data"

    if last_seen == "No data":
        last = query("SELECT updated_at AS ts FROM collector_heartbeat WHERE id=1")
        last_seen = last[0]["ts"] if last and last[0]["ts"] else "No data"

    if last_seen == "No data":
        speed_rows = live_snapshot.speeds()
        if speed_rows:
            last_seen = max((row.get("updated_at") or "") for row in speed_rows.values()) or "No data"

    if last_seen == "No data":
        last = query("SELECT MAX(updated_at) AS ts FROM live_device_speed")
        last_seen = last[0]["ts"] if last and last[0]["ts"] else "No data"

    update_state, update_age = update_run_state()
    collector_state = "Unknown"
    if last_seen != "No data":
        try:
            dt = datetime.strptime(last_seen[:19], "%Y-%m-%d %H:%M:%S")
            age = (datetime.now() - dt).total_seconds()
            collector_state = "OK" if age < 120 else "Stale"
        except Exception:
            collector_state = "Unknown"

    if update_state == "running" and update_age is not None and update_age < 900 and collector_state != "OK":
        collector_state = "Updating"
    elif update_state == "finished" and update_age is not None and update_age < 180 and collector_state != "OK":
        collector_state = "Starting"
    if disk >= 99 and collector_state != "OK":
        collector_state = "Disk Full"

    return {
        "cpu": cpu,
        "mem": mem,
        "disk": disk,
        "disk_free_gb": disk_free_gb,
        "db_size": db_size,
        "uptime": uptime,
        "last_seen": last_seen,
        "collector_state": collector_state,
    }


def system_health_snapshot(force=False, max_age=30):
    key = "system_health_snapshot"
    if not force:
        cached = cache_get(key, max_age)
        if cached is not None:
            return cached
    health = system_health()
    cache_set(key, health)
    return health


def system_health_live_only():
    if psutil:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage("/")
        disk = disk_usage.percent
        disk_free_gb = round(disk_usage.free / 1024 / 1024 / 1024, 1)
        uptime_seconds = int(time.time() - psutil.boot_time())
    else:
        cpu = mem = disk = 0
        disk_free_gb = 0
        uptime_seconds = 0

    heartbeat = live_snapshot.heartbeat()
    last_seen = heartbeat.get("updated_at") or "No data"
    collector_state = "Unknown"
    if last_seen != "No data":
        try:
            dt = datetime.strptime(last_seen[:19], "%Y-%m-%d %H:%M:%S")
            age = (datetime.now() - dt).total_seconds()
            collector_state = "OK" if age < 120 else "Stale"
        except Exception:
            collector_state = "Unknown"

    return {
        "cpu": cpu,
        "mem": mem,
        "disk": disk,
        "disk_free_gb": disk_free_gb,
        "uptime_seconds": uptime_seconds,
        "last_seen": last_seen,
        "collector_state": collector_state,
    }


def latest_quality_snapshot():
    return live_snapshot.quality() or latest_quality(connect_db)


def latest_quality_memory():
    return live_snapshot.quality()


def icon_for_app(category):
    return APP_ICONS.get(category or "Other", APP_ICONS["Other"])


def icon_for_device(dtype):
    """Return a Font Awesome icon for a device type.

    This accepts both old labels and newer labels used by the collector/UI.
    It is display-only and does not change the saved device type.
    """
    key = str(dtype or "Unknown").strip()

    aliases = {
        "Computer": "PC",
        "PC": "PC",
        "Laptop": "PC",
        "Mobile Device": "Phone",
        "Phone": "Phone",
        "Apple Device": "Phone",
        "Media Device": "TV",
        "TV": "TV",
        "Camera": "Camera",
        "Server": "Server",
        "Network Device": "Gateway",
        "Gateway": "Gateway",
        "Printer": "Printer",
        "IoT": "IoT",
        "Unknown": "Unknown",
    }

    mapped = aliases.get(key, key)
    return DEVICE_ICONS.get(mapped, DEVICE_ICONS["Unknown"])


def is_noise(domain):
    d = (domain or "").lower()
    return any(x in d for x in NOISE_DOMAINS)


def top_categories(limit=8):
    start_day = range_start_day()
    return cached_query(
        f"top_categories:{start_day}:{limit}",
        60,
        """
        SELECT category, COUNT(*) AS total
        FROM dns_querylog
        WHERE day>=?
        GROUP BY category
        ORDER BY total DESC
        LIMIT ?
        """,
        (start_day, limit),
    )


def estimated_app_usage(limit=10):
    """Return DNS-attributed measured bytes, kept separate from total device usage."""
    start_day = range_start_day()
    return cached_query(
        f"estimated_app_usage:{start_day}:{limit}",
        10,
        """
        WITH usage AS (
            SELECT
                category,
                ip,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb
            FROM estimated_app_traffic
            WHERE day>=?
            GROUP BY category, ip
        )
        SELECT
            u.category,
            u.ip,
            COALESCE(NULLIF(o.name, ''), NULLIF(d.name, ''), u.ip) AS name,
            u.downloaded_mb,
            u.uploaded_mb,
            u.total_mb
        FROM usage u
        LEFT JOIN devices d ON d.ip=u.ip
        LEFT JOIN device_overrides o ON o.ip=u.ip
        ORDER BY total_mb DESC
        LIMIT ?
        """,
        (start_day, limit),
    )


def ag_auth():
    c = cfg()
    return (c.get("adguard_user"), c.get("adguard_pass"))


def ag_control(endpoint):
    return cfg().get("adguard_url", "").rstrip("/") + "/control" + endpoint


def ag_get(endpoint, params=None):
    cache_key = "adguard_get:" + endpoint + ":" + json.dumps(params or {}, sort_keys=True)
    cached = cache_get(cache_key, ADGUARD_STATUS_CACHE_SECONDS)
    if cached is not None:
        return cached
    try:
        r = requests.get(ag_control(endpoint), auth=ag_auth(), params=params, timeout=8)
        if r.status_code == 200:
            try:
                result = (True, r.json())
            except Exception:
                result = (True, {"ok": True})
            cache_set(cache_key, result)
            return result
        result = (False, {"error": f"HTTP {r.status_code}", "body": r.text[:300]})
    except Exception as e:
        print(f"AdGuard GET {endpoint} failed: {e}")
        result = (False, {"error": "AdGuard request failed."})
    cache_set(cache_key, result)
    return result


def ag_post(endpoint, payload=None):
    try:
        if payload is None:
            r = requests.post(ag_control(endpoint), auth=ag_auth(), timeout=8)
        else:
            r = requests.post(ag_control(endpoint), auth=ag_auth(), json=payload, timeout=8)

        if r.status_code == 200:
            cache_delete_prefix("adguard_get:")
            try:
                return True, r.json()
            except Exception:
                return True, {"ok": True}

        return False, {"error": f"HTTP {r.status_code}", "body": r.text[:300]}
    except Exception as e:
        print(f"AdGuard POST {endpoint} failed: {e}")
        return False, {"error": "AdGuard request failed."}


def shell(title, body, active="Dashboard"):
    """
    Main HTML wrapper used by all NetSpecter pages.

    What this section does:
    - Builds the left sidebar navigation.
    - Loads the global CSS, favicon, Font Awesome icons and Chart.js.
    - Wraps each page's own HTML inside the standard layout.
    - Adds shared JavaScript used by multiple pages.

    Shared JavaScript included here:
    - Device table search/filter.
    - Device inline edit/save/cancel.
    - Live speed polling from /api/live every 2 seconds.
    - Live update support for Dashboard, Devices and individual Device View pages.

    Live update HTML requirements:
    - Per-device values must use:
        data-live-ip="DEVICE_IP"
        data-live-field="total|down|up"

    - Network-wide values must use:
        data-live-network="1"
        data-live-field="total|down|up"
    """

    c = cfg()
    fast_page_mode = bool(c.get("fast_page_mode", True))

    def nav_icon(name):
        return f'<img class="ns-sidebar__icon" src="/static/icons/{name}.png?v=20260711-ui5" alt="" loading="eager">'

    # ---------------------------------------------------
    # Sidebar navigation groups
    # ---------------------------------------------------
    # Each tuple is:
    #   Display name, URL, supplied PNG icon name
    # ---------------------------------------------------

    nav_groups = [
        (
            "Overview",
            False,
            [
                ("Dashboard", "/", "dashboard"),
            ],
        ),
        (
            "Network",
            False,
            [
                ("Devices", "/devices", "devices"),
                ("Traffic", "/traffic", "traffic"),
                ("History", "/history", "history"),
                ("Application Activity", "/applications", "network"),
                ("Speed Tests", "/speed-tests", "speedtest"),
                ("Exports", "/exports", "exports"),
            ],
        ),
        (
            "Reporting",
            False,
            [
                ("Reporting", "/reporting", "exports"),
            ],
        ),
        (
            "Security",
            False,
            [
                ("Blocked DNS Requests", "/blocked", "blocked"),
                ("IDS Alerts", "/ids-alerts", "ids"),
                ("Incidents", "/incidents", "ids"),
                ("Anomalies", "/anomalies", "monitor"),
            ],
        ),
        (
            "Services",
            False,
            [
                ("AdGuard", "/adguard", "adguard"),
                ("Monitor", "/monitor", "monitor"),
            ],
        ),
        (
            "Appliance",
            False,
            [
                ("Settings", "/settings", "settings"),
                ("Health", "/health", "health"),
                ("Backups", "/vault", "system"),
                ("Logs", "/system", "logs"),
            ],
        ),
    ]

    nav = ""
    logout_nav = (
        '<div class="ns-sidebar__footer">'
        f'<a class="ns-sidebar__item" href="/third-party-licences">{nav_icon("system")}<span>Legal &amp; Licences</span></a>'
        f'<a class="ns-sidebar__item ns-sidebar__item--logout nav-logout" href="/logout">{nav_icon("logout")}<span>Logout</span></a>'
        '</div>'
    )
    app_shell_pages = {"Dashboard", "Devices", "Traffic"}

    for group_label, collapsible, items in nav_groups:
        group_active = any(label == active for label, _, _ in items)
        if collapsible:
            open_attr = " open" if group_active else ""
            active_cls = " active" if group_active else ""
            nav += (
                f'<details class="nav-group ns-sidebar__section nav-dropdown{active_cls}"{open_attr}>'
                f'<summary><span>{group_label}</span></summary>'
                '<div class="nav-dropdown-items">'
            )
        else:
            nav += f'<div class="nav-group ns-sidebar__section"><div class="nav-group-label ns-sidebar__section-title">{group_label}</div>'
        for label, url, icon in items:
            is_active = label == active
            cls = "ns-sidebar__item active" if is_active else "ns-sidebar__item"
            current_attr = ' aria-current="page"' if is_active else ""
            shell_attr = ' data-app-shell="1"' if label in app_shell_pages else ""
            nav += f'<a class="{cls}" href="{url}"{current_attr}{shell_attr}>{nav_icon(icon)}<span>{label}</span></a>'
        if collapsible:
            nav += "</div></details>"
        else:
            nav += "</div>"
    nav += logout_nav

    # ---------------------------------------------------
    # Standard page shell
    # ---------------------------------------------------
    # The body parameter is the page-specific HTML.
    # ---------------------------------------------------

    return f"""<!DOCTYPE html>
<html>
<head>
<title>{h(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/static/favicon.png">
<link rel="stylesheet" href="/static/ui-tokens.css?v=20260711a">
<link rel="stylesheet" href="/static/ui-icons.css?v=20260711c">
<link rel="stylesheet" href="/static/ui-components.css?v=20260711a">
<link rel="stylesheet" href="/static/theme.css?v=20260711b">
<link rel="stylesheet" href="/static/ui-polish.css?v=20260712e">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="/static/ns-ui.js?v=20260712b" defer></script>
</head>
<body>

<!-- ===================================================
     SIDEBAR
     ===================================================
     Left navigation shown on every page.
     =================================================== -->

<div class="ns-sidebar-backdrop" data-sidebar-close></div>
<div class="sidebar ns-sidebar" id="siteSidebar" aria-label="Primary navigation">
  <div class="ns-sidebar__brand">
    <img src="/static/brand/logo-sidebar.png?v=20260711-ui5" class="brand-logo" alt="NetSpecter">
  </div>
  <nav class="nav ns-sidebar__nav" aria-label="Primary">{nav}</nav>
</div>

<header class="ns-mobile-header">
  <button class="ns-mobile-menu-button" type="button" aria-label="Open navigation" aria-controls="siteSidebar" aria-expanded="false">
    <span></span><span></span><span></span>
  </button>
  <img src="/static/brand/logo-header.png?v=20260711-ui5" class="ns-mobile-header__logo" alt="NetSpecter">
</header>

<!-- ===================================================
     CONTENT
     ===================================================
     Page-specific content is injected here.
     =================================================== -->

<main class="content ns-main" id="appContent">
{body}
<footer class="ns-legal-footer">&copy; 2026 NetSpecter. All rights reserved. <a href="/third-party-licences">Legal &amp; Licences</a></footer>
</main>

<!-- ===================================================
     GLOBAL JAVASCRIPT
     ===================================================
     Shared browser-side logic for all NetSpecter pages.
     =================================================== -->

<script>

// ---------------------------------------------------
// Device table live search
// ---------------------------------------------------
// Used on /devices. Filters visible rows as you type.
// ---------------------------------------------------
function filterDevices() {{
  const input = document.getElementById("deviceSearch");
  const typeFilter = document.getElementById("deviceTypeFilter");
  const statusFilter = document.getElementById("deviceStatusFilter");
  const table = document.getElementById("deviceTable");

  if (!input || !table) return;

  const filter = input.value.toLowerCase().trim();
  const typeValue = (typeFilter ? typeFilter.value : "").toLowerCase();
  const statusValue = (statusFilter ? statusFilter.value : "").toLowerCase();
  const rows = table.querySelectorAll("tbody tr");

  rows.forEach(row => {{
    let text = row.innerText.toLowerCase();

    row.querySelectorAll("input, select").forEach(el => {{
      text += " " + (el.value || "").toLowerCase();
    }});

    const matchesText = text.includes(filter);
    const matchesType = !typeValue || (row.dataset.type || "").toLowerCase() === typeValue;
    const matchesStatus = !statusValue || (row.dataset.online || "").toLowerCase() === statusValue || (row.dataset.status || "").toLowerCase() === statusValue;
    row.style.display = matchesText && matchesType && matchesStatus ? "" : "none";
  }});
}}

// ---------------------------------------------------
// Enable inline device editing
// ---------------------------------------------------
// Converts display fields into editable inputs/selects.
// ---------------------------------------------------
function editDeviceRow(button) {{
  const row = button.closest("tr");
  if (!row) return;

  row.querySelectorAll(".view-val").forEach(el => el.style.display = "none");
  row.querySelectorAll(".edit-field").forEach(el => el.style.display = "inline-block");

  const save = row.querySelector(".save-btn");
  const cancel = row.querySelector(".cancel-btn");
  const view = row.querySelector(".view-btn");

  if (save) save.style.display = "inline-block";
  if (cancel) cancel.style.display = "inline-block";
  if (view) view.style.display = "none";

  button.style.display = "none";
}}

// ---------------------------------------------------
// Cancel inline editing
// ---------------------------------------------------
// Reloads the page to discard unsaved edits.
// ---------------------------------------------------
function cancelDeviceEdit(button) {{
  window.location.reload();
}}

// ---------------------------------------------------
// Save inline device editing
// ---------------------------------------------------
// Builds a hidden POST form and submits to /devices.
// ---------------------------------------------------
function saveDeviceRow(button) {{
  const row = button.closest("tr");
  if (!row) return;

  const form = document.createElement("form");
  form.method = "POST";
  form.action = "/devices";

  const addField = (name, value) => {{
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value || "";
    form.appendChild(input);
  }};

  addField("ip", row.dataset.ip);

  row.querySelectorAll(".edit-field").forEach(el => {{
    addField(el.dataset.field, el.value);
  }});

  addField("_csrf_token", "{h(csrf_token())}");

  document.body.appendChild(form);
  form.submit();
}}

function runContentScripts(container) {{
  container.querySelectorAll("script").forEach(oldScript => {{
    const script = document.createElement("script");
    script.type = "module";
    if (oldScript.src) {{
      script.src = oldScript.src;
    }} else {{
      script.textContent = oldScript.textContent;
    }}
    oldScript.replaceWith(script);
  }});
}}

function closeFloatingControls() {{
  document.querySelectorAll(".ns-menu-wrap.is-open, .ns-tools-wrap.is-open").forEach(item => {{
    item.classList.remove("is-open");
  }});
  document.querySelectorAll(".ns-confirm-backdrop.is-open").forEach(item => {{
    item.classList.remove("is-open");
    item.setAttribute("hidden", "");
  }});
}}

async function loadAppShellPage(url, pushState = true) {{
  const content = document.getElementById("appContent");
  if (!content) {{
    window.location.href = url;
    return;
  }}

  const requestUrl = new URL(url, window.location.origin);
  requestUrl.searchParams.set("_partial", "1");
  closeFloatingControls();
  content.classList.add("loading");

  try {{
    const response = await fetch(requestUrl.toString(), {{
      cache: "no-store",
      headers: {{"X-NetSpecter-Partial": "1"}}
    }});

    if (!response.ok) throw new Error("HTTP " + response.status);

    const html = await response.text();
    if (/<!doctype html|<html[\\s>]/i.test(html.slice(0, 300))) {{
      window.location.href = url;
      return;
    }}
    content.innerHTML = html;
    runContentScripts(content);

    const title = response.headers.get("X-NetSpecter-Title");
    const active = response.headers.get("X-NetSpecter-Active");
    if (title) document.title = title;

    const sidebarNav = document.querySelector(".ns-sidebar__nav");
    const sidebarScrollTop = sidebarNav ? sidebarNav.scrollTop : 0;
    document.querySelectorAll(".nav a").forEach(link => {{
      const isActive = link.textContent.trim() === active;
      link.classList.toggle("active", isActive);
      if (isActive) {{
        link.setAttribute("aria-current", "page");
      }} else {{
        link.removeAttribute("aria-current");
      }}
    }});
    if (sidebarNav) sidebarNav.scrollTop = sidebarScrollTop;

    if (pushState) {{
      history.pushState({{appShell: true}}, "", url);
    }}

    refreshUpdateStatusBadge();
    refreshLiveSpeeds();
    netSpecterLiveCountdown = netSpecterLiveIntervalSeconds;
    updateLiveCountdown();
  }} catch (error) {{
    console.log("App shell navigation failed:", error);
    window.location.href = url;
  }} finally {{
    content.classList.remove("loading");
  }}
}}

document.addEventListener("click", event => {{
  const link = event.target.closest('a[data-app-shell="1"]');
  if (!link || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
  if (link.target && link.target !== "_self") return;
  event.preventDefault();
  loadAppShellPage(link.href);
}});

window.addEventListener("popstate", () => {{
  const activeLink = Array.from(document.querySelectorAll('a[data-app-shell="1"]')).find(link => {{
    return new URL(link.href).pathname === window.location.pathname;
  }});
  if (activeLink) {{
    loadAppShellPage(window.location.href, false);
  }} else {{
    window.location.reload();
  }}
}});

// ---------------------------------------------------
// Live speed refresh engine
// ---------------------------------------------------
// Polls /api/live on a visible timer and updates matching
// elements without refreshing the page.
//
// Per-device fields:
//   data-live-ip="LAN device IP"
//   data-live-field="total|down|up"
//
// Network fields:
//   data-live-network="1"
//   data-live-field="total|down|up"
// ---------------------------------------------------
async function refreshLiveSpeeds() {{
  try {{
    const res = await fetch('/api/live?t=' + Date.now(), {{cache: 'no-store'}});
    if (!res.ok) return;

    const data = await res.json();

    // Update per-device live values.
    document.querySelectorAll('[data-live-ip][data-live-field]').forEach(el => {{
      const ip = el.dataset.liveIp;
      const field = el.dataset.liveField;

      if (data[ip] && data[ip][field] !== undefined) {{
        el.textContent = data[ip][field];
      }}
    }});

    // Update network-wide live values.
    document.querySelectorAll('[data-live-network][data-live-field]').forEach(el => {{
      const field = el.dataset.liveField;

      if (data['__network__'] && data['__network__'][field] !== undefined) {{
        el.textContent = data['__network__'][field];
      }}
    }});
  }} catch (e) {{
    console.log('Live speed refresh failed:', e);
  }}
}}

// Start live polling only on pages with live speed widgets.
const netSpecterFastMode = {json.dumps(fast_page_mode)};
const netSpecterLiveIntervalSeconds = 5;
let netSpecterLiveCountdown = netSpecterLiveIntervalSeconds;
function hasLiveSpeedWidgets() {{
  return !!document.querySelector('[data-live-ip][data-live-field], [data-live-network][data-live-field]');
}}
function updateLiveCountdown() {{
  return;
}}
if (hasLiveSpeedWidgets()) {{
  refreshLiveSpeeds();
  updateLiveCountdown();
}}
setInterval(() => {{
  if (!hasLiveSpeedWidgets()) return;
  netSpecterLiveCountdown -= 1;
  if (netSpecterLiveCountdown <= 0) {{
    netSpecterLiveCountdown = netSpecterLiveIntervalSeconds;
    refreshLiveSpeeds();
  }}
  updateLiveCountdown();
}}, 1000);

async function refreshUpdateStatusBadge() {{
  const badge = document.getElementById("updateStatusBadge");
  if (!badge) return;
  try {{
    const res = await fetch("/api/update-status", {{cache: "no-store"}});
    if (!res.ok) return;
    const data = await res.json();
    const span = badge.querySelector("span");
    if (!span) return;
    if (data.available) {{
      span.textContent = "Updates: Available";
      badge.classList.add("update-available");
      const dashboardButton = document.getElementById("dashboardUpdateButton");
      if (dashboardButton) dashboardButton.style.display = "inline-flex";
    }} else if (data.ok) {{
      span.textContent = "Updates: Current";
    }} else {{
      span.textContent = "Updates: Check";
    }}
  }} catch (e) {{
    console.log("Update status check failed:", e);
  }}
}}
refreshUpdateStatusBadge();

</script>
</body>
</html>"""


def topbar(title="Dashboard"):
    c = cfg()
    adguard_url = str(c.get("adguard_url", "") or "#")
    update_badge = '<a id="updateStatusBadge" href="/health#updateProgress"><span>Checking updates...</span></a>' if title == "Dashboard" else '<a href="/health#updateProgress"><span>Updates</span></a>'
    public_ip_text = public_ip(refresh=True)
    if not public_ip_text or public_ip_text == "Unknown":
        public_ip_text = "Not detected"

    return f"""
<div class="topbar ns-page-header">
  <div class="ns-page-header__text">
    <h1>{h(title)}</h1>
    <div class="sub">Network visibility + privacy protection</div>
  </div>
  <div class="badges ns-page-header__actions">
    <span>Observed IPv4 traffic</span>
    <span>Public IP: {h(public_ip_text)}</span>
    {update_badge}
    <a href="{h(adguard_url)}" target="_blank"><span>AdGuard</span></a>
    <a href="/blocked"><span>Blocked DNS</span></a>
    <span>LAN: {h(c.get('lan_prefix'))}0/24</span>
  </div>
</div>
"""



@app.route("/api/live")
def api_live():
    """Live speed API used by the web UI polling.

    Source: live_device_speed written by live_packet_collector.py.
    Values in DB are bytes/sec. UI receives already formatted strings.
    """
    rows = list(live_snapshot.speeds().values())
    if not rows:
        freshness = f"-{live_sample_max_age()} seconds"
        rows = query(
            """
            SELECT ip, rx_bps, tx_bps, total_bps, updated_at
            FROM live_device_speed
            WHERE updated_at >= datetime('now', 'localtime', ?)
            """,
            (freshness,),
        )

    data = {}
    total_rx = 0.0
    total_tx = 0.0
    total_all = 0.0

    for r in rows:
        ip = str(r["ip"] or "")
        rx = float(r["rx_bps"] or 0)
        tx = float(r["tx_bps"] or 0)
        total = float(r["total_bps"] or 0)

        total_rx += rx
        total_tx += tx
        total_all += total

        data[ip] = {
            "down": fmt_bytes_per_sec(rx),
            "up": fmt_bytes_per_sec(tx),
            "total": fmt_bytes_per_sec(total),
            "updated": r["updated_at"] or "",
        }

    data["__network__"] = {
        "down": fmt_bytes_per_sec(total_rx),
        "up": fmt_bytes_per_sec(total_tx),
        "total": fmt_bytes_per_sec(total_all),
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    return data


def lcd_number(value, decimals=0):
    if value is None:
        return None
    try:
        number = float(value)
    except Exception:
        return None
    return round(number, int(decimals))


def lcd_state(ok=None, warning=False):
    if ok is None:
        return "unknown"
    if ok:
        return "warning" if warning else "healthy"
    return "down"


def lcd_collector_state(collector_state):
    state = str(collector_state or "").strip().lower()
    if state == "ok":
        return "healthy"
    if state in {"stale", "updating", "starting", "unknown", ""}:
        return "warning" if state not in {"unknown", ""} else "unknown"
    return "down"


def lcd_internet_status(latest):
    if not latest:
        return "degraded"
    status_text = str(latest["status"] or "").strip().lower()
    try:
        wan_up = int(latest["wan_up"] or 0) == 1
    except Exception:
        wan_up = False
    try:
        loss_pct = float(latest["internet_loss_pct"] or 0)
    except Exception:
        loss_pct = 0.0
    try:
        latency_ms = float(latest["internet_latency_ms"] or 0)
    except Exception:
        latency_ms = 0.0
    if status_text in {"down", "offline", "failed"} or not wan_up or loss_pct >= 100:
        return "offline"
    if status_text not in {"ok", "healthy"} or loss_pct > 0 or latency_ms > 150:
        return "degraded"
    return "online"


def lcd_token_hash(token):
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def lcd_display_list(config=None):
    displays = (config or cfg()).get("lcd_displays", [])
    return displays if isinstance(displays, list) else []


def lcd_find_display_by_token(token, config=None):
    if not token:
        return None
    candidate_hash = lcd_token_hash(token)
    for display in lcd_display_list(config):
        if not isinstance(display, dict) or display.get("revoked_at"):
            continue
        stored_hash = str(display.get("token_hash") or "")
        if stored_hash and secrets.compare_digest(stored_hash, candidate_hash):
            return display
    return None


def lcd_display_endpoint_url(config=None):
    c = config or cfg()
    host = str(c.get("appliance_ip") or "").strip()
    port = int(c.get("https_proxy_port") or DEFAULT_CONFIG["https_proxy_port"])
    if not host:
        configured = str(c.get("netspecter_url") or "").strip()
        parsed = urlsplit(configured)
        if parsed.hostname and parsed.scheme == "https":
            host = parsed.hostname
    if not host:
        host = request_host_without_port() if request else "127.0.0.1"
    base = f"https://{host}:{port}"
    return f"{base}/api/lcd/summary"


def lcd_display_token_suffix(display):
    suffix = str(display.get("token_suffix") or "").strip()
    if suffix:
        return suffix
    preview = str(display.get("token_preview") or "").strip()
    return preview[-6:] if preview else ""


def lcd_record_seen(display):
    display_id = str(display.get("id") or "")
    if not display_id:
        return
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    state = dict(LCD_LAST_SEEN.get(display_id, {}))
    state.update({
        "last_seen": now,
        "last_ip": request_client_ip(),
        "status": "online",
        "seen_ts": time.time(),
    })
    LCD_LAST_SEEN[display_id] = state


def lcd_rate_limited(display):
    display_id = str(display.get("id") or "")
    if not display_id:
        return False
    state = LCD_LAST_SEEN.get(display_id, {})
    last_request_ts = float(state.get("last_request_ts") or 0)
    now = time.time()
    if last_request_ts and now - last_request_ts < LCD_RATE_LIMIT_SECONDS:
        return True
    state["last_request_ts"] = now
    LCD_LAST_SEEN[display_id] = state
    return False


def lcd_seen_state(display_id):
    state = LCD_LAST_SEEN.get(str(display_id or ""), {})
    if not state:
        return {"last_seen": None, "last_ip": None, "status": "never"}
    status = "online" if time.time() - float(state.get("seen_ts") or 0) <= 60 else "offline"
    return {"last_seen": state.get("last_seen"), "last_ip": state.get("last_ip"), "status": status}


def lcd_update_traffic_history(download_mbps, upload_mbps):
    for key, value in (("download_mbps", download_mbps), ("upload_mbps", upload_mbps)):
        history = LCD_TRAFFIC_HISTORY.setdefault(key, [])
        history.append(value if value is not None else None)
        del history[:-12]


def lcd_last_speed_test(snapshot):
    speed = snapshot.get("last_speed_test") if isinstance(snapshot.get("last_speed_test"), dict) else {}
    if speed and (speed.get("completed_at") or speed.get("download_mbps") is not None or speed.get("upload_mbps") is not None):
        return {
            "completed_at": speed.get("completed_at"),
            "download_mbps": lcd_number(speed.get("download_mbps"), 2),
            "upload_mbps": lcd_number(speed.get("upload_mbps"), 2),
            "ping_ms": lcd_number(speed.get("ping_ms"), 0),
            "status": speed.get("status") or "none",
        }
    try:
        rows = cached_query(
            "lcd_last_speed_test",
            60,
            """
            SELECT ts, latency_ms, download_mbps, upload_mbps, success
            FROM speed_tests
            WHERE success=1
            ORDER BY ts DESC
            LIMIT 1
            """,
        )
    except Exception:
        rows = []
    if rows:
        row = rows[0]
        return {
            "completed_at": row.get("ts"),
            "download_mbps": lcd_number(row.get("download_mbps"), 2),
            "upload_mbps": lcd_number(row.get("upload_mbps"), 2),
            "ping_ms": lcd_number(row.get("latency_ms"), 0),
            "status": "completed" if int(row.get("success") or 0) else "failed",
        }
    return {"completed_at": None, "download_mbps": None, "upload_mbps": None, "ping_ms": None, "status": "none"}


def lcd_current_speed(snapshot, live):
    download_mbps = lcd_number(float(live.get("rx_bps") or 0) / 1000000, 2)
    upload_mbps = lcd_number(float(live.get("tx_bps") or 0) / 1000000, 2)
    if (download_mbps or 0) > 0 or (upload_mbps or 0) > 0:
        return download_mbps, upload_mbps
    summary_download = lcd_number(snapshot.get("download_mbps"), 2)
    summary_upload = lcd_number(snapshot.get("upload_mbps"), 2)
    if summary_download is not None or summary_upload is not None:
        return summary_download or 0.0, summary_upload or 0.0
    return download_mbps, upload_mbps


@app.route("/api/lcd/summary")
def api_lcd_summary():
    c = cfg()
    auth_header = str(request.headers.get("Authorization", "") or "").strip()
    supplied_token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
    display = lcd_find_display_by_token(supplied_token, c)
    env_token = str(os.environ.get("NETSPECTER_LCD_TOKEN") or "").strip()
    if not display and env_token and supplied_token and secrets.compare_digest(supplied_token, env_token):
        display = {"id": "env", "name": "Environment LCD Token"}
    if not display:
        return jsonify({"error": "unauthorized"}), 401
    if not request_from_lan(c):
        return jsonify({"error": "lan_only"}), 403
    if lcd_rate_limited(display):
        return jsonify({"error": "rate_limited"}), 429
    lcd_record_seen(display)

    now_utc = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    snapshot = live_snapshot.summary()
    health = system_health_live_only()
    latest = latest_quality_memory()
    live = live_network_speed()
    total_today_gb = lcd_number(snapshot.get("total_traffic_today_gb"), 1)

    live_speeds = live_snapshot.speeds()
    device_summary = snapshot.get("devices") if isinstance(snapshot.get("devices"), dict) else {}
    known_devices = lcd_number(device_summary.get("known"), 0)
    online_devices = lcd_number(device_summary.get("online"), 0)
    unknown_devices = lcd_number(device_summary.get("new_or_unknown"), 0)
    if known_devices is None and live_speeds:
        known_devices = len(live_speeds)
    if online_devices is None and live_speeds:
        online_devices = sum(1 for row in live_speeds.values() if float(row.get("total_bps") or 0) > 0)

    active_alerts = lcd_number(snapshot.get("active_alerts"), 0)
    if active_alerts is None:
        active_alerts = 0

    top_talker = None
    snapshot_top_talker = snapshot.get("top_talker") if isinstance(snapshot.get("top_talker"), dict) else {}
    if snapshot_top_talker:
        top_talker = {
            "name": snapshot_top_talker.get("name"),
            "mbps": lcd_number(snapshot_top_talker.get("mbps"), 2),
        }
    elif live_speeds:
        row = max(live_speeds.values(), key=lambda item: float(item.get("total_bps") or 0), default=None)
        if row:
            top_talker = {"name": row.get("name") or row.get("ip"), "mbps": lcd_number(float(row.get("total_bps") or 0) * 8 / 1000000, 2)}

    top_application = snapshot.get("top_application") if isinstance(snapshot.get("top_application"), dict) else None

    last_speed_test = lcd_last_speed_test(snapshot)

    collector_service_state = lcd_collector_state(health.get("collector_state"))
    database_ok = DB_PATH.exists()
    latest_status = str(latest.get("status") or "") if latest else ""
    dns_warning = bool(latest and (latest.get("dns_ms") is None or float(latest.get("dns_ms") or 0) > 100))
    dns_ok = None if not latest else latest_status == "ok"
    bridge_ok = None
    if psutil:
        try:
            bridge_ok = str(c.get("packet_iface", "br0")) in psutil.net_if_addrs()
        except Exception:
            bridge_ok = None
    internet_status = lcd_internet_status(latest)
    services = {
        "dns": lcd_state(dns_ok, dns_warning),
        "ids": lcd_state(None if active_alerts is None else active_alerts == 0),
        "collector": collector_service_state,
        "database": lcd_state(database_ok),
        "bridge": lcd_state(bridge_ok),
    }
    any_down = services["database"] == "down" or internet_status == "offline"
    any_warning = any(value in {"warning", "unknown"} for value in services.values())
    if (active_alerts is not None and active_alerts > 0) or any_down or internet_status == "offline":
        status = "alert"
    elif internet_status == "degraded" or any_warning:
        status = "watch"
    else:
        status = "secure"
    download_mbps, upload_mbps = lcd_current_speed(snapshot, live)
    lcd_update_traffic_history(download_mbps, upload_mbps)

    return jsonify({
        "generated_at": now_utc,
        "snapshot_age_seconds": lcd_number(snapshot.get("snapshot_age_seconds"), 1),
        "status": status,
        "internet_status": internet_status,
        "devices_online": online_devices,
        "active_alerts": active_alerts,
        "download_mbps": download_mbps,
        "upload_mbps": upload_mbps,
        "traffic_history": {
            "download_mbps": list(LCD_TRAFFIC_HISTORY.get("download_mbps", [])),
            "upload_mbps": list(LCD_TRAFFIC_HISTORY.get("upload_mbps", [])),
        },
        "total_traffic_today_gb": total_today_gb,
        "ping_ms": lcd_number(latest.get("internet_latency_ms"), 0) if latest else None,
        "jitter_ms": lcd_number(latest.get("jitter_ms"), 0) if latest else None,
        "packet_loss_pct": lcd_number(latest.get("internet_loss_pct"), 1) if latest else None,
        "dns_ms": lcd_number(latest.get("dns_ms"), 0) if latest else None,
        "services": services,
        "system": {
            "cpu_pct": lcd_number(health.get("cpu"), 0),
            "ram_pct": lcd_number(health.get("mem"), 0),
            "disk_pct": lcd_number(health.get("disk"), 0),
            "uptime_seconds": health.get("uptime_seconds"),
        },
        "top_talker": top_talker or {"name": None, "mbps": None},
        "top_application": top_application or {"name": None, "mbps": None},
        "devices": {
            "known": known_devices,
            "online": online_devices,
            "new_or_unknown": unknown_devices,
        },
        "last_speed_test": last_speed_test,
    })


@app.route("/api/update-status")
def api_update_status():
    force = request.args.get("force") == "1"
    return update_status(force=force, fetch_remote=force or request.args.get("fetch") == "1")


@app.route("/api/update-progress")
def api_update_progress():
    state, age = update_run_state()
    progress = 0
    if state == "running" and age is not None and age > 120:
        web_ok, _web_state = systemd_active("netspecter-web")
        collector_ok, _collector_state = systemd_active("netspecter-collector")
        if web_ok and collector_ok:
            state = "finished"
            age = 0
    if state == "running" and age is not None and age > 900:
        state = "failed"
    label = "Idle"
    detail = "No update running."
    if state == "running":
        label = "Running"
        detail = "Updating NetSpecter in the background. Services may restart briefly."
        progress = min(95, 20 + int(min(float(age or 0), 180) / 180 * 70))
    elif state == "finished":
        label = "Finished"
        detail = "Update finished. Refreshing page shortly."
        progress = 100
    elif state == "failed":
        label = "Failed"
        detail = "Update failed. Open Logs for the full update output."
        progress = 100
    return {"state": state, "label": label, "age": age, "detail": detail, "progress": progress}


def appliance_check_response(ok, detail):
    payload = {"ok": bool(ok), "detail": "Online" if ok else "Service check failed."}
    return jsonify(payload), (200 if ok else 503)


@app.route("/api/health/web")
def api_health_web():
    return appliance_check_response(True, "Online")


@app.route("/api/health/collector")
def api_health_collector():
    health = system_health_snapshot()
    ok = health["collector_state"] == "OK"
    return appliance_check_response(ok, health["last_seen"])


@app.route("/api/health/bridge")
def api_health_bridge():
    c = cfg()
    iface = str(c.get("packet_iface", "br0"))
    ok = False
    if psutil:
        try:
            ok = iface in psutil.net_if_addrs()
        except Exception:
            ok = False
    return appliance_check_response(ok, iface)


@app.route("/api/health/database")
def api_health_database():
    if not DB_PATH.exists():
        return appliance_check_response(False, "Database missing")
    try:
        with sqlite3.connect(DB_PATH, timeout=5) as con:
            con.execute("SELECT 1")
        size_mb = round(DB_PATH.stat().st_size / 1024 / 1024, 2)
        return appliance_check_response(True, f"{size_mb} MB")
    except Exception as exc:
        return appliance_check_response(False, exc)


@app.route("/api/dashboard-summary")
def api_dashboard_summary():
    """Refresh accumulated dashboard counters from measured history."""
    start_day = range_start_day()
    snapshot = live_snapshot.summary()
    traffic_rows = cached_query(
        f"dashboard_summary_traffic:{start_day}",
        30,
        """
        SELECT
            SUM(downloaded_mb) AS downloaded,
            SUM(uploaded_mb) AS uploaded,
            SUM(total_mb) AS total,
            COUNT(*) AS rows_seen
        FROM traffic_intervals
        WHERE day>=?
        """,
        (start_day,),
    )
    dns_rows = cached_query(
        f"dashboard_summary_dns_fast:{start_day}",
        30,
        "SELECT COUNT(*) AS total FROM dns_querylog WHERE day>=?",
        (start_day,),
    )
    blocked_rows = cached_query(
        f"dashboard_summary_blocked_fast:{start_day}",
        30,
        "SELECT COUNT(*) AS total FROM dns_querylog WHERE day>=? AND blocked=1",
        (start_day,),
    )
    domain_rows = cached_query(
        f"dashboard_summary_domains:{start_day}",
        30,
        """
        SELECT
            COUNT(DISTINCT domain) AS unique_domains,
            COUNT(DISTINCT CASE WHEN blocked=1 THEN domain END) AS blocked_domains
        FROM dns_querylog
        WHERE day>=? AND domain IS NOT NULL AND domain!=''
        """,
        (start_day,),
    )
    traffic = traffic_rows[0] if traffic_rows else {}
    down = round(float(traffic.get("downloaded") or 0), 2)
    up = round(float(traffic.get("uploaded") or 0), 2)
    total = round(float(traffic.get("total") or 0), 2)
    active_rows = cached_query(
        f"dashboard_summary_active:{start_day}",
        30,
        """
        SELECT COUNT(*) AS active
        FROM (
            SELECT ip
            FROM traffic_intervals
            WHERE day>=?
            GROUP BY ip
        )
        """,
        (start_day,),
    )
    snapshot_devices = snapshot.get("devices") if isinstance(snapshot.get("devices"), dict) else {}
    active = int(snapshot_devices.get("online") or 0) if snapshot_devices.get("online") is not None else int(active_rows[0]["active"] or 0) if active_rows else 0
    dns_total = int(dns_rows[0]["total"] or 0) if dns_rows else 0
    domains = domain_rows[0] if domain_rows else {}
    unique_domains = int(domains.get("unique_domains") or 0)
    blocked = int(blocked_rows[0]["total"] or 0) if blocked_rows else 0
    blocked_domains = int(domains.get("blocked_domains") or 0)
    blocked_pct = round((blocked / dns_total * 100), 1) if dns_total else 0

    return {
        "traffic_total": fmt_mb(total),
        "traffic_down": fmt_mb(down),
        "traffic_up": fmt_mb(up),
        "active_devices": active,
        "snapshot_age_seconds": snapshot.get("snapshot_age_seconds"),
        "blocked": blocked,
        "blocked_domains": blocked_domains,
        "blocked_pct": blocked_pct,
        "dns_total": dns_total,
        "unique_domains": unique_domains,
    }


@app.route("/api/dashboard-quality")
def api_dashboard_quality():
    latest = latest_quality_snapshot()
    if not latest:
        return {
            "ok": False,
            "status": "unknown",
            "label": "No Data",
            "diagnosis": "No internet quality samples have been collected yet.",
        }
    status = str(latest["status"] or "unknown")
    label = "Healthy" if status == "ok" else "Down" if status == "down" else "Warning" if status == "warn" else "No Data"
    return {
        "ok": True,
        "status": status,
        "label": label,
        "diagnosis": str(latest["diagnosis"] or ""),
        "gateway": quality_value(latest["gateway_latency_ms"], " ms"),
        "internet": quality_value(latest["internet_latency_ms"], " ms"),
        "packet_loss": quality_value(latest["internet_loss_pct"], "%"),
        "jitter": quality_value(latest["jitter_ms"], " ms"),
        "dns": quality_value(latest["dns_ms"], " ms"),
        "isp": str(latest["isp_name"] or latest["isp_org"] or latest["asn"] or "").strip() or "Not detected",
        "public_ip": str(latest["public_ip"] or "").strip() or "Not detected",
    }


def dashboard_png_icon(name, cls="ns-dashboard-icon"):
    return f'<img class="{cls}" src="/static/icons/{name}.png?v=20260711-ui5" alt="" loading="lazy">'


def dashboard_status_dot(state="unknown"):
    safe_state = h(state).lower()
    return f'<span class="ns-status-dot ns-status-dot--{safe_state}" aria-hidden="true"></span>'


def dashboard_app_rows():
    cats = top_categories(5)[:5]
    cat_total = sum(int(x["total"] or 0) for x in cats) or 1
    max_count = max([int(x["total"] or 1) for x in cats], default=1)
    rows = ""

    for r in cats:
        category = str(r["category"] or "Other")
        count = int(r["total"] or 0)
        width = max(4, min(count / max_count * 100, 100))
        pct = round(count / cat_total * 100, 1)
        rows += f"""
<a class="dash-app-row" href="/applications/{quote(category, safe='')}?range={range_key()}">
  <div class="dash-app-name">{dashboard_png_icon("network", "ns-dashboard-row-icon")}<span>{h(category)}</span></div>
  <div class="dash-app-bar"><span style="width:{width}%"></span></div>
  <b>{count:,}</b>
  <em>{pct}%</em>
</a>
"""

    return rows or '<div class="ns-dashboard-empty">No application data yet.</div>'


def dashboard_health_cards(health):
    def meter(label, value, icon, tone="blue", suffix="%", detail=""):
        numeric = max(0, min(float(value or 0), 100))
        return f"""
<div class="ns-health-card">
  {dashboard_png_icon(icon, "ns-dashboard-card-icon")}
  <div>
    <span>{h(label)}</span>
    <b class="{tone}">{h(value)}{suffix}</b>
    {f'<small>{h(detail)}</small>' if detail else ''}
    <div class="ns-health-meter" aria-hidden="true"><i style="width:{numeric}%"></i></div>
  </div>
</div>"""

    db_card = f"""
<div class="ns-health-card">
  {dashboard_png_icon("system", "ns-dashboard-card-icon")}
  <div><span>Database</span><b class="teal">{health['db_size']} MB</b><small>SQLite history</small></div>
</div>"""

    if health["collector_state"] == "OK":
        collector_card = f"""<div class="ns-health-card">{dashboard_png_icon("traffic", "ns-dashboard-card-icon")}<div><span>Collector</span><b class="green">{health['collector_state']}</b><small>Live collection</small></div></div>"""
    elif health["collector_state"] in ("Updating", "Starting"):
        collector_card = f"""<div class="ns-health-card">{dashboard_png_icon("traffic", "ns-dashboard-card-icon")}<div><span>Collector</span><b class="yellow">{health['collector_state']}</b><small>Update in progress</small></div></div>"""
    elif health["collector_state"] == "Disk Full":
        collector_card = f"""<div class="ns-health-card">{dashboard_png_icon("traffic", "ns-dashboard-card-icon")}<div><span>Collector</span><b class="red">{health['collector_state']}</b><small>Free disk space first</small></div></div>"""
    else:
        collector_card = f"""
<form class="ns-health-card collector-restart-card" method="post" action="/collector/restart">
  {csrf_input()}
  <input type="hidden" name="return_to" value="/">
  <button type="submit">{dashboard_png_icon("traffic", "ns-dashboard-card-icon")}<div><span>Collector</span><b class="yellow">{health['collector_state']}</b><small>Click to restart</small></div></button>
</form>"""
    return f"""
{meter("CPU", health["cpu"], "system", "blue")}
{meter("Memory", health["mem"], "telemetry", "purple")}
{meter("Disk / HDD", health["disk"], "health", "red" if health["disk"] > 85 else "green", detail=f"{health['disk_free_gb']} GB free")}
{db_card}
{collector_card}
<div class="ns-health-card">{dashboard_png_icon("monitor", "ns-dashboard-card-icon")}<div><span>Uptime</span><b>{health['uptime']}</b><small>Appliance runtime</small></div></div>
"""


def dashboard_top_clients(limit=5):
    live_rows = []
    for row in live_snapshot.speeds().values():
        total_bps = float(row.get("total_bps") or 0) * 8
        if total_bps <= 0:
            continue
        live_rows.append({
            "ip": row.get("ip") or "",
            "name": row.get("name") or row.get("ip") or "Unknown",
            "device_type": row.get("device_type") or "Unknown",
            "live_bps": total_bps,
        })
    if live_rows:
        rows = sorted(live_rows, key=lambda item: item["live_bps"], reverse=True)[:limit]
        value_key = "live_bps"
        formatter = fmt_bits_as_bytes
        source_label = "Live"
    else:
        rows = []
        value_key = "today_mb"
        formatter = fmt_mb
        source_label = "Traffic"

    start_day = range_start_day()
    today_day = today()
    if not rows:
        rows = list(
            cached_query(
                f"dashboard_top_clients:{start_day}:{today_day}:{limit}",
                20,
                """
                WITH usage AS (
                    SELECT
                        ip,
                        SUM(total_mb) AS total_mb,
                        SUM(CASE WHEN day=? THEN total_mb ELSE 0 END) AS today_mb
                    FROM traffic_intervals
                    WHERE day>=?
                    GROUP BY ip
                )
                SELECT
                    u.ip,
                    COALESCE(NULLIF(o.name, ''), NULLIF(d.name, ''), u.ip) AS name,
                    COALESCE(o.device_type, d.device_type, 'Unknown') AS device_type,
                    u.total_mb,
                    u.today_mb
                FROM usage u
                LEFT JOIN devices d ON d.ip=u.ip
                LEFT JOIN device_overrides o ON o.ip=u.ip
                ORDER BY today_mb DESC, total_mb DESC
                LIMIT ?
                """,
                (today_day, start_day, limit),
            )
        )[:5]
    total = sum(float(row[value_key] or 0) for row in rows) or 1.0
    max_total = max([float(row[value_key] or 0) for row in rows], default=1.0) or 1.0
    html = ""
    for index, row in enumerate(rows, start=1):
        value = float(row[value_key] or 0)
        width = max(4, min(value / max_total * 100, 100))
        pct = value / total * 100
        html += f"""
<a class="ns-progress-row" href="/devices?device={h(row['ip'])}&tab=activity">
  <span>{index}. {icon_for_device(row['device_type'])} {h(row['name'])}</span>
  <span class="ns-progress-bar"><span style="width:{width:.1f}%"></span></span>
  <b>{formatter(value)}</b>
  <em>{pct:.1f}%</em>
</a>"""
    if not html:
        html = '<div class="ns-dashboard-empty">No client traffic in this range yet.</div>'
    elif source_label == "Live":
        html = '<div class="ns-polish-subtle ns-dashboard-source">Showing live collector speed until today\'s traffic rollup is available.</div>' + html
    return html


def dashboard_quality_panel():
    latest = latest_quality_snapshot()
    quality_range = request.args.get("dash_quality", "1d")
    quality_ranges = {"1d": ("Today", 24), "7d": ("7 Days", 24 * 7), "30d": ("30 Days", 24 * 30)}
    if quality_range not in quality_ranges:
        quality_range = "1d"
    quality_label, quality_hours = quality_ranges[quality_range]
    rows = list(recent_quality(connect_db, hours=quality_hours, limit=2000))
    status = str(latest["status"]) if latest else "unknown"
    state_class = "ok" if status == "ok" else "danger" if status == "down" else "warn"
    label = "Healthy" if status == "ok" else "Down" if status == "down" else "Warning" if status == "warn" else "No Data"
    reason = str(latest["diagnosis"]) if latest else "No internet quality samples have been collected yet."

    chart_rows = rows
    if len(chart_rows) > 240:
        step = max(1, math.ceil(len(chart_rows) / 240))
        chart_rows = chart_rows[::step]
    chart_labels = [str(row["ts"] or "")[5:16] for row in chart_rows]
    chart_gateway = [row["gateway_latency_ms"] for row in chart_rows]
    chart_internet = [row["internet_latency_ms"] for row in chart_rows]
    chart_jitter = [row["jitter_ms"] for row in chart_rows]
    chart_loss = [row["internet_loss_pct"] for row in chart_rows]

    if not chart_labels and latest:
        chart_labels = [str(latest["ts"] or "")[5:16] or "Latest"]
        chart_gateway = [latest["gateway_latency_ms"]]
        chart_internet = [latest["internet_latency_ms"]]
        chart_jitter = [latest["jitter_ms"]]
        chart_loss = [latest["internet_loss_pct"]]

    labels = json.dumps(chart_labels)
    gateway = json.dumps(chart_gateway)
    internet = json.dumps(chart_internet)
    jitter = json.dumps(chart_jitter)
    loss = json.dumps(chart_loss)
    metric = lambda title, value, suffix="", numeric=True, element_id="": f"""
<div class="ns-mini-metric">
  <span>{h(title)}</span>
  <b{f' id="{h(element_id)}"' if element_id else ""}>{h(quality_value(value, suffix) if numeric else (str(value or "").strip() or "-"))}</b>
</div>"""
    isp_label = "-"
    public_ip_label = "-"
    if latest:
        isp_label = str(latest["isp_name"] or latest["isp_org"] or latest["asn"] or "").strip() or "Not detected"
        public_ip_label = str(latest["public_ip"] or "").strip() or "Not detected"
    range_links = ""
    for key, (label_text, _hours) in quality_ranges.items():
        active = " is-active" if key == quality_range else ""
        range_links += f'<a class="{active}" href="/?range={range_key()}&dash_quality={key}#dashboardQualityHeading">{h(label_text)}</a>'
    return f"""
<section class="ns-polish-panel" aria-labelledby="dashboardQualityHeading">
  <div class="ns-polish-header">
    <div>
      <h2 id="dashboardQualityHeading" class="ns-polish-section-title">Internet Quality <span class="ns-chip ns-chip--{state_class}">{h(label)}</span></h2>
      <div class="ns-polish-subtle">{h(reason)} · Showing {h(quality_label)}</div>
    </div>
    <div class="ns-quality-range">{range_links}</div>
  </div>
  <div class="ns-mini-metrics">
    {metric("Gateway", latest["gateway_latency_ms"] if latest else None, " ms", element_id="dashboardQualityGateway")}
    {metric("Internet", latest["internet_latency_ms"] if latest else None, " ms", element_id="dashboardQualityInternet")}
    {metric("Packet Loss", latest["internet_loss_pct"] if latest else None, "%", element_id="dashboardQualityLoss")}
    {metric("Jitter", latest["jitter_ms"] if latest else None, " ms", element_id="dashboardQualityJitter")}
    {metric("DNS Response", latest["dns_ms"] if latest else None, " ms", element_id="dashboardQualityDns")}
    {metric("ISP", isp_label, numeric=False, element_id="dashboardQualityIsp")}
    {metric("Public IP", public_ip_label, numeric=False, element_id="dashboardQualityPublicIp")}
  </div>
  <div class="ns-quality-chart">
    {('<canvas id="dashboardQualityChart" role="img" aria-label="Internet quality graph"></canvas>' if chart_labels else '<div class="ns-dashboard-empty">No quality samples yet.</div>')}
  </div>
</section>
<script>
const dashboardQualityCanvas = document.getElementById("dashboardQualityChart");
if (dashboardQualityCanvas && typeof Chart !== "undefined") {{
  new Chart(dashboardQualityCanvas, {{
    type: "line",
    data: {{
      labels: {labels},
      datasets: [
        {{label: "Gateway latency", data: {gateway}, borderColor: "#22d67a", backgroundColor: "rgba(34,214,122,.08)", tension: .28, pointRadius: 0, spanGaps: true}},
        {{label: "Internet latency", data: {internet}, borderColor: "#1688ff", backgroundColor: "rgba(22,136,255,.08)", tension: .28, pointRadius: 0, spanGaps: true}},
        {{label: "Jitter", data: {jitter}, borderColor: "#a68bff", backgroundColor: "rgba(166,139,255,.08)", tension: .28, pointRadius: 0, spanGaps: true}},
        {{label: "Loss %", data: {loss}, borderColor: "#ffb020", backgroundColor: "rgba(255,176,32,.08)", tension: .28, pointRadius: 0, spanGaps: true, yAxisID: "loss"}}
      ]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {{ legend: {{ labels: {{ color: "#a4b1c6", boxWidth: 10 }} }} }},
      scales: {{
        x: {{ ticks: {{ color: "#8ea0b8", maxTicksLimit: 6 }}, grid: {{ color: "rgba(148,163,184,.06)" }} }},
        y: {{ beginAtZero: true, ticks: {{ color: "#8ea0b8", maxTicksLimit: 5 }}, grid: {{ color: "rgba(148,163,184,.10)" }} }},
        loss: {{ position: "right", beginAtZero: true, ticks: {{ color: "#8ea0b8", maxTicksLimit: 4 }}, grid: {{ drawOnChartArea: false }} }}
      }}
    }}
  }});
}}
</script>"""


def collector_system_card(health):
    if health["collector_state"] == "OK":
        return f"""<div class="card"><div class="label">Collector</div><span class="big green">{health['collector_state']}</span></div>"""
    if health["collector_state"] in ("Updating", "Starting"):
        return f"""<div class="card"><div class="label">Collector</div><span class="big yellow">{health['collector_state']}</span><p class="sub">Update in progress. The collector will restart automatically.</p></div>"""
    if health["collector_state"] == "Disk Full":
        return f"""<div class="card"><div class="label">Collector</div><span class="big red">{health['collector_state']}</span><p class="sub">Free disk space before restarting the collector.</p></div>"""
    return f"""
<form class="card" method="post" action="/collector/restart">
  {csrf_input()}
  <input type="hidden" name="return_to" value="/system">
  <button type="submit" style="background:none; border:0; padding:0; margin:0; width:100%; min-height:82px; text-align:left; color:inherit; cursor:pointer;">
    <div class="label">Collector</div>
    <span class="big yellow">{health['collector_state']}</span>
    <small>Click to restart</small>
  </button>
</form>"""


@app.route("/api/dashboard-apps")
def api_dashboard_apps():
    return {"html": dashboard_app_rows()}


@app.route("/api/dashboard-health")
def api_dashboard_health():
    health = system_health_snapshot()
    adguard_ok, adguard_status = ag_get("/status")
    protection_enabled = adguard_status.get("protection_enabled") if adguard_ok and isinstance(adguard_status, dict) else None
    protection_text = "ON" if protection_enabled is True else "OFF" if protection_enabled is False else "UNKNOWN"
    protection_class = "green" if protection_enabled is True else "red" if protection_enabled is False else "yellow"
    protection_detail = "AdGuard filtering" if protection_enabled is not None else "AdGuard unavailable"
    return {
        "health_html": dashboard_health_cards(health),
        "protection_text": protection_text,
        "protection_class": protection_class,
        "protection_detail": protection_detail,
    }


@app.route("/")
def dashboard():
    c = cfg()
    fast_page_mode = bool(c.get("fast_page_mode", True))
    down = up = total = 0
    active = blocked = dns_total = unique_domains = blocked_domains = 0
    blocked_pct = 0
    live_down_bps = live_up_bps = live_total_bps = 0
    traffic_range_label = {
        "1d": "Today",
        "7d": "Last 7 Days",
        "30d": "Last 30 Days",
        "60d": "Last 60 Days",
        "90d": "Last 90 Days",
    }.get(range_key(), "Today")
    dashboard_period = {"1d": "24h", "7d": "7d", "30d": "30d", "60d": "60d", "90d": "90d"}.get(range_key(), "24h")
    protection_text = "LOADING"
    protection_class = "yellow"
    protection_detail = "Loading AdGuard status"
    app_rows = '<p class="sub">Loading applications...</p>'
    health_cards = '<div class="ns-dashboard-empty">Loading system health...</div>'
    live_speed = live_network_speed()
    live_down_bps = float(live_speed.get("rx_bps") or 0)
    live_up_bps = float(live_speed.get("tx_bps") or 0)
    live_total_bps = float(live_speed.get("total_bps") or 0)
    snapshot_devices = live_snapshot.summary().get("devices")
    if isinstance(snapshot_devices, dict) and snapshot_devices.get("online") is not None:
        active = int(snapshot_devices.get("online") or 0)

    body = f"""
{topbar("Dashboard")}
<style>
.ns-dashboard {{ display:flex; flex-direction:column; gap:16px; }}
.ns-dashboard-icon {{ width:24px; height:24px; object-fit:contain; flex:0 0 24px; }}
.ns-dashboard-card-icon {{ width:20px; height:20px; object-fit:contain; flex:0 0 20px; }}
.ns-dashboard-row-icon {{ width:22px; height:22px; object-fit:contain; flex:0 0 22px; }}
.ns-dashboard a:focus-visible,
.ns-dashboard button:focus-visible {{ outline:2px solid var(--ns-brand-cyan); outline-offset:2px; }}
.dash-actions {{ display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }}
.dash-left-actions {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
.dashboard-update-form {{ display:none; align-items:center; margin:0; }}
.dashboard-update-form button,
.speed-test-form button {{ min-height:38px; border-radius:8px; cursor:pointer; font-weight:800; display:inline-flex; align-items:center; justify-content:center; gap:8px; }}
.dashboard-update-form button {{ border:1px solid rgba(248,200,78,.48); background:rgba(248,200,78,.14); color:#f8c84e; padding:8px 12px; }}
.speed-test-form {{ display:flex; align-items:center; gap:10px; margin:0; }}
.speed-test-form button {{ border:1px solid rgba(22,136,255,.42); background:rgba(22,136,255,.16); color:#e9f3ff; padding:8px 13px; }}
.speed-test-form small {{ color:var(--ns-text-muted); font-weight:700; }}
.ns-dashboard__kpi-grid {{
  display:grid;
  grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));
  gap:10px;
  position:relative;
}}
.ns-kpi-card {{
  display:flex;
  gap:12px;
  min-width:0;
  min-height:104px;
  padding:14px;
  border:1px solid var(--ns-border);
  border-radius:8px;
  background:var(--ns-bg-card);
  color:var(--ns-text-primary);
  text-decoration:none;
}}
.ns-kpi-card:hover {{ border-color:var(--ns-border-hover); background:var(--ns-bg-card-hover); }}
.ns-kpi-card__icon {{
  width:42px;
  height:42px;
  display:grid;
  place-items:center;
  flex:0 0 42px;
  border-radius:8px;
  background:rgba(22,136,255,.1);
}}
.ns-kpi-card > span:last-child {{ min-width:0; }}
.ns-kpi-card .label {{ color:var(--ns-text-muted); font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.06em; }}
.ns-kpi-card__value {{ display:block; margin-top:7px; overflow:hidden; color:var(--ns-text-primary); font-size:24px; font-weight:900; line-height:1.05; text-overflow:ellipsis; white-space:nowrap; }}
.ns-kpi-card__meta {{ display:block; margin-top:7px; overflow:hidden; color:var(--ns-text-secondary); font-size:12px; font-weight:700; text-overflow:ellipsis; white-space:nowrap; }}
.dash-summary-loading {{
  position:absolute;
  left:50%;
  top:50%;
  transform:translate(-50%, -50%);
  padding:5px 10px;
  border-radius:999px;
  color:#9aa7bb;
  background:rgba(7,17,38,.78);
  border:1px solid rgba(91,168,255,.22);
  font-size:11px;
  font-weight:900;
  letter-spacing:.04em;
  pointer-events:none;
  z-index:2;
}}
.dash-summary-loading.hidden {{ display:none; }}
.ns-dashboard-error {{
  display:none;
  padding:10px 12px;
  border:1px solid rgba(248,200,78,.32);
  border-radius:8px;
  background:rgba(248,200,78,.09);
  color:#ffd978;
  font-size:13px;
  font-weight:700;
}}
.ns-dashboard-error.is-visible {{ display:block; }}
.ns-dashboard-grid {{ display:grid; grid-template-columns:minmax(min(100%, 460px), 1.35fr) repeat(2, minmax(min(100%, 300px), .8fr)); gap:12px; align-items:stretch; }}
.ns-dashboard-lower {{ display:grid; grid-template-columns:minmax(0, 1.55fr) minmax(min(100%, 380px), .95fr); gap:14px; align-items:start; }}
.ns-dashboard-lower > .ns-polish-panel {{ min-height:380px; }}
.ns-chart-card,
.ns-list-card {{
  min-height:260px;
  border:1px solid var(--ns-border);
  border-radius:12px;
  background:var(--ns-bg-card);
  padding:16px;
}}
.ns-dashboard-card-header {{ display:flex; align-items:flex-start; justify-content:space-between; gap:12px; margin-bottom:14px; }}
.ns-dashboard-card-title {{ display:flex; align-items:center; gap:9px; }}
.ns-dashboard-card-title h2 {{ margin:0; color:var(--ns-text-primary); font-size:17px; }}
.ns-dashboard-card-title small {{ display:block; margin-top:4px; color:var(--ns-text-muted); font-size:12px; font-weight:700; }}
.dash-app-row {{ display:grid; grid-template-columns:minmax(110px, 1fr) minmax(70px, 1fr) 58px 48px; align-items:center; gap:10px; margin:8px 0; padding:9px 10px; border-radius:8px; background:#0a1421; }}
.dash-app-row {{ color:#f4f7fb; text-decoration:none; border:1px solid transparent; }}
.dash-app-row:hover {{ border-color:var(--ns-border-hover); background:#111f31; }}
.dash-app-name {{ display:flex; align-items:center; gap:12px; }}
.dash-app-name span {{ min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.dash-app-bar {{ height:8px; background:#2a374b; border-radius:999px; overflow:hidden; }}
.dash-app-bar span {{ display:block; height:100%; background:linear-gradient(90deg, #00ddc7, #5ba8ff); border-radius:999px; }}
.dash-app-row em {{ color:#b7c7d8; font-style:normal; }}
.dash-chart {{ height:220px; position:relative; }}
.dash-chart canvas {{ max-height:220px; }}
.dash-chart-empty {{
  position:absolute;
  inset:0;
  display:none;
  align-items:center;
  justify-content:center;
  border:1px dashed var(--ns-border);
  border-radius:8px;
  color:var(--ns-text-secondary);
  background:rgba(7,17,30,.34);
  font-size:13px;
  font-weight:700;
  text-align:center;
}}
.dash-chart-empty.is-visible {{ display:flex; }}
.legend {{ display:flex; align-items:center; gap:18px; color:#cbd6e3; margin-bottom:8px; flex-wrap:wrap; }}
.legend .legend-live {{ margin-left:auto; font-size:16px; }}
.chart-legend {{ display:flex; align-items:center; gap:14px; margin-top:8px; color:#b8c7da; font-size:13px; font-weight:800; }}
.chart-legend span {{ display:flex; align-items:center; gap:7px; }}
.chart-legend b {{ display:inline-block; width:26px; height:4px; border-radius:999px; }}
.chart-legend .download {{ background:#18aaff; }}
.chart-legend .upload {{ background:#9c6cff; }}
.ns-dashboard__secondary-grid {{ display:grid; grid-template-columns:1fr; gap:10px; }}
.ns-health-grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:8px 12px; align-items:start; }}
.ns-health-card {{
  display:flex;
  align-items:center;
  gap:12px;
  min-width:0;
  min-height:52px;
  padding:8px 10px;
  border:0;
  border-bottom:1px solid rgba(80,112,150,.14);
  border-radius:0;
  background:transparent;
}}
.ns-health-card:nth-last-child(-n+2) {{ border-bottom:0; }}
.ns-health-card > div {{ min-width:0; flex:1 1 auto; }}
.ns-health-card span {{ display:block; color:var(--ns-text-muted); font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.05em; }}
.ns-health-card b {{ display:block; margin-top:4px; overflow:hidden; color:var(--ns-text-primary); font-size:17px; text-overflow:ellipsis; white-space:nowrap; }}
.ns-health-card small {{ display:block; margin-top:4px; overflow:hidden; color:var(--ns-text-secondary); font-size:11px; text-overflow:ellipsis; white-space:nowrap; }}
.ns-health-meter {{ width:100%; height:4px; margin-top:8px; overflow:hidden; border-radius:999px; background:#1d2d43; }}
.ns-health-meter i {{ display:block; height:100%; border-radius:999px; background:linear-gradient(90deg, #00d6ff, #1688ff); }}
.collector-restart-card {{ margin:0; }}
.collector-restart-card button {{ display:flex; align-items:center; gap:12px; width:100%; padding:0; border:0; background:transparent; color:inherit; text-align:left; cursor:pointer; font:inherit; }}
.ns-dashboard-empty {{ padding:16px; border:1px dashed var(--ns-border); border-radius:8px; color:var(--ns-text-secondary); text-align:center; }}
.blue {{ color:#5ba8ff !important; }} .purple {{ color:#a68bff !important; }} .teal {{ color:#00ddc7 !important; }} .green {{ color:#20df9f !important; }} .red {{ color:#ff526c !important; }} .yellow {{ color:#f8c84e !important; }}
@media (min-width:1500px) {{ .ns-dashboard-grid {{ grid-template-columns:minmax(520px, 1.45fr) minmax(320px, .78fr) minmax(320px, .78fr); }} .ns-dashboard-lower {{ grid-template-columns:minmax(0, 1.6fr) minmax(440px, .9fr); }} }}
@media (max-width:1280px) {{ .ns-dashboard-grid, .ns-dashboard-lower {{ grid-template-columns:1fr; }} .ns-dashboard-lower > .ns-polish-panel {{ min-height:0; }} }}
@media (max-width:700px) {{
  .ns-dashboard__kpi-grid, .ns-dashboard-grid, .ns-dashboard-lower, .ns-health-grid {{ grid-template-columns:1fr; }}
  .dash-actions {{ align-items:stretch; }}
  .speed-test-form {{ flex-direction:column; align-items:stretch; }}
  .ns-chart-card, .ns-list-card {{ padding:13px; }}
  .legend .legend-live {{ margin-left:0; font-size:13px; }}
  .dash-app-row {{ grid-template-columns:minmax(0, 1fr) auto; gap:9px; }}
  .dash-app-name, .dash-app-bar {{ grid-column:1 / -1; }}
}}
</style>

<div class="ns-dashboard">
  <div class="dash-actions">
    <div class="dash-left-actions">
      {time_picker()}
      <form id="dashboardUpdateButton" class="dashboard-update-form" method="post" action="/system">
        {csrf_input()}
        <button type="submit" aria-label="Update NetSpecter"><i class="fa-solid fa-cloud-arrow-down" aria-hidden="true"></i> Update Available</button>
      </form>
    </div>
    <form method="post" action="/speed-test" class="speed-test-form">
      {csrf_input()}
      <small>Uses internet data once</small>
      <button type="submit"><i class="fa-solid fa-gauge-high" aria-hidden="true"></i> Run Speed Test</button>
    </form>
  </div>

  <div id="dashboardErrorState" class="ns-dashboard-error" role="status" aria-live="polite"></div>

  <div class="ns-dashboard__kpi-grid">
    <div id="dashboardSummaryLoading" class="dash-summary-loading">Loading...</div>
    <a class="ns-kpi-card" href="/traffic">
      <span class="ns-kpi-card__icon">{dashboard_png_icon("traffic")}</span>
      <span><span class="label">Total Traffic</span><b id="dashboardTrafficTotal" class="ns-kpi-card__value teal">{fmt_mb(total)}</b><small class="ns-kpi-card__meta">Down <span id="dashboardTrafficDown">{fmt_mb(down)}</span> | Up <span id="dashboardTrafficUp">{fmt_mb(up)}</span></small></span>
    </a>
    <a class="ns-kpi-card" href="/applications">
      <span class="ns-kpi-card__icon">{dashboard_png_icon("network")}</span>
      <span><span class="label">DNS Queries</span><b id="dashboardDnsTotal" class="ns-kpi-card__value">{dns_total:,}</b><small class="ns-kpi-card__meta"><span id="dashboardUniqueDomains">{unique_domains:,}</span> domains</small></span>
    </a>
    <a class="ns-kpi-card" href="/devices">
      <span class="ns-kpi-card__icon">{dashboard_png_icon("devices")}</span>
      <span><span class="label">Active Devices</span><b id="dashboardTrafficDevices" class="ns-kpi-card__value blue">{active}</b><small class="ns-kpi-card__meta">Seen in {traffic_range_label}</small></span>
    </a>
    <a class="ns-kpi-card" href="/blocked">
      <span class="ns-kpi-card__icon">{dashboard_png_icon("blocked")}</span>
      <span><span class="label">Blocked Queries</span><b id="dashboardBlocked" class="ns-kpi-card__value red">{blocked:,}</b><small class="ns-kpi-card__meta">Blocked domains: <span id="dashboardBlockedDomains">{blocked_domains:,}</span></small></span>
    </a>
    <a class="ns-kpi-card" href="/adguard">
      <span class="ns-kpi-card__icon">{dashboard_png_icon("adguard")}</span>
      <span><span class="label">Protection</span><b id="dashboardProtection" class="ns-kpi-card__value {protection_class}">{protection_text}</b><small id="dashboardProtectionDetail" class="ns-kpi-card__meta">{protection_detail}</small></span>
    </a>
  </div>

  <div class="ns-dashboard-grid">
    <section class="ns-chart-card" aria-labelledby="dashboardTrafficHeading">
      <div class="ns-dashboard-card-header">
        <div class="ns-dashboard-card-title">{dashboard_png_icon("traffic", "ns-dashboard-card-icon")}<div><h2 id="dashboardTrafficHeading">Network Traffic</h2><small>{traffic_range_label}</small></div></div>
      </div>
      <div class="legend">
        <span><i class="fa-solid fa-circle blue"></i> Download / Downstream</span>
        <span><i class="fa-solid fa-circle purple"></i> Upload / Upstream</span>
        <b class="blue legend-live">DL <span data-live-network="1" data-live-field="down">{fmt_bits_as_bytes(live_down_bps)}</span> | UL <span data-live-network="1" data-live-field="up">{fmt_bits_as_bytes(live_up_bps)}</span> | Total <span data-live-network="1" data-live-field="total">{fmt_bits_as_bytes(live_total_bps)}</span></b>
      </div>
      <div class="dash-chart">
        <canvas id="dashboardTrafficChart" role="img" aria-label="Network traffic download and upload chart for {traffic_range_label}"></canvas>
        <div id="dashboardTrafficEmpty" class="dash-chart-empty">No traffic data in this range yet.</div>
      </div>
      <div class="chart-legend">
        <span><b class="download"></b> Download</span>
        <span><b class="upload"></b> Upload</span>
      </div>
    </section>

    <section class="ns-list-card" aria-labelledby="dashboardAppsHeading">
      <div class="ns-dashboard-card-header">
        <div class="ns-dashboard-card-title">{dashboard_png_icon("network", "ns-dashboard-card-icon")}<div><h2 id="dashboardAppsHeading">Top DNS Applications</h2><small>DNS-attributed query activity</small></div></div>
      </div>
      <div id="dashboardTopApps">{app_rows or '<p>No application data yet</p>'}</div>
    </section>

    <section class="ns-list-card" aria-labelledby="dashboardClientsHeading">
      <div class="ns-dashboard-card-header">
        <div class="ns-dashboard-card-title">{dashboard_png_icon("devices", "ns-dashboard-card-icon")}<div><h2 id="dashboardClientsHeading">Top Devices</h2><small>Top 5 by data used today</small></div></div>
        <a class="ns-compact-button" href="/devices?range={range_key()}">View all</a>
      </div>
      {dashboard_top_clients()}
    </section>
  </div>

  <div class="ns-dashboard-lower">
    {dashboard_quality_panel()}
    <section class="ns-polish-panel" aria-labelledby="dashboardHealthHeading">
      <div class="ns-polish-header">
        <div><h2 id="dashboardHealthHeading" class="ns-polish-section-title">System Health</h2><div class="ns-polish-subtle">Appliance status</div></div>
        <a class="ns-compact-button" href="/health">Details</a>
      </div>
      <div class="ns-health-grid" id="dashboardHealthCards">
        {health_cards}
      </div>
    </section>
  </div>

</div>
<script>
let dashboardTrafficChart = null;
const dashboardFastMode = {json.dumps(fast_page_mode)};
async function dashboardFetch(url, timeoutMs = 8000) {{
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {{
    return await fetch(url, {{cache: "no-store", signal: controller.signal}});
  }} finally {{
    clearTimeout(timer);
  }}
}}
function setDashboardError(message) {{
  const error = document.getElementById("dashboardErrorState");
  if (!error) return;
  if (message) {{
    error.textContent = message;
    error.classList.add("is-visible");
  }} else {{
    error.textContent = "";
    error.classList.remove("is-visible");
  }}
}}
async function loadDashboardSummary() {{
  try {{
    const response = await dashboardFetch("/api/dashboard-summary?range={range_key()}");
    if (!response.ok) {{
      setDashboardError("Dashboard summary data is temporarily unavailable.");
      return;
    }}
    const data = await response.json();
    const setText = (id, value) => {{
      const el = document.getElementById(id);
      if (el) el.textContent = value;
    }};
    setText("dashboardTrafficTotal", data.traffic_total);
    setText("dashboardTrafficDown", data.traffic_down);
    setText("dashboardTrafficUp", data.traffic_up);
    setText("dashboardTrafficDevices", Number(data.active_devices).toLocaleString());
    setText("dashboardBlocked", Number(data.blocked).toLocaleString());
    setText("dashboardBlockedDomains", Number(data.blocked_domains).toLocaleString());
    setText("dashboardDnsTotal", Number(data.dns_total).toLocaleString());
    setText("dashboardUniqueDomains", Number(data.unique_domains).toLocaleString());
    const loading = document.getElementById("dashboardSummaryLoading");
    if (loading) loading.classList.add("hidden");
    setDashboardError("");
  }} catch (error) {{
    console.log("Dashboard summary refresh failed:", error);
    setDashboardError("Dashboard summary data is temporarily unavailable.");
    const loading = document.getElementById("dashboardSummaryLoading");
    if (loading) loading.classList.add("hidden");
  }}
}}
async function loadDashboardTraffic() {{
  try {{
    if (typeof Chart === "undefined") {{
      console.log("Dashboard chart library not loaded");
      return;
    }}
    const canvas = document.getElementById("dashboardTrafficChart");
    if (!canvas) return;
    const response = await dashboardFetch("/api/history?period={dashboard_period}", 10000);
    if (!response.ok) {{
      console.log("Dashboard traffic graph request failed");
      setDashboardError("Dashboard traffic history is temporarily unavailable.");
      return;
    }}
    const data = await response.json();
    const empty = document.getElementById("dashboardTrafficEmpty");
    const hasData = (data.total || []).some(value => Number(value) > 0);
    if (empty) empty.classList.toggle("is-visible", !hasData);
    const context = canvas.getContext("2d");
    if (dashboardTrafficChart) dashboardTrafficChart.destroy();
    dashboardTrafficChart = new Chart(context, {{
      type: "bar",
      data: {{
        labels: data.labels || [],
        datasets: [
          {{ label: "Download", data: data.downloaded || [], borderColor: "#18aaff", backgroundColor: "rgba(24,170,255,.72)", borderWidth: 1 }},
          {{ label: "Upload", data: data.uploaded || [], borderColor: "#9c6cff", backgroundColor: "rgba(156,108,255,.72)", borderWidth: 1 }}
        ]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {{
          legend: {{ display: false }},
          tooltip: {{
            backgroundColor: "rgba(7, 16, 27, .96)",
            titleColor: "#f5f8ff",
            bodyColor: "#cbd6e3",
            borderColor: "rgba(99, 179, 237, .28)",
            borderWidth: 1,
            displayColors: true
          }}
        }},
        scales: {{
          y: {{
            beginAtZero: true,
            title: {{ display: true, text: "MB", color: "#9aa7bb" }},
            ticks: {{ color: "#9aa7bb", maxTicksLimit: 5 }},
            grid: {{ color: "rgba(148,163,184,.12)" }}
          }},
          x: {{
            ticks: {{ color: "#9aa7bb", maxTicksLimit: 8 }},
            grid: {{ color: "rgba(148,163,184,.07)" }}
          }}
        }}
      }}
    }});
    setDashboardError("");
  }} catch (error) {{
    console.log("Dashboard traffic graph failed:", error);
    setDashboardError("Dashboard traffic history is temporarily unavailable.");
  }}
}}
async function loadDashboardApps() {{
  try {{
    const response = await dashboardFetch("/api/dashboard-apps?range={range_key()}");
    if (!response.ok) {{
      setDashboardError("Dashboard application data is temporarily unavailable.");
      return;
    }}
    const data = await response.json();
    const el = document.getElementById("dashboardTopApps");
    if (el) {{
      const wrap = document.createElement("div");
      wrap.innerHTML = data.html || "<p>No application data yet</p>";
      const rows = Array.from(wrap.querySelectorAll(".dash-app-row")).slice(0, 5);
      if (rows.length) {{
        wrap.innerHTML = "";
        rows.forEach((row) => wrap.appendChild(row));
      }}
      el.innerHTML = wrap.innerHTML || "<p>No application data yet</p>";
    }}
    setDashboardError("");
  }} catch (error) {{
    console.log("Dashboard apps refresh failed:", error);
    setDashboardError("Dashboard application data is temporarily unavailable.");
  }}
}}
async function loadDashboardHealth() {{
  try {{
    const response = await dashboardFetch("/api/dashboard-health", 5000);
    if (!response.ok) {{
      setDashboardError("Dashboard health data is temporarily unavailable.");
      return;
    }}
    const data = await response.json();
    const cards = document.getElementById("dashboardHealthCards");
    if (cards) cards.innerHTML = data.health_html || "";
    const protection = document.getElementById("dashboardProtection");
    if (protection) {{
      protection.textContent = data.protection_text || "UNKNOWN";
      protection.className = "ns-kpi-card__value " + (data.protection_class || "yellow");
    }}
    const protectionStatus = document.getElementById("dashboardProtectionStatusText");
    if (protectionStatus) protectionStatus.textContent = data.protection_text || "UNKNOWN";
    const protectionDetail = document.getElementById("dashboardProtectionDetail");
    if (protectionDetail) protectionDetail.textContent = data.protection_detail || "";
    setDashboardError("");
  }} catch (error) {{
    console.log("Dashboard health refresh failed:", error);
    setDashboardError("Dashboard health data is temporarily unavailable.");
  }}
}}
async function loadDashboardQuality() {{
  try {{
    const response = await dashboardFetch("/api/dashboard-quality", 5000);
    if (!response.ok) return;
    const data = await response.json();
    const setText = (id, value) => {{
      const el = document.getElementById(id);
      if (el) el.textContent = value || "-";
    }};
    setText("dashboardQualityGateway", data.gateway);
    setText("dashboardQualityInternet", data.internet);
    setText("dashboardQualityLoss", data.packet_loss);
    setText("dashboardQualityJitter", data.jitter);
    setText("dashboardQualityDns", data.dns);
    setText("dashboardQualityIsp", data.isp);
    setText("dashboardQualityPublicIp", data.public_ip);
  }} catch (error) {{
    console.log("Dashboard quality refresh failed:", error);
  }}
}}
loadDashboardSummary();
loadDashboardApps();
loadDashboardHealth();
loadDashboardTraffic();
loadDashboardQuality();
if (!dashboardFastMode) {{
  setInterval(loadDashboardSummary, 10000);
  setInterval(loadDashboardApps, 30000);
  setInterval(loadDashboardHealth, 30000);
  setInterval(loadDashboardTraffic, 30000);
  setInterval(loadDashboardQuality, 60000);
}}
</script>
"""

    return shell("NetSpecter Dashboard", body, "Dashboard")


@app.route("/devices", methods=["GET", "POST"])
def devices():
    ensure_device_overrides_table()
    auto_lock_known_vendors()

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        name = request.form.get("name", "").strip()
        vendor = request.form.get("vendor", "").strip() or "Unknown Vendor"
        device_type = request.form.get("device_type", "").strip() or "Unknown"
        status = request.form.get("status", "").strip() or "Active"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if ip:
            run_sql("DELETE FROM device_override_unlocks WHERE ip=?", (ip,))

            # Save manual override in a separate table so collector pulls cannot overwrite it.
            run_sql(
                """
                INSERT INTO device_overrides (ip, name, vendor, device_type, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    name=excluded.name,
                    vendor=excluded.vendor,
                    device_type=excluded.device_type,
                    status=excluded.status,
                    updated_at=excluded.updated_at
                """,
                (ip, name, vendor, device_type, status, now),
            )

            # Also write to devices for compatibility, but the override is the source of truth.
            run_sql(
                """
                UPDATE devices
                SET name=?,
                    vendor=?,
                    device_type=?,
                    status=?
                WHERE ip=?
                """,
                (name, vendor, device_type, status, ip),
            )

        return redirect("/devices")

    sort = request.args.get("sort", "last")
    direction = request.args.get("dir", "desc")
    sort_map = {
        "name": "COALESCE(o.name, d.name, d.ip) COLLATE NOCASE",
        "ip": "d.ip COLLATE NOCASE",
        "mac": "COALESCE(d.mac, '') COLLATE NOCASE",
        "vendor": "COALESCE(o.vendor, d.vendor, 'Unknown Vendor') COLLATE NOCASE",
        "type": "COALESCE(o.device_type, d.device_type, 'Unknown') COLLATE NOCASE",
        "status": "COALESCE(o.status, d.status, 'Active') COLLATE NOCASE",
        "last": "d.last_seen",
    }
    sort_col = sort_map.get(sort, "d.last_seen")
    direction_sql = "ASC" if direction == "asc" else "DESC"

    rows = query(f"""
        SELECT
            d.*,
            COALESCE(o.name, d.name) AS display_name,
            COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS display_vendor,
            COALESCE(o.device_type, d.device_type, 'Unknown') AS display_type,
            COALESCE(o.status, d.status, 'Active') AS display_status,
            COALESCE(o.ignored, 0) AS ignored,
            CASE WHEN o.ip IS NOT NULL THEN 1 ELSE 0 END AS manual_locked,
            o.updated_at AS override_updated_at
        FROM devices d
        LEFT JOIN device_overrides o
            ON o.ip = d.ip
        ORDER BY
            CASE WHEN {sort_col} IS NULL OR {sort_col}='' THEN 1 ELSE 0 END,
            {sort_col} {direction_sql},
            d.ip
    """)

    def sort_link(label, key):
        next_dir = "desc"
        marker = ""
        if sort == key:
            next_dir = "asc" if direction == "desc" else "desc"
            marker = " v" if direction == "desc" else " ^"
        return f'<a class="sort-link" href="/devices?sort={h(key)}&dir={next_dir}">{h(label)}{marker}</a>'

    type_options = [
        "Unknown", "Computer", "Mobile Device", "Apple Device", "Server",
        "Network Device", "Printer", "Camera", "Media Device", "IoT", "Gateway"
    ]
    status_options = ["Active", "Known", "Watch", "DNS Blocked", "Blocked", "OK"]

    lookup_value = request.args.get("lookup", "").strip()
    requested_device = request.args.get("device", "").strip()
    lookup_notice = ""
    def requested_device_matches(row):
        requested_text = requested_device.lower()
        requested_mac = re.sub(r"[^0-9a-f]", "", requested_text)
        row_mac = re.sub(r"[^0-9a-f]", "", str(row["mac"] or "").lower())
        return (
            requested_text
            and (
                str(row["ip"] or "").lower() == requested_text
                or str(row["mac"] or "").lower() == requested_text
                or (requested_mac and requested_mac == row_mac)
            )
        )

    if lookup_value and not requested_device:
        lookup_text = lookup_value.lower()
        lookup_mac = re.sub(r"[^0-9a-f]", "", lookup_text)
        def row_mac(row):
            return re.sub(r"[^0-9a-f]", "", str(row["mac"] or "").lower())
        exact_match = next((
            row for row in rows
            if lookup_text in {
                str(row["ip"] or "").lower(),
                str(row["mac"] or "").lower(),
                str(row["display_name"] or "").lower(),
            }
            or (lookup_mac and lookup_mac == row_mac(row))
        ), None)
        partial_match = exact_match or next((
            row for row in rows
            if lookup_text
            and (
                lookup_text in str(row["display_name"] or "").lower()
                or lookup_text in str(row["mac"] or "").lower()
                or lookup_text in str(row["ip"] or "").lower()
                or (lookup_mac and lookup_mac in row_mac(row))
            )
        ), None)
        if partial_match:
            requested_device = str(partial_match["ip"])
            lookup_notice = f'<div class="setup-ok">Device matched: {h(partial_match["display_name"] or partial_match["ip"])}</div>'
        else:
            lookup_notice = f'<div class="setup-warning">No device matched {h(lookup_value)}.</div>'
    if requested_device:
        rows = sorted(rows, key=lambda row: 0 if requested_device_matches(row) else 1)

    live_speeds = live_all_host_speeds()
    table = ""
    total_devices = len(rows)
    online_devices = 0
    offline_devices = 0
    new_devices = 0
    first_device = next((row for row in rows if requested_device_matches(row)), rows[0] if rows else None)

    for idx, r in enumerate(rows):
        last_age = device_age_seconds(r["last_seen"])
        first_age = device_age_seconds(r["first_seen"])
        is_online = last_age is not None and last_age <= 300
        is_new = first_age is not None and first_age <= 86400
        online_devices += 1 if is_online else 0
        offline_devices += 0 if is_online else 1
        new_devices += 1 if is_new else 0
        ip = h(r["ip"])
        name = h(r["display_name"] or r["ip"])
        mac = h(r["mac"])
        vendor = h(r["display_vendor"] or "Unknown Vendor")
        dtype = h(r["display_type"] or "Unknown")
        status = h(r["display_status"] or "Active")
        ignored = int(r["ignored"] or 0)
        last_seen = h(r["last_seen"])
        device_icon = icon_for_device(r["display_type"] or "Unknown")
        status_chip = "online" if is_online else "offline"
        attention_chip = '<span class="ns-chip ns-chip--warn">Ignored</span>' if ignored else ''
        lifecycle_badges = device_lifecycle_badges(r["first_seen"], r["last_seen"])
        lock_badge = (
            f'<form class="unlock-device-form" method="post" action="/device/unlock/{ip}" '
            f'onsubmit="return confirm(\'Unlock this device and clear its saved identity details?\');">'
            f'{csrf_input()}<button class="badge-lock unlock-badge" type="submit" '
            f'title="Unlock and clear saved identity details">Locked <i class="fa-solid fa-lock-open"></i></button></form>'
        ) if r["manual_locked"] else ''
        private_badge = '<span class="badge-private">Private MAC</span>' if private_mac_address(r["mac"]) else ''

        type_select = '<select class="edit-field" data-field="device_type" style="display:none; max-width:150px;">'
        for opt in type_options:
            selected = " selected" if opt == (r["display_type"] or "Unknown") else ""
            type_select += f'<option value="{h(opt)}"{selected}>{h(opt)}</option>'
        type_select += '</select>'

        status_select = '<select class="edit-field" data-field="status" style="display:none; max-width:120px;">'
        for opt in status_options:
            selected = " selected" if opt == (r["display_status"] or "Active") else ""
            status_select += f'<option value="{h(opt)}"{selected}>{h(opt)}</option>'
        status_select += '</select>'

        live_data = live_speeds.get(str(r["ip"]), {"rx_bps": 0.0, "tx_bps": 0.0, "total_bps": 0.0})
        live_total = fmt_bits_as_bytes(live_data.get("total_bps", 0))
        live_rx = fmt_bits_as_bytes(live_data.get("rx_bps", 0))
        live_tx = fmt_bits_as_bytes(live_data.get("tx_bps", 0))

        selected_cls = " is-selected" if first_device and r["ip"] == first_device["ip"] else ""
        table += f"""
<tr class="ns-device-row{selected_cls}" data-ip="{ip}" data-name="{name}" data-mac="{mac}" data-vendor="{vendor}" data-type="{dtype}" data-status="{status}" data-ignored="{ignored}" data-last="{last_seen}" data-first="{h(r['first_seen'] or '-')}" data-online="{'Online' if is_online else 'Offline'}" data-total="{live_total}" data-down="{live_rx}" data-up="{live_tx}">
  <td>
    <span class="view-val"><span class="device-type-icon">{device_icon}</span><b>{name}</b> {attention_chip} {lock_badge} {private_badge} {lifecycle_badges}</span>
    <input class="edit-field" data-field="name" value="{name}" style="display:none; max-width:170px;">
    <input class="edit-field" data-field="vendor" value="{vendor}" style="display:none;">
  </td>
  <td class="mono">{ip}</td>
  <td>
    <span class="view-val"><span class="device-type-icon">{device_icon}</span>{dtype}</span>
    {type_select}
  </td>
  <td>
    <span class="view-val ns-chip ns-chip--{status_chip}">{'Online' if is_online else 'Offline'}</span>
    {status_select}
  </td>
  <td><b data-live-ip="{ip}" data-live-field="total">{live_total}</b><br><small>DL <span data-live-ip="{ip}" data-live-field="down">{live_rx}</span> | UL <span data-live-ip="{ip}" data-live-field="up">{live_tx}</span></small></td>
  <td>{last_seen}</td>
  <td><span class="ns-polish-subtle">Select row</span></td>
</tr>
"""

    drawer = '<div class="ns-polish-drawer ns-device-drawer"><div class="ns-dashboard-empty">No devices yet.</div></div>'
    if first_device:
        fd_ip = h(first_device["ip"])
        fd_name = h(first_device["display_name"] or first_device["ip"])
        fd_mac = h(first_device["mac"] or "-")
        fd_vendor = h(first_device["display_vendor"] or "Unknown Vendor")
        fd_type = h(first_device["display_type"] or "Unknown")
        fd_status = h(first_device["display_status"] or "Active")
        fd_ignored = int(first_device["ignored"] or 0)
        fd_last = h(first_device["last_seen"] or "-")
        fd_first = h(first_device["first_seen"] or "-")
        fd_icon = icon_for_device(first_device["display_type"] or "Unknown")
        fd_speed = live_speeds.get(str(first_device["ip"]), {"rx_bps": 0.0, "tx_bps": 0.0, "total_bps": 0.0})
        fd_total = fmt_bits_as_bytes(fd_speed.get("total_bps", 0))
        fd_down = fmt_bits_as_bytes(fd_speed.get("rx_bps", 0))
        fd_up = fmt_bits_as_bytes(fd_speed.get("tx_bps", 0))
        fd_is_online = device_age_seconds(first_device["last_seen"]) is not None and device_age_seconds(first_device["last_seen"]) <= 300
        fd_alerts = query("SELECT COUNT(*) AS total FROM ids_events WHERE src_ip=? OR dest_ip=?", (first_device["ip"], first_device["ip"]))
        fd_dns = query("SELECT COUNT(*) AS total FROM dns_querylog WHERE client=?", (first_device["ip"],))
        fd_traffic = query("SELECT COALESCE(SUM(total_mb), 0) AS total FROM traffic_intervals WHERE ip=? AND day>=?", (first_device["ip"], range_start_day()))
        fd_alert_count = int(fd_alerts[0]["total"] or 0) if fd_alerts else 0
        fd_dns_count = int(fd_dns[0]["total"] or 0) if fd_dns else 0
        fd_traffic_total = fmt_mb(fd_traffic[0]["total"] if fd_traffic else 0)
        drawer = f"""
<aside class="ns-polish-drawer ns-device-drawer" data-drawer-root>
  <div class="ns-drawer-head">
    <div class="ns-drawer-title">
      <span class="device-type-icon">{fd_icon}</span>
      <div><h2 id="deviceDrawerName">{fd_name}</h2><span id="deviceDrawerOnline" class="ns-chip ns-chip--{'online' if fd_is_online else 'offline'}">{'Online' if fd_is_online else 'Offline'}</span> <span id="deviceDrawerIgnored" class="ns-chip ns-chip--warn" style="{'display:inline-flex' if fd_ignored else 'display:none'}">Ignored</span></div>
    </div>
    <div class="ns-tools-wrap">
      <button class="ns-compact-button" type="button" data-tools-trigger>Tools <i class="fa-solid fa-chevron-down"></i></button>
      <div class="ns-tools-menu">
        <a id="deviceToolPing" href="/ping/{fd_ip}"><i class="fa-solid fa-satellite-dish"></i> Ping device</a>
        <a id="deviceToolScan" href="/scan/{fd_ip}"><i class="fa-solid fa-magnifying-glass"></i> Port check</a>
        <button type="button" data-device-dns-lookup><i class="fa-solid fa-globe"></i> DNS lookup</button>
        <button id="deviceToolHistory" type="button" data-drawer-tab-jump="history"><i class="fa-solid fa-clock-rotate-left"></i> Open device history</button>
        <button type="button" data-drawer-tab-jump="overview"><i class="fa-solid fa-tag"></i> Set device label</button>
        <button type="button" data-confirm-target="#confirmIgnoreDevice"><i class="fa-solid fa-eye-slash"></i> <span id="deviceIgnoreMenuText">{'Unignore device' if fd_ignored else 'Ignore device'}</span></button>
        <div class="divider">Security actions</div>
        <button class="danger" type="button" data-confirm-target="#confirmBlockDevice"><i class="fa-solid fa-ban"></i> Block device IP</button>
      </div>
    </div>
  </div>
  <div class="ns-drawer-tabs" role="tablist">
    <button class="is-active" type="button" data-drawer-tab="overview">Overview</button>
    <button type="button" data-drawer-tab="activity">Activity</button>
    <button type="button" data-drawer-tab="history">History</button>
    <button type="button" data-drawer-tab="alerts">Alerts</button>
  </div>
  <div class="ns-drawer-panel is-active" data-drawer-panel="overview">
    <div class="ns-kv">
      <span>IP Address</span><b id="deviceDrawerIp" class="mono">{fd_ip}</b>
      <span>MAC Address</span><b id="deviceDrawerMac" class="mono">{fd_mac}</b>
      <span>Type</span><b id="deviceDrawerType">{fd_type}</b>
      <span>Vendor</span><b id="deviceDrawerVendor">{fd_vendor}</b>
      <span>Status</span><b id="deviceDrawerStatus">{fd_status}</b>
      <span>First Seen</span><b id="deviceDrawerFirst">{fd_first}</b>
      <span>Last Seen</span><b id="deviceDrawerLast">{fd_last}</b>
    </div>
    <form id="deviceLabelForm" method="post" action="/device/{fd_ip}/label" class="ns-drawer-form">
      {csrf_input()}
      <label for="deviceLabelInput">Device label</label>
      <div class="ns-inline-form">
        <input id="deviceLabelInput" name="name" value="{fd_name}" maxlength="80" placeholder="Device label">
        <button class="ns-compact-button" type="submit">Save Label</button>
      </div>
      <small class="ns-polish-subtle">Saved labels override collector names and are reused across dashboard, devices and security views.</small>
    </form>
    <div id="deviceToolResult" class="ns-tool-result" role="status" aria-live="polite">Select DNS lookup from Tools to resolve this device.</div>
  </div>
  <div class="ns-drawer-panel" data-drawer-panel="activity">
    <div class="ns-drawer-range" role="group" aria-label="Device activity range">
      <button class="is-active" type="button" data-device-range="1d">Today</button>
      <button type="button" data-device-range="7d">7 Days</button>
      <button type="button" data-device-range="30d">30 Days</button>
    </div>
    <div class="ns-mini-metrics">
      <div class="ns-mini-metric"><span>Live Total</span><b id="deviceDrawerTotal" data-live-ip="{fd_ip}" data-live-field="total">{fd_total}</b></div>
      <div class="ns-mini-metric"><span>Download</span><b id="deviceDrawerDown" data-live-ip="{fd_ip}" data-live-field="down">{fd_down}</b></div>
      <div class="ns-mini-metric"><span>Upload</span><b id="deviceDrawerUp" data-live-ip="{fd_ip}" data-live-field="up">{fd_up}</b></div>
      <div class="ns-mini-metric"><span>Traffic</span><b>{fd_traffic_total}</b></div>
    </div>
    <div class="ns-device-chart"><canvas id="deviceActivityChart" role="img" aria-label="Selected device traffic history"></canvas></div>
    <div class="ns-drawer-columns">
      <div><h3>Top Applications</h3><div id="deviceTopApps" class="ns-drawer-list"></div></div>
      <div><h3>Recent Domains</h3><div id="deviceTopDomains" class="ns-drawer-list"></div></div>
    </div>
  </div>
  <div class="ns-drawer-panel" data-drawer-panel="history">
    <div class="ns-filter-bar ns-drawer-filter">
      <select id="deviceHistoryType"><option value="">All events</option><option value="inventory">Inventory</option><option value="action">Actions</option><option value="security">Security</option></select>
      <select id="deviceHistoryRange"><option value="1d">Today</option><option value="7d">7 Days</option><option value="30d">30 Days</option></select>
      <button type="button" data-device-history-refresh>Apply</button>
    </div>
    <div id="deviceHistoryList" class="ns-timeline-list"></div>
  </div>
  <div class="ns-drawer-panel" data-drawer-panel="alerts">
    <div class="ns-mini-metrics">
      <div class="ns-mini-metric"><span>IDS Alerts</span><b>{fd_alert_count}</b></div>
      <div class="ns-mini-metric"><span>DNS Queries</span><b>{fd_dns_count:,}</b></div>
    </div>
    <div id="deviceAlertsList" class="ns-drawer-list"></div>
  </div>
</aside>
<div class="ns-confirm-backdrop" id="confirmIgnoreDevice" hidden>
  <div class="ns-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="confirmIgnoreTitle">
    <h3 id="confirmIgnoreTitle"><span id="deviceIgnoreTitle">{'Unignore' if fd_ignored else 'Ignore'}</span> device?</h3>
    <p class="ns-polish-subtle">The device remains in inventory and keeps all history. Ignored devices can be excluded from attention and new-device noise where NetSpecter supports it.</p>
    <form id="deviceIgnoreForm" method="post" action="/device/{fd_ip}/ignore" class="ns-confirm-actions">
      {csrf_input()}
      <input id="deviceIgnoreValue" type="hidden" name="ignored" value="{'0' if fd_ignored else '1'}">
      <button class="ns-compact-button" type="button" data-confirm-close>Cancel</button>
      <button id="deviceIgnoreButton" class="ns-compact-button" type="submit">{'Unignore' if fd_ignored else 'Ignore'} {fd_ip}</button>
    </form>
  </div>
</div>
<div class="ns-confirm-backdrop" id="confirmBlockDevice" hidden>
  <div class="ns-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="confirmBlockTitle">
    <h3 id="confirmBlockTitle">Block device IP?</h3>
    <p class="ns-polish-subtle">This will add <span id="deviceConfirmIp">{fd_ip}</span> to the existing AdGuard disallowed client list. DNS filtering may interrupt internet access for this device until it is resumed.</p>
    <form id="deviceBlockForm" method="post" action="/device/pause/{fd_ip}" class="ns-confirm-actions">
      {csrf_input()}
      <button class="ns-compact-button" type="button" data-confirm-close>Cancel</button>
      <button id="deviceConfirmButton" class="ns-compact-button ns-compact-button--danger" type="submit">Block {fd_ip}</button>
    </form>
  </div>
</div>"""

    type_filter_options = '<option value="">All Types</option>' + "".join(
        f'<option value="{h(value)}">{h(value)}</option>'
        for value in sorted({str(row["display_type"] or "Unknown") for row in rows})
    )
    status_filter_options = """
<option value="">All Status</option>
<option value="online">Online</option>
<option value="offline">Offline</option>
<option value="Active">Active</option>
<option value="DNS Blocked">DNS Blocked</option>
<option value="Blocked">Blocked</option>
<option value="Watch">Watch</option>
"""

    body = f"""
{topbar("Devices")}
<style>
.badge-lock,
.badge-new,
.badge-online,
.badge-offline,
.badge-unknown {{
  display:inline-block;
  margin-left:8px;
  padding:2px 7px;
  border-radius:999px;
  font-size:11px;
  border:1px solid rgba(255,255,255,.12);
}}
.badge-lock {{ background:rgba(0, 220, 200, 0.16); color:#28e0d5; }}
.unlock-device-form {{ display:inline; margin:0; }}
.unlock-badge {{ font:inherit; cursor:pointer; }}
.unlock-badge:hover {{ background:rgba(0, 220, 200, 0.28); color:#eaffff; }}
.badge-private {{ display:inline-block; margin-left:8px; padding:2px 7px; border-radius:999px; font-size:11px; border:1px solid rgba(248,200,78,.28); background:rgba(248,200,78,.12); color:#f8c84e; }}
.badge-new {{ background:rgba(0, 170, 255, 0.16); color:#58c7ff; }}
.badge-online {{ background:rgba(54, 239, 126, 0.14); color:#36ef7e; }}
.badge-offline {{ background:rgba(255, 56, 96, 0.14); color:#ff6b85; }}
.badge-unknown {{ background:rgba(255, 209, 102, 0.14); color:#ffd166; }}
.device-type-icon {{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  width:26px;
  height:26px;
  margin-right:8px;
  border-radius:8px;
  background:rgba(0, 190, 255, .10);
  color:#5fc7ff;
}}
#deviceTable td {{ vertical-align: middle; }}
#deviceTable input, #deviceTable select {{
  border-radius:6px;
  border:1px solid rgba(255,255,255,.25);
  padding:6px 8px;
}}
</style>
<div class="ns-device-page">
  <div>
    {lookup_notice}
    <form class="ns-filter-bar ns-device-filter-bar" method="get" action="/devices">
      <input type="hidden" name="tab" value="activity">
      <input class="ns-device-lookup-input" name="lookup" value="{h(lookup_value)}" placeholder="IP, MAC, or device name">
      <button class="ns-compact-button" type="submit">Show Device Activity</button>
      <input id="deviceSearch" class="ns-device-search-input" placeholder="Search devices..." onkeyup="filterDevices()">
      <select id="deviceTypeFilter" aria-label="Device type filter" onchange="filterDevices()">{type_filter_options}</select>
      <select id="deviceStatusFilter" aria-label="Device status filter" onchange="filterDevices()">{status_filter_options}</select>
      <a href="/devices">Refresh</a>
    </form>
    <div class="ns-device-summary">
      <div class="ns-polish-card"><span class="label">Total Devices</span><b class="big">{total_devices}</b></div>
      <div class="ns-polish-card"><span class="label">Online</span><b class="big green">{online_devices}</b></div>
      <div class="ns-polish-card"><span class="label">Offline</span><b class="big red">{offline_devices}</b></div>
      <div class="ns-polish-card"><span class="label">New (24h)</span><b class="big blue">{new_devices}</b></div>
    </div>
    <div class="ns-table-shell">
      <table id="deviceTable" class="ns-dense-table" data-page-size="12">
        <thead><tr>
          <th>{sort_link('Device', 'name')}</th>
          <th>{sort_link('IP Address', 'ip')}</th>
          <th>{sort_link('Type', 'type')}</th>
          <th>{sort_link('Connection', 'status')}</th>
          <th>Activity</th>
          <th>{sort_link('Last Seen', 'last')}</th>
          <th>Actions</th>
        </tr></thead>
        <tbody>{table or '<tr><td colspan="7">No devices yet</td></tr>'}</tbody>
      </table>
    </div>
    <p class="ns-polish-subtle">Manual edits are locked and override collector updates. Private MAC devices can be manually renamed.</p>
  </div>
  {drawer}
</div>
<script>
document.addEventListener("DOMContentLoaded", function() {{
  var requestedTab = new URLSearchParams(window.location.search).get("tab");
  if (!requestedTab) return;
  var tabButton = document.querySelector('[data-drawer-tab="' + requestedTab + '"]');
  if (tabButton) tabButton.click();
}});
</script>
"""

    return shell("Devices", body, "Devices")


def device_drawer_payload(ip, period="1d", history_type=""):
    period_days = {"1d": 1, "7d": 7, "30d": 30}.get(period, 1)
    start_day = (datetime.now() - timedelta(days=period_days - 1)).strftime("%Y-%m-%d")
    def optional_query(sql, params=()):
        try:
            return query(sql, params)
        except sqlite3.OperationalError as error:
            if "no such table" in str(error).lower() or "no such column" in str(error).lower():
                return []
            raise

    traffic = optional_query(
        """
        SELECT day, COALESCE(SUM(downloaded_mb), 0) AS down_mb, COALESCE(SUM(uploaded_mb), 0) AS up_mb, COALESCE(SUM(total_mb), 0) AS total_mb
        FROM traffic_intervals
        WHERE ip=? AND day>=?
        GROUP BY day
        ORDER BY day
        LIMIT 60
        """,
        (ip, start_day),
    )
    apps = optional_query(
        """
        SELECT category, COUNT(*) AS total, MAX(ts) AS last_seen
        FROM dns_querylog
        WHERE client=? AND day>=?
        GROUP BY category
        ORDER BY total DESC
        LIMIT 5
        """,
        (ip, start_day),
    )
    domains = optional_query(
        """
        SELECT domain, COUNT(*) AS total, MAX(ts) AS last_seen
        FROM dns_querylog
        WHERE client=? AND day>=?
        GROUP BY domain
        ORDER BY last_seen DESC
        LIMIT 5
        """,
        (ip, start_day),
    )
    ids_rows = optional_query(
        """
        SELECT id, ts, severity, signature, src_ip, dest_ip
        FROM ids_events
        WHERE src_ip=? OR dest_ip=?
        ORDER BY ts DESC
        LIMIT 5
        """,
        (ip, ip),
    )
    anomalies = optional_query(
        """
        SELECT id, ts, rule, severity, status, reason
        FROM anomaly_events
        WHERE device_ip=?
        ORDER BY ts DESC
        LIMIT 8
        """,
        (ip,),
    )
    incidents = optional_query(
        """
        SELECT id, severity, status, title, first_event_ts, last_event_ts
        FROM security_incidents
        WHERE device_ip=?
        ORDER BY last_event_ts DESC
        LIMIT 8
        """,
        (ip,),
    )
    inventory = optional_query("SELECT first_seen, last_seen FROM devices WHERE ip=? LIMIT 1", (ip,))
    overrides = optional_query("SELECT updated_at, ignored FROM device_overrides WHERE ip=? LIMIT 1", (ip,))
    history = []
    if inventory:
        if inventory[0]["first_seen"]:
            history.append({"type": "inventory", "ts": inventory[0]["first_seen"], "title": "First seen", "detail": f"{ip} entered inventory."})
        if inventory[0]["last_seen"]:
            history.append({"type": "inventory", "ts": inventory[0]["last_seen"], "title": "Last seen", "detail": "Latest collector observation."})
    if overrides:
        state = "Ignored" if int(overrides[0]["ignored"] or 0) else "Label/status updated"
        history.append({"type": "action", "ts": overrides[0]["updated_at"] or "", "title": state, "detail": "Device override record changed."})
    for row in ids_rows[:5]:
        history.append({"type": "security", "ts": row["ts"], "title": f"IDS P{row['severity']}", "detail": row["signature"], "href": f"/ids-alerts/{row['id']}"})
    for row in anomalies[:5]:
        history.append({"type": "security", "ts": row["ts"], "title": f"Anomaly: {row['rule']}", "detail": row["reason"], "href": f"/anomalies/{row['id']}"})
    if history_type:
        history = [item for item in history if item["type"] == history_type]
    history = sorted(history, key=lambda item: item.get("ts") or "", reverse=True)[:20]
    return {
        "ip": ip,
        "period": period,
        "traffic": {
            "labels": [row["day"] for row in traffic],
            "downloaded": [round(float(row["down_mb"] or 0), 3) for row in traffic],
            "uploaded": [round(float(row["up_mb"] or 0), 3) for row in traffic],
            "total": fmt_mb(sum(float(row["total_mb"] or 0) for row in traffic)),
        },
        "apps": [{"name": row["category"] or "Other", "total": int(row["total"] or 0), "last_seen": row["last_seen"]} for row in apps],
        "domains": [{"name": row["domain"], "total": int(row["total"] or 0), "last_seen": row["last_seen"]} for row in domains],
        "history": history,
        "alerts": {
            "ids": [{"id": row["id"], "ts": row["ts"], "severity": row["severity"], "signature": row["signature"], "href": f"/ids-alerts/{row['id']}"} for row in ids_rows],
            "anomalies": [{"id": row["id"], "ts": row["ts"], "severity": row["severity"], "rule": row["rule"], "status": row["status"], "href": f"/anomalies/{row['id']}"} for row in anomalies],
            "incidents": [{"id": row["id"], "ts": row["last_event_ts"], "severity": row["severity"], "title": row["title"], "status": row["status"], "href": f"/incidents/{row['id']}"} for row in incidents],
        },
    }


@app.route("/api/device/<ip>/drawer")
def api_device_drawer(ip):
    if not valid_lan_ip(ip):
        return jsonify({"ok": False, "error": "Invalid IP address."}), 400
    try:
        return jsonify({"ok": True, **device_drawer_payload(ip, request.args.get("period", "1d"), request.args.get("history_type", ""))})
    except Exception as error:
        print(f"Device drawer API failed for {ip}: {error}")
        return jsonify({"ok": False, "error": "Device details could not be loaded."}), 500


@app.route("/device/unlock/<ip>", methods=["POST"])
def unlock_device(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    ensure_device_overrides_table()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    run_sql("DELETE FROM device_overrides WHERE ip=?", (ip,))
    run_sql(
        """
        INSERT INTO device_override_unlocks (ip, updated_at)
        VALUES (?, ?)
        ON CONFLICT(ip) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (ip, now),
    )
    run_sql(
        """
        UPDATE devices
        SET name=ip,
            vendor='Unknown Vendor',
            device_type='Unknown'
        WHERE ip=?
        """,
        (ip,),
    )
    if request.form.get("return_to") == "device":
        return_range = request.form.get("range", "1d")
        if return_range not in ["1d", "7d", "30d", "60d", "90d"]:
            return_range = "1d"
        return local_redirect(device_page_url(ip, range=return_range))
    return local_redirect("/devices")


def set_manual_status(ip, status):
    ensure_device_overrides_table()
    rows = query("SELECT name, vendor, device_type FROM device_overrides WHERE ip=?", (ip,))
    unlocked = query("SELECT 1 FROM device_override_unlocks WHERE ip=? LIMIT 1", (ip,))

    if rows:
        run_sql(
            """
            UPDATE device_overrides
            SET status=?, updated_at=?
            WHERE ip=?
            """,
            (status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip),
        )
    elif not unlocked:
        d = query("SELECT name, vendor, device_type FROM devices WHERE ip=? LIMIT 1", (ip,))
        name = d[0]["name"] if d and d[0]["name"] else ip
        vendor = d[0]["vendor"] if d and d[0]["vendor"] else "Unknown Vendor"
        dtype = d[0]["device_type"] if d and d[0]["device_type"] else "Unknown"

        run_sql(
            """
            INSERT INTO device_overrides (ip, name, vendor, device_type, status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                status=excluded.status,
                updated_at=excluded.updated_at
            """,
            (ip, name, vendor, dtype, status, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )

    run_sql("UPDATE devices SET status=? WHERE ip=?", (status, ip))


def upsert_device_override(ip, name=None, vendor=None, device_type=None, status=None, ignored=None):
    ensure_device_overrides_table()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current = query(
        """
        SELECT
            COALESCE(o.name, d.name, d.ip) AS name,
            COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS vendor,
            COALESCE(o.device_type, d.device_type, 'Unknown') AS device_type,
            COALESCE(o.status, d.status, 'Active') AS status,
            COALESCE(o.ignored, 0) AS ignored
        FROM devices d
        LEFT JOIN device_overrides o ON o.ip=d.ip
        WHERE d.ip=?
        LIMIT 1
        """,
        (ip,),
    )
    base = current[0] if current else None
    base_value = lambda key, default="": base[key] if base and key in base.keys() else default
    next_name = name if name is not None else base_value("name", ip) or ip
    next_vendor = vendor if vendor is not None else base_value("vendor", "Unknown Vendor") or "Unknown Vendor"
    next_type = device_type if device_type is not None else base_value("device_type", "Unknown") or "Unknown"
    next_status = status if status is not None else base_value("status", "Active") or "Active"
    next_ignored = int(ignored if ignored is not None else base_value("ignored", 0) or 0)
    run_sql(
        """
        INSERT INTO device_overrides (ip, name, vendor, device_type, status, ignored, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            name=excluded.name,
            vendor=excluded.vendor,
            device_type=excluded.device_type,
            status=excluded.status,
            ignored=excluded.ignored,
            updated_at=excluded.updated_at
        """,
        (ip, next_name, next_vendor, next_type, next_status, next_ignored, now),
    )
    run_sql(
        """
        UPDATE devices
        SET name=?, vendor=?, device_type=?, status=?
        WHERE ip=?
        """,
        (next_name, next_vendor, next_type, next_status, ip),
    )


@app.route("/device/<ip>/label", methods=["POST"])
def set_device_label(ip):
    if not valid_lan_ip(ip):
        return jsonify({"ok": False, "error": "Invalid IP address."}), 400
    label = str(request.form.get("name", "") or "").strip()
    if len(label) > 80:
        label = label[:80]
    upsert_device_override(ip, name=label or ip)
    return jsonify({"ok": True, "ip": ip, "name": label or ip})


@app.route("/device/<ip>/ignore", methods=["POST"])
def set_device_ignored(ip):
    if not valid_lan_ip(ip):
        return jsonify({"ok": False, "error": "Invalid IP address."}), 400
    ignored = 1 if request.form.get("ignored") == "1" else 0
    upsert_device_override(ip, ignored=ignored)
    return jsonify({"ok": True, "ip": ip, "ignored": bool(ignored)})


@app.route("/api/device/<ip>/dns-lookup", methods=["POST"])
def api_device_dns_lookup(ip):
    if not valid_lan_ip(ip):
        return jsonify({"ok": False, "error": "Invalid IP address."}), 400
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(2.0)
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)
        return jsonify({
            "ok": True,
            "ip": ip,
            "hostname": hostname,
            "aliases": aliases[:5],
            "addresses": addresses[:5],
        })
    except Exception as error:
        print(f"DNS lookup failed for {ip}: {error}")
        return jsonify({"ok": False, "ip": ip, "error": "DNS lookup could not complete."})
    finally:
        socket.setdefaulttimeout(previous_timeout)


def adguard_access_list():
    ok, data = ag_get("/access/list")
    if ok and isinstance(data, dict):
        return data

    return {
        "allowed_clients": [],
        "disallowed_clients": [],
        "blocked_hosts": [],
    }


def adguard_set_disallowed(ip, blocked=True):
    data = adguard_access_list()
    allowed = data.get("allowed_clients") or []
    disallowed = data.get("disallowed_clients") or []
    blocked_hosts = data.get("blocked_hosts") or []

    if blocked:
        if ip not in disallowed:
            disallowed.append(ip)
        allowed = [x for x in allowed if x != ip]
    else:
        disallowed = [x for x in disallowed if x != ip]

    ok, resp = ag_post("/access/set", {
        "allowed_clients": allowed,
        "disallowed_clients": disallowed,
        "blocked_hosts": blocked_hosts,
    })

    return ok, resp


def app_block_marker(ip, category):
    return f"# netspecter-app-block ip={ip} category={quote(str(category or 'Other'), safe='')}"


def app_block_rule(ip, domain):
    return f"||{domain}^$client={ip}"


def app_block_domain_valid(domain):
    text = str(domain or "").strip().lower().strip(".")
    if not text or len(text) > 253 or is_noise(text):
        return False
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", text)) and "." in text


def app_block_status(ip, category):
    ok, data = ag_get("/filtering/status")
    if not ok or not isinstance(data, dict):
        return False, [], data

    rules = data.get("user_rules") or []
    marker = app_block_marker(ip, category)
    return marker in rules, rules, data


def device_dns_client_keys(ip):
    rows = query(
        """
        SELECT
            COALESCE(o.name, d.name, d.ip) AS display_name,
            d.mac
        FROM devices d
        LEFT JOIN device_overrides o ON o.ip=d.ip
        WHERE d.ip=?
        LIMIT 1
        """,
        (ip,),
    )
    keys = [ip]
    if rows:
        for key in [rows[0]["mac"], rows[0]["display_name"]]:
            if key and key not in keys:
                keys.append(key)
    return keys


def app_domains_for_device(ip, category):
    start_day = range_start_day()
    client_keys = device_dns_client_keys(ip)
    placeholders = ",".join(["?"] * len(client_keys))
    rows = query(
        f"""
        SELECT domain, COUNT(*) AS total
        FROM dns_querylog
        WHERE client IN ({placeholders}) AND category=? AND day>=?
        GROUP BY domain
        ORDER BY total DESC
        LIMIT 200
        """,
        tuple(client_keys) + (category, start_day),
    )
    domains = []
    seen = set()
    for row in rows:
        domain = str(row["domain"] or "").strip().lower().strip(".")
        if app_block_domain_valid(domain) and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def set_app_block(ip, category, blocked=True):
    _current_blocked, rules, detail = app_block_status(ip, category)
    if not isinstance(rules, list):
        rules = []

    marker = app_block_marker(ip, category)
    cleaned = []
    skip_next_rules = False
    for rule in rules:
        if rule == marker:
            skip_next_rules = True
            continue
        if skip_next_rules and str(rule).startswith("||") and f"$client={ip}" in str(rule):
            continue
        skip_next_rules = False
        cleaned.append(rule)

    if blocked:
        domains = app_domains_for_device(ip, category)
        if not domains:
            return False, {"error": "No observed domains for this device/application yet."}
        cleaned.append(marker)
        cleaned.extend(app_block_rule(ip, domain) for domain in domains)

    ok, resp = ag_post("/filtering/set_rules", {"rules": cleaned})
    return ok, resp if ok else (resp or detail)


@app.route("/device/<ip>/app-block", methods=["POST"])
def toggle_device_app_block(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    category = request.form.get("category", "Other").strip() or "Other"
    action = request.form.get("action", "block")
    ok, resp = set_app_block(ip, category, action == "block")
    if not ok:
        session["app_block_error"] = str(resp.get("body") or resp.get("error") or resp)[:240] if isinstance(resp, dict) else str(resp)[:240]
    suffix = "app_blocked=1" if ok and action == "block" else "app_unblocked=1" if ok else "app_block_failed=1"
    return local_redirect(f"{device_page_url(ip, range=range_key())}&{suffix}#device-applications")


@app.route("/device/pause/<ip>", methods=["POST"])
def pause_device(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    ok, resp = adguard_set_disallowed(ip, True)
    set_manual_status(ip, "DNS Blocked" if ok else "DNS Block Failed")
    return local_redirect(device_page_url(ip))


@app.route("/device/resume/<ip>", methods=["POST"])
def resume_device(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    ok, resp = adguard_set_disallowed(ip, False)
    set_manual_status(ip, "Active" if ok else "Resume Failed")
    return local_redirect(device_page_url(ip))


@app.route("/ping/<ip>")
def ping_device(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    try:
        out = subprocess.check_output(
            ["ping", "-c", "4", "-W", "2", ip],
            stderr=subprocess.STDOUT,
            timeout=12,
        ).decode(errors="replace")
    except Exception as e:
        print(f"Ping failed for {ip}: {e}")
        out = operation_failed_message("Ping")

    body = f"""
{topbar('Ping Test')}
<div class="panel">
<h2>Ping {h(ip)}</h2>
<pre>{h(out)}</pre>
<p><a class="btn" href="/device/{h(ip)}">Back to Device</a></p>
</div>
"""
    return shell("Ping", body, "Devices")


@app.route("/scan/<ip>")
def scan_device(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP",
        81: "Alt HTTP", 88: "Kerberos", 135: "RPC", 139: "NetBIOS",
        443: "HTTPS", 445: "SMB", 554: "RTSP", 631: "IPP/Printer",
        1883: "MQTT", 3000: "Web UI", 3389: "RDP", 5000: "UPnP/Web",
        8000: "HTTP Alt", 8080: "HTTP Proxy", 8123: "Home Assistant",
        8443: "HTTPS Alt", 9100: "JetDirect Printer", 9443: "HTTPS Alt",
    }

    rows = ""
    open_count = 0
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.35)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_count += 1
                link = ""
                if port in [80, 81, 3000, 5000, 8000, 8080, 8123]:
                    link = f'<a class="ns-compact-button" href="http://{h(ip)}:{port}" target="_blank">Open</a>'
                elif port in [443, 8443, 9443]:
                    link = f'<a class="ns-compact-button" href="https://{h(ip)}:{port}" target="_blank">Open</a>'
                rows += f"<tr><td class='mono'>{port}</td><td>{h(service)}</td><td><span class='ns-chip ns-chip--ok'>Open</span></td><td>{link or '<span class=\"ns-polish-subtle\">No web shortcut</span>'}</td></tr>"
        except Exception:
            pass
        finally:
            sock.close()

    if not rows:
        rows = "<tr><td colspan='4'>No common LAN ports were open in this quick check.</td></tr>"

    body = f"""
{topbar('Port Scan')}
<div class="ns-polish-page">
  <section class="ns-polish-panel">
    <div class="ns-polish-header">
      <div>
        <h2 class="ns-polish-section-title">Port Check</h2>
        <div class="ns-polish-subtle">Quick TCP check of common LAN ports for <span class="mono">{h(ip)}</span>.</div>
      </div>
      <a class="ns-compact-button" href="/devices?device={h(ip)}&tab=overview">Back to Device Drawer</a>
    </div>
    <div class="ns-mini-metrics">
      <div class="ns-mini-metric"><span>Target</span><b class="mono">{h(ip)}</b></div>
      <div class="ns-mini-metric"><span>Open Ports</span><b>{open_count}</b></div>
      <div class="ns-mini-metric"><span>Mode</span><b>Quick</b></div>
      <div class="ns-mini-metric"><span>Timeout</span><b>350 ms</b></div>
    </div>
    <div class="ns-table-shell">
      <table class="ns-dense-table">
        <thead><tr><th>Port</th><th>Service</th><th>Status</th><th>Shortcut</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </section>
</div>
"""
    return shell("Port Scan", body, "Devices")


def quick_detect_services(ip):
    common_ports = {
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        554: "RTSP",
        631: "Printer",
        1883: "MQTT",
        3000: "Web UI",
        3389: "RDP",
        5000: "Web UI",
        8000: "HTTP Alt",
        8080: "HTTP Alt",
        8123: "Home Assistant",
        8443: "HTTPS Alt",
        9443: "HTTPS Alt",
        9100: "Printer",
    }

    found = []

    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.12)
        try:
            if sock.connect_ex((ip, port)) == 0:
                proto = "TCP"
                open_url = ""

                if port in [80, 3000, 5000, 8000, 8080, 8123]:
                    open_url = f"http://{ip}:{port}"
                elif port in [443, 8443, 9443]:
                    open_url = f"https://{ip}:{port}"

                found.append({
                    "port": port,
                    "service": service,
                    "proto": proto,
                    "url": open_url,
                })
        except Exception:
            pass
        finally:
            sock.close()

    return found



@app.route("/device/<ip>")
def device(ip):
    if request.args.get("legacy") != "1":
        return local_redirect(devices_page_url(device=ip, tab="history"))
    ensure_device_overrides_table()
    start_day = range_start_day()

    rows = query(
        """
        WITH usage AS (
            SELECT
                t.ip,
                MAX(t.id) AS max_id,
                SUM(t.downloaded_mb) AS downloaded_mb,
                SUM(t.uploaded_mb) AS uploaded_mb,
                SUM(t.total_mb) AS total_mb
            FROM traffic_intervals t
            WHERE t.ip=? AND t.day >= ?
        )
        SELECT
            COALESCE(o.name, d.name, t.name, t.ip) AS display_name,
            COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS display_vendor,
            COALESCE(o.device_type, d.device_type, 'Unknown') AS display_type,
            COALESCE(o.status, d.status, 'Active') AS display_status,
            CASE WHEN o.ip IS NOT NULL THEN 1 ELSE 0 END AS manual_locked,
            t.id,
            t.ip,
            t.name,
            t.mac,
            u.downloaded_mb,
            u.uploaded_mb,
            u.total_mb,
            t.live_bps,
            t.day,
            t.ts
        FROM usage u
        JOIN traffic_intervals t
            ON t.id = u.max_id
        LEFT JOIN devices d
            ON d.ip = t.ip
        LEFT JOIN device_overrides o
            ON o.ip = t.ip
        """,
        (ip, start_day),
    )

    if not rows:
        inventory = query(
            """
            SELECT
                d.*,
                COALESCE(o.name, d.name, d.ip) AS display_name,
                COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS display_vendor,
                COALESCE(o.device_type, d.device_type, 'Unknown') AS display_type,
                COALESCE(o.status, d.status, 'Active') AS display_status
            FROM devices d
            LEFT JOIN device_overrides o ON o.ip=d.ip
            WHERE d.ip=?
            LIMIT 1
            """,
            (ip,),
        )
        if inventory:
            d = inventory[0]
            inventory_body = f"""
{topbar(h(d['display_name'] or ip))}
<div class="panel">
  <h2>Device Identity</h2>
  <p>This device was discovered from network inventory or DNS activity. No measured bridge traffic is available for the selected period.</p>
  <table>
    <tr><th>Name</th><td>{h(d['display_name'] or ip)}</td></tr>
    <tr><th>IP Address</th><td>{h(ip)}</td></tr>
    <tr><th>MAC Address</th><td>{h(d['mac'] or '-')}</td></tr>
    <tr><th>Manufacturer</th><td>{h(d['display_vendor'] or 'Unknown Vendor')}</td></tr>
    <tr><th>Type</th><td>{h(d['display_type'] or 'Unknown')}</td></tr>
    <tr><th>Status</th><td>{h(d['display_status'] or 'Active')}</td></tr>
    <tr><th>First Seen</th><td>{h(d['first_seen'] or '-')}</td></tr>
    <tr><th>Last Seen</th><td>{h(d['last_seen'] or '-')}</td></tr>
  </table>
</div>
"""
            return shell("Device", inventory_body, "Devices")
        empty_body = f"{topbar('Device')}{time_picker()}<div class='panel'>No data for {h(ip)} in this period.</div>"
        return shell("Device", empty_body, "Devices")

    r = rows[0]
    device_name = r["display_name"] or ip
    vendor = r["display_vendor"] or "Unknown Vendor"
    dtype = r["display_type"] or "Unknown"
    status = r["display_status"] or "Active"
    manual_locked = bool(r["manual_locked"])
    private_mac = private_mac_address(r["mac"])

    # Per-device DNS activity must be an exact client match.
    # Do NOT use LIKE here: a gateway IP could also match longer client IPs.
    client_keys = []
    for key in [ip, r["mac"], device_name]:
        if key and key not in client_keys:
            client_keys.append(key)

    placeholders = ",".join(["?"] * len(client_keys))

    domains = query(
        f"""
        SELECT domain, category, COUNT(*) AS total
        FROM dns_querylog
        WHERE client IN ({placeholders}) AND day >= ?
        GROUP BY domain, category
        ORDER BY total DESC
        LIMIT 60
        """,
        tuple(client_keys) + (start_day,),
    )

    category_counts = {}
    domain_rows = ""

    for d in domains:
        if is_noise(d["domain"]):
            continue

        cat = d["category"] or "Other"
        count = int(d["total"] or 0)
        category_counts[cat] = category_counts.get(cat, 0) + count

        domain_rows += f"""
<tr>
  <td>{icon_for_app(cat)} {h(d['domain'])}</td>
  <td>{h(cat)}</td>
  <td>{count}</td>
</tr>
"""

    app_rows = ""
    max_count = max(category_counts.values(), default=1)
    total_queries = sum(category_counts.values())
    _ok_app_rules, app_block_rules, _app_rule_detail = app_block_status(ip, "__probe__")
    if not isinstance(app_block_rules, list):
        app_block_rules = []

    for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:8]:
        width = max(5, min(count / max_count * 100, 100))
        pct = round((count / total_queries * 100), 1) if total_queries else 0
        blocked_app = app_block_marker(ip, cat) in app_block_rules
        action = "unblock" if blocked_app else "block"
        button_label = "Unblock" if blocked_app else "Block"
        button_class = "app-toggle unblock" if blocked_app else "app-toggle block"
        blocked_badge = '<small class="app-blocked-badge">Blocked</small>' if blocked_app else ""
        app_rows += f"""
<div class="device-app-row">
  <div class="device-app-name">{icon_for_app(cat)}<span>{h(cat)}</span>{blocked_badge}</div>
  <div class="device-app-bar"><div style="width:{width}%"></div></div>
  <b>{count}</b>
  <span>{pct}%</span>
  <form class="app-toggle-form" method="post" action="/device/{h(ip)}/app-block">
    {csrf_input()}
    <input type="hidden" name="category" value="{h(cat)}">
    <button class="{button_class}" type="submit" name="action" value="{action}">{button_label}</button>
  </form>
</div>
"""

    services = quick_detect_services(ip)
    service_rows = ""
    web_url = ""

    for s in services:
        if not web_url and s["url"]:
            web_url = s["url"]

        open_link = ""
        if s["url"]:
            open_link = f'<a class="mini-link" target="_blank" href="{h(s["url"])}">Open</a>'

        service_rows += f"""
<tr>
  <td>{s['port']}</td>
  <td>{h(s['service'])}</td>
  <td>{h(s['proto'])}</td>
  <td><span class="pill-open">Open</span> {open_link}</td>
</tr>
"""

    if not service_rows:
        service_rows = "<tr><td colspan='4'>No common LAN services detected. Use Port Scan for a fuller check.</td></tr>"

    open_web_button = ""
    if web_url:
        open_web_button = f'<a class="tool-btn blue" href="{h(web_url)}" target="_blank"><i class="fa-solid fa-arrow-up-right-from-square"></i> Open Web UI</a>'

    live_speed_data = live_host_speed(ip)
    if not live_speed_data.get("total_bps") and device_name:
        live_speed_data = live_host_speed(device_name)
    live_speed = fmt_bits_as_bytes(live_speed_data.get("total_bps") or r["live_bps"] or 0)
    live_rx = fmt_bits_as_bytes(live_speed_data.get("rx_bps") or 0)
    live_tx = fmt_bits_as_bytes(live_speed_data.get("tx_bps") or 0)
    detail_lock_badge = ""
    if manual_locked:
        detail_lock_badge = (
            f'<form class="unlock-device-form" method="post" action="/device/unlock/{h(ip)}" '
            f'onsubmit="return confirm(\'Unlock this device and clear its saved identity details?\');">'
            f'{csrf_input()}<input type="hidden" name="return_to" value="device">'
            f'<input type="hidden" name="range" value="{range_key()}">'
            f'<button class="badge-lock unlock-badge" type="submit" '
            f'title="Unlock and clear saved identity details">Locked <i class="fa-solid fa-lock-open"></i></button></form>'
        )

    app_block_notice = ""
    if request.args.get("app_blocked") == "1":
        app_block_notice = '<div class="setup-ok">Application blocked for this device.</div>'
    elif request.args.get("app_unblocked") == "1":
        app_block_notice = '<div class="setup-ok">Application unblocked for this device.</div>'
    elif request.args.get("app_block_failed") == "1":
        detail = session.pop("app_block_error", "")
        app_block_notice = f'<div class="setup-warning">Application block rule could not be changed. {h(detail) if detail else "Check AdGuard settings/API access."}</div>'

    body = f"""
{topbar(h(device_name))}
<style>
.device-range-controls {{ display:flex; align-items:center; margin-bottom:14px; }}
.device-range-controls .time-picker {{ margin-left:8px; }}
.device-hero {{ display:grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap:14px; margin-bottom:16px; }}
.device-stat {{ padding:18px; border:1px solid rgba(0,190,255,.22); border-radius:14px; background:linear-gradient(145deg, rgba(6,22,36,.94), rgba(3,12,22,.96)); box-shadow:0 0 24px rgba(0,190,255,.04); }}
.device-stat .label {{ color:#b7c8d9; font-size:13px; }}
.device-stat .value {{ display:block; margin-top:8px; font-size:22px; font-weight:800; }}
.device-grid-main {{ display:grid; grid-template-columns: 1.55fr 1fr; gap:16px; margin-bottom:16px; }}
.device-grid-bottom {{ display:grid; grid-template-columns: 1.25fr 1fr; gap:16px; }}
.identity-card {{ display:grid; grid-template-columns: 110px 1fr; gap:18px; align-items:center; }}
.device-avatar {{ width:92px; height:92px; border-radius:24px; display:flex; align-items:center; justify-content:center; font-size:46px; background:radial-gradient(circle at top, rgba(0,220,255,.22), rgba(0,40,65,.82)); border:1px solid rgba(0,220,255,.22); }}
.identity-title {{ font-size:24px; font-weight:800; margin-bottom:8px; }}
.identity-line {{ display:grid; grid-template-columns: 110px 1fr; gap:8px; margin:5px 0; color:#d7e6f5; }}
.identity-line span:first-child {{ color:#93a7ba; }}
.device-tools {{ display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:10px; margin-top:16px; }}
.tool-btn {{ text-align:center; padding:12px 10px; border-radius:10px; font-weight:700; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.04); color:#dff7ff; }}
.tool-action {{ display:flex; margin:0; }}
.tool-action .tool-btn {{ width:100%; margin:0; }}
.tool-btn.blue {{ color:#22b8ff; border-color:rgba(0,150,255,.35); }}
.tool-btn.green {{ color:#38f07b; border-color:rgba(50,240,120,.35); }}
.tool-btn.yellow {{ color:#ffca3a; border-color:rgba(255,202,58,.35); }}
.tool-btn.red {{ color:#ff4b6d; border-color:rgba(255,75,109,.35); }}
.device-app-row {{ display:grid; grid-template-columns: 160px 1fr 70px 60px 94px; gap:14px; align-items:center; margin:16px 0; }}
.device-app-name {{ display:flex; align-items:center; gap:10px; }}
.device-app-bar {{ height:10px; border-radius:999px; background:rgba(130,170,200,.15); overflow:hidden; }}
.device-app-bar div {{ height:100%; border-radius:999px; background:linear-gradient(90deg, #00a9ff, #20f0d0, #9b5cff); }}
.app-toggle-form {{ margin:0; }}
.app-toggle {{ width:94px; min-height:34px; border-radius:10px; font-weight:800; cursor:pointer; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.04); color:#dff7ff; }}
.app-toggle.block {{ color:#ffca3a; border-color:rgba(255,202,58,.38); background:rgba(255,202,58,.10); }}
.app-toggle.unblock {{ color:#38f07b; border-color:rgba(50,240,120,.38); background:rgba(50,240,120,.10); }}
.app-blocked-badge {{ display:inline-block; padding:2px 7px; border-radius:999px; color:#ffca3a; border:1px solid rgba(255,202,58,.32); background:rgba(255,202,58,.10); font-size:10px; font-weight:800; }}
.device-scroll {{ max-height:440px; overflow:auto; }}
.pill-open {{ display:inline-block; padding:3px 9px; border-radius:999px; border:1px solid rgba(62,240,120,.5); color:#52ef86; font-weight:700; }}
.badge-lock {{ display:inline-block; padding:3px 8px; border-radius:999px; background:rgba(0,220,200,.16); color:#28e0d5; font-size:12px; font-weight:700; }}
.unlock-device-form {{ display:inline; margin:0; }}
.unlock-badge {{ border:1px solid rgba(0,220,200,.24); font:inherit; cursor:pointer; }}
.unlock-badge:hover {{ background:rgba(0,220,200,.28); color:#eaffff; }}
.badge-private {{ display:inline-block; padding:3px 8px; border-radius:999px; border:1px solid rgba(248,200,78,.28); background:rgba(248,200,78,.12); color:#f8c84e; font-size:12px; font-weight:700; }}
.mini-link {{ margin-left:8px; color:#28d7ff; font-weight:700; }}
@media (max-width: 1100px) {{ .device-hero, .device-grid-main, .device-grid-bottom {{ grid-template-columns:1fr; }} .device-tools {{ grid-template-columns:1fr; }} }}
@media (max-width: 600px) {{
  .device-stat {{ padding:14px; }}
  .identity-card {{ grid-template-columns:1fr; justify-items:center; }}
  .identity-title {{ text-align:center; font-size:20px; }}
  .identity-line {{ grid-template-columns:1fr; gap:2px; margin:9px 0; }}
  .device-app-row {{ grid-template-columns:minmax(0, 1fr) auto; gap:10px; }}
  .device-app-name, .device-app-bar {{ grid-column:1 / -1; }}
  .app-toggle-form {{ grid-column:1 / -1; }}
  .app-toggle {{ width:100%; }}
}}
</style>

<div class="device-range-controls">
  {time_picker()}
</div>
<div class="device-hero">
  <div class="device-stat"><div class="label">Download</div><span class="value blue">{fmt_mb(r['downloaded_mb'])}</span></div>
  <div class="device-stat"><div class="label">Upload</div><span class="value purple">{fmt_mb(r['uploaded_mb'])}</span></div>
  <div class="device-stat"><div class="label">Total</div><span class="value teal">{fmt_mb(r['total_mb'])}</span></div>
  <div class="device-stat"><div class="label">Live Speed</div><span class="value green" data-live-ip="{h(ip)}" data-live-field="total">{live_speed}</span><small>DL <span data-live-ip="{h(ip)}" data-live-field="down">{live_rx}</span> | UL <span data-live-ip="{h(ip)}" data-live-field="up">{live_tx}</span></small></div>
  <div class="device-stat"><div class="label">DNS Queries</div><span class="value blue">{total_queries}</span></div>
  <div class="device-stat"><div class="label">Alerts</div><span class="value red">{r['alerts'] if 'alerts' in r.keys() else 0}</span></div>
</div>

<div class="device-grid-main">
  <div class="panel" id="device-applications">
    <h2>Applications For This Device <span class="sub" style="float:right;">Total Queries: {total_queries}</span></h2>
    {app_block_notice}
    {app_rows or 'No per-device app data yet. Wait for AdGuard querylog collection.'}
  </div>

  <div class="panel">
    <h2>Device Identity</h2>
    <div class="identity-card">
      <div class="device-avatar">{icon_for_device(dtype)}</div>
      <div>
        <div class="identity-title">{h(device_name)} {detail_lock_badge} {'<span class="badge-private">Private MAC</span>' if private_mac else ''}</div>
        <div class="identity-line"><span>IP Address</span><b>{h(ip)}</b></div>
        <div class="identity-line"><span>MAC Address</span><b>{h(r['mac'])}</b></div>
        <div class="identity-line"><span>Vendor</span><b>{h(vendor)}</b></div>
        <div class="identity-line"><span>Type</span><b>{h(dtype)}</b></div>
        <div class="identity-line"><span>Status</span><b>{h(status)}</b></div>
        <div class="identity-line"><span>Manual Lock</span><b>{'Yes' if manual_locked else 'No'}</b></div>
        {f'<div class="identity-line"><span>Identity</span><b>Randomized by device privacy setting; disable it for this home Wi-Fi to keep tracking stable.</b></div>' if private_mac else ''}
      </div>
    </div>

    <div class="device-tools">
      <a class="tool-btn blue" href="/ping/{h(ip)}"><i class="fa-solid fa-satellite-dish"></i> Ping</a>
      <a class="tool-btn blue" href="/scan/{h(ip)}"><i class="fa-solid fa-magnifying-glass"></i> Port Scan</a>
      <form class="tool-action" method="post" action="/device/pause/{h(ip)}">{csrf_input()}<button class="tool-btn yellow" type="submit"><i class="fa-solid fa-ban"></i> Block DNS</button></form>
      <form class="tool-action" method="post" action="/device/resume/{h(ip)}">{csrf_input()}<button class="tool-btn green" type="submit"><i class="fa-solid fa-check"></i> Allow DNS</button></form>
      <a class="tool-btn blue" href="/devices"><i class="fa-solid fa-pen-to-square"></i> Edit Device</a>
      {open_web_button}
      <button class="tool-btn" onclick="navigator.clipboard.writeText('{h(ip)}')"><i class="fa-regular fa-copy"></i> Copy IP</button>
      <a class="tool-btn blue" href="/history?ip={h(ip)}"><i class="fa-solid fa-clock-rotate-left"></i> History</a>
    </div>
  </div>
</div>

<div class="device-grid-bottom">
  <div class="panel device-scroll">
    <h2>Recent Activity / Top Domains</h2>
    <table>
      <tr><th>Domain</th><th>Category</th><th>Hits</th></tr>
      {domain_rows or '<tr><td colspan="3">No per-device domains yet</td></tr>'}
    </table>
  </div>

  <div class="panel">
    <h2>Detected Services</h2>
    <p class="sub">Quick scan of common LAN ports. Use Port Scan for the fuller result.</p>
    <table>
      <tr><th>Port</th><th>Service</th><th>Protocol</th><th>Status</th></tr>
      {service_rows}
    </table>
  </div>
</div>
"""

    return shell("Device", body, "Devices")



# ===================================================
# HISTORICAL TRAFFIC GRAPH API
# ===================================================

@app.route("/api/history")
def api_history():
    period = request.args.get("period", "1h").strip().lower()
    ip_raw = request.args.get("ip", "").strip()
    ip = ""
    if ip_raw:
        try:
            ip = str(ipaddress.ip_address(ip_raw))
        except ValueError:
            ip = ""

    if period not in ["1h", "24h", "7d", "30d", "60d", "90d"]:
        period = "1h"

    if period == "1h":
        bucket_expr = "substr(ts, 1, 16)"
        since_clause = "ts >= datetime('now','localtime','-1 hour')"
    elif period == "24h":
        bucket_expr = "substr(ts, 1, 13) || ':00'"
        since_clause = "ts >= datetime('now','localtime','-24 hours')"
    elif period == "7d":
        bucket_expr = "day"
        since_clause = "day >= date('now','localtime','-7 days')"
    elif period == "60d":
        bucket_expr = "day"
        since_clause = "day >= date('now','localtime','-60 days')"
    elif period == "90d":
        bucket_expr = "day"
        since_clause = "day >= date('now','localtime','-90 days')"
    else:
        bucket_expr = "day"
        since_clause = "day >= date('now','localtime','-30 days')"

    if ip:
        rows = cached_query(
            f"api_history:{period}:ip:{ip}",
            10,
            f"""
            SELECT
                {bucket_expr} AS bucket,
                SUM(downloaded_mb) AS downloaded,
                SUM(uploaded_mb) AS uploaded,
                SUM(total_mb) AS total
            FROM traffic_intervals
            WHERE ip=?
              AND {since_clause}
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            (ip,),
        )
    else:
        rows = cached_query(
            f"api_history:{period}:network",
            10,
            f"""
            SELECT
                {bucket_expr} AS bucket,
                SUM(downloaded_mb) AS downloaded,
                SUM(uploaded_mb) AS uploaded,
                SUM(total_mb) AS total
            FROM traffic_intervals
            WHERE {since_clause}
            GROUP BY bucket
            ORDER BY bucket ASC
            """
        )

    labels = []
    downloaded = []
    uploaded = []
    total = []

    for r in rows:
        labels.append(str(r["bucket"] or ""))
        downloaded.append(round(float(r["downloaded"] or 0), 2))
        uploaded.append(round(float(r["uploaded"] or 0), 2))
        total.append(round(float(r["total"] or 0), 2))

    return {
        "period": period,
        "ip": ip,
        "labels": labels,
        "downloaded": downloaded,
        "uploaded": uploaded,
        "total": total,
    }


@app.route("/history")
def history():
    ip = request.args.get("ip", "").strip()[:80]

    title = "Network History"
    subtitle = "Network-wide traffic history"

    if ip:
        title = "Device History"
        subtitle = "Per-device traffic history"

    body = f"""
{topbar(title)}
<div class="ns-polish-page ns-network-page">
  <section class="ns-polish-panel">
    <div class="ns-polish-header">
      <div>
        <h2 class="ns-polish-section-title">{subtitle}</h2>
        <div class="ns-polish-subtle">Measured traffic by time bucket. Use a device IP for a focused view.</div>
      </div>
      <form class="ns-filter-bar" method="GET" action="/history">
        <input name="ip" placeholder="Device IP, e.g. {h(cfg().get('lan_prefix', DEFAULT_CONFIG['lan_prefix']))}58" value="{h(ip)}" aria-label="Device IP">
        <button type="submit">Show Device</button>
        <a href="/history">Network-wide</a>
      </form>
    </div>
    <div class="ns-filter-bar ns-history-ranges" aria-label="History range">
      <button type="button" data-history-period="1h" onclick="loadHistory('1h')">1 Hour</button>
      <button type="button" data-history-period="24h" onclick="loadHistory('24h')">24 Hours</button>
      <button type="button" data-history-period="7d" onclick="loadHistory('7d')">7 Days</button>
      <button type="button" data-history-period="30d" onclick="loadHistory('30d')">30 Days</button>
      <button type="button" data-history-period="60d" onclick="loadHistory('60d')">60 Days</button>
      <button type="button" data-history-period="90d" onclick="loadHistory('90d')">90 Days</button>
    </div>
    <div class="ns-chart-panel">
      <canvas id="historyChart" aria-label="Traffic history chart" role="img"></canvas>
      <div id="historyEmpty" class="ns-dashboard-empty" hidden>No traffic history for this selection yet.</div>
    </div>
  </section>
</div>

<script>
let historyChart = null;
const historyIp = "{h(ip)}";

async function loadHistory(period) {{
  const url = "/api/history?period=" + encodeURIComponent(period) +
              (historyIp ? "&ip=" + encodeURIComponent(historyIp) : "");

  const res = await fetch(url, {{cache: "no-store"}});
  if (!res.ok) return;

  const data = await res.json();

  const ctx = document.getElementById("historyChart");
  if (!ctx) return;
  document.querySelectorAll("[data-history-period]").forEach((btn) => {{
    btn.classList.toggle("is-active", btn.getAttribute("data-history-period") === period);
  }});
  const empty = document.getElementById("historyEmpty");
  const hasData = Array.isArray(data.labels) && data.labels.length > 0;
  if (empty) empty.hidden = hasData;
  ctx.hidden = !hasData;
  if (!hasData) {{
    if (historyChart) {{
      historyChart.destroy();
      historyChart = null;
    }}
    return;
  }}

  if (historyChart) {{
    historyChart.destroy();
  }}

  historyChart = new Chart(ctx, {{
    type: "bar",
    data: {{
      labels: data.labels,
      datasets: [
        {{
          label: "Downloaded MB",
          data: data.downloaded,
          backgroundColor: "rgba(24,170,255,.72)",
          borderColor: "#18aaff",
          borderWidth: 1
        }},
        {{
          label: "Uploaded MB",
          data: data.uploaded,
          backgroundColor: "rgba(156,108,255,.72)",
          borderColor: "#9c6cff",
          borderWidth: 1
        }},
        {{
          label: "Total MB",
          data: data.total,
          backgroundColor: "rgba(0,221,199,.44)",
          borderColor: "#00ddc7",
          borderWidth: 1
        }}
      ]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      interaction: {{
        mode: "index",
        intersect: false
      }},
      plugins: {{
        legend: {{
          labels: {{
            color: "#c8d6e6"
          }}
        }},
        title: {{
          display: true,
          text: (historyIp ? "Device " + historyIp + " - " : "Network - ") + period.toUpperCase(),
          color: "#eaf2ff"
        }}
      }},
      scales: {{
        y: {{
          beginAtZero: true,
          grid: {{ color: "rgba(96,126,160,.18)" }},
          ticks: {{ color: "#8ea0b8" }},
          title: {{
            display: true,
            text: "MB",
            color: "#8ea0b8"
          }}
        }},
        x: {{
          grid: {{ color: "rgba(96,126,160,.12)" }},
          ticks: {{
            color: "#8ea0b8",
            maxTicksLimit: 12
          }}
        }}
      }}
    }}
  }});
}}

loadHistory("1h");
</script>
"""
    return shell(title, body, "History")


@app.route("/traffic")
def traffic():
    mode = request.args.get("type", "total")
    sort = request.args.get("sort", "total")
    direction = request.args.get("dir", "desc")

    title = "Total Traffic"
    if mode == "download":
        title = "Download Usage"
    elif mode == "upload":
        title = "Upload Usage"

    def sort_link(label, key):
        next_dir = "desc"
        marker = ""
        if sort == key:
            next_dir = "asc" if direction == "desc" else "desc"
            marker = " ↓" if direction == "desc" else " ↑"
        return f'<a class="sort-link" href="/traffic?range={range_key()}&type={h(mode)}&sort={h(key)}&dir={next_dir}">{label}{marker}</a>'

    clear_notice = ""
    if request.args.get("cleared") == "1":
        clear_notice = "<div class='traffic-cleared'>Traffic history cleared. New traffic is now collecting from zero.</div>"
    elif request.args.get("clear_error") == "1":
        clear_notice = "<div class='traffic-clear-error'>Traffic history could not be cleared. Check the NetSpecter service log and try again.</div>"
    elif request.args.get("collector_error") == "1":
        clear_notice = "<div class='traffic-clear-error'>Traffic was cleared, but the collector did not start again. Run systemctl start netspecter-collector.</div>"

    body = f"""
{topbar(title)}
<div class="ns-polish-page ns-network-page">
  <section class="ns-polish-panel">
    <div class="ns-polish-header">
      <div>
        <h2 class="ns-polish-section-title">Traffic Usage</h2>
        <div class="ns-polish-subtle">Measured download, upload and live throughput from the existing traffic collector.</div>
      </div>
      <div class="ns-filter-bar">
        {time_picker()}
        <input id="trafficSearch" type="search" placeholder="Filter device or IP" aria-label="Filter traffic rows" data-table-search="trafficTable">
        <a class="ns-compact-button ns-compact-button--danger" href="/traffic/clear?range={range_key()}">Clear Traffic History</a>
      </div>
    </div>
    {clear_notice}
    <div class="ns-table-shell">
      <table id="trafficTable" class="ns-dense-table" data-page-size="14">
        <thead>
          <tr>
            <th>{sort_link('Device', 'device')}</th>
            <th>{sort_link('IP', 'ip')}</th>
            <th>{sort_link('Download', 'download')}</th>
            <th>{sort_link('Upload', 'upload')}</th>
            <th>{sort_link('Total', 'total')}</th>
            <th>Throughput</th>
          </tr>
        </thead>
        <tbody id="trafficRows">
          <tr class="ns-skeleton-row"><td colspan="6"><span></span><span></span><span></span></td></tr>
          <tr class="ns-skeleton-row"><td colspan="6"><span></span><span></span><span></span></td></tr>
          <tr class="ns-skeleton-row"><td colspan="6"><span></span><span></span><span></span></td></tr>
        </tbody>
      </table>
    </div>
  </section>
</div>
<script>
async function loadTrafficRows() {{
  try {{
    const response = await fetch("/api/traffic-rows?range={range_key()}&type={h(mode)}&sort={h(sort)}&dir={h(direction)}", {{cache: "no-store"}});
    if (!response.ok) return;
    const data = await response.json();
    const rows = document.getElementById("trafficRows");
    if (rows) rows.innerHTML = data.html || '<tr><td colspan="6"><div class="ns-dashboard-empty">No traffic yet.</div></td></tr>';
    if (window.NetSpecterUi && window.NetSpecterUi.refreshTables) window.NetSpecterUi.refreshTables();
    refreshLiveSpeeds();
  }} catch (error) {{
    console.log("Traffic rows failed:", error);
  }}
}}
loadTrafficRows();
</script>
"""
    return shell(title, body, "Traffic")


@app.route("/api/traffic-rows")
def api_traffic_rows():
    mode = request.args.get("type", "total")
    sort = request.args.get("sort", "total")
    direction = request.args.get("dir", "desc")
    try:
        limit = max(1, min(int(request.args.get("limit", "200") or "200"), 500))
    except Exception:
        limit = 200
    try:
        offset = max(0, int(request.args.get("offset", "0") or "0"))
    except Exception:
        offset = 0
    start_day = range_start_day()
    sort_map = {
        "device": "name",
        "ip": "ip_sort",
        "download": "downloaded_mb",
        "upload": "uploaded_mb",
        "total": "total_mb",
    }
    sort_col = sort_map.get(sort, "total_mb")
    direction_sql = "ASC" if direction == "asc" else "DESC"
    rows = cached_query(
        f"traffic_rows:{start_day}:{mode}:{sort}:{direction}:{limit}:{offset}",
        HEAVY_PAGE_CACHE_SECONDS,
        f"""
        WITH usage AS (
            SELECT
                ip,
                MAX(name) AS name,
                MAX(mac) AS mac,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb,
                MAX(live_bps) AS live_bps,
                MAX(day) AS day,
                MAX(ts) AS ts
            FROM traffic_intervals
            WHERE day>=?
            GROUP BY ip
        )
        SELECT
            COALESCE(o.name, d.name, u.name, u.ip) AS name,
            u.ip AS ip_sort,
            u.*
        FROM usage u
        LEFT JOIN devices d ON d.ip = u.ip
        LEFT JOIN device_overrides o ON o.ip = u.ip
        ORDER BY {sort_col} {direction_sql}
        LIMIT ?
        OFFSET ?
        """,
        (start_day, limit, offset),
    )
    live_speeds = live_all_host_speeds()
    html_rows = ""
    for r in rows:
        device_ip = str(r["ip"] or "")
        device_href = f"/devices?device={quote(device_ip, safe='')}&tab=activity"
        html_rows += f"""
<tr data-search="{h(str(r['name'] or '') + ' ' + device_ip)}">
  <td><a href="{h(device_href)}"><b>{h(r['name'])}</b></a></td>
  <td><a href="{h(device_href)}">{h(device_ip)}</a></td>
  <td>{fmt_mb(r['downloaded_mb'])}</td>
  <td>{fmt_mb(r['uploaded_mb'])}</td>
  <td>{fmt_mb(r['total_mb'])}</td>
  <td><span data-live-ip="{h(device_ip)}" data-live-field="total">{fmt_bits_as_bytes(live_speeds.get(device_ip, {}).get('total_bps', 0))}</span></td>
</tr>
"""
    return {"html": html_rows}


@app.route("/traffic/clear", methods=["GET", "POST"])
def clear_traffic_history():
    if request.method == "POST":
        if not collector_service_action("stop"):
            return local_redirect(f"/traffic?range={range_key()}&clear_error=1")

        try:
            init_db()
            con = connect_db()
            con.execute("DELETE FROM traffic_intervals")
            con.execute("DELETE FROM traffic_samples")
            con.execute("DELETE FROM estimated_app_traffic")
            con.execute("DELETE FROM remote_traffic_intervals")
            con.execute("DELETE FROM live_device_speed")
            con.commit()
            con.close()
        except Exception as e:
            print(f"Traffic history clear failed: {e}")
            collector_service_action("start")
            return local_redirect(f"/traffic?range={range_key()}&clear_error=1")

        if not collector_service_action("start"):
            return redirect("/traffic?range=1d&collector_error=1")
        return redirect("/traffic?range=1d&cleared=1")

    sample_rows = query("SELECT COUNT(*) AS total FROM traffic_intervals")
    sample_count = int(sample_rows[0]["total"] or 0) if sample_rows else 0

    body = f"""
{topbar('Clear Traffic History')}
<style>
.clear-warning {{ max-width:620px; }}
.clear-warning p {{ color:#b8c7da; line-height:1.55; }}
.clear-warning strong {{ color:#ff8997; }}
.clear-actions {{ display:flex; gap:10px; align-items:center; margin-top:20px; }}
.clear-actions a {{ color:#c5d3e4; text-decoration:none; font-weight:700; padding:11px 15px; }}
</style>
<div class="panel clear-warning">
  <h2>Are you sure?</h2>
  <p>This will permanently delete <strong>{sample_count:,} measured traffic intervals</strong> and reset the live traffic totals to zero.</p>
  <p>Your DNS history, settings, login and edited device names will not be changed.</p>
  <form method="post" class="clear-actions">
    {csrf_input()}
    <button class="btn-red" type="submit">Yes, Clear Traffic History</button>
    <a href="/traffic?range={range_key()}">Cancel</a>
  </form>
</div>
"""
    return shell("Clear Traffic History", body, "Traffic")


@app.route("/applications")
def applications():
    start_day = range_start_day()
    view_mode = request.args.get("view", "").strip().lower()
    sort = request.args.get("sort", "")
    direction = request.args.get("dir", "desc")
    app_page_size = 5
    try:
        app_page = max(1, int(request.args.get("app_page", "1") or "1"))
    except ValueError:
        app_page = 1
    total_usage_rows = cached_query(
        f"applications_total_usage:{start_day}",
        HEAVY_PAGE_CACHE_SECONDS,
        "SELECT COALESCE(SUM(total_mb), 0) AS total, COALESCE(SUM(downloaded_mb), 0) AS down, COALESCE(SUM(uploaded_mb), 0) AS up FROM estimated_app_traffic WHERE day>=?",
        (start_day,),
    )
    total_traffic_rows = cached_query(
        f"applications_total_traffic:{start_day}",
        HEAVY_PAGE_CACHE_SECONDS,
        "SELECT COALESCE(SUM(total_mb), 0) AS total, COALESCE(SUM(downloaded_mb), 0) AS down, COALESCE(SUM(uploaded_mb), 0) AS up FROM traffic_intervals WHERE day>=?",
        (start_day,),
    )
    attributed_total = float(total_usage_rows[0]["total"] or 0) if total_usage_rows else 0.0
    attributed_down = float(total_usage_rows[0]["down"] or 0) if total_usage_rows else 0.0
    attributed_up = float(total_usage_rows[0]["up"] or 0) if total_usage_rows else 0.0
    all_traffic_total = float(total_traffic_rows[0]["total"] or 0) if total_traffic_rows else 0.0
    all_traffic_down = float(total_traffic_rows[0]["down"] or 0) if total_traffic_rows else 0.0
    all_traffic_up = float(total_traffic_rows[0]["up"] or 0) if total_traffic_rows else 0.0
    unattributed_total = max(all_traffic_total - attributed_total, 0.0)
    unattributed_down = max(all_traffic_down - attributed_down, 0.0)
    unattributed_up = max(all_traffic_up - attributed_up, 0.0)
    coverage_total = attributed_total + unattributed_total
    classified_pct = round((attributed_total / coverage_total * 100), 1) if coverage_total else 0.0
    usage_available = attributed_total > 0
    if view_mode not in ("data", "dns"):
        view_mode = "data" if usage_available else "dns"
    if not sort:
        sort = "used" if view_mode == "data" and usage_available else "queries"
    sort_map = {
        "app": "d.category COLLATE NOCASE",
        "download": "downloaded_mb",
        "upload": "uploaded_mb",
        "used": "total_mb",
        "devices": "devices",
        "domains": "domains",
        "queries": "queries",
        "share": "share_sort",
    }
    sort_col = sort_map.get(sort, "queries")
    direction_sql = "ASC" if direction == "asc" else "DESC"
    rows = cached_query(
        f"applications_rows:{start_day}:{view_mode}:{sort}:{direction}:{app_page}",
        HEAVY_PAGE_CACHE_SECONDS,
        f"""
        WITH dns AS (
            SELECT
                category,
                COUNT(*) AS queries,
                COUNT(DISTINCT client) AS devices,
                COUNT(DISTINCT domain) AS domains,
                MAX(ts) AS last_seen
            FROM dns_querylog
            WHERE day>=?
            GROUP BY category
        ),
        usage AS (
            SELECT
                category,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb,
                COUNT(DISTINCT ip) AS usage_devices
            FROM estimated_app_traffic
            WHERE day>=?
            GROUP BY category
        )
        SELECT
            d.category,
            d.queries,
            d.devices,
            d.domains,
            d.last_seen,
            COALESCE(u.downloaded_mb, 0) AS downloaded_mb,
            COALESCE(u.uploaded_mb, 0) AS uploaded_mb,
            COALESCE(u.total_mb, 0) AS total_mb,
            COALESCE(u.total_mb, 0) AS share_sort,
            COALESCE(u.usage_devices, 0) AS usage_devices
        FROM dns d
        LEFT JOIN usage u ON u.category = d.category
        ORDER BY {sort_col} {direction_sql}, d.category COLLATE NOCASE ASC
        LIMIT 100
        """,
        (start_day, start_day),
    )
    def sort_link(label, key):
        next_dir = "desc"
        marker = ""
        if sort == key:
            next_dir = "asc" if direction == "desc" else "desc"
            marker = " v" if direction == "desc" else " ^"
        return f'<a class="sort-link" href="/applications?range={range_key()}&view={h(view_mode)}&sort={h(key)}&dir={next_dir}">{h(label)}{marker}</a>'

    max_count = max([float(r["total_mb"] or 0) if view_mode == "data" else int(r["queries"] or 0) for r in rows], default=1) or 1
    total_queries = sum([int(r["queries"] or 0) for r in rows])
    device_count_rows = cached_query(
        f"applications_device_count:{start_day}",
        HEAVY_PAGE_CACHE_SECONDS,
        "SELECT COUNT(DISTINCT client) AS total FROM dns_querylog WHERE day>=?",
        (start_day,),
    )
    total_devices = int(device_count_rows[0]["total"] or 0) if device_count_rows else 0
    domain_count_rows = cached_query(
        f"applications_domain_count:{start_day}",
        HEAVY_PAGE_CACHE_SECONDS,
        "SELECT COUNT(DISTINCT domain) AS total FROM dns_querylog WHERE day>=?",
        (start_day,),
    )
    total_domains = int(domain_count_rows[0]["total"] or 0) if domain_count_rows else 0
    range_links = ""
    for key, label in [("1d", "Today"), ("7d", "7 Days"), ("30d", "30 Days"), ("60d", "60 Days"), ("90d", "90 Days")]:
        active = "active" if key == range_key() else ""
        range_links += f'<a class="{active}" href="/applications?range={key}&view={h(view_mode)}">{label}</a>'
    app_time_picker = f'<div class="time-picker ns-app-time-picker">{range_links}</div>'

    include_unattributed = view_mode == "data" and usage_available and unattributed_total > 0.01
    display_rows = list(rows)
    if include_unattributed:
        display_rows.append({
            "category": "__unattributed__",
            "queries": 0,
            "devices": 0,
            "domains": 0,
            "downloaded_mb": unattributed_down,
            "uploaded_mb": unattributed_up,
            "total_mb": unattributed_total,
        })
    total_app_rows = len(display_rows)
    total_app_pages = max(1, math.ceil(total_app_rows / app_page_size))
    app_page = min(app_page, total_app_pages)
    page_rows = display_rows[(app_page - 1) * app_page_size:app_page * app_page_size]
    app_rows = ""
    rank = 0
    for r in page_rows:
        category = str(r["category"] or "Other")
        is_unattributed = category == "__unattributed__"
        used_total = float(r["total_mb"] or 0)
        used_down = float(r["downloaded_mb"] or 0)
        used_up = float(r["uploaded_mb"] or 0)
        confidence = "Unattributed" if is_unattributed else "Estimated" if used_total > 0 else "DNS activity only"
        confidence_class = "ns-chip--warning" if used_total > 0 else ""
        total = int(r["queries"] or 0)
        devices = int(r["devices"] or 0)
        domains = int(r["domains"] or 0)
        activity_value = used_total if view_mode == "data" else total
        width = max(5, min(activity_value / max_count * 100, 100)) if activity_value else 5
        if is_unattributed:
            width = max(5, min((unattributed_total / max(all_traffic_total, 1)) * 100, 100))
            pct = round((unattributed_total / all_traffic_total * 100), 1) if all_traffic_total else 0
        else:
            pct = round((used_total / attributed_total * 100), 1) if view_mode == "data" and attributed_total else round((total / total_queries * 100), 1) if total_queries else 0
        href = "/applications/" + quote(category, safe="") + f"?range={range_key()}&view={h(view_mode)}"
        rank += 1
        display_rank = (app_page - 1) * app_page_size + rank
        row_tag = "div" if is_unattributed else "a"
        row_href = "" if is_unattributed else f' href="{href}"'
        row_class = "app-row ns-app-activity-row ns-unattributed-row" if is_unattributed else "app-row app-link ns-app-activity-row"
        row_name = "Other / Unattributed" if is_unattributed else h(category)
        app_rows += f"""
<{row_tag} class="{row_class}"{row_href} data-search="{h(category)}">
  <span class="ns-app-rank">{display_rank}</span>
  <span class="app-icon">{icon_for_app('Other' if is_unattributed else category)}</span>
  <span class="app-name">{row_name}<small class="monitor-badge {confidence_class}">{h(confidence)}</small></span>
  <span class="app-meta">{fmt_mb(used_down)}</span>
  <span class="app-meta">{fmt_mb(used_up)}</span>
  <span class="ns-app-total-used"><b>{fmt_mb(used_total)}</b><span class="bar"><span style="width:{width}%"></span></span></span>
  <span class="app-meta">{'-' if is_unattributed else str(devices) + ' devices'}</span>
  <span class="app-meta">{'-' if is_unattributed else str(domains) + ' domains'}</span>
  <span class="app-meta">{'-' if is_unattributed else f'{total:,}'}</span>
  <span class="app-meta">{pct}%</span>
</{row_tag}>
"""

    if not app_rows:
        app_rows = "<div class='ns-dashboard-empty'>No application activity recorded for this range yet.</div>"
    if view_mode == "data" and not usage_available:
        app_rows = """
<div class='ns-dashboard-empty'>
  Bandwidth attribution is not available yet for this range. NetSpecter has DNS activity, but no DNS-to-flow byte counters have been recorded by the bridge collector.
</div>
""" + app_rows
    app_pager = ""
    if total_app_pages > 1:
        base = f"/applications?range={range_key()}&view={h(view_mode)}&sort={h(sort)}&dir={h(direction)}"
        previous_link = (
            f'<a href="{base}&app_page={app_page - 1}">&lt; Previous</a>'
            if app_page > 1
            else '<span class="is-disabled">&lt; Previous</span>'
        )
        next_link = (
            f'<a href="{base}&app_page={app_page + 1}">Next &gt;</a>'
            if app_page < total_app_pages
            else '<span class="is-disabled">Next &gt;</span>'
        )
        app_pager = (
            '<div class="ns-pagination ns-app-pagination" aria-label="Top applications pages">'
            f'{previous_link}<span class="ns-page-count">Page {app_page} of {total_app_pages}</span>{next_link}'
            '</div>'
        )

    device_rows = query(
        """
        WITH usage AS (
            SELECT ip, SUM(total_mb) AS total_mb
            FROM estimated_app_traffic
            WHERE day>=?
            GROUP BY ip
        ),
        dns AS (
            SELECT client, COUNT(*) AS queries
            FROM dns_querylog
            WHERE day>=?
            GROUP BY client
        )
        SELECT
            u.ip,
            COALESCE(o.name, d.name, u.ip) AS name,
            COALESCE(o.device_type, d.device_type, 'Unknown') AS device_type,
            COALESCE(u.total_mb, 0) AS total_mb,
            COALESCE(dns.queries, 0) AS queries,
            CASE WHEN COALESCE(u.total_mb, 0) > 0 THEN COALESCE(u.total_mb, 0) ELSE COALESCE(dns.queries, 0) END AS sort_value
        FROM usage u
        LEFT JOIN devices d ON d.ip = u.ip
        LEFT JOIN device_overrides o ON o.ip = u.ip
        LEFT JOIN dns ON dns.client = u.ip
        ORDER BY sort_value DESC, total_mb DESC, queries DESC, name ASC
        LIMIT 5
        """,
        (start_day, start_day),
    )
    device_rows = list(device_rows)[:5]
    top_device_rows = ""
    for r in device_rows:
        device_total = float(r["total_mb"] or 0)
        top_device_rows += f"""
<a class="ns-app-device-row" href="/devices?device={h(r['ip'])}&tab=activity">
  <span class="ns-app-device-id"><span class="ns-app-device-icon">{icon_for_device(r['device_type'])}</span><small>{h(r['ip'])}</small></span>
  <span class="ns-app-device-name">{h(r['name'])}</span>
  <span class="ns-app-device-total">{fmt_mb(device_total)}</span>
</a>
"""
    if not top_device_rows:
        top_device_rows = "<div class='ns-dashboard-empty'>No estimated application usage by device yet.</div>"

    coverage_width = max(0.0, min(classified_pct, 100.0)) if coverage_total else 0.0
    classified_rows = sorted(
        [r for r in rows if float(r["total_mb"] or 0) > 0],
        key=lambda r: float(r["total_mb"] or 0),
        reverse=True,
    )[:5]
    top_classified_rows = ""
    for r in classified_rows:
        category = str(r["category"] or "Other")
        used_total = float(r["total_mb"] or 0)
        share = round((used_total / attributed_total * 100), 1) if attributed_total else 0.0
        bar_width = max(4, min(share, 100)) if share else 0
        top_classified_rows += f"""
<tr>
  <td><span class="ns-coverage-app-name"><span class="app-icon">{icon_for_app(category)}</span>{h(category)}</span></td>
  <td>DNS/app mapped</td>
  <td>{fmt_mb(used_total)}</td>
  <td><span>{share}%</span><span class="ns-coverage-mini-bar purple"><span style="width:{bar_width}%"></span></span></td>
</tr>
"""
    if not top_classified_rows:
        top_classified_rows = "<tr><td colspan='4'><div class='ns-dashboard-empty'>No classified application traffic recorded for this range yet.</div></td></tr>"

    unattributed_rows = ""
    if unattributed_total > 0.01:
        unattributed_rows = f"""
<tr>
  <td>Other / Unclassified</td>
  <td>{fmt_mb(unattributed_total)}</td>
  <td><span>100.0%</span><span class="ns-coverage-mini-bar muted"><span style="width:100%"></span></span></td>
</tr>
"""
        unattributed_note = "<p class='ns-coverage-note'>Protocol split is unavailable for unattributed bridge totals.</p>"
    else:
        unattributed_rows = "<tr><td colspan='3'><div class='ns-dashboard-empty'>No unattributed traffic recorded for this range.</div></td></tr>"
        unattributed_note = ""

    if view_mode == "dns":
        coverage_section = f"""
  <section class="ns-polish-panel ns-classification-coverage">
    <div class="ns-polish-header">
      <h2 class="ns-polish-section-title">Classification Coverage</h2>
    </div>
    <div class="ns-dashboard-empty ns-coverage-empty">
      Classification coverage uses traffic byte counters and is shown in Data Used mode. DNS Activity uses query counts, so it is kept separate from byte coverage.
      <a class="ns-compact-button" href="/applications?range={range_key()}&view=data#classificationCoverage">View Data Used</a>
    </div>
  </section>
"""
    else:
        coverage_empty = ""
        if coverage_total <= 0.01:
            coverage_empty = "<div class='ns-dashboard-empty ns-coverage-empty'>No traffic bytes have been collected for this range yet.</div>"
        coverage_section = f"""
  <section class="ns-polish-panel ns-classification-coverage" id="classificationCoverage">
    <div class="ns-polish-header">
      <h2 class="ns-polish-section-title">Classification Coverage</h2>
    </div>
    <div class="ns-coverage-stats">
      <div><b>{fmt_mb(coverage_total)}</b><span>Total Traffic</span></div>
      <div><b class="purple">{fmt_mb(attributed_total)}</b><span>Classified</span></div>
      <div><b>{fmt_mb(unattributed_total)}</b><span>Unattributed</span></div>
      <div><b class="cyan">{classified_pct:.1f}%</b><span>classified</span></div>
    </div>
    <div class="ns-coverage-bar" aria-label="Classification coverage {classified_pct:.1f}%">
      <span class="ns-coverage-fill" style="width:{coverage_width}%"></span>
    </div>
    <div class="ns-coverage-helper"><i class="fa-solid fa-circle-info"></i> Improve coverage by adding DNS/app mappings</div>
    {coverage_empty}
  </section>
  <section class="ns-coverage-panels">
    <div class="ns-polish-panel ns-coverage-detail">
      <div class="ns-polish-header">
        <h2 class="ns-polish-section-title">Top Classified Data</h2>
      </div>
      <table class="ns-coverage-table">
        <thead><tr><th>Application</th><th>Category</th><th>Traffic</th><th>Percentage</th></tr></thead>
        <tbody>{top_classified_rows}</tbody>
      </table>
    </div>
    <div class="ns-polish-panel ns-coverage-detail">
      <div class="ns-polish-header">
        <h2 class="ns-polish-section-title">Unattributed Traffic</h2>
      </div>
      <table class="ns-coverage-table">
        <thead><tr><th>Application / Protocol</th><th>Traffic</th><th>Percentage</th></tr></thead>
        <tbody>{unattributed_rows}</tbody>
      </table>
      {unattributed_note}
    </div>
  </section>
"""

    clear_notice = ""
    if request.args.get("cleared") == "1":
        clear_notice = "<div class='ns-inline-notice ns-inline-notice--ok'>Application history cleared. New AdGuard activity will appear as it is imported.</div>"
    elif request.args.get("clear_error") == "1":
        clear_notice = "<div class='ns-inline-notice ns-inline-notice--error'>Application history could not be cleared. Check the NetSpecter service log and try again.</div>"

    body = f"""
{topbar('Application Activity')}
<div class="ns-polish-page ns-network-page ns-app-dashboard">
  <div class="ns-app-toolbar">
    {app_time_picker}
    <div class="ns-filter-bar">
      <a class="{'is-active' if view_mode == 'data' else ''}" href="/applications?range={range_key()}&view=data">Data Used</a>
      <a class="{'is-active' if view_mode == 'dns' else ''}" href="/applications?range={range_key()}&view=dns">DNS Activity</a>
      <input type="search" placeholder="Filter application" aria-label="Filter application activity" data-app-filter>
      <a class="ns-compact-button ns-compact-button--danger" href="/applications/clear?range={range_key()}">Clear App History</a>
    </div>
  </div>
  {clear_notice}
  <section class="ns-app-metric-grid">
    <div class="ns-polish-card ns-app-metric"><span class="ns-app-metric-icon purple"><i class="fa-solid fa-wave-square"></i></span><span class="label">Total Classified Data Used</span><b class="big blue">{fmt_mb(attributed_total)}</b><small>Coverage: {classified_pct}% classified of {fmt_mb(coverage_total)}</small></div>
    <div class="ns-polish-card ns-app-metric"><span class="ns-app-metric-icon blue"><i class="fa-solid fa-table-cells-large"></i></span><span class="label">DNS Queries</span><b class="big">{total_queries:,}</b><small>Total observed</small></div>
    <div class="ns-polish-card ns-app-metric"><span class="ns-app-metric-icon green"><i class="fa-solid fa-display"></i></span><span class="label">Active Applications</span><b class="big green">{len(rows):,}</b><small>Unique categories</small></div>
    <div class="ns-polish-card ns-app-metric"><span class="ns-app-metric-icon cyan"><i class="fa-solid fa-globe"></i></span><span class="label">Unattributed Traffic</span><b class="big yellow">{fmt_mb(unattributed_total)}</b><small>Not app-attributed</small></div>
  </section>
  <section class="ns-app-content-grid">
    <div class="ns-polish-panel apps-panel">
      <div class="ns-polish-header">
        <h2 class="ns-polish-section-title">Top Applications <span class="ns-help-dot" title="Data usage is attributed from observed network flows and DNS classification. Some traffic may be estimated or unattributed.">i</span></h2>
        <a class="ns-polish-subtle" href="/applications?range={range_key()}&view={h(view_mode)}">View all applications</a>
      </div>
      <div class="apps-header ns-apps-header">
        <span>{sort_link('Application', 'app')}</span>
        <span>{sort_link('Download', 'download')}</span>
        <span>{sort_link('Upload', 'upload')}</span>
        <span>{sort_link('Total Used', 'used')}</span>
        <span>{sort_link('Devices', 'devices')}</span>
        <span>{sort_link('Domains', 'domains')}</span>
        <span>{sort_link('Queries', 'queries')}</span>
        <span>{sort_link('Share', 'share')}</span>
      </div>
      <div class="apps-list" id="applicationActivityList">
        {app_rows}
      </div>
      {app_pager}
    </div>
    <div class="ns-polish-panel ns-app-device-panel">
      <div class="ns-polish-header">
        <h2 class="ns-polish-section-title">Top Devices <span class="ns-help-dot" title="Devices ranked by estimated application-attributed traffic.">i</span></h2>
      </div>
      <div class="ns-app-device-head"><span>Device</span><span>Data Used</span></div>
      <div class="ns-app-device-list">{top_device_rows}</div>
    </div>
  </section>
  {coverage_section}
</div>
<script>
document.querySelector("[data-app-filter]")?.addEventListener("input", (event) => {{
  const term = event.target.value.trim().toLowerCase();
  document.querySelectorAll(".ns-app-activity-row").forEach((row) => {{
    row.hidden = term && !(row.getAttribute("data-search") || "").toLowerCase().includes(term);
  }});
}});
const topDevicesList = document.querySelector(".ns-app-device-list");
if (topDevicesList) {{
  const deviceRows = Array.from(topDevicesList.querySelectorAll(".ns-app-device-row")).slice(0, 5);
  if (deviceRows.length) {{
    topDevicesList.innerHTML = "";
    deviceRows.forEach((row) => topDevicesList.appendChild(row));
  }}
}}
</script>
"""
    return shell("Application Activity", body, "Application Activity")


@app.route("/applications/clear", methods=["GET", "POST"])
def clear_application_history():
    if request.method == "POST":
        try:
            init_db()
            con = connect_db()
            con.execute("DELETE FROM dns_querylog")
            con.execute(
                "INSERT INTO dns_import_state (id, cleared_at) VALUES (1, ?) "
                "ON CONFLICT(id) DO UPDATE SET cleared_at=excluded.cleared_at",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
            )
            con.commit()
            con.close()
        except Exception as e:
            print(f"Application history clear failed: {e}")
            return local_redirect(f"/applications?range={range_key()}&clear_error=1")

        return redirect("/applications?range=1d&cleared=1")

    log_rows = query("SELECT COUNT(*) AS total FROM dns_querylog")
    query_count = int(log_rows[0]["total"] or 0) if log_rows else 0

    body = f"""
{topbar('Clear App History')}
<style>
.clear-warning {{ max-width:620px; }}
.clear-warning p {{ color:#b8c7da; line-height:1.55; }}
.clear-warning strong {{ color:#ff8997; }}
.clear-actions {{ display:flex; gap:10px; align-items:center; margin-top:20px; }}
.clear-actions a {{ color:#c5d3e4; text-decoration:none; font-weight:700; padding:11px 15px; }}
</style>
<div class="panel clear-warning">
  <h2>Are you sure?</h2>
  <p>This will permanently delete <strong>{query_count:,} stored DNS/application activity records</strong> and clear Top Applications.</p>
  <p>Your traffic history, settings, login and edited device names will not be changed.</p>
  <form method="post" class="clear-actions">
    {csrf_input()}
    <button class="btn-red" type="submit">Yes, Clear App History</button>
    <a href="/applications?range={range_key()}">Cancel</a>
  </form>
</div>
"""
    return shell("Clear App History", body, "Application Activity")


@app.route("/applications/<path:category>")
def application_detail(category):
    category = unquote(category or "Other")[:120].strip() or "Other"
    monitoring_enabled = category in MONITORED_APP_CATEGORIES
    start_day = range_start_day()
    sort = request.args.get("sort", "queries")
    direction = request.args.get("dir", "desc")

    sort_map = {
        "device": "device_name",
        "client": "l.client",
        "domains": "domains",
        "queries": "total",
        "estimated": "estimated_total_mb",
        "last": "last_seen",
    }
    sort_col = sort_map.get(sort, "total")
    direction_sql = "ASC" if direction == "asc" else "DESC"

    device_rows = cached_query(
        f"application_detail_devices:{start_day}:{category}:{sort}:{direction}",
        30,
        f"""
        SELECT
            l.client,
            COALESCE(o.name, d.name, l.client) AS device_name,
            COALESCE(o.device_type, d.device_type, 'Unknown') AS device_type,
            COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS vendor,
            COALESCE(d.ip, l.client) AS device_ip,
            COUNT(*) AS total,
            COUNT(DISTINCT l.domain) AS domains,
            MAX(l.ts) AS last_seen,
            COALESCE(MAX(m.downloaded_mb), 0) AS estimated_downloaded_mb,
            COALESCE(MAX(m.total_mb), 0) AS estimated_total_mb
        FROM dns_querylog l
        LEFT JOIN devices d
            ON d.ip = l.client
            OR LOWER(d.mac) = LOWER(l.client)
        LEFT JOIN device_overrides o
            ON o.ip = COALESCE(d.ip, l.client)
        LEFT JOIN (
            SELECT ip, SUM(downloaded_mb) AS downloaded_mb, SUM(total_mb) AS total_mb
            FROM estimated_app_traffic
            WHERE day>=? AND category=?
            GROUP BY ip
        ) m ON m.ip = COALESCE(d.ip, l.client)
        WHERE l.day>=? AND l.category=?
        GROUP BY l.client
        ORDER BY {sort_col} {direction_sql}
        LIMIT 200
        """,
        (start_day, category, start_day, category),
    )

    domain_rows = cached_query(
        f"application_detail_domains:{start_day}:{category}",
        30,
        """
        SELECT domain, COUNT(*) AS total, COUNT(DISTINCT client) AS devices, MAX(ts) AS last_seen
        FROM dns_querylog
        WHERE day>=? AND category=?
        GROUP BY domain
        ORDER BY total DESC
        LIMIT 100
        """,
        (start_day, category),
    )

    total_queries = sum(int(r["total"] or 0) for r in device_rows)
    max_device_queries = max([int(r["total"] or 1) for r in device_rows], default=1)
    measured_rows = cached_query(
        f"application_detail_measured:{start_day}:{category}",
        30,
        """
        SELECT
            ip,
            SUM(downloaded_mb) AS downloaded_mb,
            SUM(uploaded_mb) AS uploaded_mb,
            SUM(total_mb) AS total_mb
        FROM estimated_app_traffic
        WHERE day>=? AND category=?
        GROUP BY ip
        """,
        (start_day, category),
    ) if monitoring_enabled else []
    estimated_down = sum(float(r["downloaded_mb"] or 0) for r in measured_rows)
    estimated_up = sum(float(r["uploaded_mb"] or 0) for r in measured_rows)
    estimated_total = sum(float(r["total_mb"] or 0) for r in measured_rows)
    estimated_cards = f"""
  <div class="mini-card"><span>Attributed Download</span><b>{fmt_mb(estimated_down)}</b></div>
  <div class="mini-card"><span>Attributed Upload</span><b>{fmt_mb(estimated_up)}</b></div>
  <div class="mini-card"><span>Attributed Traffic</span><b>{fmt_mb(estimated_total)}</b></div>
""" if monitoring_enabled else ""
    estimated_note = (
        "<p>Attributed traffic includes only flows that NetSpecter could confidently link to this service. Actual usage may be higher.</p>"
        if monitoring_enabled
        else ""
    )
    empty_colspan = 7 if monitoring_enabled else 6

    def sort_link(label, key):
        next_dir = "desc"
        marker = ""
        if sort == key:
            next_dir = "asc" if direction == "desc" else "desc"
            marker = " ↓" if direction == "desc" else " ↑"
        href_raw = f"/applications/{quote(category, safe='')}?range={quote(range_key(), safe='')}&sort={quote(key, safe='')}&dir={quote(next_dir, safe='')}"
        href = h(href_raw)
        return f'<a class="sort-link" href="{href}">{h(label)}{marker}</a>'

    estimated_header = f"<th>{sort_link('Est. Download / Total', 'estimated')}</th>" if monitoring_enabled else ""
    ai_detail_panel = ""
    if category in {"ChatGPT", "OpenAI API", "Microsoft Copilot", "GitHub Copilot", "Claude", "Gemini", "Perplexity", "DeepSeek", "Grok", "Mistral", "Meta AI", "Hugging Face", "Cursor AI", "Windsurf", "Amazon Q"}:
        ai_summary = ai_attribution_summary({}, start_day + " 00:00:00", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        ai_service = next((row for row in ai_summary.get("services", []) if row.get("service") == category), None)
        if ai_service:
            ai_detail_panel = f"""
<div class="layout">
  <div class="panel">
    <h2>Detection</h2>
    <div class="apps-summary">
      <div class="mini-card"><span>Detected</span><b>{"Yes" if ai_service.get("service_detected") else "No"}</b></div>
      <div class="mini-card"><span>Detection Confidence</span><b>{h(ai_service.get("service_detection_confidence"))}</b></div>
      <div class="mini-card"><span>Devices</span><b>{len(ai_service.get("devices") or []):,}</b></div>
      <div class="mini-card"><span>Evidence</span><b>{h(ai_service.get("evidence_summary"))}</b></div>
    </div>
    <p>First seen: {h(ai_service.get("first_seen") or "N/A")}<br>Last seen: {h(ai_service.get("last_seen") or "N/A")}</p>
  </div>
  <div class="panel">
    <h2>Traffic Attribution</h2>
    <div class="apps-summary">
      <div class="mini-card"><span>Confidently Attributed</span><b>{h(fmt_mb(ai_service.get("attributed_mb") or 0))}</b></div>
      <div class="mini-card"><span>Upload</span><b>{h(fmt_mb(ai_service.get("uploaded_mb") or 0))}</b></div>
      <div class="mini-card"><span>Download</span><b>{h(fmt_mb(ai_service.get("downloaded_mb") or 0))}</b></div>
      <div class="mini-card"><span>Status</span><b>{h(ai_service.get("traffic_attribution_status"))}</b></div>
    </div>
    <p title="Attributed traffic includes only network flows that could be confidently linked to this service. Actual usage may be higher.">Traffic attribution confidence: {h(ai_service.get("traffic_attribution_confidence"))}. Actual usage may be higher where encrypted, CDN, shared-cloud, or long-lived traffic could not be assigned with sufficient confidence.</p>
  </div>
</div>
"""

    devices_table = ""
    for r in device_rows:
        device_ip = str(r["device_ip"] or r["client"] or "")
        total = int(r["total"] or 0)
        width = max(5, min(total / max_device_queries * 100, 100))
        href = f"/device/{quote(device_ip, safe='')}" if valid_lan_ip(device_ip) else "#"
        estimated_cell = (
            f"<td>{fmt_mb(r['estimated_downloaded_mb'])} / "
            f"<b>{fmt_mb(r['estimated_total_mb'])}</b></td>"
            if monitoring_enabled
            else ""
        )
        devices_table += f"""
<tr>
  <td>{icon_for_device(r['device_type'])} <a href="{h(href)}"><b>{h(r['device_name'])}</b></a><br><span>{h(r['vendor'])}</span></td>
  <td>{h(r['client'])}</td>
  <td>{int(r['domains'] or 0):,}</td>
  <td><div class="bar table-bar"><div style="width:{width}%"></div></div></td>
  <td><b>{total:,}</b></td>
  {estimated_cell}
  <td>{h(r['last_seen'])}</td>
</tr>
"""

    domains_table = ""
    for r in domain_rows:
        domains_table += f"""
<tr>
  <td>{h(r['domain'])}</td>
  <td>{int(r['devices'] or 0):,}</td>
  <td>{int(r['total'] or 0):,}</td>
  <td>{h(r['last_seen'])}</td>
</tr>
"""

    body = f"""
{topbar(category)}
{time_picker()}
<div class="app-detail-title">
  <a class="btn" href="/applications">Back to Application Activity</a>
  <div class="app-detail-icon">{icon_for_app(category)}</div>
  <div>
    <h2>{h(category)}</h2>
    <p>{len(device_rows):,} devices used this app today across {len(domain_rows):,} domains.</p>
  </div>
</div>
<div class="apps-summary">
  <div class="mini-card"><span>DNS Hits</span><b>{total_queries:,}</b></div>
  <div class="mini-card"><span>Devices</span><b>{len(device_rows):,}</b></div>
  <div class="mini-card"><span>Domains</span><b>{len(domain_rows):,}</b></div>
  {estimated_cards}
</div>
{ai_detail_panel}
<div class="layout">
  <div class="panel">
    <h2>Devices Using {h(category)}</h2>
    {estimated_note}
    <table>
      <tr>
        <th>{sort_link('Device', 'device')}</th>
        <th>{sort_link('Client', 'client')}</th>
        <th>{sort_link('Domains', 'domains')}</th>
        <th>Activity</th>
        <th>{sort_link('DNS Hits', 'queries')}</th>
        {estimated_header}
        <th>{sort_link('Last Seen', 'last')}</th>
      </tr>
      {devices_table or f'<tr><td colspan="{empty_colspan}">No devices recorded for this app today.</td></tr>'}
    </table>
  </div>
  <div class="panel">
    <h2>Top Domains</h2>
    <table>
      <tr><th>Domain</th><th>Devices</th><th>Queries</th><th>Last Seen</th></tr>
      {domains_table or '<tr><td colspan="4">No domains recorded for this app today.</td></tr>'}
    </table>
  </div>
</div>
"""
    return shell("Application Activity", body, "Application Activity")


@app.route("/blocked")
def blocked():
    start_day = range_start_day()
    device_filter = request.args.get("device", "").strip()
    category_filter = request.args.get("category", "").strip()
    domain_filter = request.args.get("domain", "").strip()
    where = ["day>=?", "blocked=1"]
    params = [start_day]
    if device_filter:
        where.append("client=?")
        params.append(device_filter)
    if category_filter:
        where.append("category=?")
        params.append(category_filter)
    if domain_filter:
        where.append("domain LIKE ?")
        params.append(f"%{domain_filter}%")
    where_sql = " AND ".join(where)
    cache_filter_key = f"{device_filter}:{category_filter}:{domain_filter}"
    rows = cached_query(
        f"blocked_rows:{start_day}:{cache_filter_key}",
        HEAVY_PAGE_CACHE_SECONDS,
        f"""
        SELECT client, domain, category, COUNT(*) AS total, MAX(ts) AS last_seen
        FROM dns_querylog
        WHERE {where_sql}
        GROUP BY client, domain, category
        ORDER BY total DESC, last_seen DESC
        LIMIT 200
        """,
        tuple(params),
    )
    summary_rows = cached_query(
        f"blocked_summary:{start_day}:{cache_filter_key}",
        HEAVY_PAGE_CACHE_SECONDS,
        f"""
        SELECT
            COUNT(*) AS total,
            COUNT(DISTINCT domain) AS domains,
            COUNT(DISTINCT client) AS devices
        FROM dns_querylog
        WHERE {where_sql}
        """,
        tuple(params),
    )
    top_category_rows = cached_query(
        f"blocked_top_category:{start_day}:{cache_filter_key}",
        HEAVY_PAGE_CACHE_SECONDS,
        f"""
        SELECT category, COUNT(*) AS total
        FROM dns_querylog
        WHERE {where_sql}
        GROUP BY category
        ORDER BY total DESC
        LIMIT 1
        """,
        tuple(params),
    )
    category_rows = cached_query(
        f"blocked_categories:{start_day}",
        HEAVY_PAGE_CACHE_SECONDS,
        """
        SELECT category
        FROM dns_querylog
        WHERE day>=? AND blocked=1
        GROUP BY category
        ORDER BY category COLLATE NOCASE
        """,
        (start_day,),
    )
    summary = summary_rows[0] if summary_rows else {}
    total_blocked = int(summary["total"] or 0) if summary else 0
    blocked_domains = int(summary["domains"] or 0) if summary else 0
    affected_devices = int(summary["devices"] or 0) if summary else 0
    top_category = str(top_category_rows[0]["category"] or "None") if top_category_rows else "None"
    category_options = '<option value="">All categories</option>'
    for row in category_rows:
        value = str(row["category"] or "Other")
        selected = " selected" if value == category_filter else ""
        category_options += f'<option value="{h(value)}"{selected}>{h(value)}</option>'

    table = ""
    for r in rows:
        client = str(r["client"] or "")
        category = str(r["category"] or "Other")
        domain = str(r["domain"] or "")
        table += f"""
<tr data-search="{h(client + ' ' + domain + ' ' + category)}">
  <td><a href="/devices?device={h(client)}&tab=alerts">{h(client)}</a></td>
  <td class="ns-truncate">{icon_for_app(category)} <a href="/blocked?range={range_key()}&domain={quote(domain, safe='')}">{h(domain)}</a></td>
  <td><span class="ns-chip">{h(category)}</span></td>
  <td><b>{int(r['total'] or 0):,}</b></td>
  <td>{h(r['last_seen'])}</td>
</tr>
"""

    body = f"""
{topbar('Blocked DNS Requests')}
<div class="ns-polish-page ns-network-page">
  <section class="ns-polish-panel">
    <div class="ns-polish-header">
      <div>
        <h2 class="ns-polish-section-title">Blocked DNS Requests</h2>
        <div class="ns-polish-subtle">Blocked DNS decisions imported from the existing AdGuard query log.</div>
      </div>
      <form class="ns-filter-bar" method="GET" action="/blocked">
        {time_picker()}
        <input type="search" name="domain" value="{h(domain_filter)}" placeholder="Domain contains" aria-label="Filter blocked domain">
        <input type="search" name="device" value="{h(device_filter)}" placeholder="Device IP or client" aria-label="Filter blocked device">
        <select name="category" aria-label="Filter blocked category">{category_options}</select>
        <button type="submit">Apply</button>
        <a href="/blocked?range={range_key()}">Reset</a>
      </form>
    </div>
    <div class="ns-summary-grid">
      <div class="ns-polish-card"><span class="label">Blocked Requests</span><b class="big red">{total_blocked:,}</b></div>
      <div class="ns-polish-card"><span class="label">Blocked Domains</span><b class="big">{blocked_domains:,}</b></div>
      <div class="ns-polish-card"><span class="label">Affected Devices</span><b class="big yellow">{affected_devices:,}</b></div>
      <div class="ns-polish-card"><span class="label">Top Category</span><b class="big">{h(top_category)}</b></div>
    </div>
  </section>
  <section class="ns-polish-panel">
    <div class="ns-polish-header">
      <h2 class="ns-polish-section-title">Recent Blocked Domains</h2>
      <input class="ns-inline-search" type="search" placeholder="Filter visible rows" aria-label="Filter visible blocked rows" data-table-search="blockedDnsTable">
    </div>
    <div class="ns-table-shell">
      <table id="blockedDnsTable" class="ns-dense-table" data-page-size="14">
        <thead><tr><th>Client</th><th>Domain</th><th>Category</th><th>Blocked</th><th>Last Seen</th></tr></thead>
        <tbody>{table or '<tr><td colspan="5"><div class="ns-dashboard-empty">No blocked DNS records for this range.</div></td></tr>'}</tbody>
      </table>
    </div>
  </section>
</div>
"""
    return shell("Blocked DNS Requests", body, "Blocked DNS Requests")


@app.route("/blocked-services")
def blocked_services():
    return local_redirect(f"/blocked?range={range_key()}")


def recent_suricata_alerts(limit=300, filters=None):
    """Read structured Suricata alerts, with bounded fast.log fallback."""
    try:
        if (filters or {}).get("event_type") and (filters or {}).get("event_type") != "alert":
            alerts = recent_structured_event_summaries(connect_db, limit=limit, filters=filters or {})
        else:
            alerts = recent_structured_alerts(connect_db, limit=limit, filters=filters or {})
        if alerts:
            return alerts, ""
    except Exception as error:
        print(f"Structured IDS query failed: {error}")
    if not SURICATA_FAST_LOG.exists():
        if not SURICATA_EVE_LOG.exists():
            return [], "Suricata eve.json and fast.log were not found."
        return [], "No structured Suricata alerts have been imported yet."
    try:
        result = subprocess.run(
            ["tail", "-n", str(limit), str(SURICATA_FAST_LOG)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            check=False,
        )
        if result.returncode != 0:
            return [], "Suricata alert log could not be read."
    except Exception as error:
        print(f"Suricata alert log read failed: {error}")
        return [], "Suricata alert log could not be read."

    return fast_log_alerts_from_text(result.stdout, limit), ""


def ids_device_names():
    rows = query(
        """
        SELECT d.ip, COALESCE(o.name, d.name, d.ip) AS name
        FROM devices d
        LEFT JOIN device_overrides o ON o.ip=d.ip
        """
    )
    return {str(row["ip"]): str(row["name"] or row["ip"]) for row in rows}


def send_smtp_message(config, subject, body):
    host = str(config.get("smtp_host", "") or "").strip()
    username = str(config.get("smtp_username", "") or "").strip()
    password = str(config.get("smtp_password", "") or "")
    from_address = str(config.get("smtp_from", "") or username).strip()
    to_address = str(config.get("smtp_to", "") or "").strip()
    security = str(config.get("smtp_security", "starttls") or "starttls").strip().lower()
    if not host or not from_address or not to_address:
        return False, "Enter SMTP host, From address and alert recipient first."
    try:
        port = int(config.get("smtp_port", 587) or 587)
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = from_address
        message["To"] = to_address
        message.set_content(body)
        if security == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, timeout=12, context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(host, port, timeout=12)
        with smtp:
            if security == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
        return True, "Test email sent."
    except Exception as error:
        print(f"SMTP test failed: {error}")
        return False, operation_failed_message("SMTP test")


@app.route("/ids-alerts", methods=["GET", "POST"])
def ids_alerts():
    c = cfg()
    action_notice = ""
    action_ok = True
    if request.method == "POST":
        action = request.form.get("action", "filters")
        if action in {"investigate_alert", "acknowledge_alert", "close_alert", "suppress_alert", "reopen_alert", "delete_alert"}:
            status_map = {
                "investigate_alert": "investigating",
                "acknowledge_alert": "acknowledged",
                "close_alert": "closed",
                "suppress_alert": "suppressed",
                "reopen_alert": "open",
            }
            try:
                event_id = int(request.form.get("event_id", "0") or 0)
            except ValueError:
                event_id = 0
            if not event_id:
                action_ok, action_notice = False, "Cannot update this alert because its event id is invalid."
            elif action == "delete_alert":
                try:
                    deleted = delete_alert(connect_db, event_id)
                except Exception as error:
                    print(f"IDS alert delete failed for {event_id}: {error}")
                    deleted = False
                    action_ok, action_notice = False, operation_failed_message("IDS alert delete")
                if deleted:
                    return redirect("/ids-alerts?saved=deleted")
                action_ok, action_notice = False, "Could not find an IDS alert with that event id."
            else:
                try:
                    updated = update_alert_status(connect_db, event_id, status_map[action])
                except Exception as error:
                    print(f"IDS alert status update failed for {event_id}: {error}")
                    updated = False
                    action_ok, action_notice = False, operation_failed_message("IDS alert update")
                if updated:
                    if action == "investigate_alert":
                        return local_redirect(f"/ids-alerts/{event_id}")
                    return local_redirect(f"/ids-alerts?saved={status_map[action]}")
                action_ok, action_notice = False, "Could not find an open IDS alert with that event id."
        elif action == "ignore_source":
            source_ip = request.form.get("source_ip", "").strip()
            if not valid_ipv4_ip(source_ip):
                action_ok, action_notice = False, "Cannot ignore this alert source because its IP address is invalid."
            else:
                c["ids_excluded_ips"] = sorted(set(cfg_list(c.get("ids_excluded_ips", []))) | {source_ip})
                save_cfg(c)
                restart_collector_service()
                return redirect("/ids-alerts?saved=ignored")
        elif action in {"ban_source", "ban_destination"}:
            banned_ip = request.form.get("endpoint_ip", "").strip()
            if not valid_ipv4_ip(banned_ip):
                action_ok, action_notice = False, "Cannot ban this endpoint because its IPv4 address is invalid."
            else:
                c["ids_banned_ips"] = sorted(set(cfg_list(c.get("ids_banned_ips", []))) | {banned_ip})
                save_cfg(c)
                try:
                    event_id = int(request.form.get("event_id", "0") or 0)
                except ValueError:
                    event_id = 0
                if event_id:
                    update_alert_status(connect_db, event_id, "banned")
                restart_collector_service()
                return redirect("/ids-alerts?saved=banned")
        elif action == "unban_ip":
            banned_ip = request.form.get("endpoint_ip", "").strip()
            actor = session.get("admin_user") or session.get("username") or "admin"
            names = ids_device_names()
            device_name = names.get(banned_ip, "External / unknown endpoint")
            c["ids_banned_ips"] = [ip for ip in cfg_list(c.get("ids_banned_ips", [])) if ip != banned_ip]
            save_cfg(c)
            if valid_ipv4_ip(banned_ip):
                run_sql(
                    """
                    UPDATE ids_events
                    SET alert_status='open'
                    WHERE event_type='alert'
                      AND alert_status='banned'
                      AND (src_ip=? OR dest_ip=?)
                    """,
                    (banned_ip, banned_ip),
                )
                send_telegram_message(
                    c,
                    "NetSpecter IDS Manual Unblock\n"
                    f"IP: {banned_ip}\n"
                    f"Device: {device_name}\n"
                    "Rule: IDS banned endpoint\n"
                    "Reason: Manual unblock / false positive\n"
                    f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"By: {actor}",
                )
            restart_collector_service()
            return redirect("/ids-alerts?saved=unbanned")
        elif action == "filters":
            c["ids_unknown_only"] = request.form.get("ids_unknown_only") == "1"
            requested_ips = cfg_list(request.form.get("ids_excluded_ips", ""))
            c["ids_excluded_ips"] = [ip for ip in requested_ips if valid_lan_ip(ip)]
            save_cfg(c)
            restart_collector_service()
            return redirect("/ids-alerts?saved=filters")
        else:
            c["ids_email_enabled"] = request.form.get("ids_email_enabled") == "1"
            c["ids_telegram_enabled"] = request.form.get("ids_telegram_enabled") == "1"
            c["smtp_host"] = request.form.get("smtp_host", "").strip()
            c["smtp_security"] = request.form.get("smtp_security", "starttls").strip()
            c["smtp_username"] = request.form.get("smtp_username", "").strip()
            c["smtp_from"] = request.form.get("smtp_from", "").strip()
            c["smtp_to"] = request.form.get("smtp_to", "").strip()
            smtp_password = request.form.get("smtp_password", "")
            if smtp_password:
                c["smtp_password"] = smtp_password
            if request.form.get("clear_smtp_password") == "1":
                c["smtp_password"] = ""
            try:
                c["smtp_port"] = max(1, min(65535, int(request.form.get("smtp_port", "587"))))
            except ValueError:
                c["smtp_port"] = 587
            try:
                c["ids_email_cooldown_minutes"] = max(1, min(1440, int(request.form.get("ids_email_cooldown_minutes", "480"))))
            except ValueError:
                c["ids_email_cooldown_minutes"] = 480
            save_cfg(c)
            restart_collector_service()
            if action == "test_email":
                action_ok, action_notice = send_smtp_message(
                    c,
                    "NetSpecter IDS email test",
                    "This is a test email from NetSpecter IDS alert notifications.",
                )
            else:
                return redirect("/ids-alerts?saved=email")

    ids_filters = {
        "severity": request.args.get("severity", "").strip(),
        "device": request.args.get("device", "").strip(),
        "event_type": request.args.get("event_type", "").strip(),
        "protocol": request.args.get("protocol", "").strip(),
        "destination": request.args.get("destination", "").strip(),
        "signature": request.args.get("signature", "").strip(),
    }
    alerts, error = recent_suricata_alerts(filters=ids_filters)
    names = ids_device_names()
    excluded_ips = set(cfg_list(c.get("ids_excluded_ips", [])))
    banned_ips = set(ip for ip in cfg_list(c.get("ids_banned_ips", [])) if valid_ipv4_ip(ip))
    unknown_only = bool(c.get("ids_unknown_only"))
    visible_alerts = []
    for alert in alerts:
        source_ip = ids_endpoint_ip(alert["source"])
        destination_ip = ids_endpoint_ip(alert["destination"])
        alert["source_ip"] = source_ip
        alert["destination_ip"] = destination_ip
        alert["source_name"] = names.get(source_ip, "")
        alert["destination_name"] = names.get(destination_ip, "")
        if source_ip in excluded_ips:
            continue
        if unknown_only and source_ip in names:
            continue
        visible_alerts.append(alert)

    hidden_count = len(alerts) - len(visible_alerts)
    priority_counts = Counter(alert["priority"] for alert in visible_alerts)
    pcount = lambda value: priority_counts.get(value, 0) + priority_counts.get(str(value), 0)
    signature_counts = Counter(alert["signature"] for alert in visible_alerts)
    now_dt = datetime.now()

    def ids_parse_ts(value):
        raw = str(value or "").strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.strptime(raw[:32], fmt)
                return parsed.replace(tzinfo=None)
            except Exception:
                continue
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            return None

    def ids_human_ts(value):
        parsed = ids_parse_ts(value)
        return parsed.strftime("%d %b %Y, %H:%M") if parsed else h(str(value or "-")[:19])

    parsed_alert_times = [ids_parse_ts(alert.get("ts")) for alert in visible_alerts]
    parsed_alert_times = [ts for ts in parsed_alert_times if ts]
    recent_cutoff = now_dt - timedelta(hours=24)
    new_24h_count = sum(1 for ts in parsed_alert_times if ts >= recent_cutoff)
    affected_devices_count = len({alert.get("source_ip") for alert in visible_alerts if alert.get("source_ip")})
    most_recent_incident = max(parsed_alert_times).strftime("%d %b %Y, %H:%M") if parsed_alert_times else "-"
    open_alerts = [alert for alert in visible_alerts if str(alert.get("alert_status") or "open").lower() == "open"]
    open_incident_total = len(open_alerts)

    hour_labels = []
    hour_counts = []
    current_hour = now_dt.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    for idx in range(24):
        bucket_start = current_hour + timedelta(hours=idx)
        bucket_end = bucket_start + timedelta(hours=1)
        hour_labels.append(bucket_start.strftime("%H:00"))
        hour_counts.append(sum(1 for ts in parsed_alert_times if bucket_start <= ts < bucket_end))
    chart_max = max(hour_counts) if hour_counts else 0
    if chart_max:
        chart_points = []
        for idx, count in enumerate(hour_counts):
            x = 28 + (idx * (344 / 23 if len(hour_counts) > 1 else 0))
            y = 132 - ((count / chart_max) * 92)
            chart_points.append(f"{x:.1f},{y:.1f}")
        chart_svg = f"""
<svg class="ids-chart-svg" viewBox="0 0 400 170" role="img" aria-label="IDS alerts over the last 24 hours">
  <g class="ids-chart-grid">
    <line x1="28" y1="40" x2="372" y2="40"></line><line x1="28" y1="86" x2="372" y2="86"></line><line x1="28" y1="132" x2="372" y2="132"></line>
  </g>
  <polyline points="{' '.join(chart_points)}"></polyline>
  {''.join(f'<circle cx="{28 + (idx * (344 / 23)):.1f}" cy="{132 - ((count / chart_max) * 92):.1f}" r="3"><title>{h(hour_labels[idx])}: {count} alerts</title></circle>' for idx, count in enumerate(hour_counts))}
  <text x="28" y="158">{h(hour_labels[0])}</text><text x="184" y="158">Time</text><text x="332" y="158">{h(hour_labels[-1])}</text>
  <text x="4" y="44">{chart_max}</text><text x="10" y="136">0</text>
</svg>"""
    else:
        chart_svg = '<div class="ns-dashboard-empty">No alert history available for the selected period.</div>'

    incident_rows = ""
    for alert in visible_alerts[:80]:
        priority = int(alert["priority"] or 3)
        alert_status = str(alert.get("alert_status") or "open").lower()
        level = "critical" if priority == 1 else "high" if priority == 2 else "medium"
        reputation = latest_reputation_for_event(connect_db, alert.get("id") or 0, alert["destination_ip"], "")
        rep_label = reputation.get("reputation", "Unknown")
        rep_class = "red" if rep_label == "Malicious" else "yellow" if rep_label == "Suspicious" else "green" if rep_label == "Clean" else "blue"
        source_actions = f"""
<details class="ids-row-actions">
  <summary class="ids-actions-button">Actions <i class="fa-solid fa-chevron-down"></i></summary>
  <div class="ids-row-actions__menu">
    {f'''<form class="ids-action" method="post">
  {csrf_input()}<input type="hidden" name="event_id" value="{int(alert["id"])}">
      <button class="ids-menu-item ids-menu-item--primary" type="submit" name="action" value="investigate_alert"><i class="fa-solid fa-shield-halved"></i> Investigate</button>
    </form>''' if alert.get('id') else ''}
    {f'''<form class="ids-action" method="post">
  {csrf_input()}<input type="hidden" name="event_id" value="{int(alert["id"])}">
      <button class="ids-menu-item" type="submit" name="action" value="acknowledge_alert"><i class="fa-solid fa-circle-check"></i> Acknowledge</button>
    </form>
    <form class="ids-action" method="post">
  {csrf_input()}<input type="hidden" name="event_id" value="{int(alert["id"])}">
      <button class="ids-menu-item" type="submit" name="action" value="close_alert"><i class="fa-solid fa-lock"></i> Close</button>
    </form>''' if alert.get('id') and alert_status == 'open' else ''}
    {f'''<form class="ids-action" method="post">
  {csrf_input()}<input type="hidden" name="event_id" value="{int(alert["id"])}">
      <button class="ids-menu-item" type="submit" name="action" value="reopen_alert"><i class="fa-solid fa-rotate-left"></i> Reopen</button>
    </form>''' if alert.get('id') and alert_status != 'open' else ''}
    <div class="ids-menu-separator"></div>
    <form class="ids-action" method="post">
  {csrf_input()}<input type="hidden" name="source_ip" value="{h(alert['source_ip'])}">
      <button class="ids-menu-item" type="submit" name="action" value="ignore_source"><i class="fa-solid fa-eye-slash"></i> Ignore Source</button>
    </form>
    <form class="ids-action" method="post">
  {csrf_input()}<input type="hidden" name="endpoint_ip" value="{h(alert['source_ip'])}"><input type="hidden" name="event_id" value="{int(alert['id']) if alert.get('id') else 0}">
      <button class="ids-menu-item ids-menu-item--enforce" type="submit" name="action" value="ban_source" onclick="return confirm('Ban source IP {h(alert['source_ip'])}?')"><i class="fa-solid fa-user-slash"></i> Ban Source IP</button>
    </form>
    <form class="ids-action" method="post">
  {csrf_input()}<input type="hidden" name="endpoint_ip" value="{h(alert['destination_ip'])}"><input type="hidden" name="event_id" value="{int(alert['id']) if alert.get('id') else 0}">
      <button class="ids-menu-item ids-menu-item--enforce" type="submit" name="action" value="ban_destination" onclick="return confirm('Ban destination IP {h(alert['destination_ip'])}?')"><i class="fa-solid fa-network-wired"></i> Ban Destination IP</button>
    </form>
    <div class="ids-menu-separator"></div>
    {f'''<form class="ids-action" method="post">
  {csrf_input()}<input type="hidden" name="event_id" value="{int(alert["id"])}">
      <button class="ids-menu-item ids-menu-item--delete" type="submit" name="action" value="delete_alert" onclick="return confirm('Delete this IDS alert?')"><i class="fa-solid fa-trash"></i> Delete Incident</button>
    </form>''' if alert.get('id') else ''}
  </div>
</details>"""
        if alert_status == "acknowledged":
            status_chip, status_class = "Acknowledged", "acknowledged"
        elif alert_status == "investigating":
            status_chip, status_class = "Investigating", "investigating"
        elif alert_status == "banned":
            status_chip, status_class = "Banned", "banned"
        elif alert_status in {"closed", "ignored", "suppressed"}:
            status_chip = "Ignored" if alert_status in {"ignored", "suppressed"} else "Closed"
            status_class = "closed"
        else:
            status_chip, status_class = "Open", "open"
        incident_title = (
            f'<a href="/ids-alerts/{int(alert["id"])}">{h(alert["signature"])}</a>'
            if alert.get("id") else f'<span>{h(alert["signature"])}</span>'
        )
        incident_rows += f"""
<div class="ids-incident-row ids-incident-row--{level}">
  <div><span class="ids-severity-pill ids-severity-pill--{level}"><span></span>{'Critical' if priority == 1 else 'High' if priority == 2 else 'Medium'}</span><small>IDS Alert</small></div>
  <div class="ids-incident-title">{incident_title}<small>{h(alert['classification']) or 'Structured event'}</small></div>
  <div><span class="mono">{h(alert['source_ip'])}</span><small>{h(alert['source_name'] or 'Local')}</small></div>
  <div><span class="mono">{h(alert['destination'])}</span><small class="{rep_class}">{h(rep_label)}</small></div>
  <div><span>{h(alert.get('protocol') or '-')}</span><small>Protocol</small></div>
  <div><span>{ids_human_ts(alert.get('ts'))}</span><small>First seen</small></div>
  <div><span>{ids_human_ts(alert.get('ts'))}</span><small>Updated</small></div>
  <div><span class="ids-status-pill ids-status-pill--{status_class}"><span></span>{h(status_chip)}</span></div>
  <div>{source_actions}</div>
</div>
"""

    notice = f'<div class="setup-warning">{h(error)}</div>' if error else ""
    if request.args.get("saved") == "filters":
        notice += '<div class="setup-ok">IDS display filters saved.</div>'
    if request.args.get("saved") == "ignored":
        notice += '<div class="setup-ok">Alert source added to the ignored source list.</div>'
    if request.args.get("saved") == "banned":
        notice += '<div class="setup-ok">Endpoint IP added to the firewall ban list. The collector has restarted.</div>'
    if request.args.get("saved") == "unbanned":
        notice += '<div class="setup-ok">Endpoint IP removed from the firewall ban list.</div>'
    if request.args.get("saved") == "email":
        notice += '<div class="setup-ok">IDS email settings saved. The collector has restarted.</div>'
    if request.args.get("saved") == "acknowledged":
        notice += '<div class="setup-ok">IDS alert acknowledged. It will not send repeat notifications unless reopened.</div>'
    if request.args.get("saved") == "suppressed":
        notice += '<div class="setup-ok">IDS alert suppressed. It will not send repeat notifications unless reopened.</div>'
    if request.args.get("saved") == "open":
        notice += '<div class="setup-ok">IDS alert reopened and can notify again.</div>'
    if request.args.get("saved") == "deleted":
        notice += '<div class="setup-ok">IDS alert deleted.</div>'
    if action_notice:
        notice += f'<div class="{"setup-ok" if action_ok else "setup-warning"}">{h(action_notice)}</div>'
    unknown_checked = " checked" if unknown_only else ""
    excluded_value = ", ".join(sorted(excluded_ips))
    event_type_options = "".join(
        f'<option value="{value}"{" selected" if ids_filters["event_type"] == value else ""}>{label}</option>'
        for value, label in [("", "All alert events"), ("alert", "Alerts"), ("dns", "DNS"), ("http", "HTTP"), ("tls", "TLS"), ("fileinfo", "Files"), ("anomaly", "Anomalies")]
    )
    severity_options = "".join(
        f'<option value="{value}"{" selected" if ids_filters["severity"] == value else ""}>{label}</option>'
        for value, label in [("", "All severities"), ("1", "Priority 1"), ("2", "Priority 2"), ("3", "Priority 3+")]
    )
    banned_rows = ""
    for banned_ip in sorted(banned_ips):
        banned_rows += f"""
<tr>
  <td><span class="mono">{h(banned_ip)}</span></td>
  <td>{h(names.get(banned_ip, "External / unknown endpoint"))}</td>
  <td><form class="ids-action" method="post">{csrf_input()}<input type="hidden" name="endpoint_ip" value="{h(banned_ip)}"><button type="submit" name="action" value="unban_ip">Remove Ban</button></form></td>
</tr>"""
    email_checked = " checked" if c.get("ids_email_enabled") else ""
    ids_telegram_checked = " checked" if c.get("ids_telegram_enabled") else ""
    telegram_ready = bool(c.get("telegram_enabled") and c.get("telegram_bot_token") and c.get("telegram_chat_id"))
    ids_telegram_disabled = "" if telegram_ready else " disabled"
    security_options = "".join(
        f'<option value="{option}"{" selected" if str(c.get("smtp_security", "starttls")) == option else ""}>{label}</option>'
        for option, label in [("starttls", "STARTTLS"), ("ssl", "SSL/TLS"), ("none", "No TLS")]
    )
    incident_cards = ""
    for incident in []:
        incident_id, severity, device_ip, device_mac, device_name, first_ts, last_ts, status, assigned_to, title = incident
        sev = int(severity or 3)
        sev_name = "critical" if sev == 1 else "high" if sev == 2 else "medium"
        incident_cards += f"""
<a class="ns-incident-card {sev_name}" href="/incidents/{incident_id}">
  <b>{h(title)}</b>
  <div class="ns-polish-subtle">{h(device_name or device_ip or device_mac or '-')} • {h(status.title())}</div>
  <div class="ns-mini-metrics" style="grid-template-columns:1fr 1fr; margin-top:10px;">
    <div class="ns-mini-metric"><span>Severity</span><b>{h(severity_label(severity))}</b></div>
    <div class="ns-mini-metric"><span>Updated</span><b>{h(last_ts or '-')}</b></div>
  </div>
</a>"""
    signature_list = "".join(
        f'<div class="ids-signature-row"><span></span><b>{h(signature[:34])}</b><em>{total:,} ({round((total / max(1, len(visible_alerts))) * 100):.0f}%)</em></div>'
        for signature, total in signature_counts.most_common(4)
    )
    body = f"""
{topbar('IDS Alerts')}
{notice}
<style>
.ids-action {{ display:block; margin:0; }}
.ids-action button {{ width:100%; }}
.ids-row-actions {{ position:relative; display:flex; justify-content:flex-end; }}
.ids-row-actions summary {{ list-style:none; }}
.ids-row-actions summary::-webkit-details-marker {{ display:none; }}
.ids-actions-button {{ display:inline-flex; align-items:center; justify-content:center; gap:8px; min-width:96px; height:34px; padding:0 12px; border:1px solid rgba(61,133,211,.55); border-radius:8px; color:#d9ecff; background:rgba(10,28,48,.78); cursor:pointer; font-size:13px; font-weight:800; line-height:1; }}
.ids-actions-button:hover {{ border-color:rgba(20,133,255,.82); background:rgba(20,133,255,.14); }}
.ids-row-actions__menu {{ position:absolute; right:0; z-index:20; width:224px; max-height:min(380px, calc(100vh - 32px)); overflow-y:auto; overscroll-behavior:contain; padding:8px; border:1px solid var(--ns-line); border-radius:8px; background:#071322; box-shadow:0 18px 44px rgba(0,0,0,.46); }}
.ids-menu-item, .ids-action .ids-menu-item {{ appearance:none; display:flex; align-items:center; gap:9px; width:100%; min-height:34px; padding:8px 10px; border:1px solid transparent; border-radius:7px; color:#f2f7ff; background:transparent; box-shadow:none; text-decoration:none; font-size:13px; font-weight:800; line-height:1.2; text-align:left; cursor:pointer; }}
.ids-menu-item:hover {{ border-color:rgba(61,133,211,.45); background:rgba(20,133,255,.12); }}
.ids-menu-item--primary {{ color:#9fd0ff; border-color:rgba(61,133,211,.55); background:rgba(20,133,255,.10); }}
.ids-menu-item--enforce {{ color:#ff8fa0; }}
.ids-menu-item--delete {{ color:#ff6378; }}
.ids-menu-separator {{ height:1px; margin:7px 0; background:rgba(125,176,224,.15); }}
.ids-page {{ display:grid; gap:14px; }}
.ids-score-strip {{ display:grid; grid-template-columns:minmax(180px, 1.2fr) repeat(4, minmax(110px, 1fr)) minmax(130px, auto); align-items:center; gap:0; padding:18px 22px; }}
.ids-score-strip > div {{ min-width:0; padding:0 22px; border-left:1px solid rgba(125,176,224,.14); }}
.ids-score-strip > div:first-child {{ border-left:0; padding-left:0; }}
.ids-score-strip > a {{ justify-self:end; white-space:nowrap; }}
.ids-score-strip b {{ font-size:17px; }}
.ids-score-strip strong {{ display:block; font-size:30px; line-height:1; margin:6px 0; }}
.ids-score-strip small, .ids-incident-row small, .ids-panel-subtitle {{ display:block; color:var(--ns-text-secondary); }}
.ids-open-shell {{ display:grid; gap:16px; }}
.ids-panel {{ border:1px solid var(--ns-border); border-radius:8px; background:linear-gradient(145deg, rgba(8,25,42,.96), rgba(4,15,27,.98)); box-shadow:0 16px 40px rgba(0,0,0,.22); }}
.ids-panel-pad {{ padding:20px; }}
.ids-section-head {{ display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom:16px; }}
.ids-section-title {{ display:flex; align-items:center; gap:10px; }}
.ids-section-title h2 {{ margin:0; font-size:22px; }}
.ids-count-pill {{ display:inline-grid; min-width:32px; height:28px; place-items:center; border-radius:999px; color:#fff; background:linear-gradient(135deg, #ff355d, #8b1e3d); font-weight:800; }}
.ids-summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:10px; }}
.ids-summary-card {{ padding:14px; border:1px solid rgba(61,133,211,.28); border-radius:8px; background:rgba(3,15,28,.62); }}
.ids-summary-card strong {{ display:block; font-size:24px; line-height:1.1; margin-bottom:6px; }}
.ids-summary-card b {{ display:block; margin-bottom:4px; }}
.ids-summary-card small {{ color:var(--ns-text-secondary); line-height:1.35; }}
.ids-incident-table {{ display:grid; grid-template-columns:minmax(96px, .72fr) minmax(280px, 1.45fr) minmax(110px, .75fr) minmax(120px, .85fr) minmax(66px, .48fr) minmax(104px, .68fr) minmax(104px, .68fr) minmax(124px, .75fr) minmax(98px, .55fr); gap:0; }}
.ids-incident-head, .ids-incident-row {{ display:contents; }}
.ids-incident-head > span {{ padding:0 12px 12px; color:var(--ns-text-secondary); font-weight:800; font-size:13px; }}
.ids-incident-row > div {{ min-width:0; padding:15px 12px; border-top:1px solid rgba(125,176,224,.14); background:rgba(4,16,29,.44); }}
.ids-incident-row > div:nth-child(8), .ids-incident-row > div:nth-child(9) {{ display:flex; align-items:center; }}
.ids-incident-row > div:nth-child(8) {{ justify-content:flex-start; padding-right:18px; }}
.ids-incident-row > div:nth-child(9) {{ justify-content:flex-end; }}
.ids-incident-row > div:first-child {{ border-left:3px solid #1485ff; border-radius:8px 0 0 8px; }}
.ids-incident-row > div:last-child {{ border-radius:0 8px 8px 0; }}
.ids-incident-row--critical > div:first-child {{ border-left-color:#ff355d; }}
.ids-incident-row--high > div:first-child {{ border-left-color:#ff8d1a; }}
.ids-incident-title a {{ color:var(--ns-text-primary); text-decoration:none; font-weight:900; line-height:1.35; }}
.ids-severity-pill, .ids-status-pill {{ display:inline-flex; align-items:center; gap:7px; padding:7px 10px; border-radius:8px; border:1px solid rgba(125,176,224,.18); font-weight:850; line-height:1; white-space:nowrap; max-width:100%; }}
.ids-severity-pill span, .ids-status-pill span, .ids-signature-row span {{ width:8px; height:8px; border-radius:99px; background:#1485ff; flex:0 0 auto; }}
.ids-severity-pill--critical span, .ids-status-pill--open span, .ids-signature-row span {{ background:#ff355d; }}
.ids-severity-pill--high span {{ background:#ff8d1a; }}
.ids-status-pill--open {{ color:#ff6b83; border-color:rgba(255,53,93,.42); border-left:4px solid #ff355d; background:rgba(255,53,93,.09); }}
.ids-status-pill--acknowledged {{ color:#8ec8ff; border-color:rgba(20,133,255,.42); border-left:4px solid #1485ff; background:rgba(20,133,255,.10); }}
.ids-status-pill--acknowledged span {{ background:#1485ff; }}
.ids-status-pill--investigating {{ color:#c9a7ff; border-color:rgba(150,101,255,.42); border-left:4px solid #9665ff; background:rgba(150,101,255,.10); }}
.ids-status-pill--investigating span {{ background:#9665ff; }}
.ids-status-pill--closed {{ color:#8ee6b7; border-color:rgba(72,211,139,.38); border-left:4px solid #48d38b; background:rgba(72,211,139,.09); }}
.ids-status-pill--closed span {{ background:#48d38b; }}
.ids-status-pill--banned {{ color:#8ee6b7; border-color:rgba(72,211,139,.38); border-left:4px solid #48d38b; background:rgba(72,211,139,.09); }}
.ids-status-pill--banned span {{ background:#48d38b; }}
.ids-flag {{ display:inline-grid; place-items:center; width:26px; height:20px; border-radius:6px; background:rgba(20,133,255,.14); color:#8ec8ff; font-size:11px; font-weight:900; vertical-align:middle; }}
.ids-lower-grid {{ display:grid; grid-template-columns:minmax(320px, 1.15fr) minmax(280px, .9fr) minmax(220px, .58fr); gap:14px; }}
.ids-filter-grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:14px 28px; }}
.ids-filter-grid label {{ color:var(--ns-text-secondary); font-weight:800; font-size:13px; }}
.ids-filter-grid input, .ids-filter-grid select {{ width:100%; margin-top:7px; }}
.ids-filter-actions {{ grid-column:1/-1; display:grid; grid-template-columns:1fr auto; gap:10px; align-items:center; }}
.ids-chart-card {{ min-height:278px; overflow:hidden; }}
.ids-chart-svg {{ width:100%; height:210px; }}
.ids-chart-svg .ids-chart-grid line {{ stroke:rgba(125,176,224,.12); }}
.ids-chart-svg polyline {{ fill:none; stroke:#ff355d; stroke-width:3; }}
.ids-chart-svg circle {{ fill:#ff355d; stroke:#071322; stroke-width:2; }}
.ids-chart-svg text {{ fill:var(--ns-text-secondary); font-size:12px; }}
.ids-signature-donut {{ width:150px; height:150px; margin:22px auto; border-radius:50%; background:conic-gradient(#ff355d 0 100%); display:grid; place-items:center; }}
.ids-signature-donut div {{ width:88px; height:88px; border-radius:50%; background:#071322; display:grid; place-items:center; text-align:center; }}
.ids-signature-row {{ display:flex; align-items:center; gap:9px; margin-top:10px; }}
.ids-signature-row b {{ min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1; }}
.ids-signature-row em {{ color:var(--ns-text-secondary); font-style:normal; }}
@media (max-width:1380px) {{ .ids-incident-table {{ grid-template-columns:1fr; }} .ids-incident-head {{ display:none; }} .ids-incident-row {{ display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:0; margin-bottom:10px; border:1px solid rgba(125,176,224,.14); border-left:3px solid #1485ff; border-radius:8px; overflow:visible; background:rgba(4,16,29,.44); }} .ids-incident-row > div {{ display:block; border-top:1px solid rgba(125,176,224,.10); background:transparent; }} .ids-incident-row > div:first-child {{ border-left:0; border-radius:0; }} .ids-incident-row > div:last-child {{ border-radius:0; }} .ids-incident-row > div:nth-child(9) {{ justify-content:flex-start; }} }}
@media (max-width:1180px) {{ .ids-open-shell, .ids-lower-grid {{ grid-template-columns:1fr; }} .ids-score-strip {{ grid-template-columns:repeat(2, minmax(0, 1fr)); gap:12px; }} .ids-score-strip > div {{ padding:0; border-left:0; }} .ids-score-strip > a {{ justify-self:start; }} }}
@media (max-width:720px) {{ .ids-panel-pad {{ padding:14px; }} .ids-section-head {{ align-items:flex-start; flex-direction:column; }} .ids-score-strip, .ids-summary-grid, .ids-filter-grid, .ids-filter-actions, .ids-incident-row {{ grid-template-columns:1fr; }} .ids-row-actions {{ justify-content:flex-start; }} .ids-row-actions__menu {{ left:0; right:auto; max-width:calc(100vw - 48px); }} }}
</style>
<div class="ids-page">
  <div class="ns-polish-panel ids-score-strip">
    <div><b>Alerts (24h)</b><small>Structured IDS events</small></div>
    <div><span class="ns-dot red"></span><strong class="red">{pcount(1):,}</strong><small>Critical</small></div>
    <div><span class="ns-dot orange"></span><strong>{pcount(2):,}</strong><small>High</small></div>
    <div><span class="ns-dot yellow"></span><strong>{pcount(3):,}</strong><small>Medium</small></div>
    <div><span class="ns-dot blue"></span><strong>{max(0, len(visible_alerts) - pcount(1) - pcount(2) - pcount(3)):,}</strong><small>Low</small></div>
    <a class="ns-compact-button" href="#allAlerts">View all alerts <i class="fa-solid fa-chevron-right"></i></a>
  </div>

  <section class="ids-panel ids-panel-pad">
    <div class="ids-section-head">
      <div><div class="ids-section-title"><h2>Open Incidents</h2><span class="ids-count-pill">{open_incident_total:,}</span></div><div class="ids-panel-subtitle">Active security incidents requiring attention</div></div>
    </div>
    <div class="ids-open-shell">
      <div class="ids-summary-grid">
        <div class="ids-summary-card"><strong>{open_incident_total:,}</strong><b>Total open</b><small>Currently actionable IDS alerts</small></div>
        <div class="ids-summary-card"><strong class="red">{pcount(1):,}</strong><b>Critical</b><small>Requires immediate attention</small></div>
        <div class="ids-summary-card"><strong>{pcount(2):,}</strong><b>High</b><small>High priority incidents</small></div>
        <div class="ids-summary-card"><strong>{max(0, len(visible_alerts) - pcount(1) - pcount(2)):,}</strong><b>Medium / Low</b><small>Lower priority incidents</small></div>
        <div class="ids-summary-card"><strong>{new_24h_count:,}</strong><b>New in 24h</b><small>Seen during the last day</small></div>
        <div class="ids-summary-card"><strong>{affected_devices_count:,}</strong><b>Affected devices</b><small>Most recent: {h(most_recent_incident)}</small></div>
      </div>
      <div class="ids-incident-table" id="allAlerts">
        <div class="ids-incident-head"><span>Severity</span><span>Incident</span><span>Source</span><span>Destination</span><span>Protocol</span><span>First Seen</span><span>Updated</span><span>Status</span><span>Actions</span></div>
        {incident_rows or '<div class="ns-dashboard-empty" style="grid-column:1/-1;">No recent Suricata alerts found.</div>'}
      </div>
    </div>
  </section>

  <div class="ids-lower-grid">
    <section class="ids-panel ids-panel-pad settings" id="securityFilters">
      <div class="ids-section-head"><h2 class="ns-polish-section-title">Event Filters</h2><a class="ns-compact-button" href="/ids-alerts">Clear all</a></div>
      <form method="get"><div class="ids-filter-grid">
        <label>Severity<select name="severity">{severity_options}</select></label>
        <label>Device / Source IP<input name="device" value="{h(ids_filters['device'])}" placeholder="e.g. 192.168.1.50"></label>
        <label>Event Type<select name="event_type">{event_type_options}</select></label>
        <label>Destination IP<input name="destination" value="{h(ids_filters['destination'])}" placeholder="e.g. 8.8.8.8"></label>
        <label>Protocol<input name="protocol" value="{h(ids_filters['protocol'])}" placeholder="TCP, UDP, TLS"></label>
        <label>Signature Contains<input name="signature" value="{h(ids_filters['signature'])}" placeholder="Enter signature or keyword"></label>
        <div class="ids-filter-actions"><button type="submit"><i class="fa-solid fa-filter"></i> Apply Filters</button><span class="ns-polish-subtle">{hidden_count:,} hidden by display filters</span></div>
      </div></form>
    </section>
    <section class="ids-panel ids-panel-pad ids-chart-card"><div class="ids-section-head"><h2 class="ns-polish-section-title">Alerts Over Time</h2><span class="ns-chip">24h</span></div>{chart_svg}</section>
    <section class="ids-panel ids-panel-pad"><div class="ids-section-head"><h2 class="ns-polish-section-title">Top Signatures (24h)</h2><span class="ns-chip">24h</span></div><div class="ids-signature-donut"><div><b>{len(visible_alerts):,}</b><small>Total</small></div></div>{signature_list or '<div class="ns-dashboard-empty">No alerts to summarise.</div>'}</section>
  </div>

  <div class="ids-lower-grid">
    <section class="ids-panel ids-panel-pad settings">
      <h2>Alert Display Filters</h2>
      <form method="post">
        {csrf_input()}
        <label><input type="checkbox" name="ids_unknown_only" value="1" style="width:auto"{unknown_checked}> Only show alerts from source IPs not already known in Devices</label>
        <small>Known devices can still become compromised; hidden alerts remain in Suricata logs.</small>
        <label>Excluded Source IPs</label>
        <input name="ids_excluded_ips" value="{h(excluded_value)}" placeholder="Comma-separated expected source IPs">
        <button type="submit" name="action" value="filters">Save IDS Display Filters</button>
      </form>
    </section>
    <section class="ids-panel ids-panel-pad">
      <h2>Firewall Ban List</h2>
      <table><tr><th>Banned IP</th><th>Known Name</th><th>Action</th></tr>{banned_rows or '<tr><td colspan="3">No endpoint IPs currently banned.</td></tr>'}</table>
    </section>
    <section class="ids-panel ids-panel-pad settings">
      <h2>Notifications</h2>
      <form method="post">
        {csrf_input()}
        <label><input type="checkbox" name="ids_email_enabled" value="1" style="width:auto"{email_checked}> Enable IDS email alerts</label>
        <label><input type="checkbox" name="ids_telegram_enabled" value="1" style="width:auto"{ids_telegram_disabled}{ids_telegram_checked}> Enable IDS Telegram alerts for P1/P2</label>
        <label>Repeat Alert Cooldown Minutes</label>
        <input name="ids_email_cooldown_minutes" value="{h(c.get('ids_email_cooldown_minutes', 480))}">
        <button type="submit" name="action" value="save_email">Save Notification Settings</button>
      </form>
    </section>
  </div>
</div>
{auto_refresh_script(60)}
"""
    return shell("IDS Alerts", body, "IDS Alerts")


@app.route("/ids-alerts/<int:event_id>")
def ids_alert_detail(event_id):
    rows = query("SELECT * FROM ids_events WHERE id=?", (event_id,))
    if not rows:
        return shell("IDS Event", f"{topbar('IDS Event')}<div class=\"panel\"><h2>Event Not Found</h2><p class=\"sub\">This IDS event is no longer available.</p><a class=\"btn\" href=\"/ids-alerts\">Back to IDS Alerts</a></div>", "IDS Alerts"), 404
    row = rows[0]
    reputation = latest_reputation_for_event(connect_db, event_id, row["dest_ip"], row["query"] or row["hostname"] or "")
    device_rows = query(
        """
        SELECT ip, COALESCE(o.name, d.name, d.ip) AS name
        FROM devices d
        LEFT JOIN device_overrides o ON o.ip=d.ip
        WHERE d.ip IN (?, ?)
        """,
        (row["src_ip"], row["dest_ip"]),
    )
    associated_devices = ", ".join(f"{device['name']} ({device['ip']})" for device in device_rows)
    dns_count = query("SELECT COUNT(*) AS total FROM dns_querylog WHERE client=? OR domain IN (?, ?)", (row["src_ip"], row["query"], row["hostname"]))
    traffic_total = query("SELECT COALESCE(SUM(total_mb), 0) AS total FROM remote_traffic_intervals WHERE remote_ip=?", (row["dest_ip"],))
    suricata_count = query("SELECT COUNT(*) AS total FROM ids_events WHERE dest_ip=? OR src_ip=?", (row["dest_ip"], row["dest_ip"]))
    fields = [
        ("Reputation", reputation.get("reputation", "Unknown")),
        ("Threat Feed Source", reputation.get("source", "")),
        ("Threat Indicator", reputation.get("indicator", "")),
        ("Threat Confidence", reputation.get("confidence", "")),
        ("Threat Reason", reputation.get("reason", "")),
        ("Country", reputation.get("country", "")),
        ("ASN", reputation.get("asn", "")),
        ("Hosting Provider", reputation.get("provider", "")),
        ("Threat First Seen", reputation.get("first_seen", "")),
        ("Threat Last Seen", reputation.get("last_seen", "")),
        ("Associated Devices", associated_devices),
        ("Related Suricata Alerts", suricata_count[0]["total"] if suricata_count else ""),
        ("Related DNS Queries", dns_count[0]["total"] if dns_count else ""),
        ("Total Transferred", fmt_mb(traffic_total[0]["total"] if traffic_total else 0)),
        ("Time", row["ts"]),
        ("Event Type", row["event_type"]),
        ("Severity", row["severity"]),
        ("Signature ID", row["signature_id"]),
        ("Signature", row["signature"]),
        ("Category", row["category"]),
        ("Source", f"{row['src_ip']}:{row['src_port']}" if row["src_port"] else row["src_ip"]),
        ("Destination", f"{row['dest_ip']}:{row['dest_port']}" if row["dest_port"] else row["dest_ip"]),
        ("Protocol", row["protocol"]),
        ("Application Protocol", row["app_proto"]),
        ("Flow ID", row["flow_id"]),
        ("DNS Query", row["query"]),
        ("DNS Type", row["query_type"]),
        ("DNS Response", row["rcode"]),
        ("Answer Summary", row["answer_summary"]),
        ("HTTP Hostname", row["hostname"]),
        ("HTTP Method", row["method"]),
        ("HTTP URL Path", row["url_path"]),
        ("HTTP User-Agent", row["user_agent"]),
        ("HTTP Status", row["status"]),
        ("TLS SNI", row["tls_sni"]),
        ("TLS Version", row["tls_version"]),
        ("Certificate Subject", row["cert_subject"]),
        ("Certificate Issuer", row["cert_issuer"]),
        ("JA3", row["ja3"]),
        ("JA4", row["ja4"]),
        ("Filename", row["filename"]),
        ("File Size", row["file_size"]),
        ("MIME Type", row["mime_type"]),
        ("Hashes", row["hashes"]),
        ("Stored By Suricata", "Yes" if row["stored"] else "No"),
        ("Anomaly", row["anomaly_event"]),
    ]
    detail_rows = "".join(f"<tr><th>{h(label)}</th><td>{h(value)}</td></tr>" for label, value in fields if value not in (None, ""))
    body = f"""
{topbar('IDS Event Detail')}
<div class="panel">
  <a class="btn" href="/ids-alerts">Back to IDS Alerts</a>
  <table>{detail_rows}</table>
</div>
"""
    return shell("IDS Event Detail", body, "IDS Alerts")


@app.route("/incidents")
def incidents_page():
    rows = ""
    for incident in list_incidents(connect_db, 200):
        incident_id, severity, device_ip, device_mac, device_name, first_ts, last_ts, status, assigned_to, title = incident
        sev_class = "red" if int(severity or 3) == 1 else "yellow" if int(severity or 3) == 2 else "blue"
        device = device_name or device_ip or device_mac or "-"
        rows += f"""
<tr>
  <td><span class="{sev_class}">{h(severity_label(severity))}</span></td>
  <td>{h(device)}</td>
  <td>{h(first_ts)}</td>
  <td>{h(last_ts)}</td>
  <td>{h(status.title())}</td>
  <td>{h(assigned_to or '-')}</td>
  <td>{h(title)}</td>
  <td><a class="btn small" href="/incidents/{incident_id}">Investigate</a></td>
</tr>
"""
    body = f"""
{topbar('Security Incidents')}
<div class="panel">
  <h2>Incident Timeline</h2>
  <p class="sub">Incidents are created from configured P1/P2 IDS alerts and link back to source evidence without copying raw records.</p>
  <table>
    <tr><th>Severity</th><th>Device</th><th>First Event</th><th>Last Event</th><th>Status</th><th>Assigned</th><th>Title</th><th></th></tr>
    {rows or '<tr><td colspan="8">No security incidents yet.</td></tr>'}
  </table>
</div>
"""
    return shell("Security Incidents", body, "Incidents")


@app.route("/incidents/<int:incident_id>", methods=["GET", "POST"])
def incident_investigation(incident_id):
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "update":
            update_incident(
                connect_db,
                incident_id,
                status=request.form.get("status", "").strip() or None,
                assigned_to=request.form.get("assigned_to", "").strip(),
                note=request.form.get("note", "").strip() or None,
                actor=session.get("username", "analyst"),
            )
        return local_redirect(f"/incidents/{incident_id}")

    incident, events, notes, audit_rows, related = incident_detail(connect_db, incident_id)
    if not incident:
        return shell("Incident Not Found", f"{topbar('Security Incidents')}<div class=\"panel\">Incident not found.</div>", "Incidents"), 404
    sev_class = "red" if int(incident[2] or 3) == 1 else "yellow" if int(incident[2] or 3) == 2 else "blue"
    status_options = "".join(
        f'<option value="{value}"{" selected" if incident[8] == value else ""}>{label}</option>'
        for value, label in [
            ("new", "New"),
            ("acknowledged", "Acknowledged"),
            ("under_investigation", "Under Investigation"),
            ("resolved", "Resolved"),
            ("closed", "Closed"),
            ("banned", "Banned"),
            ("blocked", "Blocked"),
        ]
    )
    timeline = ""
    for source_table, source_id, event_ts, event_type, summary, reason in events:
        ref = f"{source_table} #{source_id}" if str(source_id).isdigit() else f"{source_table} {source_id}"
        timeline += f"""
<tr>
  <td>{h(event_ts or 'expired')}</td>
  <td>{h(event_type.replace('_', ' ').title())}</td>
  <td>{h(summary or 'Source record expired')}</td>
  <td>{h(reason)}</td>
  <td><span class="mono">{h(ref)}</span></td>
</tr>
"""
    note_rows = "".join(f"<tr><td>{h(ts)}</td><td>{h(author or '-')}</td><td>{h(note)}</td></tr>" for _, ts, author, note in notes)
    audit_table = "".join(f"<tr><td>{h(ts)}</td><td>{h(action)}</td><td>{h(actor or '-')}</td><td>{h(detail)}</td></tr>" for ts, action, actor, detail in audit_rows)
    domain_text = ", ".join(related.get("domains") or []) or "-"
    sig_text = ", ".join(related.get("signatures") or []) or "-"
    traffic = query(
        """
        SELECT COALESCE(SUM(total_mb), 0) AS total
        FROM remote_traffic_intervals
        WHERE ip=? AND ts BETWEEN ? AND ?
        """,
        (incident[3], incident[6], incident[7]),
    )[0]["total"]
    body = f"""
{topbar('Incident Investigation')}
<div class="grid">
  <div class="card"><div class="label">Severity</div><span class="big {sev_class}">{h(severity_label(incident[2]))}</span><small>{h(incident[10] or '')}</small></div>
  <div class="card"><div class="label">Device</div><span class="big blue">{h(incident[5] or incident[3] or '-')}</span><small>{h(incident[4] or '')}</small></div>
  <div class="card"><div class="label">Status</div><span class="big purple">{h((incident[8] or 'new').title())}</span><small>Assigned: {h(incident[9] or '-')}</small></div>
  <div class="card"><div class="label">Traffic Evidence</div><span class="big green">{float(traffic or 0):.2f} MB</span><small>Linked investigation window</small></div>
</div>
<div class="panel">
  <h2>Investigation Window</h2>
  <div class="tabs">
    <a class="btn small" href="{h(f'/incidents/{incident_id}?window=15')}">15 min</a>
    <a class="btn small" href="{h(f'/incidents/{incident_id}?window=30')}">30 min</a>
    <a class="btn small" href="{h(f'/incidents/{incident_id}?window=60')}">60 min</a>
  </div>
  <p class="sub">Default correlation uses 15 minutes before/after. Wider views are available for analyst review; source links degrade gracefully if raw records have expired.</p>
</div>
<div class="panel">
  <h2>Related Evidence</h2>
  <table>
    <tr><td>Domains / Indicators</td><td>{h(domain_text)}</td></tr>
    <tr><td>IDS Signatures</td><td>{h(sig_text)}</td></tr>
    <tr><td>First Event</td><td>{h(incident[6])}</td></tr>
    <tr><td>Last Event</td><td>{h(incident[7])}</td></tr>
  </table>
</div>
<div class="panel">
  <h2>Timeline</h2>
  <table>
    <tr><th>Time</th><th>Type</th><th>Evidence</th><th>Grouping Reason</th><th>Reference</th></tr>
    {timeline or '<tr><td colspan="5">No linked evidence yet.</td></tr>'}
  </table>
</div>
<div class="panel">
  <h2>Analyst Actions</h2>
  <form method="post">
    {csrf_input()}
    <input type="hidden" name="action" value="update">
    <label>Status</label>
    <select name="status">{status_options}</select>
    <label>Assigned To</label>
    <input name="assigned_to" value="{h(incident[9] or '')}">
    <label>Analyst Note</label>
    <textarea name="note" rows="4"></textarea>
    <button>Save Incident</button>
  </form>
</div>
<div class="panel">
  <h2>Analyst Notes</h2>
  <table><tr><th>Time</th><th>Author</th><th>Note</th></tr>{note_rows or '<tr><td colspan="3">No notes yet.</td></tr>'}</table>
</div>
<div class="panel">
  <h2>Audit History</h2>
  <table><tr><th>Time</th><th>Action</th><th>Actor</th><th>Detail</th></tr>{audit_table or '<tr><td colspan="4">No audit events yet.</td></tr>'}</table>
</div>
"""
    return shell("Incident Investigation", body, "Incidents")


@app.route("/anomalies")
def anomalies_page():
    summary = baseline_summary(connect_db)
    c = cfg()
    min_days = int(c.get("anomaly_min_learning_days", 7) or 7)
    recommended = int(c.get("anomaly_recommended_learning_days", 14) or 14)
    maturity_class = "green" if summary["days"] >= recommended else "yellow" if summary["days"] >= min_days else "blue"
    maturity_label = "Mature" if summary["days"] >= recommended else "Usable" if summary["days"] >= min_days else "Learning"
    rows = ""
    for event in list_anomalies(connect_db, 200):
        event_id, ts, device_ip, device_type, rule, severity, confidence, status, current, normal, threshold, reason, maturity_days, learning_only = event
        sev_class = "red" if severity == "high" else "yellow" if severity == "medium" else "blue"
        learning_badge = "Learning" if learning_only else "Active"
        rows += f"""
<tr>
  <td>{h(ts)}</td>
  <td>{h(device_ip)}<br><small>{h(device_type or 'Unknown')}</small></td>
  <td><span class="{sev_class}">{h(severity.title())}</span></td>
  <td>{h(rule.replace('_', ' ').title())}</td>
  <td>{h(confidence)}%</td>
  <td>{h(status.title())}<br><small>{h(learning_badge)}</small></td>
  <td>{h(reason)}</td>
  <td><a class="btn small" href="/anomalies/{event_id}">Details</a></td>
</tr>
"""
    body = f"""
{topbar('Anomalies')}
<div class="grid">
  <div class="card"><div class="label">Baseline</div><span class="big {maturity_class}">{h(maturity_label)}</span><small>{summary['days']} usable day(s), recommended {recommended}</small></div>
  <div class="card"><div class="label">Devices Learned</div><span class="big blue">{summary['devices']}</span><small>Compact daily/hourly aggregates</small></div>
  <div class="card"><div class="label">Open Events</div><span class="big yellow">{summary['open']}</span><small>Learning-only: {'on' if c.get('anomaly_learning_only', True) else 'off'}</small></div>
  <div class="card"><div class="label">Latest Baseline</div><span class="big purple">{h(summary['latest'])}</span><small>No automatic blocking</small></div>
</div>
<div class="panel">
  <h2>Network Baseline and Anomaly Detection</h2>
  <p class="sub">Transparent rules only. Normal anomaly alerts stay learning-only until at least {min_days} usable days are collected; expected events are only learned when explicitly marked.</p>
  <table>
    <tr><th>Time</th><th>Device</th><th>Severity</th><th>Rule</th><th>Confidence</th><th>Status</th><th>Reason</th><th></th></tr>
    {rows or '<tr><td colspan="8">No anomaly events yet. The baseline is learning.</td></tr>'}
  </table>
</div>
"""
    return shell("Anomalies", body, "Anomalies")


@app.route("/anomalies/<int:event_id>", methods=["GET", "POST"])
def anomaly_event_detail(event_id):
    if request.method == "POST":
        action = request.form.get("action", "")
        if action in ("expected", "learn"):
            mark_expected(
                connect_db,
                event_id,
                actor=session.get("username", "analyst"),
                note=request.form.get("note", "").strip(),
                learn=action == "learn",
            )
        return local_redirect(f"/anomalies/{event_id}")
    event, expected_rows = anomaly_detail(connect_db, event_id)
    if not event:
        return shell("Anomaly Not Found", f"{topbar('Anomalies')}<div class=\"panel\">Anomaly event not found.</div>", "Anomalies"), 404
    severity = event[7]
    sev_class = "red" if severity == "high" else "yellow" if severity == "medium" else "blue"
    expected_table = "".join(
        f"<tr><td>{h(ts)}</td><td>{h(actor or '-')}</td><td>{h(note or '')}</td><td>{'Yes' if learn else 'No'}</td></tr>"
        for ts, actor, note, learn in expected_rows
    )
    body = f"""
{topbar('Anomaly Detail')}
<div class="grid">
  <div class="card"><div class="label">Severity</div><span class="big {sev_class}">{h(severity.title())}</span><small>{h(event[6].replace('_', ' ').title())}</small></div>
  <div class="card"><div class="label">Confidence</div><span class="big blue">{h(event[8])}%</span><small>{h(event[15])} usable baseline day(s)</small></div>
  <div class="card"><div class="label">Mode</div><span class="big purple">{'Learning' if event[16] else 'Active'}</span><small>No automatic blocking</small></div>
  <div class="card"><div class="label">Status</div><span class="big green">{h(event[9].title())}</span><small>{h(event[4])}</small></div>
</div>
<div class="panel">
  <h2>Explanation</h2>
  <table>
    <tr><td>Device</td><td>{h(event[4])} ({h(event[5] or 'Unknown')})</td></tr>
    <tr><td>Current Value</td><td>{h(event[10])}</td></tr>
    <tr><td>Normal Value</td><td>{h(event[11])}</td></tr>
    <tr><td>Baseline Period</td><td>{h(event[12])}</td></tr>
    <tr><td>Threshold</td><td>{h(event[13])}</td></tr>
    <tr><td>Trigger Reason</td><td>{h(event[14])}</td></tr>
    <tr><td>Suppressed Until</td><td>{h(event[19] or '-')}</td></tr>
  </table>
</div>
<div class="panel">
  <h2>Expected Event Controls</h2>
  <form method="post">
    {csrf_input()}
    <label>Analyst Note</label>
    <textarea name="note" rows="4"></textarea>
    <button name="action" value="expected">Mark Expected</button>
    <button name="action" value="learn">Learn From This Expected Event</button>
  </form>
</div>
<div class="panel">
  <h2>Expected/Learning History</h2>
  <table><tr><th>Time</th><th>Actor</th><th>Note</th><th>Learned</th></tr>{expected_table or '<tr><td colspan="4">No expected-event decisions yet.</td></tr>'}</table>
</div>
"""
    return shell("Anomaly Detail", body, "Anomalies")


MAP_DNS_DOMAIN_LIMIT = 250
MAP_TILE_URL = "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"


def is_public_ip(value):
    try:
        return ipaddress.ip_address(str(value or "").strip()).is_global
    except ValueError:
        return False


def valid_map_coordinate(latitude, longitude):
    try:
        lat = float(latitude)
        lon = float(longitude)
    except (TypeError, ValueError):
        return None
    if math.isfinite(lat) and math.isfinite(lon) and -90 <= lat <= 90 and -180 <= lon <= 180:
        return lat, lon
    return None


def dns_destination_map_rows(start_day):
    """Return cached DNS destination rows without doing live DNS during page render."""
    return query(
        """
        WITH top_dns AS (
            SELECT domain, COUNT(*) AS queries, COUNT(DISTINCT client) AS devices
            FROM dns_querylog
            WHERE day >= ? AND blocked=0 AND domain <> ''
            GROUP BY domain
            ORDER BY COUNT(*) DESC
            LIMIT ?
        )
        SELECT r.remote_ip,
               GROUP_CONCAT(DISTINCT top_dns.domain) AS domains,
               SUM(top_dns.queries) AS queries,
               MAX(top_dns.devices) AS devices,
               l.city, l.region, l.country, l.latitude, l.longitude
        FROM top_dns
        JOIN dns_resolved_ips r ON r.domain = top_dns.domain
        JOIN remote_ip_locations l ON l.remote_ip = r.remote_ip
        WHERE l.latitude IS NOT NULL AND l.longitude IS NOT NULL
        GROUP BY r.remote_ip, l.city, l.region, l.country, l.latitude, l.longitude
        ORDER BY SUM(top_dns.queries) DESC
        LIMIT 250
        """,
        (start_day, MAP_DNS_DOMAIN_LIMIT),
    )


@app.route("/map")
def network_map():
    start_day = range_start_day()
    rows = query(
        """
        SELECT r.remote_ip, r.category, l.city, l.region, l.country, l.latitude, l.longitude,
               SUM(r.downloaded_mb) AS downloaded_mb,
               SUM(r.uploaded_mb) AS uploaded_mb,
               SUM(r.total_mb) AS total_mb,
               COUNT(DISTINCT r.ip) AS devices
        FROM remote_traffic_intervals r
        JOIN remote_ip_locations l ON l.remote_ip = r.remote_ip
        WHERE r.day >= ? AND l.latitude IS NOT NULL AND l.longitude IS NOT NULL
        GROUP BY r.remote_ip, r.category, l.city, l.region, l.country, l.latitude, l.longitude
        ORDER BY SUM(r.total_mb) DESC
        LIMIT 250
        """,
        (start_day,),
    )
    points = []
    for r in rows:
        coordinate = valid_map_coordinate(r["latitude"], r["longitude"])
        remote_ip = str(r["remote_ip"] or "")
        if not coordinate or not is_public_ip(remote_ip):
            continue
        lat, lon = coordinate
        points.append({
            "ip": h(remote_ip),
            "category": h(r["category"]),
            "source": "Traffic",
            "location": h(", ".join(x for x in (r["city"], r["region"], r["country"]) if x) or "Unknown GeoIP location"),
            "latitude": lat,
            "longitude": lon,
            "downloaded": float(r["downloaded_mb"] or 0),
            "uploaded": float(r["uploaded_mb"] or 0),
            "total": float(r["total_mb"] or 0),
            "devices": int(r["devices"] or 0),
        })
    points_json = json.dumps(points).replace("</", "<\\/")
    map_tile_url = h(MAP_TILE_URL)
    body = f"""
{topbar('Network Map')}
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin="">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
<div class="panel destination-map-panel">
  <div class="destination-map-heading">
    <div>
      <h2>Internet Destinations</h2>
    </div>
    <div class="map-legend"><span class="download-dot"></span> Traffic</div>
  </div>
  <div id="destinationMap"></div>
  <p class="map-empty" id="mapEmpty" style="display:none">No geolocated external traffic destinations are available for the selected period.</p>
</div>
<script>
const destinationPoints = {points_json};
const destinationMap = L.map("destinationMap", {{
  zoomControl: true,
  attributionControl: true,
  worldCopyJump: true,
  minZoom: 2
}}).setView([20, 0], 2);
L.tileLayer("{map_tile_url}", {{
  attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
  subdomains: "abcd",
  maxZoom: 20
}}).addTo(destinationMap);
const markerBounds = [];
destinationPoints.forEach((point) => {{
  const color = "#5ba8ff";
  const radius = Math.min(28, 6 + Math.sqrt(Math.max(point.total, 0)) * 1.7);
  const lat = Number(point.latitude);
  const lon = Number(point.longitude);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return;
  L.circleMarker([lat, lon], {{
    radius: radius, color: color, weight: 2, fillColor: color, fillOpacity: 0.56
  }}).addTo(destinationMap).bindPopup(
    "<b>" + point.category + "</b><br>Remote IP: " + point.ip + "<br>GeoIP: " + point.location +
    "<br>Download: " + point.downloaded.toFixed(2) + " MB" +
    "<br>Upload: " + point.uploaded.toFixed(2) + " MB" +
    "<br>Total: " + point.total.toFixed(2) + " MB" +
    "<br>Devices: " + point.devices
  );
  markerBounds.push([lat, lon]);
}});
if (markerBounds.length) {{
  destinationMap.fitBounds(markerBounds, {{padding: [28, 28], maxZoom: 6}});
}} else {{
  document.getElementById("mapEmpty").style.display = "block";
}}
</script>
"""
    return shell("Network Map", body, "Map")


def csv_response(filename, headers, rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(headers)
    for row in rows:
        values = []
        for hh in headers:
            try:
                values.append(row[hh])
            except Exception:
                values.append("")
        writer.writerow(values)
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def vault_archive_path(name):
    try:
        filename = valid_backup_archive_name(name)
    except ValueError:
        return None
    base = vault_backup_dir()
    for path in base.glob("*.nsbackup"):
        if path.name == filename:
            return path
    return None


def vault_archives():
    base = vault_backup_dir()
    if not base.exists():
        return []
    rows = []
    for path in sorted(base.glob("*.nsbackup"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            rows.append({
                "name": path.name,
                "size_mb": round(path.stat().st_size / 1024 / 1024, 2),
                "mtime": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
        except Exception:
            continue
    return rows


@app.route("/vault", methods=["GET", "POST"])
def vault_page():
    notice = request.args.get("notice", "")
    notice_class = "setup-warning" if request.args.get("notice_class") == "warning" else "setup-ok"
    inspect_result = None
    vault_config = load_vault_config()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "backup":
            ok, detail = start_background_vault_backup()
            cls = "ok" if ok else "warning"
            return local_redirect(f"/vault?notice={quote(detail)}&notice_class={cls}")
        elif action == "verify":
            path = vault_archive_path(request.form.get("archive", ""))
            if not path:
                notice = "Backup archive not found."
                notice_class = "setup-warning"
            else:
                result = verify_backup(path.name)
                record_event("verify", "ok" if result.ok else "failed", result.detail, archive=path.name)
                notice = f"{path.name}: {result.detail}"
                notice_class = "setup-ok" if result.ok else "setup-warning"
        elif action == "restore_prepare":
            path = vault_archive_path(request.form.get("archive", ""))
            if not path:
                notice = "Backup archive not found."
                notice_class = "setup-warning"
            else:
                try:
                    inspect_result = inspect_backup(path.name)
                    record_event("restore-preview", "ok", "backup restore preview opened", archive=path.name)
                    notice = f"{path.name}: backup verified."
                    notice_class = "setup-ok"
                except VaultError as error:
                    print(f"Restore preview failed for {path.name}: {error}")
                    record_event("restore-preview", "failed", operation_failed_message("Restore preview"), archive=path.name)
                    notice = operation_failed_message("Restore preview")
                    notice_class = "setup-warning"
        elif action == "restore_config":
            path = vault_archive_path(request.form.get("archive", ""))
            confirmation = request.form.get("confirmation", "")
            if not path:
                notice = "Backup archive not found."
                notice_class = "setup-warning"
            else:
                ok, detail = start_background_restore_config(path.name, confirmation)
                cls = "ok" if ok else "warning"
                return local_redirect(f"/vault?notice={quote(detail)}&notice_class={cls}")
        elif action == "restore_full":
            path = vault_archive_path(request.form.get("archive", ""))
            confirmation = request.form.get("confirmation", "")
            if not path:
                notice = "Backup archive not found."
                notice_class = "setup-warning"
            else:
                ok, detail = start_background_restore_full(path.name, confirmation)
                cls = "ok" if ok else "warning"
                return local_redirect(f"/vault?notice={quote(detail)}&notice_class={cls}")
        elif action == "save_schedule":
            vault_config = save_vault_config({
                "schedule_enabled": request.form.get("schedule_enabled") == "1",
                "schedule_time": request.form.get("schedule_time", "02:30"),
                "retention_daily": request.form.get("retention_daily", "7"),
                "retention_weekly": request.form.get("retention_weekly", "4"),
                "retention_monthly": request.form.get("retention_monthly", "6"),
                "min_free_mb": request.form.get("min_free_mb", "2048"),
                "max_archive_mb": request.form.get("max_archive_mb", "2048"),
                "usb_backup_enabled": request.form.get("usb_backup_enabled") == "1",
                "usb_backup_uuid": request.form.get("usb_backup_uuid", ""),
                "smb_backup_enabled": request.form.get("smb_backup_enabled") == "1",
                "smb_share": request.form.get("smb_share", ""),
                "smb_username": request.form.get("smb_username", ""),
                "smb_password": request.form.get("smb_password", ""),
                "smb_domain": request.form.get("smb_domain", ""),
                "smb_options": request.form.get("smb_options", "vers=3.0"),
            })
            record_event("schedule-config", "ok", "Backup schedule settings saved")
            notice = "Backup schedule settings saved."
        elif action == "apply_retention":
            result = apply_retention(
                daily=vault_config["retention_daily"],
                weekly=vault_config["retention_weekly"],
                monthly=vault_config["retention_monthly"],
            )
            record_event("retention", "ok", f"deleted {len(result['deleted'])} old backup(s)")
            notice = f"Retention applied. Deleted {len(result['deleted'])} old backup(s)."
        elif action == "usb_backup":
            try:
                dest = copy_latest_backup_to_usb(request.form.get("usb_uuid", ""))
                notice = f"USB backup copied and verified: {dest.name}"
            except VaultError as error:
                print(f"USB backup failed: {error}")
                notice = operation_failed_message("USB backup")
                notice_class = "setup-warning"
        elif action == "usb_eject":
            try:
                eject_usb(request.form.get("usb_uuid") or request.form.get("usb_backup_uuid", ""))
                notice = "USB safely unmounted."
                notice_class = "setup-ok"
            except VaultError as error:
                print(f"USB eject failed: {error}")
                notice = operation_failed_message("USB eject")
                notice_class = "setup-warning"
            cls = "warning" if notice_class == "setup-warning" else "ok"
            return local_redirect(f"/vault?notice={quote(notice)}&notice_class={cls}#vault-schedule")

    archives = vault_archives()
    newest = archives[0] if archives else None
    total_mb = round(sum(float(row["size_mb"]) for row in archives), 2)
    backup_path = vault_backup_dir()
    backup_state, backup_age = vault_backup_run_state()
    backup_status_label = "Running" if backup_state == "running" and backup_age is not None and backup_age < 3600 else "Idle"
    if backup_state == "finished" and backup_age is not None and backup_age < 600:
        backup_status_label = "Finished"
    elif backup_state == "failed" and backup_age is not None and backup_age < 600:
        backup_status_label = "Failed"
    schedule_checked = " checked" if vault_config.get("schedule_enabled") else ""
    usb_backup_checked = " checked" if vault_config.get("usb_backup_enabled") else ""
    smb_backup_checked = " checked" if vault_config.get("smb_backup_enabled") else ""
    selected_usb_uuid = str(vault_config.get("usb_backup_uuid") or "")
    archive_rows = ""
    for row in archives[:50]:
        archive_rows += f"""
<tr>
  <td><span class="mono">{h(row['name'])}</span></td>
  <td>{h(row['mtime'])}</td>
  <td><b>{h(row['size_mb'])} MB</b></td>
  <td>
    <form method="post" style="display:inline">
      {csrf_input()}
      <input type="hidden" name="archive" value="{h(row['name'])}">
      <button type="submit" name="action" value="restore_prepare">Restore</button>
    </form>
    <a class="btn" href="/vault/download/{quote(row['name'], safe='')}">Download</a>
  </td>
</tr>"""
    history_rows = ""
    for row in recent_events(30):
        cls = "green" if row.get("status") == "ok" else "yellow" if row.get("status") == "skipped" else "red"
        history_rows += f"""
<tr>
  <td>{h(row.get('ts', ''))}</td>
  <td>{h(row.get('action', ''))}</td>
  <td><span class="{cls}"><b>{h(row.get('status', ''))}</b></span></td>
  <td>{h(row.get('archive', ''))}</td>
  <td>{h(row.get('detail', ''))}</td>
</tr>"""
    usb_detection_error = ""
    try:
        usb_devices = removable_partitions()
    except Exception as error:
        print(f"USB detection failed: {error}")
        usb_devices = []
        usb_detection_error = "USB detection could not complete."
    usb_options = '<option value="">No USB selected</option>'
    selected_usb_detected = False
    for dev in usb_devices:
        uuid = str(dev.get("uuid") or "")
        if not uuid:
            continue
        selected = " selected" if uuid == selected_usb_uuid else ""
        selected_usb_detected = selected_usb_detected or bool(selected)
        label_parts = [
            " ".join(part for part in [str(dev.get("vendor") or "").strip(), str(dev.get("model") or "").strip()] if part),
            str(dev.get("label") or "").strip(),
            str(dev.get("size") or "").strip(),
            str(dev.get("fstype") or "").strip(),
            uuid,
        ]
        label = " - ".join(part for part in label_parts if part)
        usb_options += f'<option value="{h(uuid)}"{selected}>{h(label)}</option>'
    if selected_usb_uuid and not selected_usb_detected:
        usb_options += f'<option value="{h(selected_usb_uuid)}" selected>Saved USB {h(selected_usb_uuid)} (not detected)</option>'
    usb_help = "Only detected removable USB drives are listed."
    if usb_detection_error:
        usb_help = f"USB detection failed: {usb_detection_error}"
    inspect_panel = ""
    if inspect_result:
        metadata = inspect_result.get("metadata") or {}
        targets = {target.get("target") for target in inspect_result.get("restore_targets") or []}
        has_settings = "/etc/netspecter/config.json" in targets
        has_adguard = any(str(target).startswith("/etc/netspecter/adguard/") for target in targets)
        has_gatus = "/etc/netspecter/gatus/config.yaml" in targets
        has_database = "/var/lib/netspecter/netspecter.db" in targets
        restore_summary = [
            ("Settings", has_settings),
            ("AdGuard", has_adguard),
            ("Monitor config", has_gatus),
            ("Database", has_database),
        ]
        summary_rows = ""
        for label, present in restore_summary:
            summary_rows += f'<tr><td>{h(label)}</td><td><span class="{"green" if present else "yellow"}"><b>{"Included" if present else "Not in backup"}</b></span></td></tr>'
        inspect_panel = f"""
<div class="panel" id="vaultInspect">
  <h2>Restore Preview</h2>
  <div class="grid">
    <div class="card"><div class="label">Backup</div><span class="big blue">{h(inspect_result.get('archive'))}</span><small>Verified</small></div>
    <div class="card"><div class="label">Created</div><span class="big teal">{h(metadata.get('created_at'))}</span><small>{h(metadata.get('hostname'))}</small></div>
  </div>
  <p class="sub">Preview only. Nothing has been restored or changed.</p>
  <table>
    <tr><th>Area</th><th>Status</th></tr>
    {summary_rows}
  </table>
  <form method="post" style="margin-top:16px">
    {csrf_input()}
    <input type="hidden" name="archive" value="{h(inspect_result.get('archive'))}">
    <label>Type RESTORE CONFIG to restore settings only</label>
    <input name="confirmation" placeholder="RESTORE CONFIG">
    <button class="btn-yellow" type="submit" name="action" value="restore_config">Restore Config</button>
  </form>
  <p class="sub">Config restore will safety-copy current config files, restore settings/keys/AdGuard/Gatus config, then restart NetSpecter services.</p>
  <form method="post" style="margin-top:16px">
    {csrf_input()}
    <input type="hidden" name="archive" value="{h(inspect_result.get('archive'))}">
    <label>Type RESTORE FULL to restore settings and database</label>
    <input name="confirmation" placeholder="RESTORE FULL">
    <button class="btn-red" type="submit" name="action" value="restore_full">Restore Full Backup</button>
  </form>
  <p class="sub">Full restore safety-copies current files, restores settings and history database, then restarts NetSpecter web and collector. Use only when the appliance can be briefly interrupted.</p>
</div>
"""

    body = f"""
{topbar('Backups')}
{f'<div class="{notice_class}">{h(notice)}</div>' if notice else ''}
{inspect_panel}
<div class="related-page backups-page">
<div class="grid health-grid backup-metrics-grid">
  <div class="card appliance-metric-card"><span class="appliance-metric-icon blue"><i class="fa-solid fa-box-archive"></i></span><div><div class="label">Backups</div><span class="big blue">{len(archives)}</span><small>Local backup archives</small></div></div>
  <div class="card appliance-metric-card"><span class="appliance-metric-icon teal"><i class="fa-solid fa-hard-drive"></i></span><div><div class="label">Storage Used</div><span class="big teal">{h(total_mb)} MB</span><small>{h(str(backup_path))}</small></div></div>
  <div class="card appliance-metric-card"><span class="appliance-metric-icon {'green' if newest else 'yellow'}"><i class="fa-solid fa-clock-rotate-left"></i></span><div><div class="label">Newest Backup</div><span class="big {'green' if newest else 'yellow'}">{h(newest['mtime'] if newest else 'None')}</span><small>{h(newest['name'] if newest else 'No local backup yet')}</small></div></div>
  <div class="card appliance-metric-card"><span class="appliance-metric-icon {'green' if vault_config.get('schedule_enabled') else 'yellow'}"><i class="fa-solid fa-calendar-check"></i></span><div><div class="label">Schedule</div><span class="big {'green' if vault_config.get('schedule_enabled') else 'yellow'}">{'On' if vault_config.get('schedule_enabled') else 'Off'}</span><small>Daily at {h(vault_config.get('schedule_time'))}</small></div></div>
</div>
<div class="panel settings related-card">
  <h2>Local Backup</h2>
  <p class="sub">Creates a verified archive with NetSpecter config, a safe SQLite database snapshot, AdGuard config, Gatus config, metadata, manifest and checksums.</p>
  <form method="post">
    {csrf_input()}
    <button type="submit" name="action" value="backup"><i class="fa-solid fa-box-archive"></i> Backup Now</button>
  </form>
  <p><b>Status:</b> <span class="{'yellow' if backup_status_label == 'Running' else 'red' if backup_status_label == 'Failed' else 'green' if backup_status_label == 'Finished' else ''}">{h(backup_status_label)}</span></p>
  <small>USB and SMB copies are configured in the schedule below.</small>
</div>
<div id="vault-schedule" class="panel settings related-card vault-schedule-card">
  <h2>Automatic Local Backups</h2>
  <style>
    .vault-dependent {{ display:none; }}
  </style>
  <form method="post" class="vault-schedule-form">
    {csrf_input()}
    <label><input type="checkbox" name="schedule_enabled" value="1" style="width:auto"{schedule_checked}> Enable daily local backup</label>
    <label>Backup Time</label>
    <input type="time" name="schedule_time" value="{h(vault_config.get('schedule_time'))}">
    <label>Daily Backups To Keep</label>
    <input type="number" name="retention_daily" min="1" value="{h(vault_config.get('retention_daily'))}">
    <label>Weekly Backups To Keep</label>
    <input type="number" name="retention_weekly" min="1" value="{h(vault_config.get('retention_weekly'))}">
    <label>Monthly Backups To Keep</label>
    <input type="number" name="retention_monthly" min="1" value="{h(vault_config.get('retention_monthly'))}">
    <label>Minimum Free Disk Before Backup (MB)</label>
    <input type="number" name="min_free_mb" min="128" value="{h(vault_config.get('min_free_mb'))}">
    <label>Maximum Archive Size (MB)</label>
    <input type="number" name="max_archive_mb" min="16" value="{h(vault_config.get('max_archive_mb'))}">
    <label><input id="vault-usb-toggle" type="checkbox" name="usb_backup_enabled" value="1" style="width:auto"{usb_backup_checked}> Copy scheduled backups to USB</label>
    <div class="vault-dependent vault-usb-settings">
      <label>USB Drive</label>
      <select name="usb_backup_uuid">{usb_options}</select>
      <small>{h(usb_help)} If a saved USB is unplugged, it stays selected so the schedule does not forget it.</small>
      <button type="submit" name="action" value="usb_eject">Eject Selected USB</button>
      <a class="btn" href="/vault#vault-schedule"><i class="fa-solid fa-rotate"></i> Recheck USB Drives</a>
    </div>
    <label><input id="vault-smb-toggle" type="checkbox" name="smb_backup_enabled" value="1" style="width:auto"{smb_backup_checked}> Copy scheduled backups to SMB share</label>
    <div class="vault-dependent vault-smb-settings">
      <label>SMB Share</label>
      <input name="smb_share" value="{h(vault_config.get('smb_share'))}" placeholder="//server/share">
      <label>SMB Username</label>
      <input name="smb_username" value="{h(vault_config.get('smb_username'))}">
      <label>SMB Password</label>
      <input type="password" name="smb_password" value="{h(vault_config.get('smb_password'))}">
      <label>SMB Domain / Workgroup</label>
      <input name="smb_domain" value="{h(vault_config.get('smb_domain'))}" placeholder="Optional">
      <label>SMB Mount Options</label>
      <input name="smb_options" value="{h(vault_config.get('smb_options'))}" placeholder="vers=3.0">
      <small>Use a share like //192.168.99.10/Backups. Credentials are saved in /etc/netspecter/vault.json with root-only permissions.</small>
    </div>
    <button type="submit" name="action" value="save_schedule">Save Schedule</button>
    <button type="submit" name="action" value="apply_retention">Apply Retention Now</button>
  </form>
  <script>
    function toggleVaultTarget(id, selector) {{
      const checkbox = document.getElementById(id);
      const block = document.querySelector(selector);
      if (checkbox && block) block.style.display = checkbox.checked ? 'block' : 'none';
    }}
    ['change', 'DOMContentLoaded'].forEach(function(eventName) {{
      document.addEventListener(eventName, function(event) {{
        if (eventName === 'DOMContentLoaded' || event.target.id === 'vault-usb-toggle') toggleVaultTarget('vault-usb-toggle', '.vault-usb-settings');
        if (eventName === 'DOMContentLoaded' || event.target.id === 'vault-smb-toggle') toggleVaultTarget('vault-smb-toggle', '.vault-smb-settings');
      }});
    }});
  </script>
  <small>The systemd timer checks hourly and only creates a backup after the configured daily time.</small>
</div>
<div class="panel related-card backup-table-card">
  <h2>Local Backups</h2>
  <table>
    <tr><th>Archive</th><th>Created</th><th>Size</th><th>Actions</th></tr>
    {archive_rows or '<tr><td colspan="4">No backups created yet.</td></tr>'}
  </table>
</div>
<div class="panel related-card backup-table-card">
  <h2>Backup History</h2>
  <table>
    <tr><th>Time</th><th>Action</th><th>Status</th><th>Archive</th><th>Detail</th></tr>
    {history_rows or '<tr><td colspan="5">No backup history yet.</td></tr>'}
  </table>
</div>
"""
    return shell("Backups", body, "Backups")


@app.route("/vault/download/<name>")
def vault_download(name):
    path = vault_archive_path(name)
    if not path:
        return Response("Backup archive not found.", status=404, mimetype="text/plain")
    return send_file(path, as_attachment=True, download_name=path.name, mimetype="application/gzip")


@app.route("/exports")
def exports_page():
    current_range = range_label()
    export_cards = [
        ("devices", "Devices", "Names, IP addresses, MACs, vendors, device types and current status.", "devices", "blue", "All devices"),
        ("traffic", "Traffic", "Download, upload, total usage and live throughput for the selected range.", "traffic", "teal", current_range),
        ("dns", "DNS Logs", "Client DNS queries, domains, blocked state and categories for the selected range.", "history", "purple", current_range),
        ("blocked", "Blocked DNS", "Blocked DNS requests, clients, categories and timestamps for the selected range.", "blocked", "red", current_range),
    ]
    cards = ""
    for kind, title, description, icon, color, scope in export_cards:
        href = f"/export/{kind}" if kind == "devices" else f"/export/{kind}?range={range_key()}"
        cards += f"""
  <article class="ns-export-card">
    <div class="ns-export-card__icon {color}">{dashboard_png_icon(icon, "ns-dashboard-card-icon")}</div>
    <div>
      <h2>{h(title)}</h2>
      <p>{h(description)}</p>
      <span>{h(scope)}</span>
    </div>
    <a class="ns-compact-button" href="{href}"><i class="fa-solid fa-download" aria-hidden="true"></i> Download CSV</a>
  </article>"""
    body = f"""
{topbar('Exports')}
<div class="ns-polish-page">
  <section class="ns-polish-panel">
    <div class="ns-polish-header">
      <div>
        <h2 class="ns-polish-section-title">Export Data</h2>
        <div class="ns-polish-subtle">Download CSV snapshots from the current appliance data.</div>
      </div>
      {time_picker()}
    </div>
    <div class="ns-export-grid">
      {cards}
    </div>
  </section>
</div>
"""
    return shell("Exports", body, "Exports")


@app.route("/api/microsoft365-endpoints/refresh", methods=["POST"])
def api_microsoft365_endpoints_refresh():
    c = cfg()
    try:
        result = refresh_microsoft365_endpoints(c.get("microsoft365_endpoint_instance", "worldwide"))
        return jsonify(result)
    except Exception as error:
        print(f"Microsoft 365 endpoint refresh failed: {error}")
        return jsonify({"ok": False, "error": "Microsoft 365 endpoint refresh failed."}), 502


@app.route("/reporting")
def reporting_page():
    c = cfg()
    if request.args.get("generate") != "1":
        devices = query(
            """
            SELECT d.ip, d.mac, COALESCE(o.name, d.name, d.ip) AS name
            FROM devices d
            LEFT JOIN device_overrides o ON o.ip=d.ip
            ORDER BY name COLLATE NOCASE
            LIMIT 300
            """
        )

        def setup_device_options():
            options = ['<option value="" selected>All devices</option>']
            for row in devices:
                name = str(row["name"] or row["ip"] or "").strip()
                ip = str(row["ip"] or "").strip()
                value = name or ip
                label = f"{name} ({ip})" if name and ip and name != ip else value
                options.append(f'<option value="{h(value)}">{h(label)}</option>')
            return "".join(options)

        body = f"""
{topbar("Reporting")}
<style>
.ns-reporting-page {{ display:flex; flex-direction:column; gap:16px; }}
.ns-report-setup {{ padding:18px 20px; }}
.ns-report-setup h2,.ns-report-panel h2 {{ margin:0 0 18px; color:var(--ns-text-primary); font-size:20px; }}
.ns-report-setup-grid {{ display:grid; grid-template-columns:minmax(180px, 1fr) minmax(180px, 1fr) minmax(180px, 1fr) minmax(220px, 1fr) max-content; gap:16px; align-items:end; }}
.ns-report-setup label {{ display:flex; flex-direction:column; gap:8px; color:var(--ns-text-secondary); font-size:13px; }}
.ns-report-period {{ display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); border:1px solid var(--ns-line); border-radius:8px; overflow:hidden; background:rgba(7,16,28,.45); }}
.ns-report-period input {{ position:absolute; opacity:0; pointer-events:none; }}
.ns-report-period span {{ display:grid; place-items:center; min-height:38px; color:var(--ns-text-secondary); font-weight:800; cursor:pointer; }}
.ns-report-period input:checked + span {{ background:linear-gradient(135deg, #00c8ff, #00ddc7); color:#03111f; }}
.ns-report-custom-dates {{ display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:10px; margin-top:12px; }}
.ns-report-layout {{ display:grid; grid-template-columns:minmax(0, 1.35fr) minmax(340px, .9fr); gap:16px; align-items:start; }}
.ns-report-panel {{ padding:18px; }}
.ns-report-placeholder {{ min-height:360px; display:grid; place-items:center; text-align:center; color:var(--ns-text-secondary); }}
.ns-report-placeholder strong {{ display:block; margin-bottom:8px; color:var(--ns-text-primary); font-size:22px; }}
.ns-report-checks {{ display:grid; gap:13px; }}
.ns-report-checks label {{ display:flex; align-items:center; gap:10px; color:var(--ns-text-primary); font-weight:700; }}
.ns-report-checks input {{ width:18px; height:18px; accent-color:#00d6ff; }}
@media (max-width: 1100px) {{ .ns-report-layout,.ns-report-setup-grid {{ grid-template-columns:1fr; }} }}
@media (max-width: 700px) {{ .ns-report-custom-dates {{ grid-template-columns:1fr; }} }}
</style>
<div class="ns-polish-page ns-reporting-page">
  <div>
    <h1>Reporting</h1>
    <p class="ns-polish-subtle">Create and export clear network reports.</p>
  </div>
  <form class="ns-polish-panel ns-report-setup" method="get" id="reportSetupForm">
    <input type="hidden" name="generate" value="1">
    <h2>Report setup</h2>
    <div class="ns-report-setup-grid">
      <label>Report type
        <select class="ns-select" name="report_type">
          <option value="management" selected>Management Overview</option>
          <option value="internet">Internet Report</option>
        </select>
      </label>
      <label>Start <input class="ns-input" type="date" name="start"></label>
      <label>End <input class="ns-input" type="date" name="end"></label>
      <label>Devices
        <select class="ns-select" name="device_lookup">{setup_device_options()}</select>
      </label>
      <button class="ns-button" type="submit"><i class="fa-regular fa-file-lines" aria-hidden="true"></i> Generate Report</button>
    </div>
  </form>
  <div class="ns-report-layout">
    <section class="ns-polish-panel ns-report-panel ns-report-placeholder">
      <div>
        <strong>No report generated yet</strong>
        Choose the period, device scope and report contents, then click Generate Report. NetSpecter will only calculate the selected report when requested.
      </div>
    </section>
    <aside class="ns-report-side">
      <section class="ns-polish-panel ns-report-panel">
        <h2>Report Contents</h2>
        <div class="ns-report-checks">
          <label><input form="reportSetupForm" type="checkbox" name="section" value="traffic" checked> Traffic</label>
          <label><input form="reportSetupForm" type="checkbox" name="section" value="devices" checked> Devices</label>
          <label><input form="reportSetupForm" type="checkbox" name="section" value="applications" checked> Applications</label>
          <label><input form="reportSetupForm" type="checkbox" name="section" value="blocked_dns"> Blocked DNS</label>
          <label><input form="reportSetupForm" type="checkbox" name="section" value="security"> Security Events</label>
        </div>
      </section>
    </aside>
  </div>
</div>
"""
        return shell("Reporting", body, "Reporting")

    m365_status = microsoft365_endpoint_cache_status(c.get("microsoft365_endpoint_cache_hours", 168))
    if c.get("microsoft365_endpoint_import_enabled") and request.args.get("m365_ready") != "1" and not m365_status["fresh"]:
        body = f"""
{topbar("Reporting")}
<div class="ns-polish-page">
  <section class="ns-polish-panel">
    <div class="ns-polish-header">
      <div>
        <h2 class="ns-polish-section-title">Preparing Report</h2>
        <div class="ns-polish-subtle">Refreshing Microsoft 365 endpoint mappings before building the report.</div>
      </div>
    </div>
    <div class="ns-empty-state" id="m365ReportRefreshState">Loading Microsoft 365 endpoint classifications...</div>
  </section>
</div>
<script>
(function() {{
  var state = document.getElementById("m365ReportRefreshState");
  var form = new FormData();
  form.append("_csrf_token", "{h(csrf_token())}");
  fetch("/api/microsoft365-endpoints/refresh", {{
    method: "POST",
    body: form,
    credentials: "same-origin"
  }}).then(function(response) {{
    return response.json().catch(function() {{ return {{ ok: false, error: "Invalid response" }}; }});
  }}).then(function(data) {{
    if (state) {{
      state.textContent = data.ok
        ? "Microsoft 365 endpoint classifications loaded. Opening report..."
        : "Microsoft 365 endpoint refresh failed. Opening report with cached/manual mappings...";
    }}
    var url = new URL(window.location.href);
    url.searchParams.set("m365_ready", "1");
    window.location.href = url.toString();
  }}).catch(function() {{
    if (state) state.textContent = "Microsoft 365 endpoint refresh failed. Opening report with cached/manual mappings...";
    var url = new URL(window.location.href);
    url.searchParams.set("m365_ready", "1");
    window.location.href = url.toString();
  }});
}})();
</script>
"""
        return shell("Reporting", body, "Reporting")

    report_context = build_reporting_context_from_request(request.args)
    start_time = report_context["start_time"]
    end_time = report_context["end_time"]
    selected_devices = report_context["selected_devices"]
    selected_device_lookup = report_context["selected_device_lookup"]
    selected_application = report_context["selected_application"]
    selected_domain = report_context["selected_domain"]
    devices = report_context["devices"]
    device_lookup_notice = ""
    if selected_device_lookup:
        matched_device = report_context["matched_device"]
        if matched_device:
            matched_ip = str(matched_device["ip"])
            device_lookup_notice = f'<div class="setup-ok">Device selected: {h(matched_device["name"] or matched_ip)} ({h(matched_ip)})</div>'
        else:
            device_lookup_notice = f'<div class="setup-warning">No device matched {h(selected_device_lookup)}.</div>'

    filters = report_context["filters"]
    overview = report_context["overview"]
    dns_rows = report_context["dns_rows"]
    app_rows = report_context["app_rows"]
    destination_rows = report_context["destination_rows"]
    quality_rows = report_context["quality_rows"]
    internet_issue_rows = report_context.get("internet_issue_rows") or []
    internet_quality_rollup = report_context.get("internet_quality_rollup") or {}
    speedtest_rows = report_context.get("speedtest_rows") or []
    timeline = report_context["timeline"]
    top_users = report_context["top_users"]
    top_devices = report_context["top_devices"]
    app_options = report_context["app_options"]
    domain_options = report_context["domain_options"]
    category_report = report_context["category_report"]
    category_rows = report_context["category_rows"]
    report_type_key = str(request.args.get("report_type") or "management").strip().lower()
    report_type_title = "Internet Report" if report_type_key == "internet" else "Management Overview Report"
    period_key = str(request.args.get("period") or report_context.get("period") or "30d").lower()
    if period_key not in {"7d", "30d", "custom"}:
        period_key = "30d"
    default_report_sections = ["traffic", "devices", "applications"]
    selected_sections = request.args.getlist("section") or default_report_sections
    selected_sections = {str(value) for value in selected_sections}
    query_suffix = request.query_string.decode("utf-8")
    if not query_suffix:
        query_suffix = "period=30d&report_type=management&" + "&".join(f"section={section}" for section in default_report_sections)
    selected_device_label = "All devices"
    if selected_devices:
        raw_device_label = str(selected_devices[0] or "")[:200]
        suffix_at = raw_device_label.find(" (")
        selected_device_label = raw_device_label[:suffix_at].strip() if suffix_at >= 0 else raw_device_label.strip()
        selected_device_label = selected_device_label or raw_device_label.strip()

    def report_dt_input(value):
        return h(str(value or "")[:10])

    def report_device_options():
        options = [f'<option value=""{" selected" if not selected_device_lookup else ""}>All devices</option>']
        for row in devices:
            name = str(row["name"] or row["ip"] or "").strip()
            ip = str(row["ip"] or "").strip()
            value = name or ip
            label = f"{name} ({ip})" if name and ip and name != ip else value
            selected = " selected" if selected_device_lookup and selected_device_lookup.lower() in {name.lower(), ip.lower()} else ""
            options.append(f'<option value="{h(value)}"{selected}>{h(label)}</option>')
        return "".join(options)

    def report_content_checked(key):
        return " checked" if key in selected_sections else ""

    def top_device_report_rows():
        total = float(overview.get("total_mb") or 0)
        rows_html = ""
        for index, row in enumerate((top_devices or [])[:5], 1):
            traffic = float(row["total_mb"] or 0)
            pct = round((traffic / total * 100), 1) if total else 0.0
            rows_html += f"""
<tr>
  <td>{index}</td>
  <td>{h(row["name"] or row["ip"])}</td>
  <td>{h(row["ip"] or "")}</td>
  <td>{h(fmt_mb(traffic))}</td>
  <td>{pct}%</td>
</tr>
"""
        if not rows_html:
            rows_html = '<tr><td colspan="5">No device traffic recorded for this period.</td></tr>'
        return rows_html

    def top_application_report_rows():
        rows_html = ""
        for row in (app_rows or [])[:5]:
            traffic = float(row["total_mb"] or 0)
            app_name = str(row["category"] or "Other")
            rows_html += f"""
<tr>
  <td>{h(app_name)}</td>
  <td>{h(app_name)}</td>
  <td>{h(fmt_mb(traffic))}</td>
  <td>{int(row["devices"] or 0):,}</td>
</tr>
"""
        if not rows_html:
            rows_html = '<tr><td colspan="4">No application traffic recorded for this period.</td></tr>'
        return rows_html

    def fmt_metric(value, suffix="", decimals=1):
        if value is None or value == "":
            return "-"
        try:
            number = float(value)
        except (TypeError, ValueError):
            return "-"
        return f"{number:.{decimals}f}{suffix}"

    def internet_issue_report_rows():
        rows_html = ""
        for row in internet_issue_rows[:8]:
            isp_text = str(row["isp_name"] or row["isp_org"] or row["asn"] or row["public_ip"] or "").strip() or "-"
            rows_html += f"""
<tr>
  <td>{h(row["ts"] or "")}</td>
  <td>{h(row["status"] or "Issue")}</td>
  <td>{h(row["diagnosis"] or "Internet quality issue recorded.")}</td>
  <td>{h(isp_text)}</td>
  <td>{h(fmt_metric(row["internet_latency_ms"], " ms"))}</td>
  <td>{h(fmt_metric(row["internet_loss_pct"], "%"))}</td>
  <td>{h(fmt_metric(row["jitter_ms"], " ms"))}</td>
  <td>{h(fmt_metric(row["dns_ms"], " ms"))}</td>
</tr>
"""
        if not rows_html:
            rows_html = '<tr><td colspan="8">No internet quality issues recorded for this period.</td></tr>'
        return rows_html

    def speedtest_report_rows():
        rows_html = ""
        for row in speedtest_rows[:6]:
            status = "OK" if int(row["success"] or 0) else "Failed"
            rows_html += f"""
<tr>
  <td>{h(row["ts"] or "")}</td>
  <td>{h(display_speed_source(row["source"]))}</td>
  <td>{h(fmt_metric(row["latency_ms"], " ms"))}</td>
  <td>{h(fmt_metric(row["download_mbps"], " Mbps"))}</td>
  <td>{h(fmt_metric(row["upload_mbps"], " Mbps"))}</td>
  <td>{h(status)}</td>
</tr>
"""
        if not rows_html:
            rows_html = '<tr><td colspan="6">No speed-test results recorded for this period.</td></tr>'
        return rows_html

    def internet_report_summary_grid():
        samples = int(internet_quality_rollup["samples"] or 0) if internet_quality_rollup else 0
        issues = int(internet_quality_rollup["issue_samples"] or 0) if internet_quality_rollup else 0
        issue_rate = (issues / samples * 100) if samples else 0
        isp_name = str(internet_quality_rollup["latest_isp_name"] or internet_quality_rollup["latest_asn"] or "").strip() if internet_quality_rollup else ""
        public_ip_text = str(internet_quality_rollup["latest_public_ip"] or "").strip() if internet_quality_rollup else ""
        isp_count = int(internet_quality_rollup["isp_count"] or 0) if internet_quality_rollup else 0
        public_ip_count = int(internet_quality_rollup["public_ip_count"] or 0) if internet_quality_rollup else 0
        return f"""
  <div class="ns-report-summary-grid">
    <div><span>Quality samples</span><b>{samples:,}</b></div>
    <div><span>Issue samples</span><b>{issues:,}</b></div>
    <div><span>Issue rate</span><b>{issue_rate:.1f}%</b></div>
    <div><span>Worst loss</span><b>{h(fmt_metric(internet_quality_rollup["worst_loss_pct"] if internet_quality_rollup else None, "%"))}</b></div>
  </div>
  <div class="ns-report-summary-grid ns-report-summary-grid--internet">
    <div><span>Average latency</span><b>{h(fmt_metric(internet_quality_rollup["avg_latency_ms"] if internet_quality_rollup else None, " ms"))}</b></div>
    <div><span>Worst latency</span><b>{h(fmt_metric(internet_quality_rollup["worst_latency_ms"] if internet_quality_rollup else None, " ms"))}</b></div>
    <div><span>Average DNS</span><b>{h(fmt_metric(internet_quality_rollup["avg_dns_ms"] if internet_quality_rollup else None, " ms"))}</b></div>
    <div><span>Worst DNS</span><b>{h(fmt_metric(internet_quality_rollup["worst_dns_ms"] if internet_quality_rollup else None, " ms"))}</b></div>
  </div>
  <div class="ns-report-summary-grid ns-report-summary-grid--internet">
    <div><span>Latest ISP</span><b>{h(isp_name or "Not detected")}</b></div>
    <div><span>Latest Public IP</span><b>{h(public_ip_text or "Not detected")}</b></div>
    <div><span>ISP changes</span><b>{max(0, isp_count - 1)}</b></div>
    <div><span>Public IP changes</span><b>{max(0, public_ip_count - 1)}</b></div>
  </div>
"""

    classified_category_rows = [
        row for row in (category_rows or [])
        if row.get("category") != "Unclassified / Other Network Traffic" and float(row.get("total_mb") or 0) > 0
    ]
    donut_segments = []
    donut_start = 0.0
    for row in classified_category_rows:
        pct = max(0.0, float(row.get("share_classified_pct") or 0))
        if pct <= 0:
            continue
        donut_end = min(100.0, donut_start + pct)
        donut_segments.append(f'{h(row.get("color") or "#64748b")} {donut_start:.1f}% {donut_end:.1f}%')
        donut_start = donut_end
        if donut_start >= 100:
            break
    category_donut_style = "conic-gradient(" + ", ".join(donut_segments or ["#24364c 0% 100%"]) + ")"
    coverage_pct = float(category_report.get("classification_coverage_pct") or 0)
    category_legend = ""
    for row in classified_category_rows[:7]:
        share = float(row.get("share_classified_pct") or 0)
        category_legend += f"""
<div class="ns-report-category-row">
  <span><i style="background:{h(row.get("color") or "#64748b")}"></i>{h(row.get("category") or "Other")}</span>
  <b>{h(fmt_mb(row.get("total_mb") or 0))}</b>
  <em>{share:.1f}%</em>
</div>
"""
    if not category_legend:
        category_legend = '<div class="ns-dashboard-empty">No classified application category traffic for this period.</div>'

    preview_sections = ""
    if report_type_key == "internet":
        preview_sections += f"""
<section class="ns-report-a4-section">
  <h2>Internet Quality Summary</h2>
  {internet_report_summary_grid()}
</section>
<section class="ns-report-a4-section">
  <h2>Internet Issues</h2>
  <p>Issue rows are recorded quality checks where the internet status was not healthy.</p>
  <table class="ns-report-a4-table">
    <thead><tr><th>When</th><th>Status</th><th>What happened</th><th>ISP</th><th>Latency</th><th>Loss</th><th>Jitter</th><th>DNS</th></tr></thead>
    <tbody>{internet_issue_report_rows()}</tbody>
  </table>
</section>
<section class="ns-report-a4-section">
  <h2>Speed Tests</h2>
  <table class="ns-report-a4-table">
    <thead><tr><th>When</th><th>Source</th><th>Latency</th><th>Download</th><th>Upload</th><th>Status</th></tr></thead>
    <tbody>{speedtest_report_rows()}</tbody>
  </table>
</section>
"""
    elif "traffic" in selected_sections:
        preview_sections += f"""
<section class="ns-report-a4-section">
  <h2>Network Summary</h2>
  <div class="ns-report-summary-grid">
    <div><span>Total traffic</span><b>{h(fmt_mb(overview.get("total_mb") or 0))}</b></div>
    <div><span>Active devices</span><b>{int(overview.get("active_devices") or 0):,}</b></div>
    <div><span>DNS queries</span><b>{int(overview.get("dns_total") or 0):,}</b></div>
    <div><span>Blocked requests</span><b>{int(overview.get("dns_blocked") or 0):,}</b></div>
  </div>
</section>
"""
    if report_type_key != "internet" and "devices" in selected_sections:
        preview_sections += f"""
<section class="ns-report-a4-section">
  <h2>Top Devices by Traffic</h2>
  <table class="ns-report-a4-table">
    <thead><tr><th>Number</th><th>Device</th><th>IP Address</th><th>Traffic</th><th>Percentage</th></tr></thead>
    <tbody>{top_device_report_rows()}</tbody>
  </table>
</section>
"""
    if report_type_key != "internet" and "applications" in selected_sections:
        preview_sections += f"""
<section class="ns-report-a4-section">
  <h2>Application Categories</h2>
  <p>Application categories — classified traffic. Classification coverage: {coverage_pct:.1f}%.</p>
</section>
<section class="ns-report-a4-section">
  <h2>Top Applications by Data Used</h2>
  <table class="ns-report-a4-table">
    <thead><tr><th>Application</th><th>Category</th><th>Data Used</th><th>Devices</th></tr></thead>
    <tbody>{top_application_report_rows()}</tbody>
  </table>
</section>
"""
    if "blocked_dns" in selected_sections:
        preview_sections += f"""
<section class="ns-report-a4-section ns-report-compact-line">
  <h2>Blocked DNS</h2>
  <p>{int(overview.get("dns_blocked") or 0):,} blocked requests recorded for this period.</p>
</section>
"""
    if "security" in selected_sections:
        security_count = int(overview.get("ids_alerts") or 0) + int(overview.get("open_incidents") or 0)
        security_text = f"{security_count:,} security events recorded for this period." if security_count else "No security incidents recorded for this period."
        preview_sections += f"""
<section class="ns-report-a4-section ns-report-compact-line">
  <h2>Security Events</h2>
  <p>{h(security_text)}</p>
</section>
"""

    body = f"""
{topbar("Reporting")}
<style>
.ns-reporting-page {{ display:flex; flex-direction:column; gap:16px; }}
.ns-report-setup {{ padding:18px 20px; }}
.ns-report-setup h2 {{ margin:0 0 18px; color:var(--ns-text-primary); font-size:20px; }}
.ns-report-setup-grid {{ display:grid; grid-template-columns:minmax(180px, 1fr) minmax(180px, 1fr) minmax(180px, 1fr) minmax(220px, 1fr) max-content; gap:16px; align-items:end; }}
.ns-report-setup label {{ display:flex; flex-direction:column; gap:8px; color:var(--ns-text-secondary); font-size:13px; }}
.ns-report-period {{ display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); border:1px solid var(--ns-line); border-radius:8px; overflow:hidden; background:rgba(7,16,28,.45); }}
.ns-report-period input {{ position:absolute; opacity:0; pointer-events:none; }}
.ns-report-period span {{ display:grid; place-items:center; min-height:38px; color:var(--ns-text-secondary); font-weight:800; cursor:pointer; }}
.ns-report-period input:checked + span {{ background:linear-gradient(135deg, #00c8ff, #00ddc7); color:#03111f; }}
.ns-report-custom-dates {{ display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:10px; margin-top:12px; }}
.ns-report-layout {{ display:grid; grid-template-columns:minmax(0, 1.35fr) minmax(340px, .9fr); gap:16px; align-items:start; }}
.ns-report-preview-wrap {{ display:flex; flex-direction:column; gap:12px; }}
.ns-report-a4 {{ max-width:900px; min-height:780px; padding:34px 38px; border:1px solid #cbd5e1; border-radius:8px; background:#f8fafc; color:#111827; box-shadow:0 18px 45px rgba(0,0,0,.28); }}
.ns-report-a4-header {{ display:flex; align-items:center; gap:20px; padding-bottom:20px; border-bottom:1px solid #cbd5e1; }}
.ns-report-a4-logo {{ width:82px; height:auto; object-fit:contain; }}
.ns-report-a4 h1 {{ margin:0; color:#0f172a; font-size:28px; line-height:1.1; }}
.ns-report-a4-meta {{ margin-top:7px; color:#475569; font-size:14px; }}
.ns-report-a4-section {{ margin-top:24px; }}
.ns-report-a4-section h2 {{ margin:0 0 12px; color:#111827; font-size:18px; }}
.ns-report-a4-section p {{ margin:0; color:#475569; font-size:13px; }}
.ns-report-summary-grid {{ display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:0; border:1px solid #d7dee8; border-radius:6px; overflow:hidden; }}
.ns-report-summary-grid div {{ padding:15px 14px; border-right:1px solid #d7dee8; background:#fff; }}
.ns-report-summary-grid div:last-child {{ border-right:0; }}
.ns-report-summary-grid span {{ display:block; color:#475569; font-size:12px; }}
.ns-report-summary-grid b {{ display:block; margin-top:7px; color:#0f172a; font-size:18px; }}
.ns-report-a4-table {{ width:100%; border-collapse:collapse; background:#fff; font-size:13px; }}
.ns-report-a4-table th,.ns-report-a4-table td {{ padding:10px 12px; border:1px solid #d7dee8; text-align:left; }}
.ns-report-a4-table th {{ color:#334155; background:#f1f5f9; font-size:12px; }}
.ns-report-result {{ padding:20px; }}
.ns-report-result-header {{ display:flex; align-items:center; gap:16px; padding-bottom:16px; border-bottom:1px solid rgba(96,126,160,.18); }}
.ns-report-result-logo {{ width:70px; height:auto; object-fit:contain; }}
.ns-report-result h1 {{ margin:0; color:var(--ns-text-primary); font-size:25px; }}
.ns-report-result .ns-report-a4-meta {{ color:var(--ns-text-secondary); }}
.ns-report-result .ns-report-a4-section h2 {{ color:var(--ns-text-primary); }}
.ns-report-result .ns-report-a4-section p {{ color:var(--ns-text-secondary); }}
.ns-report-result .ns-report-summary-grid {{ border-color:rgba(96,126,160,.2); }}
.ns-report-result .ns-report-summary-grid div {{ background:rgba(7,16,28,.46); border-right-color:rgba(96,126,160,.18); }}
.ns-report-result .ns-report-summary-grid span {{ color:var(--ns-text-secondary); }}
.ns-report-result .ns-report-summary-grid b {{ color:var(--ns-text-primary); }}
.ns-report-result .ns-report-a4-table {{ background:rgba(7,16,28,.42); }}
.ns-report-result .ns-report-a4-table th,.ns-report-result .ns-report-a4-table td {{ border-color:rgba(96,126,160,.18); color:var(--ns-text-secondary); }}
.ns-report-result .ns-report-a4-table th {{ background:rgba(5,16,29,.62); color:#b7c9df; }}
.ns-report-exports {{ display:flex; gap:10px; }}
.ns-report-side {{ display:flex; flex-direction:column; gap:16px; }}
.ns-report-panel {{ padding:18px; }}
.ns-report-panel h2 {{ margin:0 0 14px; color:var(--ns-text-primary); font-size:20px; }}
.ns-report-category-layout {{ display:grid; grid-template-columns:210px minmax(0,1fr); gap:18px; align-items:center; }}
.ns-report-donut {{ width:210px; height:210px; border-radius:50%; display:grid; place-items:center; background:{category_donut_style}; box-shadow:inset 0 0 0 44px rgba(5,18,34,.96); }}
.ns-report-donut b {{ color:#fff; font-size:20px; }}
.ns-report-donut span {{ display:block; color:#9eb0c8; font-size:12px; text-align:center; }}
.ns-report-category-row {{ display:grid; grid-template-columns:minmax(0, 1fr) 78px 48px; gap:10px; align-items:center; padding:9px 0; color:var(--ns-text-secondary); border-bottom:1px solid rgba(148,163,184,.12); font-size:13px; }}
.ns-report-category-row span {{ display:flex; align-items:center; gap:9px; min-width:0; }}
.ns-report-category-row i {{ width:12px; height:12px; flex:0 0 12px; border-radius:50%; }}
.ns-report-category-row b {{ color:var(--ns-text-primary); text-align:right; }}
.ns-report-category-row em {{ color:var(--ns-text-muted); font-style:normal; text-align:right; }}
.ns-report-coverage {{ margin-top:12px; color:var(--ns-text-secondary); font-size:13px; }}
.ns-report-checks {{ display:grid; gap:13px; }}
.ns-report-checks label {{ display:flex; align-items:center; gap:10px; color:var(--ns-text-primary); font-weight:700; }}
.ns-report-checks input {{ width:18px; height:18px; accent-color:#00d6ff; }}
@media (max-width: 1100px) {{ .ns-report-layout,.ns-report-setup-grid,.ns-report-category-layout {{ grid-template-columns:1fr; }} .ns-report-summary-grid {{ grid-template-columns:1fr 1fr; }} }}
@media (max-width: 700px) {{ .ns-report-custom-dates,.ns-report-summary-grid {{ grid-template-columns:1fr; }} .ns-report-a4 {{ padding:22px 18px; }} }}
</style>
<div class="ns-polish-page ns-reporting-page">
  <div>
    <h1>Reporting</h1>
    <p class="ns-polish-subtle">Create and export clear network reports.</p>
  </div>
  <form class="ns-polish-panel ns-report-setup" method="get" id="reportSetupForm">
    <input type="hidden" name="generate" value="1">
    <h2>Report setup</h2>
    <div class="ns-report-setup-grid">
      <label>Report type
        <select class="ns-select" name="report_type">
          <option value="management"{" selected" if report_type_key != "internet" else ""}>Management Overview</option>
          <option value="internet"{" selected" if report_type_key == "internet" else ""}>Internet Report</option>
        </select>
      </label>
      <label>Start <input class="ns-input" type="date" name="start" value="{report_dt_input(start_time)}"></label>
      <label>End <input class="ns-input" type="date" name="end" value="{report_dt_input(end_time)}"></label>
      <label>Devices
        <select class="ns-select" name="device_lookup">{report_device_options()}</select>
      </label>
      <button class="ns-button" type="submit"><i class="fa-regular fa-file-lines" aria-hidden="true"></i> Generate Report</button>
    </div>
  </form>
  <div class="ns-report-layout">
    <div class="ns-report-preview-wrap">
      <article class="ns-polish-panel ns-report-result">
        <header class="ns-report-result-header">
          <img class="ns-report-result-logo" src="/static/brand/logo-sidebar.png?v=20260711-ui5" alt="NetSpecter">
          <div>
            <h1>{h(report_type_title)}</h1>
            <div class="ns-report-a4-meta">{h(start_time)} to {h(end_time)}</div>
            <div class="ns-report-a4-meta">Device scope: {h(selected_device_label)}</div>
          </div>
        </header>
        {preview_sections}
      </article>
      <div class="ns-report-exports">
        <a class="ns-button ns-button--secondary" href="/reporting/pdf?{h(query_suffix)}"><i class="fa-solid fa-file-pdf" aria-hidden="true"></i> Download PDF</a>
        <a class="ns-button ns-button--secondary" href="/reporting/excel?{h(query_suffix)}"><i class="fa-solid fa-file-excel" aria-hidden="true"></i> Download Excel</a>
      </div>
    </div>
    <aside class="ns-report-side">
      <section class="ns-polish-panel ns-report-panel">
        <h2>Application Categories</h2>
        <div class="ns-report-category-layout">
          <div class="ns-report-donut"><div><b>{h(fmt_mb(overview.get("total_mb") or 0))}</b><span>Total Traffic</span></div></div>
          <div>{category_legend}</div>
        </div>
        <div class="ns-report-coverage">Application categories — classified traffic. Classification coverage: {coverage_pct:.1f}%.</div>
      </section>
      <section class="ns-polish-panel ns-report-panel">
        <h2>Report Contents</h2>
        <div class="ns-report-checks">
          <label><input form="reportSetupForm" type="checkbox" name="section" value="traffic"{report_content_checked("traffic")}> Traffic</label>
          <label><input form="reportSetupForm" type="checkbox" name="section" value="devices"{report_content_checked("devices")}> Devices</label>
          <label><input form="reportSetupForm" type="checkbox" name="section" value="applications"{report_content_checked("applications")}> Applications</label>
          <label><input form="reportSetupForm" type="checkbox" name="section" value="blocked_dns"{report_content_checked("blocked_dns")}> Blocked DNS</label>
          <label><input form="reportSetupForm" type="checkbox" name="section" value="security"{report_content_checked("security")}> Security Events</label>
        </div>
      </section>
    </aside>
  </div>
</div>
"""
    return shell("Reporting", body, "Reporting")

    findings = report_context["findings"]
    def dt_input(value):
        return h(str(value or "").replace(" ", "T")[:16])

    def device_suggestions():
        if not devices:
            return ""
        options = []
        seen = set()
        for row in devices:
            name = str(row["name"] or row["ip"] or "")
            ip = str(row["ip"] or "")
            mac = str(row["mac"] or "")
            label = " / ".join(part for part in (ip, mac) if part)
            for value in (name, ip, mac):
                value = str(value or "").strip()
                if not value or value.lower() in seen:
                    continue
                seen.add(value.lower())
                options.append(f'<option value="{h(value)}" label="{h(label or name)}"></option>')
        return "".join(options)

    def application_options():
        options = ['<option value="">All Applications</option>']
        for row in app_options:
            value = str(row["category"] or "")
            options.append(f'<option value="{h(value)}"{" selected" if value == selected_application else ""}>{h(value)} ({h(fmt_mb(row["total_mb"] or 0))})</option>')
        return "".join(options)

    def domain_options_html():
        options = ['<option value="">All Domains</option>']
        for row in domain_options:
            value = str(row["domain"] or "")
            options.append(f'<option value="{h(value)}"{" selected" if value == selected_domain else ""}>{h(value)} ({h(row["requests"])} requests)</option>')
        return "".join(options)

    def stat_card(label, value, detail="", icon="chart-line", tone="blue"):
        return f"""
<div class="ns-card ns-card--compact ns-reporting-stat">
  <div class="ns-reporting-stat-icon ns-reporting-stat-icon--{h(tone)}"><i class="fa-solid fa-{h(icon)}" aria-hidden="true"></i></div>
  <div>
    <div class="ns-muted">{h(label)}</div>
    <strong>{h(value)}</strong>
    {f'<small>{h(detail)}</small>' if detail else ''}
  </div>
</div>
"""

    def table(headers, rows, empty, row_fn):
        head = "".join(f"<th>{h(header)}</th>" for header in headers)
        body_rows = "".join(row_fn(row) for row in rows)
        if not body_rows:
            body_rows = f'<tr><td colspan="{len(headers)}">{h(empty)}</td></tr>'
        return f"""
<div class="ns-table-wrapper">
  <table class="table">
    <thead><tr>{head}</tr></thead>
    <tbody>{body_rows}</tbody>
  </table>
</div>
"""

    app_table = table(
        ["Application", "Traffic", "Upload", "Devices"],
        app_rows,
        "No application data found for this period.",
        lambda row: f'<tr><td>{h(row["category"])}</td><td>{h(fmt_mb(row["total_mb"] or 0))}</td><td>{h(fmt_mb(row["uploaded_mb"] or 0))}</td><td>{h(row["devices"])}</td></tr>',
    )
    destination_table = table(
        ["Destination", "Country", "Category", "Traffic"],
        destination_rows,
        "No destination data found for this period.",
        lambda row: f'<tr><td>{h(row["remote_ip"])}</td><td>{h(row["country"])}</td><td>{h(row["category"])}</td><td>{h(fmt_mb(row["total_mb"] or 0))}</td></tr>',
    )
    user_heading = "Top Assigned Users"
    if selected_application:
        user_heading = f"Top Assigned Users for {selected_application}"
    elif selected_domain:
        user_heading = f"Top Assigned Users for {selected_domain}"
    if selected_domain:
        top_users_table = table(
            ["User", "Devices", "DNS Requests", "Last Seen"],
            top_users,
            "No assigned user DNS activity found for this site.",
            lambda row: f'<tr><td>{h(row["user_label"])}</td><td>{h(row["devices"])}</td><td>{h(row["requests"])}</td><td>{h(row["last_seen"])}</td></tr>',
        )
    else:
        top_users_table = table(
            ["User", "Devices", "Total", "Upload", "Download", "Last Seen"],
            top_users,
            "No assigned user usage found for this period.",
            lambda row: f'<tr><td>{h(row["user_label"])}</td><td>{h(row["devices"])}</td><td>{h(fmt_mb(row["total_mb"] or 0))}</td><td>{h(fmt_mb(row["uploaded_mb"] or 0))}</td><td>{h(fmt_mb(row["downloaded_mb"] or 0))}</td><td>{h(row["last_seen"])}</td></tr>',
        )
    top_users_section = ""
    if top_users:
        top_users_section = f"""
      <section class="ns-card ns-reporting-section" id="traffic">
        <h2>{h(user_heading)}</h2>
        {top_users_table}
      </section>
"""
    top_devices_table = table(
        ["Device", "MAC", "IP", "Total", "Upload", "Download", "Last Seen"],
        top_devices,
        "No device usage found for this period.",
        lambda row: f'<tr><td><a href="/devices?device={quote(str(row["mac"] or row["ip"] or ""), safe="")}&tab=activity">{h(row["name"])}</a></td><td>{h(row["mac"] or "")}</td><td>{h(row["ip"])}</td><td>{h(fmt_mb(row["total_mb"] or 0))}</td><td>{h(fmt_mb(row["uploaded_mb"] or 0))}</td><td>{h(fmt_mb(row["downloaded_mb"] or 0))}</td><td>{h(row["last_seen"])}</td></tr>',
    )

    def category_row(row):
        names = list(row.get("application_names") or []) if hasattr(row, "get") else []
        if names:
            app_links = "".join(
                f'<a class="ns-category-app" href="/applications/{quote(str(name), safe="")}">{h(name)}</a>'
                for name in names[:14]
            )
            if len(names) > 14:
                app_links += f'<span class="ns-category-app ns-category-app--muted">+{len(names) - 14} more</span>'
            app_cell = f"""
<details class="ns-category-details">
  <summary>{h(len(names))} app{"s" if len(names) != 1 else ""}</summary>
  <div class="ns-category-app-list">{app_links}</div>
</details>
"""
        else:
            app_cell = '<span class="ns-muted">None</span>'
        return f'<tr><td><span class="ns-category-dot" style="background:{h(row["color"])}"></span>{h(row["category"])}</td><td>{h(row["usage_group"])}</td><td>{h(fmt_mb(row["total_mb"] or 0))}</td><td>{h(row["share_total_pct"])}%</td><td>{h(row["share_classified_pct"])}%</td><td>{app_cell}</td></tr>'

    category_table = table(
        ["Category", "Usage Group", "Traffic", "Share of Total", "Share of Classified", "Applications"],
        category_rows,
        "No classified application traffic found for this period.",
        category_row,
    )
    ai_summary = report_context.get("ai_summary") or {}
    ai_summary_panel = ""
    if ai_summary.get("services_detected"):
        top_ai_service = next((row for row in (ai_summary.get("services") or []) if row.get("service")), {})
        top_ai_text = str(top_ai_service.get("service") or "AI activity")
        if ai_summary.get("services_detected", 0) > 1:
            top_ai_text += f' +{int(ai_summary.get("services_detected") or 0) - 1} more'
        ai_summary_panel = f"""
        <div class="ns-ai-summary-strip">
          <span><strong>AI Services</strong> detected</span>
          <span>{h(top_ai_text)}</span>
          <span>{h(fmt_mb(ai_summary.get("attributed_mb") or 0))} attributed</span>
          <span>{h(ai_summary.get("attribution_coverage", "Unknown"))} attribution</span>
        </div>
"""
    category_legend = "".join(
        f'<div class="ns-category-row"><span><i style="background:{h(row["color"])}"></i>{h(row["category"])}</span><b>{h(row["share_total_pct"])}%</b><em>{h(fmt_mb(row["total_mb"] or 0))}</em></div>'
        for row in category_rows
    )
    donut_segments = []
    donut_start = 0.0
    for row in category_rows:
        if row.get("category") == "Unclassified / Other Network Traffic":
            continue
        pct = max(0.0, float(row.get("share_classified_pct") or row.get("share_total_pct") or 0))
        if pct <= 0:
            continue
        donut_end = min(100.0, donut_start + pct)
        color = str(row.get("color") or "#94a3b8")
        donut_segments.append(f"{color} {donut_start:.1f}% {donut_end:.1f}%")
        donut_start = donut_end
        if donut_start >= 100:
            break
    category_donut_style = "conic-gradient(" + ", ".join(donut_segments or ["#1f2937 0% 100%"]) + ")"
    coverage_pct = float(category_report["classification_coverage_pct"] or 0)
    if coverage_pct < 20:
        coverage_label = "Low coverage"
        coverage_class = "ns-coverage-warning"
    elif coverage_pct < 60:
        coverage_label = "Partial coverage"
        coverage_class = "ns-coverage-partial"
    elif coverage_pct < 85:
        coverage_label = "Good coverage"
        coverage_class = "ns-coverage-good"
    else:
        coverage_label = "High coverage"
        coverage_class = "ns-coverage-good"
    copy_report = h(structured_report_text(report_context))
    clear_m365_ready_script = ""
    if request.args.get("m365_ready") == "1":
        clear_m365_ready_script = """
<script>
(function() {
  var url = new URL(window.location.href);
  if (url.searchParams.has("m365_ready")) {
    url.searchParams.delete("m365_ready");
    window.history.replaceState({}, "", url.toString());
  }
})();
</script>
"""

    body = f"""
{topbar("Reporting")}
<style>
.ns-reporting {{ display:flex; flex-direction:column; gap:16px; }}
.ns-reporting-hero {{ display:flex; align-items:flex-start; justify-content:space-between; gap:14px; padding:16px; }}
.ns-reporting-hero h1 {{ margin:0; font-size:20px; line-height:1.2; }}
.ns-reporting-crumbs {{ margin-top:6px; color:var(--ns-text-muted); font-size:13px; }}
.ns-reporting-actions {{ display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; }}
.ns-reporting-stat {{ display:flex; align-items:center; gap:14px; padding:14px; min-height:92px; }}
.ns-reporting-stat-icon {{ width:48px; height:48px; flex:0 0 48px; display:grid; place-items:center; border-radius:999px; border:1px solid rgba(91,168,255,.34); background:rgba(22,136,255,.1); color:#5ba8ff; font-size:22px; }}
.ns-reporting-stat-icon--green {{ border-color:rgba(32,223,159,.34); background:rgba(32,223,159,.1); color:#20df9f; }}
.ns-reporting-stat-icon--yellow {{ border-color:rgba(248,200,78,.38); background:rgba(248,200,78,.1); color:#f8c84e; }}
.ns-reporting-stat-icon--red {{ border-color:rgba(255,82,108,.38); background:rgba(255,82,108,.1); color:#ff526c; }}
.ns-reporting-stat-icon--teal {{ border-color:rgba(0,221,199,.34); background:rgba(0,221,199,.1); color:#00ddc7; }}
.ns-reporting-stat strong {{ display:block; margin-top:8px; color:var(--ns-text-primary); font-size:22px; line-height:1.1; }}
.ns-reporting-stat small {{ display:block; margin-top:7px; color:var(--ns-text-secondary); }}
.ns-reporting-shell {{ display:grid; grid-template-columns:224px minmax(0, 1fr); gap:12px; align-items:start; }}
.ns-reporting-filters {{ padding:12px; position:sticky; top:16px; }}
.ns-reporting-filters h2 {{ margin:0 0 12px; font-size:15px; }}
.ns-reporting-filter-stack {{ display:flex; flex-direction:column; gap:10px; }}
.ns-reporting-main {{ display:flex; flex-direction:column; gap:12px; }}
.ns-reporting-panel {{ padding:0; overflow:hidden; }}
.ns-reporting-panel-body {{ padding:16px; }}
.ns-reporting-grid {{ display:grid; grid-template-columns:minmax(0, 1fr) minmax(0, 1fr); gap:12px; }}
.ns-reporting-section {{ padding:16px; }}
.ns-reporting-section h2 {{ margin:0 0 12px; font-size:17px; }}
.ns-reporting-list {{ margin:0; padding-left:18px; color:var(--ns-text-secondary); }}
.ns-reporting-list li {{ margin:8px 0; }}
.ns-reporting-wide {{ grid-column:1 / -1; }}
.ns-category-panel {{ display:grid; grid-template-columns:minmax(220px,.52fr) minmax(0,1fr); gap:14px; align-items:center; }}
.ns-category-donut {{ width:190px; height:190px; border-radius:999px; margin:auto; display:grid; place-items:center; background:{category_donut_style}; box-shadow:inset 0 0 0 28px rgba(4,11,27,.92); }}
.ns-category-donut span {{ display:block; text-align:center; color:var(--ns-text-primary); font-weight:800; }}
.ns-category-donut small {{ display:block; margin-top:5px; color:var(--ns-text-muted); font-size:11px; font-weight:700; }}
.ns-category-row {{ display:grid; grid-template-columns:minmax(0,1fr) 46px 74px; gap:8px; align-items:center; padding:8px 0; border-bottom:1px solid rgba(148,163,184,.12); color:var(--ns-text-secondary); font-size:13px; }}
.ns-category-row span {{ display:flex; align-items:center; gap:8px; min-width:0; }}
.ns-category-row i,.ns-category-dot {{ width:10px; height:10px; flex:0 0 10px; display:inline-block; border-radius:999px; }}
.ns-category-row b {{ color:var(--ns-text-primary); }}
.ns-category-row em {{ color:var(--ns-text-muted); font-style:normal; text-align:right; }}
.ns-category-dot {{ margin-right:8px; vertical-align:middle; }}
.ns-category-details summary {{ cursor:pointer; color:#5ba8ff; font-weight:700; }}
.ns-category-app-list {{ display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; min-width:220px; }}
.ns-category-app {{ display:inline-flex; align-items:center; min-height:24px; padding:3px 8px; border:1px solid var(--ns-border); border-radius:999px; background:rgba(91,168,255,.08); color:var(--ns-text-secondary); text-decoration:none; font-size:12px; }}
.ns-category-app:hover {{ color:var(--ns-text-primary); border-color:rgba(91,168,255,.42); }}
.ns-category-app--muted {{ color:var(--ns-text-muted); }}
.ns-coverage-note {{ margin-top:10px; padding:10px 12px; border-radius:8px; border:1px solid var(--ns-border); color:var(--ns-text-secondary); background:rgba(7,17,30,.42); }}
.ns-coverage-warning {{ border-color:rgba(248,200,78,.34); background:rgba(248,200,78,.08); color:#ffd978; }}
.ns-coverage-partial {{ border-color:rgba(91,168,255,.28); }}
.ns-coverage-good {{ border-color:rgba(32,223,159,.28); }}
.ns-ai-summary-strip {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, max-content)); gap:8px 0; align-items:center; margin-top:10px; padding:8px 10px; border:1px solid rgba(91,168,255,.24); border-radius:8px; background:rgba(91,168,255,.06); color:var(--ns-text-secondary); font-size:13px; overflow:hidden; }}
.ns-ai-summary-strip span {{ display:inline-flex; align-items:center; gap:4px; min-height:22px; min-width:0; padding:0 10px; border-right:1px solid rgba(148,163,184,.18); white-space:nowrap; }}
.ns-ai-summary-strip span:first-child {{ padding-left:0; }}
.ns-ai-summary-strip span:last-child {{ border-right:0; padding-right:0; }}
.ns-ai-summary-strip strong {{ color:var(--ns-text-primary); }}
.ns-reporting-copy-source {{ position:absolute; left:-9999px; top:auto; width:1px; height:1px; opacity:0; }}
@media (max-width: 980px) {{
  .ns-reporting-hero {{ display:block; }}
  .ns-reporting-actions {{ justify-content:flex-start; margin-top:12px; }}
  .ns-reporting-shell,
  .ns-reporting-grid,
  .ns-category-panel {{ grid-template-columns:1fr; }}
  .ns-reporting-filters {{ position:static; }}
}}
</style>
<div class="ns-reporting">
  <section class="ns-card ns-reporting-hero">
    <div>
      <h1>Reporting Overview</h1>
      <div class="ns-reporting-crumbs">Reporting &rsaquo; Overview Reports</div>
      <p class="ns-muted">Period: {h(start_time)} to {h(end_time)}. Site overview for client reporting, top users, top devices, top applications, destinations, and internet quality.</p>
    </div>
    <div class="ns-reporting-actions">
      <button class="ns-button ns-button--secondary" type="button" data-copy-target="report-data"><i class="fa-regular fa-copy" aria-hidden="true"></i> Copy Report Data</button>
      <a class="ns-button ns-button--secondary" href="/reporting/pdf?{h(request.query_string.decode('utf-8'))}"><i class="fa-solid fa-file-pdf" aria-hidden="true"></i> Export PDF</a>
      <a class="ns-button ns-button--ghost" href="/export/traffic"><i class="fa-solid fa-file-csv" aria-hidden="true"></i> Export CSV</a>
    </div>
  </section>

  <div class="ns-card-grid">
    {stat_card("Total Traffic", fmt_mb(overview["total_mb"]), "All monitored traffic", "globe", "blue")}
    {stat_card("Download", fmt_mb(overview["downloaded_mb"]), "Client download usage", "download", "green")}
    {stat_card("Upload", fmt_mb(overview["uploaded_mb"]), "Client upload usage", "upload", "yellow")}
    {stat_card("Active Devices", f'{overview["active_devices"]:,}', "Devices seen in period", "desktop", "blue")}
    {stat_card("Applications", f'{overview["applications"]:,}', "Detected categories", "grip", "blue")}
    {stat_card("Destinations", f'{overview["unique_destinations"]:,}', "Remote IPs contacted", "location-dot", "teal")}
    {stat_card("Classification Coverage", f'{coverage_pct}%', f'{fmt_mb(category_report["classified_application_mb"])} of {fmt_mb(category_report["total_network_mb"])} classified', "chart-pie", "teal")}
  </div>

  <div class="ns-reporting-shell">
    <form class="ns-card ns-reporting-filters" method="get">
      <h2>Filters</h2>
      <div class="ns-reporting-filter-stack">
        <label><span class="ns-field-label">Start</span><input class="ns-input" type="datetime-local" name="start" value="{dt_input(start_time)}"></label>
        <label><span class="ns-field-label">End</span><input class="ns-input" type="datetime-local" name="end" value="{dt_input(end_time)}"></label>
        {device_lookup_notice}
        <label><span class="ns-field-label">Devices</span><input class="ns-input" name="device_lookup" value="{h(selected_device_lookup)}" placeholder="Type IP, MAC, or device name" list="reporting-device-suggestions"></label>
        <datalist id="reporting-device-suggestions">{device_suggestions()}</datalist>
        <label><span class="ns-field-label">Application</span><select class="ns-select" name="application">{application_options()}</select></label>
        <label><span class="ns-field-label">Site / Domain</span><select class="ns-select" name="domain">{domain_options_html()}</select></label>
        <button class="ns-button ns-button--secondary" type="submit"><i class="fa-solid fa-filter" aria-hidden="true"></i> Apply Filters</button>
        <a class="ns-button ns-button--ghost" href="/reporting"><i class="fa-solid fa-rotate-left" aria-hidden="true"></i> Clear</a>
      </div>
    </form>

    <div class="ns-reporting-main">
      <div class="ns-reporting-grid">
      <section class="ns-card ns-reporting-section ns-reporting-wide">
        <h2>Application Usage by Category</h2>
        <p class="ns-muted">Default view is based on total network traffic. The table also shows each category's share of classified application traffic.</p>
        <div class="ns-coverage-note {coverage_class}"><strong>{h(coverage_label)}:</strong> {h(coverage_pct)}% of total network traffic was identified by application category. Category percentages should be interpreted with this coverage in mind.</div>
        {ai_summary_panel}
        <div class="ns-category-panel">
          <div class="ns-category-donut"><span>{h(fmt_mb(overview["total_mb"]))}<small>Total Traffic</small></span></div>
          <div>{category_legend or '<div class="ns-empty-state">No classified category data yet.</div>'}</div>
        </div>
        {category_table}
      </section>
      {top_users_section}
      <section class="ns-card ns-reporting-section ns-reporting-wide">
        <h2>Top Devices</h2>
        {top_devices_table}
      </section>
      <section class="ns-card ns-reporting-section" id="dns">
        <h2>Top Sites</h2>
        {table(["Domain", "Category", "Requests", "Clients"], dns_rows, "No DNS data found for this period.", lambda row: f'<tr><td>{h(row["domain"])}</td><td>{h(row["category"])}</td><td>{h(row["requests"])}</td><td>{h(row["clients"])}</td></tr>')}
      </section>
      <section class="ns-card ns-reporting-section" id="applications">
        <h2>Top Applications</h2>
        {app_table}
      </section>
      <section class="ns-card ns-reporting-section" id="destinations">
        <h2>Top Destinations</h2>
        {destination_table}
      </section>
      <section class="ns-card ns-reporting-section" id="internet">
        <h2>Internet Quality</h2>
        {table(["Time", "Status", "Latency", "Loss", "DNS"], quality_rows, "No internet-quality data found for this period.", lambda row: f'<tr><td>{h(row["ts"])}</td><td>{h(row["status"])}</td><td>{h(row["internet_latency_ms"])}</td><td>{h(row["internet_loss_pct"])}</td><td>{h(row["dns_ms"])}</td></tr>')}
      </section>
      <section class="ns-card ns-reporting-section" id="notes">
        <h2>Notes</h2>
        <textarea class="ns-textarea" placeholder="Technician notes and conclusion"></textarea>
      </section>
      </div>
    </div>
  </div>
  <textarea id="report-data" class="ns-reporting-copy-source" readonly>{copy_report}</textarea>
</div>
{clear_m365_ready_script}
<script>
document.querySelectorAll("[data-copy-target]").forEach((button) => {{
  button.addEventListener("click", async () => {{
    const source = document.getElementById(button.dataset.copyTarget);
    if (!source) return;
    try {{
      await navigator.clipboard.writeText(source.value);
      const oldText = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => {{ button.textContent = oldText; }}, 1200);
    }} catch (error) {{
      source.focus();
      source.select();
      document.execCommand("copy");
    }}
  }});
}});
</script>
"""
    return shell("Reporting", body, "Reporting")


@app.route("/reporting/pdf")
def reporting_pdf():
    report_context = build_reporting_context_from_request(request.args)
    filename, data = reporting_pdf_response(report_context)
    return Response(
        data,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/reporting/excel")
def reporting_excel():
    report_context = build_reporting_context_from_request(request.args)
    report_slug = "internet-report" if str(report_context.get("report_type") or "").lower().startswith("internet") else "management-overview"
    filename = f"netspecter-{report_slug}-{safe_report_date(report_context['start_time'])}-{safe_report_date(report_context['end_time'])}.xlsx"
    data = reporting_xlsx_response(report_context, request.args.getlist("section"))
    return Response(
        data,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def safe_report_date(value):
    return re.sub(r"[^0-9]+", "", str(value or ""))[:12] or "report"


def reporting_xlsx_response(context, sections=None):
    selected = set(sections or ["traffic", "devices", "applications"])
    overview = context["overview"]
    total_mb = float(overview.get("total_mb") or 0)
    sheets = []
    is_internet_report = str(context.get("report_type") or "").lower().startswith("internet")
    if "traffic" in selected:
        sheets.append(("Summary", [
            ["Metric", "Value"],
            ["Report Type", context.get("report_type") or "Management Overview"],
            ["Start", context["start_time"]],
            ["End", context["end_time"]],
            ["Device Scope", ", ".join(context.get("selected_devices") or []) or "All devices"],
            ["Total Traffic", fmt_mb(total_mb)],
            ["Active Devices", int(overview.get("active_devices") or 0)],
            ["DNS Queries", int(overview.get("dns_total") or 0)],
            ["Blocked Requests", int(overview.get("dns_blocked") or 0)],
        ]))
    if is_internet_report:
        rollup = context.get("internet_quality_rollup") or {}
        samples = int(rollup["samples"] or 0) if rollup else 0
        issues = int(rollup["issue_samples"] or 0) if rollup else 0
        issue_rate = round((issues / samples * 100), 1) if samples else 0.0
        sheets.append(("Internet Summary", [
            ["Metric", "Value"],
            ["Quality Samples", samples],
            ["Issue Samples", issues],
            ["Issue Rate", f"{issue_rate}%"],
            ["Average Latency", fmt_report_metric(rollup["avg_latency_ms"] if rollup else None, " ms")],
            ["Worst Latency", fmt_report_metric(rollup["worst_latency_ms"] if rollup else None, " ms")],
            ["Average Packet Loss", fmt_report_metric(rollup["avg_loss_pct"] if rollup else None, "%")],
            ["Worst Packet Loss", fmt_report_metric(rollup["worst_loss_pct"] if rollup else None, "%")],
            ["Average Jitter", fmt_report_metric(rollup["avg_jitter_ms"] if rollup else None, " ms")],
            ["Worst Jitter", fmt_report_metric(rollup["worst_jitter_ms"] if rollup else None, " ms")],
            ["Average DNS", fmt_report_metric(rollup["avg_dns_ms"] if rollup else None, " ms")],
            ["Worst DNS", fmt_report_metric(rollup["worst_dns_ms"] if rollup else None, " ms")],
            ["Latest ISP", (rollup["latest_isp_name"] or rollup["latest_asn"] or "Not detected") if rollup else "Not detected"],
            ["Latest Public IP", (rollup["latest_public_ip"] or "Not detected") if rollup else "Not detected"],
            ["ISP Changes", max(0, int(rollup["isp_count"] or 0) - 1) if rollup else 0],
            ["Public IP Changes", max(0, int(rollup["public_ip_count"] or 0) - 1) if rollup else 0],
        ]))
        issue_rows = [["When", "Status", "What Happened", "ISP", "Public IP", "Latency", "Loss", "Jitter", "DNS"]]
        for row in context.get("internet_issue_rows") or []:
            isp_text = str(row["isp_name"] or row["isp_org"] or row["asn"] or "").strip()
            issue_rows.append([
                row["ts"] or "",
                row["status"] or "Issue",
                row["diagnosis"] or "Internet quality issue recorded.",
                isp_text,
                row["public_ip"] or "",
                fmt_report_metric(row["internet_latency_ms"], " ms"),
                fmt_report_metric(row["internet_loss_pct"], "%"),
                fmt_report_metric(row["jitter_ms"], " ms"),
                fmt_report_metric(row["dns_ms"], " ms"),
            ])
        if len(issue_rows) == 1:
            issue_rows.append(["No internet quality issues recorded for this period.", "", "", "", "", "", "", "", ""])
        sheets.append(("Internet Issues", issue_rows))
        speed_rows = [["When", "Source", "Latency", "Download", "Upload", "Status"]]
        for row in context.get("speedtest_rows") or []:
            speed_rows.append([
                row["ts"] or "",
                display_speed_source(row["source"]),
                fmt_report_metric(row["latency_ms"], " ms"),
                fmt_report_metric(row["download_mbps"], " Mbps"),
                fmt_report_metric(row["upload_mbps"], " Mbps"),
                "OK" if int(row["success"] or 0) else "Failed",
            ])
        if len(speed_rows) == 1:
            speed_rows.append(["No speed-test results recorded for this period.", "", "", "", "", ""])
        sheets.append(("Speed Tests", speed_rows))
        return build_xlsx(sheets)
    if "devices" in selected:
        rows = [["Number", "Device", "IP Address", "Traffic", "Percentage"]]
        for index, row in enumerate((context.get("top_devices") or [])[:5], 1):
            traffic = float(row["total_mb"] or 0)
            pct = round((traffic / total_mb * 100), 1) if total_mb else 0.0
            rows.append([index, row["name"] or row["ip"], row["ip"] or "", fmt_mb(traffic), f"{pct}%"])
        sheets.append(("Top Devices", rows))
    if "applications" in selected:
        category_report = context.get("category_report") or {}
        rows = [["Category", "Traffic", "Share of Classified", "Classification Coverage"]]
        for row in context.get("category_rows") or []:
            if row.get("category") == "Unclassified / Other Network Traffic" or float(row.get("total_mb") or 0) <= 0:
                continue
            rows.append([
                row.get("category") or "Other",
                fmt_mb(row.get("total_mb") or 0),
                f"{float(row.get('share_classified_pct') or 0):.1f}%",
                f"{float(category_report.get('classification_coverage_pct') or 0):.1f}%",
            ])
        sheets.append(("Applications", rows))
        app_rows = [["Application", "Category", "Data Used", "Devices"]]
        for row in (context.get("app_rows") or [])[:5]:
            name = row["category"] or "Other"
            app_rows.append([name, name, fmt_mb(row["total_mb"] or 0), int(row["devices"] or 0)])
        sheets.append(("Top Apps", app_rows))
    if "blocked_dns" in selected:
        rows = [["Domain", "Category", "Blocked Requests", "Clients"]]
        for row in context.get("dns_rows") or []:
            if int(row["blocked"] or 0):
                rows.append([row["domain"], row["category"], int(row["requests"] or 0), int(row["clients"] or 0)])
        if len(rows) == 1:
            rows.append(["No blocked DNS requests recorded for this period.", "", 0, 0])
        sheets.append(("Blocked DNS", rows))
    if "security" in selected:
        count = int(overview.get("ids_alerts") or 0) + int(overview.get("open_incidents") or 0)
        sheets.append(("Security Events", [["Status", "Count"], ["No security incidents recorded for this period." if not count else "Security events recorded for this period.", count]]))
    return build_xlsx(sheets or [("Summary", [["Message"], ["No report sections selected."]])])


def fmt_report_metric(value, suffix="", decimals=1):
    if value is None or value == "":
        return "-"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "-"
    return f"{number:.{decimals}f}{suffix}"


def build_xlsx(sheets):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
""" + "".join(f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for index, _sheet in enumerate(sheets, 1)) + "</Types>")
        archive.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>""")
        archive.writestr("xl/_rels/workbook.xml.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
""" + "".join(f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>' for index, _sheet in enumerate(sheets, 1)) + "</Relationships>")
        archive.writestr("xl/workbook.xml", """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>
""" + "".join(f'<sheet name="{xml_escape(name[:31])}" sheetId="{index}" r:id="rId{index}"/>' for index, (name, _rows) in enumerate(sheets, 1)) + "</sheets></workbook>")
        for index, (_name, rows) in enumerate(sheets, 1):
            archive.writestr(f"xl/worksheets/sheet{index}.xml", worksheet_xml(rows))
    return output.getvalue()


def worksheet_xml(rows):
    body = []
    for row_index, row in enumerate(rows, 1):
        cells = []
        for col_index, value in enumerate(row, 1):
            ref = f"{xlsx_col(col_index)}{row_index}"
            cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{xml_escape(value)}</t></is></c>')
        body.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    return '<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>' + "".join(body) + "</sheetData></worksheet>"


def xlsx_col(index):
    letters = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def xml_escape(value):
    return (
        str(value if value is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


@app.route("/export/<kind>")
def export_csv(kind):
    start_day = range_start_day()
    if kind == "devices":
        rows = query(
            """
            SELECT
                d.ip, COALESCE(o.name, d.name) AS name, d.mac,
                COALESCE(o.vendor, d.vendor) AS vendor,
                COALESCE(o.device_type, d.device_type) AS device_type,
                COALESCE(o.status, d.status) AS status,
                d.first_seen, d.last_seen
            FROM devices d
            LEFT JOIN device_overrides o ON o.ip=d.ip
            ORDER BY d.ip
            """
        )
        headers = ["ip", "name", "mac", "vendor", "device_type", "status", "first_seen", "last_seen"]
        return csv_response("netspecter-devices.csv", headers, rows)

    if kind == "traffic":
        rows = query(
            """
            SELECT
                ip,
                MAX(name) AS name,
                MAX(mac) AS mac,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb,
                MAX(live_bps) AS live_bps,
                day,
                MAX(ts) AS ts
            FROM traffic_intervals
            WHERE day>=?
            GROUP BY day, ip
            ORDER BY ts DESC
            """,
            (start_day,),
        )
        headers = ["ip", "name", "mac", "downloaded_mb", "uploaded_mb", "total_mb", "live_bps", "day", "ts"]
        return csv_response("netspecter-traffic.csv", headers, rows)

    if kind == "dns":
        rows = query(
            """
            SELECT day, ts, client, domain, blocked, category
            FROM dns_querylog
            WHERE day>=?
            ORDER BY ts DESC
            LIMIT 20000
            """,
            (start_day,),
        )
        headers = ["day", "ts", "client", "domain", "blocked", "category"]
        return csv_response("netspecter-dns.csv", headers, rows)

    if kind == "blocked":
        rows = query(
            """
            SELECT day, ts, client, domain, blocked, category
            FROM dns_querylog
            WHERE day>=? AND blocked=1
            ORDER BY ts DESC
            LIMIT 20000
            """,
            (start_day,),
        )
        headers = ["day", "ts", "client", "domain", "blocked", "category"]
        return csv_response("netspecter-blocked.csv", headers, rows)

    return redirect("/exports")


@app.route("/health")
def health_page():
    c = cfg()
    health = system_health_snapshot(force=request.args.get("check") == "1")

    notice = ""
    if request.args.get("collector") == "restarted":
        notice = '<div class="setup-ok">Collector restart requested.</div>'
    elif request.args.get("collector") == "restart_failed":
        notice = '<div class="setup-warning">Collector restart failed. Check Logs.</div>'
    load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
    service_rows = ""
    for label, service in [
        ("Web UI", "netspecter-web"),
        ("Collector", "netspecter-collector"),
        ("Service Watch", "gatus"),
        ("Metrics Engine", "beszel-hub"),
        ("AdGuard DNS", "AdGuardHome"),
    ]:
        ok, state = systemd_active(service)
        service_rows += f"""
<tr>
  <td>{h(label)}</td>
  <td><span class="{'green' if ok else 'red'}"><b>{h(state)}</b></span></td>
</tr>"""
    process_rows = ""
    for row in process_summary(["gunicorn", "live_packet_collector.py", "gatus", "beszel", "AdGuardHome"]):
        process_rows += f"""
<tr>
  <td>{h(friendly_process_name(row))}</td>
  <td>{h(row['pid'])}</td>
  <td><b>{h(row['memory'])} MB</b></td>
</tr>"""
    disk_rows = ""
    for label, size in disk_usage_rows():
        disk_rows += f"<tr><td>{h(label)}</td><td><b>{h(size)} MB</b></td></tr>"
    update_state, update_age = update_run_state()
    update_status_label = "Idle"
    if update_state == "running":
        update_status_label = "Running"
    elif update_state == "finished" and update_age is not None and update_age < 600:
        update_status_label = "Finished"
    elif update_state == "failed" and update_age is not None and update_age < 600:
        update_status_label = "Failed"
    force_update_check = request.args.get("check") == "1"
    update_status_data = update_status(force=force_update_check, fetch_remote=force_update_check)
    if request.args.get("update") == "started":
        notice += '<div class="setup-ok">Update started. This page will show progress below.</div>'
    elif request.args.get("update") == "failed":
        notice += '<div class="setup-warning">Update could not start. Check the source checkout path.</div>'
    if update_status_data.get("ok"):
        update_label = "Updates Available" if update_status_data.get("available") else "Current"
        update_detail = f"Installed {h(update_status_data.get('current', '-'))}; latest {h(update_status_data.get('latest', '-'))}."
    else:
        update_label = "Check Failed"
        update_detail = h(update_status_data.get("detail", "Update status unavailable."))
    update_button = "Update Available" if update_status_data.get("available") else "Reinstall Current Version"
    body = f"""
{topbar('Service Health')}
{notice}
<div class="related-page health-page">
<div class="grid health-grid health-metrics-grid">
  <div class="card appliance-metric-card"><span class="appliance-metric-icon blue"><i class="fa-solid fa-microchip"></i></span><div><div class="label">CPU</div><span class="big blue">{health['cpu']}%</span><small>Current appliance load</small></div></div>
  <div class="card appliance-metric-card"><span class="appliance-metric-icon purple"><i class="fa-solid fa-memory"></i></span><div><div class="label">Memory</div><span class="big purple">{health['mem']}%</span><small>System RAM used</small></div></div>
  <div class="card appliance-metric-card"><span class="appliance-metric-icon {'red' if health['disk'] > 85 else 'green'}"><i class="fa-solid fa-hard-drive"></i></span><div><div class="label">Disk / HDD</div><span class="big {'red' if health['disk'] > 85 else 'green'}">{health['disk']}%</span><small>{health['disk_free_gb']} GB free</small></div></div>
  <div class="card appliance-metric-card"><span class="appliance-metric-icon teal"><i class="fa-solid fa-gauge-high"></i></span><div><div class="label">Load Average</div><span class="big teal">{load_avg[0]:.2f}</span><small>{load_avg[1]:.2f} / {load_avg[2]:.2f}</small></div></div>
  <div class="card appliance-metric-card"><span class="appliance-metric-icon blue"><i class="fa-regular fa-clock"></i></span><div><div class="label">Uptime</div><span class="big">{health['uptime']}</span><small>Since last boot</small></div></div>
</div>
<div class="panel related-card" id="updateProgress">
  <h2>Update Progress</h2>
  <p><b>Version:</b> {update_label}</p>
  <p class="sub">{update_detail}</p>
  <form method="post" action="/system">
    {csrf_input()}
    <button class="btn-yellow" type="submit">{update_button}</button>
    <a class="btn" href="/health?check=1#updateProgress">Check Again</a>
  </form>
  <p><b>Status:</b> <span id="updateProgressState">{h(update_status_label)}</span></p>
  <div class="update-progress-bar"><div id="updateProgressFill" class="update-progress-fill"></div></div>
  <p class="sub" id="updateProgressDetail">Waiting for update activity.</p>
</div>
<div class="layout2 health-panels">
  <div class="panel related-card">
    <h2>Appliance Services</h2>
    <table>
      <tr><th>Service</th><th>Status</th></tr>
      {service_rows}
    </table>
  </div>
  <div class="panel related-card">
    <h2>Process Footprint</h2>
    <table>
      <tr><th>Process</th><th>PID</th><th>Memory</th></tr>
      {process_rows or '<tr><td colspan="3">Process details unavailable.</td></tr>'}
    </table>
  </div>
  <div class="panel related-card">
    <h2>Disk Usage</h2>
    <table>
      <tr><th>Area</th><th>Used</th></tr>
      {disk_rows or '<tr><td colspan="2">Disk usage details unavailable.</td></tr>'}
    </table>
  </div>
</div>
<script>
let updatePollFailures = 0;
let updateWasRunning = false;
async function refreshUpdateProgress() {{
  const stateEl = document.getElementById("updateProgressState");
  const fillEl = document.getElementById("updateProgressFill");
  const detailEl = document.getElementById("updateProgressDetail");
  if (!stateEl || !fillEl || !detailEl) return;
  try {{
    const res = await fetch("/api/update-progress", {{cache: "no-store"}});
    const data = await res.json();
    updatePollFailures = 0;
    stateEl.textContent = data.label || "Idle";
    let pct = Number(data.progress || 0);
    fillEl.style.width = pct + "%";
    detailEl.textContent = data.detail || "No update running.";
    if (data.state === "running") {{
      updateWasRunning = true;
      sessionStorage.removeItem("netspecterUpdateRefreshed");
    }}
    if ((data.state === "finished" || data.state === "failed") && sessionStorage.getItem("netspecterUpdateRefreshed") !== "1") {{
      sessionStorage.setItem("netspecterUpdateRefreshed", "1");
      setTimeout(() => window.location.replace("/health?check=1&_=" + Date.now() + "#updateProgress"), 5000);
    }}
  }} catch (error) {{
    updatePollFailures += 1;
    detailEl.textContent = "Waiting for NetSpecter to come back online...";
    if (updateWasRunning && updatePollFailures >= 8) {{
      setTimeout(() => window.location.replace("/health?_=" + Date.now() + "#updateProgress"), 3000);
    }}
  }}
}}
refreshUpdateProgress();
setInterval(refreshUpdateProgress, 3000);
</script>
</div>
"""
    return shell("Service Health", body, "Health")


@app.route("/third-party-licences")
def third_party_licences():
    license_path = ROOT / "LICENSE"
    eula_path = ROOT / "EULA.md"
    notice_path = ROOT / "THIRD_PARTY_NOTICES.md"
    gpl_path = ROOT / "licenses" / "AdGuardHome-GPL-3.0.txt"
    license_text = license_path.read_text(encoding="utf-8") if license_path.exists() else "LICENSE is not installed."
    eula_text = eula_path.read_text(encoding="utf-8") if eula_path.exists() else "EULA.md is not installed."
    notice_text = notice_path.read_text(encoding="utf-8") if notice_path.exists() else "THIRD_PARTY_NOTICES.md is not installed."
    gpl_text = gpl_path.read_text(encoding="utf-8") if gpl_path.exists() else "licenses/AdGuardHome-GPL-3.0.txt is not installed."
    body = f"""
{topbar('Third-party licences')}
<div class="related-page">
  <section class="panel settings">
    <h2>NetSpecter licence</h2>
    <p class="sub">NetSpecter's proprietary licence applies only to NetSpecter. Separately identified third-party software remains subject to its own licence terms.</p>
    <pre class="legal-notice">{h(license_text)}</pre>
  </section>
  <section class="panel settings">
    <h2>NetSpecter EULA</h2>
    <pre class="legal-notice">{h(eula_text)}</pre>
  </section>
  <section class="panel settings">
    <h2>Third-party notices</h2>
    <p class="sub">Administrators can review third-party software notices, source links, and licence text used by this appliance.</p>
    <pre class="legal-notice">{h(notice_text)}</pre>
  </section>
  <section class="panel settings">
    <h2>AdGuard Home GPL-3.0 licence text</h2>
    <pre class="legal-notice">{h(gpl_text)}</pre>
  </section>
</div>
"""
    return shell("Third-party licences", body, "Health")


@app.route("/telemetry")
def telemetry():
    rows = query(
        """
        SELECT source, target, metric, value, ts
        FROM telemetry_readings
        ORDER BY ts DESC, id DESC
        LIMIT 200
        """
    )
    table = ""
    for r in rows:
        table += f"""
<tr>
  <td>{h(str(r['source']).upper())}</td>
  <td>{h(r['target'])}</td>
  <td>{h(r['metric'])}</td>
  <td><span class="mono">{h(str(r['value'])[:240])}</span></td>
  <td>{h(r['ts'])}</td>
</tr>"""
    body = f"""
{topbar('Telemetry')}
<div class="panel">
  <h2>SNMP and MQTT Pulled Data</h2>
  <p class="sub">NetSpecter stores SNMP poll results and MQTT subscribed messages here. Configure targets and topics under Settings.</p>
  <table>
    <tr><th>Source</th><th>Target / Topic</th><th>Metric</th><th>Value</th><th>Time</th></tr>
    {table or '<tr><td colspan="5">No SNMP or MQTT telemetry has been pulled yet.</td></tr>'}
  </table>
</div>
"""
    return shell("Telemetry", body, "Telemetry")



def ag_enabled(endpoint):
    ok, data = ag_get(endpoint)
    if ok and isinstance(data, dict):
        return data.get("enabled")
    return None

def toggle_card(label, enabled, on_action, off_action, icon, color="green"):
    if enabled is None:
        txt = "Unknown"
        action = ""
        cls = "yellow"
    elif enabled:
        txt = "ON"
        action = off_action
        cls = color
    else:
        txt = "OFF"
        action = on_action
        cls = "red"
    if not action:
        return f"""
<div class="card">
  <div class="label">{icon} {label}</div>
  <span class="big {cls}">{txt}</span>
</div>
"""
    return f"""
<form class="card" method="post" action="/adguard/action">
  {csrf_input()}
  <input type="hidden" name="action" value="{h(action)}">
  <button type="submit" style="background:none; border:0; padding:0; margin:0; width:100%; min-height:82px; text-align:left; color:inherit;">
    <div class="label">{icon} {label}</div>
    <span class="big {cls}">{txt}</span>
  </button>
</form>
"""

@app.route("/adguard")
def adguard():
    ok_status, status = ag_get("/status")
    ok_stats, stats = ag_get("/stats")

    protection = status.get("protection_enabled") if isinstance(status, dict) else None
    safe_browsing = ag_enabled("/safebrowsing/status")
    parental = ag_enabled("/parental/status")
    safe_search = ag_enabled("/safesearch/status")
    c = cfg()

    body = f"""
{topbar('AdGuard Control')}

<div class="grid">
  <div class="card"><div class="label">API Status</div><span class="big {'green' if ok_status else 'red'}">{'Online' if ok_status else 'Offline'}</span></div>
  <div class="card"><div class="label">DNS Queries</div><span class="big blue">{stats.get('num_dns_queries','-') if ok_stats else '-'}</span></div>
  <div class="card"><div class="label">Blocked</div><span class="big red">{stats.get('num_blocked_filtering','-') if ok_stats else '-'}</span></div>
  {toggle_card("Protection", protection, "protection_on", "protection_off", "Shield")}
  {toggle_card("Parental", parental, "parental_on", "parental_off", "Family", "yellow")}
  {toggle_card("Safe Browsing", safe_browsing, "safebrowsing_on", "safebrowsing_off", "Web")}
  {toggle_card("Safe Search", safe_search, "safesearch_on", "safesearch_off", "Search")}
  <a class="card" href="{c.get('adguard_url')}" target="_blank"><div class="label">Open AdGuard</div><span class="big green">Launch</span></a>
  <a class="card" href="/blocked"><div class="label">Blocked DNS Requests</div><span class="big red">Open</span></a>
</div>

<div class="panel">
<h2>Quick Controls</h2>
<form method="post" action="/adguard/action">
  {csrf_input()}
  <button name="action" value="cache_clear">Clear Cache</button>
  <button name="action" value="filter_refresh">Refresh Filters</button>
</form>
</div>
"""
    return shell("AdGuard", body, "AdGuard")


@app.route("/adguard/action", methods=["POST"])
def adguard_action():
    action = request.form.get("action", "")

    mapping = {
        "protection_on": ("/protection", {"enabled": True, "duration": 0}),
        "protection_off": ("/protection", {"enabled": False, "duration": 0}),
        "cache_clear": ("/cache_clear", {}),
        "filter_refresh": ("/filtering/refresh", {"force": True}),
        "safebrowsing_on": ("/safebrowsing/enable", None),
        "safebrowsing_off": ("/safebrowsing/disable", None),
        "parental_on": ("/parental/enable", None),
        "parental_off": ("/parental/disable", None),
        "safesearch_on": ("/safesearch/enable", None),
        "safesearch_off": ("/safesearch/disable", None),
    }

    if action in mapping:
        endpoint, payload = mapping[action]
        ag_post(endpoint, payload)

    return redirect("/adguard")


def unifi_connector_bases(config):
    base = str(config.get("unifi_connector_url", "") or "").strip().rstrip("/")
    if not base:
        return []
    if "/proxy/network/integration" not in base and "/network/integration" in base:
        base = base.replace("/network/integration", "/proxy/network/integration", 1)
    return [base]


def unifi_site_endpoint(base):
    return f"{base}/v1/sites"


def unifi_legacy_base(base):
    origin = unifi_origin(base)
    if not origin:
        return ""
    return f"{origin}/proxy/network"


def unifi_legacy_site_endpoint(base):
    legacy_base = unifi_legacy_base(base)
    return f"{legacy_base}/api/self/sites" if legacy_base else ""


def unifi_client_endpoint(config, base=None):
    base = base or str(config.get("unifi_connector_url", "") or "").strip().rstrip("/")
    site_id = quote(str(config.get("unifi_site_id", "") or "").strip(), safe="")
    if not base or not site_id:
        return ""
    return f"{base}/v1/sites/{site_id}/clients?offset=0&limit=25"


def unifi_site_name(site):
    if not isinstance(site, dict):
        return ""
    for key in ("name", "site", "site_name"):
        value = str(site.get(key, "") or "").strip()
        if value:
            return value
    return ""


def unifi_legacy_client_endpoint(site_name, base):
    legacy_base = unifi_legacy_base(base)
    site_name = quote(str(site_name or "").strip(), safe="")
    if not legacy_base or not site_name:
        return ""
    return f"{legacy_base}/api/s/{site_name}/stat/sta"


def unifi_verify_tls(config):
    verify = not bool(config.get("unifi_skip_tls_verify"))
    if not verify:
        requests.packages.urllib3.disable_warnings()
    return verify


def unifi_origin(base):
    parsed = urlsplit(str(base or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def unifi_auth_mode(config, base):
    username = str(config.get("unifi_username", "") or "").strip()
    password = str(config.get("unifi_password", "") or "").strip()
    if username and password:
        return "local_session"
    return "none"


def unifi_session_key(config, base):
    return (
        unifi_origin(base),
        str(config.get("unifi_username", "") or "").strip(),
        bool(config.get("unifi_skip_tls_verify")),
    )


def unifi_token_headers(token):
    token = str(token or "").strip()
    if not token:
        return {}
    return {
        "Authorization": f"Bearer {token}",
        "X-Auth-Token": token,
    }


def unifi_cached_session(config, base, headers, verify):
    key = unifi_session_key(config, base)
    now = time.monotonic()
    cached = unifi_session_cache.get(key)
    if cached and now < cached.get("blocked_until", 0):
        wait_seconds = max(1, int(cached["blocked_until"] - now))
        raise RuntimeError(f"UniFi login is being rate limited. Wait about {wait_seconds} seconds and try again.")
    if cached and now < cached.get("expires_at", 0):
        return cached["session"], None

    origin = unifi_origin(base)
    if not origin:
        raise RuntimeError("UniFi gateway URL is not valid.")

    session = requests.Session()
    login = session.post(
        f"{origin}/api/auth/login",
        json={
            "username": str(config.get("unifi_username", "") or "").strip(),
            "password": str(config.get("unifi_password", "") or "").strip(),
        },
        headers=headers,
        timeout=12,
        verify=verify,
    )
    login_payload = None
    try:
        login_payload = login.json()
    except ValueError:
        login_payload = None
    if login.status_code == 429:
        unifi_session_cache[key] = {
            "session": session,
            "token": "",
            "expires_at": 0,
            "blocked_until": now + UNIFI_RATE_LIMIT_COOLDOWN_SECONDS,
        }
        return None, login
    if login.status_code not in (200, 201):
        unifi_session_cache.pop(key, None)
        return None, login
    device_token = ""
    if isinstance(login_payload, dict):
        device_token = str(login_payload.get("deviceToken", "") or "").strip()

    unifi_session_cache[key] = {
        "session": session,
        "token": device_token,
        "expires_at": now + UNIFI_SESSION_TTL_SECONDS,
        "blocked_until": 0,
    }
    return session, None


def unifi_request(config, base, url, params=None):
    headers = {"Accept": "application/json"}
    verify = unifi_verify_tls(config)
    mode = unifi_auth_mode(config, base)
    if mode == "local_session":
        session, login = unifi_cached_session(config, base, headers, verify)
        if login is not None:
            return login
        cached = unifi_session_cache.get(unifi_session_key(config, base), {})
        request_headers = dict(headers)
        request_headers.update(unifi_token_headers(cached.get("token")))
        result = session.get(url, params=params, headers=request_headers, timeout=12, verify=verify)
        if result.status_code == 401:
            unifi_session_cache.pop(unifi_session_key(config, base), None)
            session, login = unifi_cached_session(config, base, headers, verify)
            if login is not None:
                return login
            cached = unifi_session_cache.get(unifi_session_key(config, base), {})
            request_headers = dict(headers)
            request_headers.update(unifi_token_headers(cached.get("token")))
            return session.get(url, params=params, headers=request_headers, timeout=12, verify=verify)
        if result.status_code == 429:
            cached = unifi_session_cache.get(unifi_session_key(config, base))
            if cached:
                cached["blocked_until"] = time.monotonic() + UNIFI_RATE_LIMIT_COOLDOWN_SECONDS
        return result
    raise RuntimeError("Enter a local UniFi username and password first.")


def unifi_json_response(result):
    content_type = str(result.headers.get("Content-Type", "") or "").lower()
    try:
        return result.json(), ""
    except ValueError:
        detail = "UniFi returned an empty response." if not result.text.strip() else "UniFi returned a non-JSON response."
        if "application/json" not in content_type:
            detail += " Check that this console supports the Network API connector (UniFi OS firmware 5.0.3 or newer)."
        return None, detail


def unifi_site_id(site):
    if not isinstance(site, dict):
        return ""
    for key in ("id", "siteId", "site_id", "networkId", "network_id", "_id"):
        value = str(site.get(key, "") or "").strip()
        if value:
            return value
    return ""


def unifi_site_matches(site, selected):
    selected = str(selected or "").strip().lower()
    if not selected:
        return False
    values = [
        unifi_site_id(site),
        unifi_site_name(site),
        str(site.get("desc", "") or "").strip(),
        str(site.get("description", "") or "").strip(),
        str(site.get("displayName", "") or "").strip(),
    ]
    return any(str(value).strip().lower() == selected for value in values if str(value).strip())


def unifi_site_label(site, index):
    if not isinstance(site, dict):
        return f"Site {index}"
    name = str(site.get("name") or site.get("description") or site.get("displayName") or "").strip()
    site_id = unifi_site_id(site)
    label = name or f"Site {index}"
    if site_id:
        label += f" = {site_id}"
    return label


def find_unifi_site(config):
    bases = unifi_connector_bases(config)
    if not bases:
        return False, "Enter the Connector URL first."
    try:
        failure = ""
        for base in bases:
            sites = []
            result = unifi_request(config, base, unifi_site_endpoint(base), params={"offset": 0, "limit": 100})
            if result.status_code == 200:
                payload, response_error = unifi_json_response(result)
                if response_error:
                    failure = response_error
                    continue
                sites = payload.get("data", []) if isinstance(payload, dict) else []
            else:
                legacy_result = unifi_request(config, base, unifi_legacy_site_endpoint(base))
                if legacy_result.status_code != 200:
                    failure = f"UniFi API returned HTTP {legacy_result.status_code}. Check the gateway URL, username, password, and selected site permissions."
                    continue
                payload, response_error = unifi_json_response(legacy_result)
                if response_error:
                    failure = response_error
                    continue
                sites = payload.get("data", []) if isinstance(payload, dict) else []
            if not sites:
                return False, "UniFi connected, but it returned no Network sites."
            preferred = next(
                (site for site in sites if unifi_site_name(site).lower() == "default"),
                sites[0] if len(sites) == 1 else None,
            )
            if not preferred or not unifi_site_id(preferred):
                labels = ", ".join(unifi_site_label(site, index) for index, site in enumerate(sites, start=1))
                return False, f"Multiple UniFi sites found: {labels}. Copy the correct ID into UniFi Site ID and click Save and Test UniFi."
            changed_url = base != str(config.get("unifi_connector_url", "") or "").strip().rstrip("/")
            config["unifi_connector_url"] = base
            config["unifi_site_id"] = unifi_site_id(preferred)
            adjusted = " Connector URL corrected automatically." if changed_url else ""
            site_name = str(preferred.get("name") or preferred.get("description") or preferred.get("displayName") or "selected site").strip()
            return True, f"Found UniFi site: {site_name}. Site ID saved.{adjusted}"
        return False, failure or "UniFi site lookup did not return a usable response."
    except Exception as error:
        print(f"UniFi site lookup failed: {error}")
        return False, operation_failed_message("UniFi site lookup")


def check_unifi_connection(config):
    if not config.get("unifi_enabled"):
        return False, "UniFi integration is disabled."
    bases = unifi_connector_bases(config)
    if not bases or not config.get("unifi_site_id"):
        return False, "Enter the Connector URL and site ID first."
    try:
        failure = ""
        for base in bases:
            result = unifi_request(config, base, unifi_client_endpoint(config, base))
            if result.status_code != 200:
                legacy_sites = unifi_request(config, base, unifi_legacy_site_endpoint(base))
                if legacy_sites.status_code != 200:
                    failure = f"UniFi API returned HTTP {result.status_code}."
                    continue
                payload, response_error = unifi_json_response(legacy_sites)
                if response_error:
                    failure = response_error
                    continue
                sites = payload.get("data", []) if isinstance(payload, dict) else []
                selected_site = next((site for site in sites if unifi_site_matches(site, config.get("unifi_site_id"))), None)
                if not selected_site:
                    failure = "UniFi connected, but could not match the selected site for the legacy Network API."
                    continue
                legacy_result = unifi_request(config, base, unifi_legacy_client_endpoint(unifi_site_name(selected_site), base))
                if legacy_result.status_code != 200:
                    failure = f"UniFi API returned HTTP {legacy_result.status_code}."
                    continue
                payload, response_error = unifi_json_response(legacy_result)
                if response_error:
                    failure = response_error
                    continue
                clients = payload.get("data", []) if isinstance(payload, dict) else []
                named = sum(1 for client in clients if str(client.get("name") or client.get("hostname") or "").strip())
                checked = len(clients)
                return True, f"Connected. UniFi legacy API reports {checked} connected client(s); {named} have a UniFi name."
            payload, response_error = unifi_json_response(result)
            if response_error:
                failure = response_error
                continue
            count = payload.get("totalCount", payload.get("count", 0)) if isinstance(payload, dict) else 0
            clients = payload.get("data", []) if isinstance(payload, dict) else []
            named = sum(1 for client in clients if str(client.get("name", "") or "").strip())
            checked = len(clients)
            return True, f"Connected. UniFi reports {int(count or 0)} connected client(s); {named} of {checked} sampled client(s) have a UniFi name."
        return False, failure or "UniFi connection did not return a usable response."
    except Exception as error:
        print(f"UniFi connection failed: {error}")
        return False, operation_failed_message("UniFi connection")





@app.route("/api/monitor-alert", methods=["POST"])
def api_monitor_alert():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    state = str(payload.get("state", "TRIGGERED") or "TRIGGERED").upper()
    name = str(payload.get("name", "Monitor") or "Monitor").strip()
    url = str(payload.get("url", "") or "").strip()
    event_state = "up" if state == "RESOLVED" else "down"
    record_monitor_event(name, url, event_state)

    if state == "RESOLVED":
        text = f"NetSpecter Monitor\n{name} is back online."
    else:
        text = f"NetSpecter Monitor\n{name} is offline."
    if url:
        text += f"\nURL: {url}"

    ok, detail = send_telegram_message(cfg(), text)
    if not ok:
        print(f"Telegram alert failed: {detail}")
    return jsonify({"ok": ok, "detail": "Telegram alert sent." if ok else operation_failed_message("Telegram alert")}), (200 if ok else 500)


def settings_menu(active):
    items = [
        ("Settings", "/settings", "fa-gear"),
        ("Health", "/health", "fa-heart-pulse"),
        ("Backups", "/vault", "fa-box-archive"),
        ("Logs", "/system", "fa-clipboard-list"),
    ]
    links = ""
    for label, url, icon in items:
        cls = "active" if label == active else ""
        links += f'<a class="{cls}" href="{url}"><i class="fa-solid {icon}"></i>{label}</a>'
    return f'<div class="settings-menu">{links}</div>'


def service_card(name, url, icon, color="green"):
    if url:
        return f"""
<a class="card" href="{h(url)}" target="_blank">
  <div class="label">{h(name)}</div>
  <span class="big {color}">Open</span>
  <small>{h(url)}</small>
</a>
"""
    return f"""
<div class="card">
  <div class="label">{h(name)}</div>
  <span class="big yellow">Setup</span>
  <small>Use this page to configure it</small>
</div>
"""


def auto_refresh_script(seconds=60):
    delay_ms = max(10, int(seconds)) * 1000
    return f"""
<script>
(function() {{
  const delayMs = {delay_ms};
  let formDirty = false;
  document.querySelectorAll('input, select, textarea').forEach((field) => {{
    field.addEventListener('input', () => formDirty = true);
    field.addEventListener('change', () => formDirty = true);
  }});
  function canRefresh() {{
    const active = document.activeElement;
    const tag = active && active.tagName ? active.tagName.toLowerCase() : "";
    return !formDirty && !["input", "select", "textarea", "button"].includes(tag);
  }}
  setInterval(() => {{
    if (canRefresh()) {{
      window.location.reload();
    }}
  }}, delayMs);
}})();
</script>
"""


def save_url_setting(key, field_name=None):
    c = cfg()
    c[key] = request.form.get(field_name or key, "").strip()
    save_cfg(c)
    restart_collector_service()
    return c


@app.route("/unifi", methods=["GET", "POST"])
def unifi_page():
    if request.method == "GET":
        return redirect("/settings?section=unifi")
    c = cfg()
    notice = ""
    notice_class = "setup-ok"
    if request.method == "POST":
        c["unifi_enabled"] = request.form.get("unifi_enabled") == "1"
        c["unifi_connector_url"] = request.form.get("unifi_connector_url", "").strip()
        c["unifi_site_id"] = request.form.get("unifi_site_id", "").strip()
        c["unifi_skip_tls_verify"] = request.form.get("unifi_skip_tls_verify") == "1"
        username = request.form.get("unifi_username", "").strip()
        if username:
            c["unifi_username"] = username
        if request.form.get("clear_unifi_username") == "1":
            c["unifi_username"] = ""
        password = request.form.get("unifi_password", "")
        if password:
            c["unifi_password"] = password
        if request.form.get("clear_unifi_password") == "1":
            c["unifi_password"] = ""
        save_cfg(c)
        restart_collector_service()
        action = request.form.get("action")
        if action == "find_unifi_site":
            ok, notice = find_unifi_site(c)
            if ok:
                save_cfg(c)
                restart_collector_service()
            notice_class = "setup-ok" if ok else "setup-warning"
        elif action == "test_unifi":
            ok, notice = check_unifi_connection(c)
            notice_class = "setup-ok" if ok else "setup-warning"
        else:
            notice = "UniFi options saved. The collector has restarted."
    params = {"section": "unifi", "saved": "1", "notice": notice[:220] if notice else ""}
    if notice_class == "setup-warning":
        params["notice_class"] = "warning"
    return local_redirect(f"/settings?section={quote(params['section'])}&saved={quote(params['saved'])}&notice={quote(params['notice'])}&notice_class={quote(params.get('notice_class', ''))}")


@app.route("/gatus", methods=["GET", "POST"])
def gatus_page():
    return redirect("/monitor")


def quality_value(value, suffix=""):
    if value is None:
        return "-"
    try:
        return f"{float(value):.2f}{suffix}"
    except Exception:
        return "-"


def quality_range_hours():
    value = request.args.get("quality_range", "24h")
    return {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}.get(value, 24)


def quality_range_key():
    hours = quality_range_hours()
    return "30d" if hours == 24 * 30 else "7d" if hours == 24 * 7 else "24h"


def quality_range_picker():
    current = quality_range_key()
    links = ""
    for key, label in (("24h", "24 Hours"), ("7d", "7 Days"), ("30d", "30 Days")):
        cls = "active" if key == current else ""
        links += f'<a class="{cls}" href="/monitor?quality_range={key}#internetQuality">{label}</a>'
    return f'<div class="time-picker">{links}</div>'


def latest_speedtest_rows(limit=5):
    return query(
        """
        SELECT ts, source, latency_ms, download_mbps, upload_mbps, success
        FROM speed_tests
        ORDER BY ts DESC
        LIMIT ?
        """,
        (limit,),
    )


@app.route("/monitor", methods=["GET", "POST"])
def monitor_page():
    c = cfg()
    monitors = normalise_gatus_monitors(c)
    monitor_state_map = monitor_latest_states()
    gatus_url = internal_gatus_url(c)
    gatus_live_state_map = gatus_latest_states(gatus_url)
    notice = ""
    notice_class = "setup-ok"
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "refresh_checks":
            refreshed = 0
            for monitor in monitors:
                monitor_ok, _detail = check_monitor_service(monitor, timeout=2.0, brief=True)
                record_monitor_event(monitor.get("name", "Monitor"), monitor.get("url", ""), "up" if monitor_ok else "down")
                refreshed += 1
            monitor_state_map = monitor_latest_states()
            gatus_live_state_map = gatus_latest_states(gatus_url)
            cache_delete_prefix("monitor_gatus_status:")
            notice = f"Refreshed {refreshed} monitor check{'' if refreshed == 1 else 's'}."
            notice_class = "setup-ok"
        remove_index = request.form.get("remove_index")
        if remove_index is not None:
            try:
                index = int(remove_index)
            except Exception:
                index = -1
            if 0 <= index < len(monitors):
                previous_monitors = list(monitors)
                monitors.pop(index)
                c["gatus_monitors"] = monitors
                ok, notice = apply_gatus_monitor_config(c, previous_monitors)
                notice_class = "setup-ok" if ok else "setup-warning"
        elif action in ("add_monitor", "update_monitor"):
            name = request.form.get("name", "").strip()
            monitor_type = request.form.get("monitor_type", "http").strip().lower()
            url = build_monitor_url(monitor_type, request.form.get("monitor_target") or request.form.get("url", ""))
            interval = request.form.get("interval", "60s").strip().lower()
            if name and url:
                dns_query_type = request.form.get("dns_query_type", "A").strip().upper()
                dns_query_name = request.form.get("dns_query_name", "").strip()
                monitor_payload = {
                    "name": name,
                    "url": url,
                    "type": monitor_type if monitor_type in MONITOR_TYPE_INFO else monitor_type_for_url(url),
                    "dns_query_type": dns_query_type if dns_query_type in DNS_QUERY_TYPES else "A",
                    "dns_query_name": dns_query_name,
                    "interval": interval,
                    "email": request.form.get("email") == "1",
                    "telegram": request.form.get("telegram") == "1",
                    "verify_tls": request.form.get("skip_tls_verify") != "1",
                }
                if action == "update_monitor":
                    try:
                        edit_index = int(request.form.get("edit_index", "-1"))
                    except Exception:
                        edit_index = -1
                    if 0 <= edit_index < len(monitors):
                        monitors[edit_index] = monitor_payload
                else:
                    monitors.append(monitor_payload)
                previous_monitors = normalise_gatus_monitors(c)
                c["gatus_monitors"] = normalise_gatus_monitors({"gatus_monitors": monitors})
                ok, notice = apply_gatus_monitor_config(c, previous_monitors)
                notice_class = "setup-ok" if ok else "setup-warning"
            else:
                notice = "Name and URL are required."
                notice_class = "setup-warning"
        elif action == "remove_monitor":
            try:
                index = int(request.form.get("index", "-1"))
            except Exception:
                index = -1
            if 0 <= index < len(monitors):
                previous_monitors = list(monitors)
                monitors.pop(index)
                c["gatus_monitors"] = monitors
                ok, notice = apply_gatus_monitor_config(c, previous_monitors)
                notice_class = "setup-ok" if ok else "setup-warning"
        elif action == "save_monitors":
            updated = []
            for index, monitor in enumerate(monitors):
                monitor["email"] = request.form.get(f"monitor_email_{index}") == "1"
                monitor["telegram"] = request.form.get(f"monitor_telegram_{index}") == "1"
                updated.append(monitor)
            c["gatus_monitors"] = normalise_gatus_monitors({"gatus_monitors": updated})
            ok, notice = apply_gatus_monitor_config(c, monitors)
            notice_class = "setup-ok" if ok else "setup-warning"
        notice_param = quote(notice[:220], safe="")
        return local_redirect(f"/monitor?saved={'1' if notice_class == 'setup-ok' else '0'}&notice={notice_param}")

    if request.args.get("saved") == "1":
        notice = request.args.get("notice") or "Monitor settings saved."
    elif request.args.get("saved") == "0":
        notice = request.args.get("notice") or "Monitor settings could not be applied. Check Gatus service status."
        notice_class = "setup-warning"

    gatus_cache_key = f"monitor_gatus_status:{gatus_url}"
    gatus_cached = cache_get(gatus_cache_key, 60)
    if gatus_cached is None:
        gatus_status_url = f"{gatus_url.rstrip('/')}/api/v1/endpoints/statuses" if gatus_url else ""
        gatus_ok, gatus_detail = check_http_service(gatus_status_url, "Gatus", timeout=0.8, brief=True)
        if not gatus_ok and gatus_live_state_map:
            gatus_ok = True
            gatus_detail = "Gatus API reachable."
        cache_set(gatus_cache_key, {"ok": gatus_ok, "detail": gatus_detail})
    else:
        gatus_ok = bool(gatus_cached.get("ok"))
        gatus_detail = str(gatus_cached.get("detail") or "Gatus status cached.")
    email_ready = bool(c.get("ids_email_enabled") and c.get("smtp_host") and c.get("smtp_to"))
    telegram_ready = bool(c.get("telegram_enabled") and c.get("telegram_bot_token") and c.get("telegram_chat_id"))
    try:
        edit_index = int(request.args.get("edit", "-1"))
    except Exception:
        edit_index = -1
    edit_monitor = monitors[edit_index] if 0 <= edit_index < len(monitors) else {}
    show_monitor_form = bool(edit_monitor) or request.args.get("add") == "1"
    edit_email_checked = " checked" if edit_monitor.get("email") else ""
    edit_telegram_checked = " checked" if edit_monitor.get("telegram") else ""
    edit_skip_tls_checked = " checked" if edit_monitor.get("verify_tls") is False else ""
    edit_button_label = "Save Monitor" if edit_monitor else "Add Monitor"
    edit_action = "update_monitor" if edit_monitor else "add_monitor"
    edit_heading = "Edit Monitor" if edit_monitor else "Add Monitor"
    edit_monitor_type = str(edit_monitor.get("type") or monitor_type_for_url(edit_monitor.get("url", ""))).lower()
    if edit_monitor_type not in MONITOR_TYPE_INFO:
        edit_monitor_type = "http"
    edit_monitor_target = monitor_target_from_url(edit_monitor.get("url", ""))
    edit_dns_query_type = str(edit_monitor.get("dns_query_type") or "A").upper()
    if edit_dns_query_type not in DNS_QUERY_TYPES:
        edit_dns_query_type = "A"
    edit_dns_query_name = str(edit_monitor.get("dns_query_name") or "")
    dns_type_options = ""
    for dns_type in DNS_QUERY_TYPES:
        selected = " selected" if dns_type == edit_dns_query_type else ""
        dns_type_options += f'<option value="{dns_type}"{selected}>{dns_type}</option>'
    monitor_type_options = ""
    for type_key, type_info in MONITOR_TYPE_INFO.items():
        selected = " selected" if type_key == edit_monitor_type else ""
        monitor_type_options += f'<option value="{h(type_key)}"{selected}>{h(type_info["label"])}</option>'
    monitor_type_js = json.dumps(MONITOR_TYPE_INFO)
    monitor_cards = ""
    for index, monitor in enumerate(monitors):
        state_key = monitor_key(monitor.get("name", ""), monitor.get("url", ""))
        live_state_row = gatus_live_state_map.get(f"name:{str(monitor.get('name', '')).strip().lower()}") or {}
        state_row = live_state_row or monitor_state_map.get(state_key) or {}
        current_state = str(state_row.get("state") or "unknown")
        last_ts = state_row.get("ts")
        state_source = str(state_row.get("source") or ("history" if state_row else "none"))
        monitor_ok = current_state == "up"
        source_label = "Gatus live state" if state_source == "gatus" else "NetSpecter recorded history" if state_source == "history" else "No state source"
        monitor_detail = f"{source_label}: {current_state.upper()}" if current_state != "unknown" else "No recorded monitor state yet."
        monitor_state = "healthy" if monitor_ok else "offline"
        event_state = current_state if current_state in ("up", "down") else ("up" if monitor_ok else "down")
        alerts = []
        if monitor.get("email"):
            alerts.append("Email")
        if monitor.get("telegram"):
            alerts.append("Telegram")
        bars = ""
        segments = monitor_history_segments(monitor.get("name", ""), monitor.get("url", ""), event_state)
        uptime = monitor_state_percent(segments, "up")
        for segment_state in segments:
            cls = "down" if segment_state == "down" else "unknown" if segment_state == "unknown" else ""
            label = "Down" if segment_state == "down" else "Unknown" if segment_state == "unknown" else "Up"
            bars += f"<span class='{cls}' title='{label}'></span>"
        response_text = "Stale"
        last_check_text = "Unknown"
        if last_ts:
            check_time = datetime.fromtimestamp(int(last_ts)).strftime("%H:%M:%S")
            response_text = "Live" if state_source == "gatus" else f"Checked {check_time}"
            last_check_text = check_time
        elif monitor_ok:
            response_text = "OK"
            last_check_text = "Now"
        status_label = "Healthy" if monitor_ok else "Offline"
        alerts_text = ", ".join(alerts) if alerts else "No alerts"
        icon_name = monitor_icon_name(monitor)
        safe_url = h(monitor.get("url", ""))
        monitor_cards += f"""
<div class="monitor-card">
  <div class="monitor-card-head">
    <div class="monitor-card-main">
      <span class="monitor-type-icon"><svg class="ui-icon ui-icon--monitor" aria-hidden="true"><use href="/static/icons.svg?v=20260711c#icon-{icon_name}"></use></svg></span>
      <div class="monitor-card-copy">
        <div class="monitor-title">{h(monitor.get('name', ''))}</div>
        <div class="monitor-meta">{h(monitor_type_label(monitor))} - {h(monitor_display_target(monitor))}</div>
      </div>
    </div>
    <div class="monitor-menu-wrap">
      <span class="monitor-status-dot {monitor_state}" title="{status_label}"></span>
      <button type="button" class="monitor-menu-button" aria-haspopup="menu" aria-expanded="false" title="Monitor actions"><svg class="ui-icon ui-icon--button" aria-hidden="true"><use href="/static/icons.svg?v=20260711c#icon-ellipsis"></use></svg></button>
      <div class="monitor-menu" role="menu">
        <a role="menuitem" href="{safe_url}" target="_blank">Open Monitor</a>
        <a role="menuitem" href="/monitor?edit={index}#monitorForm">Edit Monitor</a>
        <a role="menuitem" href="/monitor?edit={index}#monitorForm">Alert Settings</a>
        <a role="menuitem" href="/monitor#monitor-{index}">View History</a>
        <a role="menuitem" href="/system">View Logs</a>
        <button type="button" role="menuitem" disabled>Pause Monitor</button>
        <button class="danger" role="menuitem" name="remove_index" value="{index}">Delete Monitor</button>
      </div>
    </div>
  </div>
  <div class="monitor-stats">
    <div><span>Uptime</span><b class="{monitor_state}">{uptime}%</b></div>
    <div><span>Response</span><b>{h(response_text)}</b></div>
    <div><span>Last Check</span><b>{h(last_check_text)}</b></div>
  </div>
  <div class="monitor-bars" aria-label="8 hour monitor history">{bars}</div>
  <div class="monitor-foot">
    <span>{h(monitor.get('interval', '60s'))} interval</span>
    <span title="{h(monitor_detail)}">{h(alerts_text)}</span>
  </div>
</div>
"""
    email_disabled = "" if email_ready else " disabled"
    telegram_disabled = "" if telegram_ready else " disabled"
    notice_block = f'<div class="{notice_class}">{h(notice)}</div>' if notice else ""
    body = f"""
{topbar('Monitor')}
{notice_block}
<div class="grid">
  <div class="card"><div class="label">Monitor Engine</div><span class="big {'green' if gatus_ok else 'yellow'}">{'OK' if gatus_ok else 'Check'}</span><br><small>{h(gatus_detail)}</small></div>
  <div class="card"><div class="label">Targets</div><span class="big blue">{len(monitors)}</span><small>Gatus checks managed by NetSpecter</small></div>
  <div class="card"><div class="label">Email Warnings</div><span class="big {'green' if email_ready else 'yellow'}">{'Ready' if email_ready else 'Off'}</span><small>Uses IDS email settings</small></div>
  <div class="card"><div class="label">Telegram Warnings</div><span class="big {'green' if telegram_ready else 'yellow'}">{'Ready' if telegram_ready else 'Off'}</span><small>Uses Telegram service settings</small></div>
</div>
<div class="panel" style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap">
  <div>
    <h2>Monitor Status</h2>
    <p class="sub">The page uses live Gatus state when available, with recorded history as fallback. Use Check Now to run live checks on demand.</p>
  </div>
  <form method="post" style="margin:0">
    {csrf_input()}
    <button type="submit" name="action" value="refresh_checks">Check Now</button>
  </form>
</div>
<div class="panel">
  <h2>Monitored Services</h2>
  <form method="post">
    {csrf_input()}
    <div class="monitor-grid">
      {monitor_cards or '<p class="sub">No monitor targets configured.</p>'}
    </div>
    <a class="btn" href="/monitor?add=1#monitorForm">Add Monitor</a>
  </form>
</div>
{f'''
<div class="panel settings" id="monitorForm">
  <h2>{edit_heading}</h2>
  <form method="post">
    {csrf_input()}
    <input type="hidden" name="edit_index" value="{edit_index}">
    <label>Name</label>
    <input name="name" value="{h(edit_monitor.get('name', ''))}" placeholder="Website, router, NVR, VPN">
    <label>Monitor Type</label>
    <select name="monitor_type" id="monitorType">
      {monitor_type_options}
    </select>
    <small id="monitorTypeHelp">{h(MONITOR_TYPE_INFO[edit_monitor_type]["help"])}</small>
    <label>Target</label>
    <input name="monitor_target" id="monitorTarget" value="{h(edit_monitor_target)}" placeholder="{h(MONITOR_TYPE_INFO[edit_monitor_type]["placeholder"])}">
    <div id="dnsOptions" style="display:none">
      <label>DNS Query Name</label>
      <input name="dns_query_name" value="{h(edit_dns_query_name)}" placeholder="example.com">
      <label>DNS Record Type</label>
      <select name="dns_query_type">
        {dns_type_options}
      </select>
    </div>
    <label>Check Interval</label>
    <select name="interval">
      <option value="30s"{" selected" if edit_monitor.get('interval') == '30s' else ""}>30 seconds</option>
      <option value="60s"{" selected" if edit_monitor.get('interval', '60s') == '60s' else ""}>60 seconds</option>
      <option value="5m"{" selected" if edit_monitor.get('interval') == '5m' else ""}>5 minutes</option>
      <option value="15m"{" selected" if edit_monitor.get('interval') == '15m' else ""}>15 minutes</option>
    </select>
    <label><input type="checkbox" name="email" value="1" style="width:auto"{email_disabled}{edit_email_checked}> Email warning</label>
    <label><input type="checkbox" name="telegram" value="1" style="width:auto"{telegram_disabled}{edit_telegram_checked}> Telegram warning</label>
    <label><input type="checkbox" name="skip_tls_verify" value="1" style="width:auto"{edit_skip_tls_checked}> Allow self-signed HTTPS certificate</label>
    <small>Email uses IDS email settings. Telegram uses Services > Telegram.</small>
    <button type="submit" name="action" value="{edit_action}">{edit_button_label}</button>
    {('<a class="btn" href="/monitor">Cancel Edit</a>' if edit_monitor else '')}
  </form>
</div>
<script>
const monitorTypeInfo = {monitor_type_js};
const monitorType = document.getElementById('monitorType');
const monitorTarget = document.getElementById('monitorTarget');
const monitorTypeHelp = document.getElementById('monitorTypeHelp');
function updateMonitorTypeFields() {{
  const info = monitorTypeInfo[monitorType.value] || monitorTypeInfo.http;
  monitorTarget.placeholder = info.placeholder;
  monitorTypeHelp.textContent = info.help;
  const dnsOptions = document.getElementById('dnsOptions');
  if (dnsOptions) {{
    dnsOptions.style.display = monitorType.value === 'dns' ? 'block' : 'none';
  }}
}}
if (monitorType && monitorTarget && monitorTypeHelp) {{
  monitorType.addEventListener('change', updateMonitorTypeFields);
  updateMonitorTypeFields();
}}
</script>
''' if show_monitor_form else ''}
<script>
document.querySelectorAll('.monitor-menu-button').forEach((button) => {{
  button.addEventListener('click', (event) => {{
    event.preventDefault();
    event.stopPropagation();
    const wrap = button.closest('.monitor-menu-wrap');
    const isOpen = wrap.classList.contains('open');
    document.querySelectorAll('.monitor-menu-wrap.open').forEach((item) => {{
      item.classList.remove('open');
      const trigger = item.querySelector('.monitor-menu-button');
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
    }});
    if (!isOpen) {{
      wrap.classList.add('open');
      button.setAttribute('aria-expanded', 'true');
    }}
  }});
}});
document.addEventListener('click', () => {{
  document.querySelectorAll('.monitor-menu-wrap.open').forEach((item) => {{
    item.classList.remove('open');
    const trigger = item.querySelector('.monitor-menu-button');
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
  }});
}});
document.addEventListener('keydown', (event) => {{
  if (event.key === 'Escape') {{
    document.querySelectorAll('.monitor-menu-wrap.open').forEach((item) => {{
      item.classList.remove('open');
      const trigger = item.querySelector('.monitor-menu-button');
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
    }});
  }}
}});
</script>
{'' if show_monitor_form else auto_refresh_script(60)}
"""
    return shell("Monitor", body, "Monitor")


@app.route("/beszel", methods=["GET", "POST"])
def beszel_page():
    return redirect("/health")


@app.route("/telegram", methods=["GET", "POST"])
def telegram_page():
    if request.method == "GET":
        return redirect("/settings?section=telegram")
    c = cfg()
    notice = ""
    notice_class = "setup-ok"
    if request.method == "POST":
        c["telegram_enabled"] = request.form.get("telegram_enabled") == "1"
        c["telegram_chat_id"] = request.form.get("telegram_chat_id", "").strip()
        telegram_token = request.form.get("telegram_bot_token", "")
        if telegram_token:
            c["telegram_bot_token"] = telegram_token
        if request.form.get("clear_telegram_bot_token") == "1":
            c["telegram_bot_token"] = ""
        save_cfg(c)
        restart_collector_service()
        if request.form.get("action") == "test_telegram":
            ok, notice = send_telegram_message(c, "NetSpecter Telegram integration test.")
            if not ok:
                print(f"Telegram test failed: {notice}")
                notice = operation_failed_message("Telegram test")
            notice_class = "setup-ok" if ok else "setup-warning"
        else:
            notice = "Telegram options saved."
    params = {"section": "telegram", "saved": "1", "notice": notice[:220] if notice else ""}
    if notice_class == "setup-warning":
        params["notice_class"] = "warning"
    return local_redirect(f"/settings?section={quote(params['section'])}&saved={quote(params['saved'])}&notice={quote(params['notice'])}&notice_class={quote(params.get('notice_class', ''))}")


@app.route("/integrations", methods=["GET", "POST"])
def integrations():
    return redirect("/unifi")


@app.route("/settings", methods=["GET", "POST"])
def settings():
    c = cfg()
    inferred_appliance_ip = appliance_ip_from_host(request.host)
    if inferred_appliance_ip and not str(c.get("appliance_ip") or "").strip():
        c["appliance_ip"] = inferred_appliance_ip
    section = request.values.get("section", "network").strip().lower()
    valid_sections = {"network", "adguard", "unifi", "telegram", "telemetry", "speed", "applications", "lcd", "web"}
    if section not in valid_sections:
        section = "network"
    section_keys = {
        "network": [
            "appliance_ip", "gateway_ip", "ignore_ips", "lan_prefix", "packet_iface",
            "collect_interval_seconds", "traffic_retention_days", "dns_retention_days", "fast_page_mode",
        ],
        "adguard": ["adguard_url", "adguard_user", "adguard_pass", "adguard_querylog_interval_seconds"],
        "telemetry": [
            "snmp_enabled", "snmp_targets", "snmp_version", "snmp_port", "snmp_community", "snmp_poll_seconds",
            "mqtt_enabled", "mqtt_host", "mqtt_port", "mqtt_tls", "mqtt_username", "mqtt_password",
            "mqtt_client_id", "mqtt_subscribe_topics",
        ],
        "web": ["web_host", "web_port", "auth_enabled", "admin_user"],
    }
    hidden_settings = {"app_name", "tagline", "admin_password_hash"} | INTEGRATION_SETTINGS_KEYS
    editable_keys = [key for key in c.keys() if key not in hidden_settings]

    if request.method == "POST" and section == "lcd":
        action = request.form.get("action", "add")
        displays = [dict(item) for item in lcd_display_list(c) if isinstance(item, dict)]
        now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        notice_text = "LCD display settings saved."
        notice_class = "ok"

        def issue_display_token(display):
            token = "ns_lcd_" + secrets.token_urlsafe(32)
            display["token_hash"] = lcd_token_hash(token)
            display["token_suffix"] = token[-6:]
            display.pop("token_preview", None)
            display["revoked_at"] = ""
            display["updated_at"] = now
            session["lcd_new_token"] = token
            session["lcd_new_token_display_id"] = display.get("id")
            return token

        if action == "add":
            name = request.form.get("display_name", "").strip()
            if not name:
                notice_text = "Give the LCD display a friendly name first."
                notice_class = "warning"
            else:
                display = {
                    "id": secrets.token_urlsafe(10),
                    "name": name[:80],
                    "created_at": now,
                    "updated_at": now,
                    "revoked_at": "",
                }
                issue_display_token(display)
                displays.append(display)
                notice_text = f"LCD display '{name[:80]}' added. Copy the token now."
        else:
            display_id = request.form.get("display_id", "").strip()
            target = next((item for item in displays if str(item.get("id") or "") == display_id), None)
            if not target:
                notice_text = "LCD display not found."
                notice_class = "warning"
            elif action == "regenerate":
                issue_display_token(target)
                notice_text = f"Token regenerated for {target.get('name') or 'LCD display'}. Copy the new token now."
            elif action == "revoke":
                target["revoked_at"] = now
                target["updated_at"] = now
                LCD_LAST_SEEN.pop(str(target.get("id") or ""), None)
                notice_text = f"Token revoked for {target.get('name') or 'LCD display'}."
            elif action == "remove":
                displays = [item for item in displays if str(item.get("id") or "") != display_id]
                LCD_LAST_SEEN.pop(display_id, None)
                notice_text = f"LCD display {target.get('name') or 'LCD display'} removed."
            elif action == "rename":
                name = request.form.get("display_name", "").strip()
                if name:
                    target["name"] = name[:80]
                    target["updated_at"] = now
                    notice_text = "LCD display renamed."

        c["lcd_displays"] = displays
        save_cfg(c)
        return local_redirect(f"/settings?section=lcd&saved=1&notice={quote(notice_text)}&notice_class={notice_class}")

    if request.method == "POST" and section == "applications":
        action = request.form.get("action", "save")
        c["microsoft365_endpoint_import_enabled"] = True
        c["microsoft365_endpoint_instance"] = str(c.get("microsoft365_endpoint_instance") or "worldwide").strip().lower() or "worldwide"
        try:
            c["microsoft365_endpoint_cache_hours"] = max(1, int(c.get("microsoft365_endpoint_cache_hours", 168) or 168))
        except Exception:
            c["microsoft365_endpoint_cache_hours"] = 168
        applications = request.form.getlist("mapping_application")
        categories_selected = request.form.getlist("mapping_category")
        ips = request.form.getlist("mapping_ip")
        domain_applications = request.form.getlist("domain_mapping_application")
        domain_categories = request.form.getlist("domain_mapping_category")
        domains = request.form.getlist("mapping_domain")
        mappings = []
        domain_mappings = []
        seen = set()
        seen_domains = set()
        valid_category_names = {row["name"] for row in application_categories()}
        for app_name, category_name, ip in zip(applications, categories_selected, ips):
            app_name = str(app_name or "").strip()
            category_name = str(category_name or "").strip()
            ip = str(ip or "").strip()
            if not app_name and not category_name and not ip:
                continue
            if not app_name or not category_name or not valid_ipv4_ip(ip):
                continue
            if category_name not in valid_category_names:
                continue
            key = (app_name.lower(), ip)
            if key in seen:
                continue
            seen.add(key)
            mappings.append({"application": app_name, "category": category_name, "ip": ip})
        for app_name, category_name, domain in zip(domain_applications, domain_categories, domains):
            app_name = str(app_name or "").strip()
            category_name = str(category_name or "").strip()
            domain = str(domain or "").strip().lower().rstrip(".")
            if not app_name and not category_name and not domain:
                continue
            if not app_name or not category_name or not valid_domain_pattern(domain):
                continue
            if category_name not in valid_category_names:
                continue
            key = (app_name.lower(), category_name.lower(), domain)
            if key in seen_domains:
                continue
            seen_domains.add(key)
            domain_mappings.append({"application": app_name, "category": category_name, "domain": domain})
        c["site_application_mappings"] = mappings
        c["site_domain_mappings"] = domain_mappings
        c["app_name"] = "NetSpecter"
        c["tagline"] = "Monitor | Filter | Protect"
        notice_text = "Application mappings saved."
        notice_class = "ok"
        save_cfg(c)
        restart_collector_service()
        return local_redirect(f"/settings?section=applications&saved=1&collector=restarted&notice={quote(notice_text)}&notice_class={notice_class}")

    if request.method == "POST" and section in section_keys:
        post_keys = set(section_keys[section])
        for key in editable_keys:
            if key not in post_keys:
                continue
            if isinstance(c[key], bool):
                c[key] = request.form.get(key) == "1"
                continue
            if key in request.form:
                val = request.form.get(key)
                if key in SENSITIVE_CONFIG_KEYS and val == "":
                    continue
                if isinstance(c[key], bool):
                    val = str(val).strip().lower() in ["1", "true", "yes", "on"]
                elif isinstance(c[key], int):
                    try:
                        val = int(val)
                    except Exception:
                        pass
                elif isinstance(c[key], list):
                    val = cfg_list(val)
                c[key] = val

        if section == "network":
            inherited_gateway = str(c.get("gateway_ip") or "").strip() or default_gateway_from_prefix(c.get("lan_prefix"))
            if inherited_gateway:
                c["ignore_ips"] = [ip for ip in cfg_list(c.get("ignore_ips", [])) if ip != inherited_gateway]

        new_password = request.form.get("admin_new_password", "")
        confirm_password = request.form.get("admin_confirm_password", "")
        if section == "web" and new_password:
            if len(new_password) >= 8 and new_password == confirm_password:
                c["admin_password_hash"] = generate_password_hash(new_password)

        notice_text = ""
        notice_class = "ok"
        if section == "network" and request.form.get("sync_appliance_urls") == "1":
            if apply_appliance_ip_urls(c, c.get("appliance_ip")):
                notice_text = "Network settings saved. Service URLs were updated from the appliance IP."
            else:
                notice_text = "Network settings saved, but service URLs were not updated because the appliance IP is invalid."
                notice_class = "warning"

        c["app_name"] = "NetSpecter"
        c["tagline"] = "Monitor | Filter | Protect"

        save_cfg(c)
        restart_collector_service()
        notice_suffix = f"&notice={quote(notice_text)}&notice_class={notice_class}" if notice_text else ""
        return local_redirect(f"/settings?section={section}&saved=1&collector=restarted{notice_suffix}")

    setting_help = {
        "appliance_ip": "Main IP address of this NetSpecter appliance. Use the sync option to update NetSpecter, AdGuard, Gatus and Beszel URLs from this one IP.",
        "gateway_ip": "Router/gateway IP. Leave blank to use LAN Prefix + 1. NetSpecter excludes it from device usage totals and live collector stats.",
        "ignore_ips": "Extra IPs to ignore, separated by commas. The gateway IP is always ignored automatically.",
        "packet_iface": "Bridge carrying monitored traffic, usually br0. Linux nftables counts forwarded bytes on this bridge.",
        "lan_prefix": "LAN prefix used to identify local devices, for example 192.168.1.",
        "adguard_url": "AdGuard Home URL used for DNS stats and controls.",
        "collect_interval_seconds": "Seconds between measured traffic interval writes. Live speed freshness follows this value.",
        "traffic_retention_days": "Number of calendar days of measured traffic history to keep. Use 90 for the 90-day view.",
        "dns_retention_days": "Number of calendar days of imported DNS/application activity to keep. Use 90 for the 90-day view.",
        "fast_page_mode": "Speeds up navigation by disabling dashboard background refresh and loading the traffic graph only when requested.",
        "snmp_enabled": "Enable NetSpecter to poll existing SNMP devices such as switches, routers, APs, UPS units and printers.",
        "snmp_targets": "Comma-separated IPs or hostnames to poll with SNMP, for example gateway, switches and APs.",
        "snmp_version": "SNMP version to use for polling. The first collector pass supports v2c targets.",
        "snmp_port": "SNMP UDP port, usually 161.",
        "snmp_community": "SNMP v2c community string. Stored encrypted in the local NetSpecter config.",
        "snmp_poll_seconds": "Seconds between SNMP polling runs.",
        "mqtt_enabled": "Enable NetSpecter to subscribe to an existing MQTT broker and pull telemetry messages.",
        "mqtt_host": "MQTT broker host or IP address.",
        "mqtt_port": "MQTT broker port, usually 1883 or 8883 for TLS.",
        "mqtt_tls": "Use TLS when connecting to the MQTT broker.",
        "mqtt_username": "MQTT username, if your broker requires authentication.",
        "mqtt_password": "MQTT password. Stored encrypted in the local NetSpecter config.",
        "mqtt_client_id": "Client ID NetSpecter should use when subscribing to MQTT.",
        "mqtt_subscribe_topics": "Comma-separated MQTT topics to subscribe to, for example sensors/#, home/+/status.",
        "auth_enabled": "Enable or disable the NetSpecter login screen.",
        "admin_user": "Username used to sign in to NetSpecter.",
    }
    setting_labels = {
        "appliance_ip": "Appliance IP",
        "gateway_ip": "Gateway IP",
        "ignore_ips": "Extra Ignored IPs",
        "packet_iface": "Monitored Bridge Interface",
        "lan_prefix": "LAN Prefix",
        "adguard_url": "AdGuard URL",
        "adguard_user": "AdGuard User",
        "adguard_pass": "AdGuard Password",
        "collect_interval_seconds": "Traffic Sample Interval Seconds",
        "traffic_retention_days": "Traffic Retention Days",
        "dns_retention_days": "DNS/App Retention Days",
        "fast_page_mode": "Fast Page Mode",
        "snmp_enabled": "SNMP Enabled",
        "snmp_targets": "SNMP Targets",
        "snmp_version": "SNMP Version",
        "snmp_port": "SNMP Port",
        "snmp_community": "SNMP Community",
        "snmp_poll_seconds": "SNMP Poll Seconds",
        "mqtt_enabled": "MQTT Enabled",
        "mqtt_host": "MQTT Broker Host",
        "mqtt_port": "MQTT Broker Port",
        "mqtt_tls": "MQTT TLS Enabled",
        "mqtt_username": "MQTT Username",
        "mqtt_password": "MQTT Password",
        "mqtt_client_id": "MQTT Client ID",
        "mqtt_subscribe_topics": "MQTT Subscribe Topics",
        "web_host": "Web Host",
        "web_port": "Web Port",
        "auth_enabled": "Login Enabled",
        "admin_user": "Admin Username",
    }
    section_tabs = [
        ("network", "Network", "fa-network-wired"),
        ("adguard", "AdGuard", "fa-shield-halved"),
        ("unifi", "UniFi", "fa-wifi"),
        ("telegram", "Telegram", "fa-paper-plane"),
        ("telemetry", "Telemetry", "fa-satellite-dish"),
        ("speed", "Speed Tests", "fa-gauge-high"),
        ("applications", "App Mapping", "fa-layer-group"),
        ("lcd", "LCD Displays", "fa-display"),
        ("web", "Web / Login", "fa-window-maximize"),
    ]
    settings_section_menu = ""
    for key, label, icon in section_tabs:
        cls = "active" if key == section else ""
        settings_section_menu += f'<a class="{cls}" href="/settings?section={key}"><i class="fa-solid {icon}"></i>{label}</a>'
    settings_section_menu = f'<div class="settings-category-menu" aria-label="Settings categories">{settings_section_menu}</div>'
    section_title = next(label for key, label, _ in section_tabs if key == section)

    if section == "lcd":
        endpoint_url = lcd_display_endpoint_url(c)
        new_token = session.pop("lcd_new_token", "")
        new_token_display_id = session.pop("lcd_new_token_display_id", "")
        notice_text = request.args.get("notice") or ("LCD display settings saved." if request.args.get("saved") == "1" else "")
        notice_class = "setup-warning" if request.args.get("notice_class") == "warning" else "setup-ok"
        notice = f'<div class="{notice_class}">{h(notice_text)}</div>' if notice_text else ""
        active_displays = [item for item in lcd_display_list(c) if isinstance(item, dict) and not item.get("revoked_at")]
        revoked_displays = [item for item in lcd_display_list(c) if isinstance(item, dict) and item.get("revoked_at")]

        def status_badge(status):
            cls = "green" if status == "online" else "yellow" if status == "never" else "red"
            label = "Seen recently" if status == "online" else "Not seen yet" if status == "never" else "Stale"
            return f'<span class="{cls}">{label}</span>'

        def display_row(display):
            display_id = str(display.get("id") or "")
            state = lcd_seen_state(display_id)
            token_value = new_token if new_token and new_token_display_id == display_id else ""
            token_box = ""
            if token_value:
                token_box = f"""
      <div class="setup-ok">
        <strong>New display token</strong>
        <div class="ns-lcd-copy-row"><input readonly value="{h(token_value)}" data-copy-field><button class="ns-compact-button" type="button" data-copy-nearest>Copy token</button></div>
        <small>This is the only time NetSpecter shows the full token. Regenerate it if you need a fresh copy later.</small>
      </div>
"""
            return f"""
  <tr>
    <td>
      <form method="post" class="ns-lcd-inline-form">
        {csrf_input()}
        <input type="hidden" name="section" value="lcd">
        <input type="hidden" name="display_id" value="{h(display_id)}">
        <input name="display_name" value="{h(display.get('name') or 'LCD Display')}" maxlength="80">
        <button class="ns-compact-button" name="action" value="rename">Save</button>
      </form>
      {token_box}
    </td>
    <td><code>{h('...' + lcd_display_token_suffix(display) if lcd_display_token_suffix(display) else 'token saved')}</code></td>
    <td>{status_badge(state['status'])}</td>
    <td>{h(state.get('last_seen') or '-')}</td>
    <td>{h(state.get('last_ip') or '-')}</td>
    <td>
      <form method="post" class="ns-lcd-actions">
        {csrf_input()}
        <input type="hidden" name="section" value="lcd">
        <input type="hidden" name="display_id" value="{h(display_id)}">
        <button class="ns-compact-button" name="action" value="regenerate">Regenerate token</button>
        <button class="ns-compact-button ns-compact-button--danger" name="action" value="revoke" onclick="return confirm('Revoke this LCD display token?')">Revoke</button>
        <button class="ns-compact-button ns-compact-button--danger" name="action" value="remove" onclick="return confirm('Remove this LCD display?')">Remove</button>
      </form>
    </td>
  </tr>
"""

        rows = "".join(display_row(display) for display in active_displays)
        if not rows:
            rows = '<tr><td colspan="6">No LCD displays have been added yet.</td></tr>'
        revoked_rows = "".join(
            f"<tr><td>{h(display.get('name') or 'LCD Display')}</td><td><code>{h('...' + lcd_display_token_suffix(display) if lcd_display_token_suffix(display) else '-')}</code></td><td colspan='3'>Revoked {h(display.get('revoked_at') or '')}</td></tr>"
            for display in revoked_displays[-5:]
        )
        revoked_table = f"""
<div class="panel settings settings-card ns-lcd-settings">
  <h2>Revoked Displays</h2>
  <table class="table compact">
    <thead><tr><th>Name</th><th>Token</th><th>Status</th></tr></thead>
    <tbody>{revoked_rows}</tbody>
  </table>
</div>
""" if revoked_rows else ""
        body = f"""
{topbar('Settings')}
<div class="settings-page">
  <p class="sub settings-intro">Configure network, service and login settings in one place.</p>
  {settings_section_menu}
  {notice}
  <div class="grid settings-status-grid">
    <div class="card"><div class="label">LCD Endpoint</div><span class="big blue">Ready</span><small>Display-only access to /api/lcd/summary</small></div>
    <div class="card"><div class="label">Active Displays</div><span class="big green">{len(active_displays)}</span><small>Each display has its own token</small></div>
  </div>
<div class="panel settings settings-card">
  <h2>LCD Displays</h2>
  <p class="sub">Add small LAN displays such as ESP32 screens. Tokens only allow the read-only LCD summary endpoint and do not grant admin access.</p>
  <label>Endpoint URL</label>
  <div class="ns-lcd-copy-row"><input readonly value="{h(endpoint_url)}" data-copy-field><button class="ns-compact-button" type="button" data-copy-nearest>Copy URL</button></div>
  <form method="post" class="ns-lcd-add-form">
    {csrf_input()}
    <input type="hidden" name="section" value="lcd">
    <label>Add LCD display</label>
    <div class="ns-lcd-copy-row"><input name="display_name" maxlength="80" placeholder="Kitchen display, rack OLED, office ESP32"><button class="ns-compact-button" name="action" value="add">Generate token</button></div>
  </form>
  <table class="table compact">
    <thead><tr><th>Display</th><th>Token</th><th>Status</th><th>Last seen</th><th>Last IP</th><th>Actions</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
{revoked_table}
<script>
document.querySelectorAll('[data-copy-nearest]').forEach(function(button) {{
  button.addEventListener('click', function() {{
    var row = button.closest('.ns-lcd-copy-row');
    var input = row ? row.querySelector('[data-copy-field], input') : null;
    if (!input) return;
    input.select();
    input.setSelectionRange(0, input.value.length);
    navigator.clipboard.writeText(input.value).then(function() {{
      var old = button.textContent;
      button.textContent = 'Copied';
      setTimeout(function() {{ button.textContent = old; }}, 1400);
    }});
  }});
}});
</script>
</div>
"""
        return shell("Settings", body, "Settings")

    if section == "unifi":
        ok, detail = check_unifi_connection(c)
        enabled_checked = " checked" if c.get("unifi_enabled") else ""
        skip_tls_checked = " checked" if c.get("unifi_skip_tls_verify") else ""
        notice_text = request.args.get("notice") or ("UniFi settings saved." if request.args.get("saved") == "1" else "")
        notice_class = "setup-warning" if request.args.get("notice_class") == "warning" else "setup-ok"
        notice = f'<div class="{notice_class}">{h(notice_text)}</div>' if notice_text else ""
        body = f"""
{topbar('Settings')}
<div class="settings-page">
  <p class="sub settings-intro">Configure network, service and login settings in one place.</p>
  {settings_section_menu}
  {notice}
  <div class="grid settings-status-grid">
    <div class="card"><div class="label">UniFi Discovery</div><span class="big {'green' if ok else 'yellow'}">{'Ready' if ok else 'Setup'}</span><small>{h(detail)}</small></div>
    <a class="card" href="/devices"><div class="label">Imported Clients</div><span class="big blue">Devices</span><small>UniFi names appear in Devices</small></a>
  </div>
<div class="panel settings settings-card">
  <h2>UniFi Settings</h2>
  <form method="post" action="/unifi">
    {csrf_input()}
    <label><input type="checkbox" name="unifi_enabled" value="1" style="width:auto"{enabled_checked}> Enable UniFi Device Discovery</label>
    <label>UniFi Network API URL</label>
    <input name="unifi_connector_url" value="{h(c.get('unifi_connector_url', ''))}" placeholder="https://gateway-address/proxy/network/integration">
    <label><input type="checkbox" name="unifi_skip_tls_verify" value="1" style="width:auto"{skip_tls_checked}> Allow self-signed certificate for local UniFi gateway</label>
    <label>UniFi Site ID</label>
    <input name="unifi_site_id" value="{h(c.get('unifi_site_id', ''))}" placeholder="Your UniFi site ID">
    <label>Local UniFi Username</label>
    <input name="unifi_username" value="{h(c.get('unifi_username', ''))}" placeholder="Only needed for local gateway auth">
    <label>Local UniFi Password</label>
    <input name="unifi_password" type="password" placeholder="Leave blank to keep saved local UniFi password">
    <small>The local UniFi password is encrypted in NetSpecter's local config.</small>
    <label><input type="checkbox" name="clear_unifi_username" value="1" style="width:auto"> Clear saved UniFi username</label>
    <label><input type="checkbox" name="clear_unifi_password" value="1" style="width:auto"> Clear saved UniFi password</label>
    <button type="submit" name="action" value="save">Save UniFi</button>
    <button type="submit" name="action" value="find_unifi_site">Find Site Automatically</button>
    <button type="submit" name="action" value="test_unifi">Save and Test UniFi</button>
  </form>
</div>
</div>
</div>
"""
        return shell("Settings", body, "Settings")

    if section == "telegram":
        ok, detail = check_telegram_config(c)
        telegram_checked = " checked" if c.get("telegram_enabled") else ""
        notice_text = request.args.get("notice") or ("Telegram settings saved." if request.args.get("saved") == "1" else "")
        notice_class = "setup-warning" if request.args.get("notice_class") == "warning" else "setup-ok"
        notice = f'<div class="{notice_class}">{h(notice_text)}</div>' if notice_text else ""
        body = f"""
{topbar('Settings')}
<div class="settings-page">
  <p class="sub settings-intro">Configure network, service and login settings in one place.</p>
  {settings_section_menu}
  {notice}
  <div class="grid settings-status-grid">
    <div class="card"><div class="label">Bot</div><span class="big {'green' if ok else 'yellow'}">{'Ready' if ok else 'Setup'}</span><small>{h(detail)}</small></div>
  </div>
<div class="panel settings settings-card">
  <h2>Telegram Settings</h2>
  <form method="post" action="/telegram">
    {csrf_input()}
    <label><input type="checkbox" name="telegram_enabled" value="1" style="width:auto"{telegram_checked}> Enable Telegram Alerts</label>
    <label>Telegram Bot Token</label>
    <input name="telegram_bot_token" type="password" placeholder="Leave blank to keep saved token">
    <small>The bot token is encrypted in the local NetSpecter config.</small>
    <label>Telegram Chat ID</label>
    <input name="telegram_chat_id" value="{h(c.get('telegram_chat_id', ''))}" placeholder="123456789">
    <label><input type="checkbox" name="clear_telegram_bot_token" value="1" style="width:auto"> Clear saved Telegram bot token</label>
    <button type="submit" name="action" value="save">Save Telegram</button>
    <button type="submit" name="action" value="test_telegram">Save and Send Test</button>
  </form>
</div>
</div>
"""
        return shell("Settings", body, "Settings")

    if section == "speed":
        body = f"""
{topbar('Settings')}
<div class="settings-page">
  <p class="sub settings-intro">Configure network, service and login settings in one place.</p>
  {settings_section_menu}
<div class="panel settings settings-card">
  <h2>Speed Tests Settings</h2>
  <p class="sub">Speed-test history and automatic testing schedule now live on the Speed Tests page.</p>
  <a class="btn" href="/speed-tests#automaticTesting">Open Speed Tests</a>
</div>
</div>
"""
        return shell("Settings", body, "Settings")

    if section == "applications":
        notice_text = request.args.get("notice") or ("Application mappings saved." if request.args.get("saved") == "1" else "")
        notice_class = "setup-warning" if request.args.get("notice_class") == "warning" else "setup-ok"
        notice = f'<div class="{notice_class}">{h(notice_text)}</div>' if notice_text else ""
        category_names = [row["name"] for row in application_categories()]
        current_mappings = c.get("site_application_mappings") if isinstance(c.get("site_application_mappings"), list) else []
        current_domain_mappings = c.get("site_domain_mappings") if isinstance(c.get("site_domain_mappings"), list) else []
        rows = list(current_mappings) or [{}]
        domain_rows = list(current_domain_mappings) or [{}]

        def category_options(selected_category=""):
            return "".join(
                f'<option value="{h(name)}"{" selected" if name == selected_category else ""}>{h(name)}</option>'
                for name in category_names
            )

        def ip_mapping_row(row=None):
            row = row or {}
            app_value = h(row.get("application", ""))
            ip_value = h(row.get("ip", ""))
            selected_category = str(row.get("category") or "")
            return f"""
      <tr>
        <td><input name="mapping_application" value="{app_value}" placeholder="Application name"></td>
        <td><select name="mapping_category"><option value="">Choose category</option>{category_options(selected_category)}</select></td>
        <td><input name="mapping_ip" value="{ip_value}" placeholder="IP address"></td>
      </tr>
"""

        def domain_mapping_row(row=None):
            row = row or {}
            app_value = h(row.get("application", ""))
            domain_value = h(row.get("domain", ""))
            selected_category = str(row.get("category") or "")
            return f"""
      <tr>
        <td><input name="domain_mapping_application" value="{app_value}" placeholder="Application name"></td>
        <td><select name="domain_mapping_category"><option value="">Choose category</option>{category_options(selected_category)}</select></td>
        <td><input name="mapping_domain" value="{domain_value}" placeholder="Domain pattern"></td>
      </tr>
"""
        mapping_rows = "".join(ip_mapping_row(row) for row in rows)
        domain_mapping_rows = "".join(domain_mapping_row(row) for row in domain_rows)
        blank_ip_row = ip_mapping_row({})
        blank_domain_row = domain_mapping_row({})
        body = f"""
{topbar('Settings')}
<div class="settings-page">
  <p class="sub settings-intro">Configure network, service and login settings in one place.</p>
  {settings_section_menu}
  {notice}
<div class="panel settings settings-card">
  <h2>Application Mapping Settings</h2>
  <p class="sub">Map local IPs or domain patterns to an application category for client overview reporting.</p>
  <form method="post">
    {csrf_input()}
    <input type="hidden" name="section" value="applications">
    <h3>Local IP Mappings</h3>
    <table class="table compact">
      <thead><tr><th>Application</th><th>Category</th><th>Local IP</th></tr></thead>
      <tbody id="ipMappingRows">{mapping_rows}</tbody>
    </table>
    <button type="button" class="btn" data-add-row="ipMappingRows" data-template="ipMappingTemplate">+</button>
    <small>Use this when a known local IP carries traffic for a specific application.</small>
    <h3>Domain Pattern Mappings</h3>
    <table class="table compact">
      <thead><tr><th>Application</th><th>Category</th><th>Domain Pattern</th></tr></thead>
      <tbody id="domainMappingRows">{domain_mapping_rows}</tbody>
    </table>
    <button type="button" class="btn" data-add-row="domainMappingRows" data-template="domainMappingTemplate">+</button>
    <small>Use wildcard domain patterns when a site or CDN should report under a specific application category.</small>
    <button name="action" value="save">Save Application Mappings</button>
  </form>
  <p class="green">Settings save now automatically restarts the collector service.</p>
</div>
<template id="ipMappingTemplate">{blank_ip_row}</template>
<template id="domainMappingTemplate">{blank_domain_row}</template>
<script>
document.querySelectorAll('[data-add-row]').forEach(function(button) {{
  button.addEventListener('click', function() {{
    var target = document.getElementById(button.getAttribute('data-add-row'));
    var template = document.getElementById(button.getAttribute('data-template'));
    if (!target || !template) return;
    target.insertAdjacentHTML('beforeend', template.innerHTML);
  }});
}});
</script>
</div>
"""
        return shell("Settings", body, "Settings")

    preferred_order = section_keys[section]
    ordered_keys = [k for k in preferred_order if k in c] + [k for k in c.keys() if k not in preferred_order]

    fields = ""
    for key in ordered_keys:
        if key not in preferred_order:
            continue
        val = c[key]
        if key in ["app_name", "tagline", "admin_password_hash"] or key in INTEGRATION_SETTINGS_KEYS:
            continue
        if isinstance(val, bool):
            checked = " checked" if val else ""
            help_text = f"<small>{h(setting_help[key])}</small>" if key in setting_help else ""
            fields += f"<label><input type='checkbox' name='{key}' value='1' style='width:auto'{checked}> {h(setting_labels.get(key, key))}</label>{help_text}"
            continue
        typ = "password" if "pass" in key else "text"
        display_val = "" if key in SENSITIVE_CONFIG_KEYS else ", ".join(val) if isinstance(val, list) else val
        help_text = f"<small>{h(setting_help[key])}</small>" if key in setting_help else ""
        placeholder = " placeholder='Leave blank to keep existing password'" if key in SENSITIVE_CONFIG_KEYS else ""
        fields += f"<label>{h(setting_labels.get(key, key))}</label><input type='{typ}' name='{key}' value='{h(display_val)}'{placeholder}>{help_text}"

    password_fields = """
<label>New Admin Password</label>
<input type="password" name="admin_new_password" placeholder="Leave blank to keep current login password">
<small>Use this to change the NetSpecter login password. Minimum 8 characters.</small>
<label>Confirm New Admin Password</label>
<input type="password" name="admin_confirm_password" placeholder="Repeat new login password">
"""
    if section == "web":
        fields += password_fields
    if section == "network":
        appliance_ip = str(c.get("appliance_ip") or "").strip()
        preview_ip = appliance_ip if valid_ipv4_ip(appliance_ip) else "APPLIANCE-IP"
        fields += f"""
<div class="setup-warning">
  <h2>One-IP Service URL Sync</h2>
  <p>Use this when NetSpecter, AdGuard, service monitor and metrics are on the same appliance IP.</p>
  <label><input type="checkbox" name="sync_appliance_urls" value="1" style="width:auto"> Update service URLs from Appliance IP on save</label>
  <small>Preview: NetSpecter https://{h(preview_ip)}:{h(c.get('https_proxy_port', 9443))} | AdGuard http://{h(preview_ip)} | Gatus http://{h(preview_ip)}:18080 | Beszel http://{h(preview_ip)}:8090</small>
</div>
"""

    body = f"""
{topbar('Settings')}
<div class="settings-page">
  <p class="sub settings-intro">Configure network, service and login settings in one place.</p>
  {settings_section_menu}
  {('<div class="' + ('setup-warning' if request.args.get('notice_class') == 'warning' else 'setup-ok') + '">' + h(request.args.get('notice')) + '</div>') if request.args.get('notice') else ''}
<div class="panel settings settings-card">
{setup_banner()}
<h2>{h(section_title)} Settings</h2>
<form method="post">
{csrf_input()}
<input type="hidden" name="section" value="{h(section)}">
{fields}
<button>Save Settings</button>
</form>
<p class="green">Settings save now automatically restarts the collector service.</p>
</div>
</div>
"""
    return shell("Settings", body, "Settings")


def parse_speedtest_metrics(output):
    def value(pattern):
        match = re.search(pattern, output or "", re.IGNORECASE)
        return float(match.group(1)) if match else None
    return (
        value(r"(?:Latency|Ping):\s*([0-9.]+)\s*ms"),
        value(r"Download:\s*([0-9.]+)\s*(?:Mbit/s|Mbps)"),
        value(r"Upload:\s*([0-9.]+)\s*(?:Mbit/s|Mbps)"),
    )


def speedtest_command():
    candidates = [
        ("/usr/bin/speedtest", ["--accept-license", "--accept-gdpr"]),
        ("/usr/bin/speedtest-cli", []),
    ]
    for path, args in candidates:
        if Path(path).exists():
            return [path] + args
    return None


def run_and_store_speedtest(source="manual"):
    success = False
    try:
        command = speedtest_command()
        if not command:
            raise FileNotFoundError("No supported speed test client found")
        speedtest_env = os.environ.copy()
        speedtest_env.setdefault("HOME", "/root")
        speedtest_env.setdefault("LANG", "C.UTF-8")
        speedtest_env.setdefault("LC_ALL", "C.UTF-8")
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
            env=speedtest_env,
        )
        output = (result.stdout or "").strip() or "Speed test returned no output."
        if result.returncode != 0:
            output = f"Speed test failed (exit {result.returncode}).\n{output}"
        else:
            success = True
    except FileNotFoundError:
        output = "No supported speed test client is installed. Re-run the NetSpecter installer to install speedtest-cli."
    except subprocess.TimeoutExpired:
        output = "Speed test timed out after 120 seconds."
    except Exception as error:
        print(f"Speed test failed: {error}")
        output = operation_failed_message("Speed test")
    latency, download, upload = parse_speedtest_metrics(output)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    run_sql(
        """
        INSERT INTO speed_tests (ts, source, latency_ms, download_mbps, upload_mbps, result_text, success)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (ts, source, latency, download, upload, output, 1 if success else 0),
    )
    live_snapshot.update_summary({
        "last_speed_test": {
            "completed_at": ts if success else None,
            "download_mbps": download,
            "upload_mbps": upload,
            "ping_ms": latency,
            "status": "completed" if success else "failed",
            "source": source,
        }
    }, ts)
    return output


@app.route("/speed-test", methods=["POST"])
def speed_test():
    """Run an administrator-triggered speed test and store its result."""
    run_and_store_speedtest("manual")
    return redirect("/speed-tests?ran=1")


def display_speed_source(source):
    text = str(source or "").strip()
    lower = text.lower()
    if lower in {"manual", "user"}:
        return "Manual"
    if lower in {"scheduled", "schedule", "auto", "automatic"}:
        return "Scheduled"
    return text.title() if text else "Unknown"


def speedtest_next_run_label(frequency, schedule_time):
    if frequency not in {"daily", "weekly"}:
        return ""
    label = "Daily" if frequency == "daily" else "Weekly"
    return f"Next scheduled: {label.lower()} at {schedule_time}"


def speed_metric_status(metric, value):
    try:
        value = float(value)
    except Exception:
        return ""
    if metric == "latency":
        return "Excellent" if value <= 20 else "Good" if value <= 50 else "Review"
    return "Excellent" if value >= 100 else "Good" if value >= 25 else "Review"


def speedtest_server_label(result_text):
    lines = str(result_text or "").splitlines()
    for line in lines:
        text = line.strip()
        lower = text.lower()
        if lower.startswith(("server:", "hosted by:", "hosted by ", "server ")):
            return text.split(":", 1)[1].strip() if ":" in text else text
    return ""


@app.route("/speed-tests", methods=["GET", "POST"])
def speed_tests():
    c = cfg()
    notice = '<div class="ns-inline-notice ns-inline-notice--ok">Speed test completed and saved.</div>' if request.args.get("ran") == "1" else ""
    if request.args.get("failed") == "1":
        notice = '<div class="ns-inline-notice ns-inline-notice--error">Speed test failed. Check the latest result details.</div>'
    if request.method == "POST":
        enabled = request.form.get("scheduled_speedtests_enabled") == "1"
        frequency = request.form.get("scheduled_speedtest_frequency", "daily").strip().lower()
        if not enabled:
            frequency = "disabled"
        if frequency not in ("daily", "weekly", "disabled"):
            frequency = "daily" if enabled else "disabled"
        c["scheduled_speedtests_per_day"] = 1 if frequency in ("daily", "weekly") else 0
        c["scheduled_speedtest_frequency"] = frequency
        c["scheduled_speedtest_time"] = request.form.get("scheduled_speedtest_time", "12:00").strip() or "12:00"
        save_cfg(c)
        return redirect("/speed-tests?saved=1#automaticTesting")

    speed_days = request.args.get("speed_days", "7")
    if speed_days not in ("1", "7", "30"):
        speed_days = "7"
    speed_day_count = int(speed_days)
    rows = query(
        """
        SELECT ts, source, latency_ms, download_mbps, upload_mbps, result_text, success
        FROM speed_tests
        ORDER BY ts DESC
        LIMIT 100
        """
    )
    successful_rows = [row for row in rows if int(row["success"] or 0) and row["download_mbps"] is not None and row["upload_mbps"] is not None]
    chart_cutoff = datetime.now() - timedelta(days=speed_day_count - 1)
    daily_rows = []
    seen_days = set()
    for row in successful_rows:
        day = str(row["ts"] or "")[:10]
        try:
            if datetime.strptime(day, "%Y-%m-%d").date() < chart_cutoff.date():
                continue
        except ValueError:
            continue
        if not day or day in seen_days:
            continue
        seen_days.add(day)
        daily_rows.append(row)
        if len(daily_rows) >= speed_day_count:
            break
    chart_rows = list(reversed(daily_rows))
    chart_labels = json.dumps([str(r["ts"] or "")[:10] for r in chart_rows])
    chart_download = json.dumps([float(r["download_mbps"] or 0) for r in chart_rows])
    chart_upload = json.dumps([float(r["upload_mbps"] or 0) for r in chart_rows])
    chart_latency = json.dumps([float(r["latency_ms"] or 0) for r in chart_rows])
    chart_tooltips = json.dumps([
        {
            "timestamp": str(r["ts"] or ""),
            "source": display_speed_source(r["source"]),
            "server": speedtest_server_label(r["result_text"]),
            "download": round(float(r["download_mbps"] or 0), 2),
            "upload": round(float(r["upload_mbps"] or 0), 2),
            "latency": round(float(r["latency_ms"] or 0), 2),
            "status": "Pass" if int(r["success"] or 0) else "Fail",
        }
        for r in chart_rows
    ])
    latest = successful_rows[0] if successful_rows else None
    schedule_count = int(c.get("scheduled_speedtests_per_day", 0) or 0)
    frequency = str(c.get("scheduled_speedtest_frequency") or ("daily" if schedule_count else "disabled")).lower()
    if not schedule_count:
        frequency = "disabled"
    if frequency not in ("daily", "weekly", "disabled"):
        frequency = "daily"
    schedule_time = str(c.get("scheduled_speedtest_time") or "12:00").strip()[:5] or "12:00"
    schedule_checked = " checked" if schedule_count else ""
    frequency_disabled = " disabled" if not schedule_count else ""
    next_run = speedtest_next_run_label(frequency, schedule_time)
    if request.args.get("saved") == "1":
        notice = f'<div class="ns-inline-notice ns-inline-notice--ok">Speed-test schedule saved. {h(next_run) if next_run else "Automatic tests disabled."}</div>'
    show_full_history = request.args.get("history") == "full"
    table_rows = rows if show_full_history else rows[:6]
    table = ""
    for r in table_rows:
        latency_text = f"{r['latency_ms']:.2f} ms" if r["latency_ms"] is not None else "-"
        download_text = f"{r['download_mbps']:.2f} Mbps" if r["download_mbps"] is not None else "-"
        upload_text = f"{r['upload_mbps']:.2f} Mbps" if r["upload_mbps"] is not None else "-"
        ok = int(r["success"] or 0) == 1
        table += f"""
<tr>
  <td>{h(r['ts'])}</td>
  <td>{h(display_speed_source(r['source']))}</td>
  <td>{h(latency_text)}</td>
  <td>{h(download_text)}</td>
  <td>{h(upload_text)}</td>
  <td><span class="ns-speed-status-dot {'is-ok' if ok else 'is-failed'}" title="{'Successful test' if ok else 'Failed test'}"></span><span class="sr-only">{'Successful test' if ok else 'Failed test'}</span>{'OK' if ok else 'Failed'}</td>
</tr>
"""
    latest_download = f"{latest['download_mbps']:.0f} Mbps" if latest and latest["download_mbps"] is not None else "No results yet"
    latest_upload = f"{latest['upload_mbps']:.0f} Mbps" if latest and latest["upload_mbps"] is not None else "No results yet"
    latest_latency = f"{latest['latency_ms']:.0f} ms" if latest and latest["latency_ms"] is not None else "No results yet"
    latest_download_status = speed_metric_status("speed", latest["download_mbps"]) if latest else ""
    latest_upload_status = speed_metric_status("speed", latest["upload_mbps"]) if latest else ""
    latest_latency_status = speed_metric_status("latency", latest["latency_ms"]) if latest else ""
    schedule_value = "On · Daily" if frequency == "daily" else "On · Weekly" if frequency == "weekly" else "Off"
    daily_selected = " selected" if frequency == "daily" else ""
    weekly_selected = " selected" if frequency == "weekly" else ""
    disabled_selected = " selected" if frequency == "disabled" else ""
    view_history = ""
    if len(rows) > 6:
        view_history = (
            '<a class="ns-polish-subtle" href="/speed-tests?history=full#recentResults">View full history</a>'
            if not show_full_history
            else '<a class="ns-polish-subtle" href="/speed-tests#recentResults">Show recent only</a>'
        )
    chart_empty = ""
    if len(chart_rows) < 2:
        chart_empty = f"<div class='ns-dashboard-empty ns-speed-chart-empty'>At least two completed daily speed tests are needed before the {speed_day_count}-day trend is shown.</div>"
    speed_ranges = "".join(
        f'<a class="{"active" if speed_days == key else ""}" href="/speed-tests?tab=speed&speed_days={key}">{label}</a>'
        for key, label in (("1", "1 Day"), ("7", "7 Days"), ("30", "30 Days"))
    )
    internet_tab = request.args.get("tab", "speed").strip().lower()
    if internet_tab not in ("speed", "quality"):
        internet_tab = "speed"
    quality_days = request.args.get("quality_days", "7")
    if quality_days not in ("7", "14", "30"):
        quality_days = "7"
    quality_rows = query(
        """
        SELECT ts, status, gateway_latency_ms, internet_latency_ms, internet_loss_pct, jitter_ms, dns_ms
        FROM internet_quality
        WHERE ts >= datetime('now', 'localtime', ?)
        ORDER BY ts ASC
        LIMIT 500
        """,
        (f"-{quality_days} days",),
    )
    quality_labels = json.dumps([str(r["ts"] or "") for r in quality_rows])
    quality_gateway = json.dumps([float(r["gateway_latency_ms"] or 0) for r in quality_rows])
    quality_internet = json.dumps([float(r["internet_latency_ms"] or 0) for r in quality_rows])
    quality_dns = json.dumps([float(r["dns_ms"] or 0) for r in quality_rows])
    quality_loss = json.dumps([float(r["internet_loss_pct"] or 0) for r in quality_rows])
    quality_jitter = json.dumps([float(r["jitter_ms"] or 0) for r in quality_rows])
    quality_count = len(quality_rows)
    avg_quality_latency = sum(float(r["internet_latency_ms"] or 0) for r in quality_rows) / quality_count if quality_count else 0
    avg_quality_loss = sum(float(r["internet_loss_pct"] or 0) for r in quality_rows) / quality_count if quality_count else 0
    avg_quality_dns = sum(float(r["dns_ms"] or 0) for r in quality_rows) / quality_count if quality_count else 0
    quality_status = "Healthy" if quality_count and avg_quality_loss < 1 and avg_quality_latency < 100 else "Needs review" if quality_count else "No data"
    quality_ranges = "".join(
        f'<a class="{"is-active" if quality_days == key else ""}" href="/speed-tests?tab=quality&quality_days={key}">{label}</a>'
        for key, label in (("7", "7 Days"), ("14", "14 Days"), ("30", "30 Days"))
    )
    internet_tabs = f"""
<div class="ns-internet-tabs">
  <a class="{"is-active" if internet_tab == "speed" else ""}" href="/speed-tests?tab=speed">Speed Tests</a>
  <a class="{"is-active" if internet_tab == "quality" else ""}" href="/speed-tests?tab=quality&quality_days={h(quality_days)}">Quality</a>
</div>
"""
    speed_tab_content = f"""
  <section class="ns-polish-panel ns-speed-panel">
    <div class="ns-speed-panel-header">
      <div>
        <h2>Connection performance</h2>
        <div class="ns-polish-subtle">Daily completed speed-test trend for the selected range.</div>
      </div>
      <div class="ns-speed-actions">
        <form method="post" action="/speed-test" id="speedRunForm">
          {csrf_input()}
          <button class="ns-button" type="submit" id="speedRunButton"><i class="fa-solid fa-play" aria-hidden="true"></i> Run speed test</button>
        </form>
        <a class="ns-button ns-button--secondary" href="#automaticTesting"><i class="fa-regular fa-calendar-days" aria-hidden="true"></i> Test schedule</a>
      </div>
    </div>
    <div class="ns-speed-latest">
      <div class="ns-polish-card ns-speed-card ns-speed-card--metric"><div class="label">Latest download</div><span class="big blue">{h(latest_download)}</span>{f'<small class="ns-status-good"><span></span>{h(latest_download_status)}</small>' if latest_download_status else ''}</div>
      <div class="ns-polish-card ns-speed-card ns-speed-card--metric"><div class="label">Latest upload</div><span class="big purple">{h(latest_upload)}</span>{f'<small class="ns-status-good"><span></span>{h(latest_upload_status)}</small>' if latest_upload_status else ''}</div>
      <div class="ns-polish-card ns-speed-card ns-speed-card--metric"><div class="label">Latest latency</div><span class="big teal">{h(latest_latency)}</span>{f'<small class="ns-status-good"><span></span>{h(latest_latency_status)}</small>' if latest_latency_status else ''}</div>
    </div>
    <div class="time-picker ns-speed-range-picker">{speed_ranges}</div>
    <div class="ns-speed-progress" id="speedRunProgress"></div>
    <div class="ns-speed-chart-wrap">
      <canvas id="speedHistoryChart" height="104"></canvas>
      {chart_empty}
    </div>
  </section>
  <section class="ns-speed-bottom">
    <div class="ns-polish-panel ns-speed-subpanel" id="recentResults">
      <div class="ns-polish-header"><h2>Recent results</h2>{view_history}</div>
      <table class="ns-speed-table">
        <thead><tr><th>Date / time</th><th>Source</th><th>Latency</th><th>Download</th><th>Upload</th><th>Status</th></tr></thead>
        <tbody>{table or '<tr><td colspan="6">No saved speed tests yet.</td></tr>'}</tbody>
      </table>
    </div>
    <div class="ns-polish-panel ns-speed-subpanel" id="automaticTesting" tabindex="-1">
      <h2>Automatic testing</h2>
      <p class="ns-polish-subtle">Status: <b>{h(schedule_value)}</b>{f' · {h(next_run)}' if next_run else ''}</p>
      <form class="ns-speed-schedule-form {'is-disabled' if not schedule_count else ''}" method="post" id="speedScheduleForm">
        {csrf_input()}
        <label class="ns-speed-toggle-line">Enable automatic tests <input type="checkbox" name="scheduled_speedtests_enabled" value="1"{schedule_checked} id="speedScheduleEnabled"></label>
        <label>Frequency
          <select class="ns-select" name="scheduled_speedtest_frequency"{frequency_disabled}>
            <option value="daily"{daily_selected}>Daily</option>
            <option value="weekly"{weekly_selected}>Weekly</option>
            <option value="disabled"{disabled_selected}>Disabled</option>
          </select>
        </label>
        <label>Preferred test time
          <input class="ns-input" type="time" name="scheduled_speedtest_time" value="{h(schedule_time)}"{frequency_disabled}>
        </label>
        <div class="ns-speed-helper"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i> Scheduled tests use internet data.</div>
        <button class="ns-button" type="submit"><i class="fa-regular fa-floppy-disk" aria-hidden="true"></i> Save schedule</button>
      </form>
    </div>
  </section>
"""
    quality_tab_content = f"""
  <section class="ns-polish-panel ns-speed-panel">
    <div class="ns-speed-panel-header">
      <div>
        <h2>Internet quality</h2>
        <div class="ns-polish-subtle">Latency, packet loss, jitter and DNS response from regular quality checks.</div>
      </div>
      <div class="time-picker ns-quality-picker">{quality_ranges}</div>
    </div>
    <div class="ns-speed-summary ns-quality-summary">
      <div class="ns-polish-card ns-speed-card"><div class="label">Average latency</div><span class="big teal">{avg_quality_latency:.2f} ms</span></div>
      <div class="ns-polish-card ns-speed-card"><div class="label">Packet loss</div><span class="big {'green' if avg_quality_loss < 1 else 'red'}">{avg_quality_loss:.2f}%</span></div>
      <div class="ns-polish-card ns-speed-card"><div class="label">DNS response</div><span class="big blue">{avg_quality_dns:.2f} ms</span></div>
      <div class="ns-polish-card ns-speed-card"><div class="label">Quality status</div><span class="big {'green' if quality_status == 'Healthy' else 'yellow'}">{h(quality_status)}</span></div>
    </div>
    <div class="ns-speed-chart-wrap">
      <canvas id="internetQualityChart" height="104"></canvas>
      {"<div class='ns-dashboard-empty ns-speed-chart-empty'>No internet quality samples found for this range yet.</div>" if quality_count < 2 else ""}
    </div>
  </section>
"""
    active_internet_content = speed_tab_content if internet_tab == "speed" else quality_tab_content

    body = f"""
{topbar('Internet')}
<style>
.ns-speed-page {{ display:flex; flex-direction:column; gap:16px; }}
.ns-speed-page h1 {{ margin:0; color:var(--ns-text-primary); font-size:28px; }}
.ns-speed-summary,.ns-speed-latest {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(240px, 1fr)); gap:14px; }}
.ns-speed-latest {{ grid-template-columns:repeat(3, minmax(0, 1fr)); margin:14px 0 16px; }}
.ns-speed-card {{ min-height:92px; padding:18px; text-align:center; }}
.ns-speed-card--metric {{ display:grid; grid-template-columns:1fr auto; align-items:center; text-align:left; }}
.ns-speed-card .label {{ color:var(--ns-text-secondary); font-size:13px; font-weight:800; }}
.ns-speed-card .big {{ display:block; margin-top:9px; font-size:24px; font-weight:900; }}
.ns-speed-card small {{ display:block; margin-top:7px; color:var(--ns-text-muted); }}
.ns-speed-card--metric small {{ grid-column:2; grid-row:1 / span 2; align-self:center; margin:0; }}
.ns-status-good {{ color:#8df59f !important; font-weight:800; }}
.ns-status-good span {{ display:inline-block; width:8px; height:8px; margin-right:8px; border-radius:50%; background:#8df59f; box-shadow:0 0 10px rgba(141,245,159,.45); }}
.ns-speed-panel {{ padding:20px; }}
.ns-speed-panel-header {{ display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:16px; }}
.ns-speed-panel-header h2,.ns-speed-subpanel h2 {{ margin:0; color:var(--ns-text-primary); font-size:21px; }}
.ns-speed-actions {{ display:flex; gap:10px; flex-wrap:wrap; justify-content:flex-end; }}
.ns-speed-range-picker {{ justify-content:flex-start; margin-bottom:8px; }}
.ns-speed-chart-wrap {{ position:relative; min-height:360px; }}
.ns-speed-chart-wrap canvas {{ max-height:390px; }}
.ns-speed-chart-empty {{ position:absolute; inset:28px 0 0; display:grid; place-items:center; background:rgba(7,16,28,.58); }}
.ns-speed-bottom {{ display:grid; grid-template-columns:minmax(0, 1.08fr) minmax(340px, .92fr); gap:16px; }}
.ns-speed-subpanel {{ padding:18px; }}
.ns-speed-table {{ width:100%; border-collapse:collapse; margin-top:14px; }}
.ns-speed-table th,.ns-speed-table td {{ padding:11px 10px; border-top:1px solid rgba(96,126,160,.15); color:var(--ns-text-secondary); text-align:left; font-size:13px; }}
.ns-speed-table th {{ color:#b7c9df; background:rgba(5,16,29,.36); font-size:12px; font-weight:900; }}
.ns-speed-status-dot {{ display:inline-block; width:10px; height:10px; margin-right:8px; border-radius:50%; vertical-align:middle; }}
.ns-speed-status-dot.is-ok {{ background:#20df9f; box-shadow:0 0 12px rgba(32,223,159,.35); }}
.ns-speed-status-dot.is-failed {{ background:#ff526c; box-shadow:0 0 12px rgba(255,82,108,.35); }}
.sr-only {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }}
.ns-speed-schedule-form {{ display:grid; gap:16px; margin-top:18px; }}
.ns-speed-toggle-line {{ display:flex; justify-content:space-between; align-items:center; gap:12px; color:var(--ns-text-primary); font-weight:800; }}
.ns-speed-toggle-line input {{ width:44px; height:22px; accent-color:#00d6ff; }}
.ns-speed-schedule-form label:not(.ns-speed-toggle-line) {{ display:grid; gap:8px; color:var(--ns-text-secondary); font-size:13px; }}
.ns-speed-schedule-form.is-disabled select,.ns-speed-schedule-form.is-disabled input[type=time] {{ opacity:.48; pointer-events:none; }}
.ns-speed-helper {{ color:#f8c84e; font-size:13px; }}
.ns-speed-progress {{ min-height:20px; color:#48dfff; font-weight:800; }}
.ns-internet-tabs {{ display:inline-flex; gap:6px; padding:5px; border:1px solid rgba(80,112,150,.28); border-radius:12px; background:rgba(9,24,42,.72); }}
.ns-internet-tabs a {{ min-width:118px; padding:9px 14px; border-radius:8px; color:#aebfd3; font-size:13px; font-weight:900; text-align:center; text-decoration:none; }}
.ns-internet-tabs a.is-active {{ background:rgba(0,214,255,.2); color:#fff; }}
.ns-quality-summary {{ margin-bottom:16px; }}
.ns-quality-picker a {{ min-width:70px; }}
@media (max-width: 1100px) {{ .ns-speed-summary,.ns-speed-latest,.ns-speed-bottom {{ grid-template-columns:1fr 1fr; }} }}
@media (max-width: 760px) {{ .ns-speed-summary,.ns-speed-latest,.ns-speed-bottom {{ grid-template-columns:1fr; }} .ns-speed-panel-header {{ align-items:flex-start; flex-direction:column; }} .ns-speed-actions {{ justify-content:flex-start; }} }}
</style>
<div class="ns-polish-page ns-speed-page">
  <div>
    <h1>Internet</h1>
    <p class="ns-polish-subtle">Measure and track your internet connection.</p>
  </div>
  {notice}
  {internet_tabs}
  {active_internet_content}
</div>
<script>
const speedCtx = document.getElementById('speedHistoryChart');
const speedChartRows = {len(chart_rows)};
if (speedCtx && speedChartRows >= 2) {{
  new Chart(speedCtx, {{
    type: "line",
    data: {{
      labels: {chart_labels},
      datasets: [
        {{label: 'Download (Mbps)', data: {chart_download}, borderColor: '#1688ff', backgroundColor: '#1688ff', borderWidth: 2, tension: 0, pointRadius: 5, pointHoverRadius: 7, pointBorderWidth: 2, pointBorderColor: '#80bdff', fill: false, yAxisID: 'speed'}},
        {{label: 'Upload (Mbps)', data: {chart_upload}, borderColor: '#a68bff', backgroundColor: '#a68bff', borderWidth: 2, tension: 0, pointRadius: 5, pointHoverRadius: 7, pointBorderWidth: 2, pointBorderColor: '#d1c4ff', fill: false, yAxisID: 'speed'}},
        {{label: 'Latency (ms)', data: {chart_latency}, borderColor: '#00ddc7', backgroundColor: '#00ddc7', borderWidth: 2, tension: 0, pointRadius: 5, pointHoverRadius: 7, pointBorderWidth: 2, pointBorderColor: '#75fff3', fill: false, yAxisID: 'latency'}}
      ]
    }},
    options: {{
      responsive:true,
      maintainAspectRatio:false,
      interaction:{{mode:'index', intersect:false}},
      plugins:{{
        legend:{{labels:{{color:'#d7e6f5', usePointStyle:true}}}},
        tooltip:{{
          callbacks:{{
            title:function(items){{ const meta = {chart_tooltips}; return items[0] ? meta[items[0].dataIndex].timestamp : ''; }},
            label:function(item){{ const unit = item.dataset.yAxisID === 'latency' ? ' ms' : ' Mbps'; return item.dataset.label + ': ' + item.formattedValue + unit; }},
            afterBody:function(items){{
              const meta = {chart_tooltips};
              if (!items[0]) return [];
              const row = meta[items[0].dataIndex] || {{}};
              const details = [];
              if (row.server) details.push('Server: ' + row.server);
              if (row.source) details.push('Source: ' + row.source);
              details.push('Status: ' + (row.status || 'Unknown'));
              return details;
            }}
          }}
        }}
      }},
      scales:{{
        x:{{offset:true, ticks:{{color:'#b8c4d6', maxRotation:0, callback:function(value){{ const raw = this.getLabelForValue(value); if (!raw) return ''; const d = new Date(raw + 'T00:00:00'); return d.toLocaleDateString(undefined, {{weekday:'short', day:'2-digit', month:'short'}}).replace(',', ''); }}}}, grid:{{color:'rgba(148,163,184,.12)', borderDash:[4,4]}}}},
        speed:{{position:'left', beginAtZero:true, title:{{display:true, text:'Mbps', color:'#d7e6f5', align:'end'}}, ticks:{{color:'#b8c4d6'}}, grid:{{color:'rgba(148,163,184,.14)', borderDash:[4,4]}}}},
        latency:{{position:'right', beginAtZero:true, suggestedMax:20, grace:'15%', title:{{display:true, text:'ms', color:'#d7e6f5', align:'end'}}, ticks:{{color:'#b8c4d6'}}, grid:{{drawOnChartArea:false}}}}
      }}
    }}
  }});
}}
const qualityCtx = document.getElementById('internetQualityChart');
const qualityRows = {quality_count};
if (qualityCtx && qualityRows >= 2) {{
  new Chart(qualityCtx, {{
    type: "bar",
    data: {{
      labels: {quality_labels},
      datasets: [
        {{label: 'Internet latency (ms)', data: {quality_internet}, borderColor: '#1688ff', backgroundColor: '#1688ff', borderWidth: 2, tension: .25, pointRadius: 2, yAxisID: 'latency'}},
        {{label: 'Gateway latency (ms)', data: {quality_gateway}, borderColor: '#20df9f', backgroundColor: '#20df9f', borderWidth: 2, tension: .25, pointRadius: 2, yAxisID: 'latency'}},
        {{label: 'DNS response (ms)', data: {quality_dns}, borderColor: '#00ddc7', backgroundColor: '#00ddc7', borderWidth: 2, tension: .25, pointRadius: 2, yAxisID: 'latency'}},
        {{label: 'Jitter (ms)', data: {quality_jitter}, borderColor: '#a68bff', backgroundColor: '#a68bff', borderWidth: 2, tension: .25, pointRadius: 2, yAxisID: 'latency'}},
        {{label: 'Packet loss (%)', data: {quality_loss}, borderColor: '#f8c84e', backgroundColor: '#f8c84e', borderWidth: 2, tension: .25, pointRadius: 2, yAxisID: 'loss'}}
      ]
    }},
    options: {{
      responsive:true,
      maintainAspectRatio:false,
      interaction:{{mode:'index', intersect:false}},
      plugins:{{legend:{{labels:{{color:'#d7e6f5', usePointStyle:true}}}}}},
      scales:{{
        x:{{ticks:{{color:'#9aa7bb', maxRotation:0, callback:function(value){{ const raw = this.getLabelForValue(value); return raw ? raw.slice(5,16) : ''; }}}}, grid:{{color:'rgba(148,163,184,.09)'}}}},
        latency:{{position:'left', title:{{display:true, text:'Latency / response (ms)', color:'#d7e6f5'}}, ticks:{{color:'#9aa7bb'}}, grid:{{color:'rgba(148,163,184,.12)'}}}},
        loss:{{position:'right', title:{{display:true, text:'Packet loss (%)', color:'#d7e6f5'}}, ticks:{{color:'#9aa7bb'}}, grid:{{drawOnChartArea:false}}}}
      }}
    }}
  }});
}}
document.getElementById('speedRunForm')?.addEventListener('submit', function() {{
  const button = document.getElementById('speedRunButton');
  const progress = document.getElementById('speedRunProgress');
  if (button) {{ button.disabled = true; button.textContent = 'Running speed test...'; }}
  if (progress) progress.textContent = 'Running speed test...';
}});
document.getElementById('speedScheduleEnabled')?.addEventListener('change', function(event) {{
  const form = document.getElementById('speedScheduleForm');
  form?.classList.toggle('is-disabled', !event.target.checked);
  form?.querySelectorAll('select,input[type=time]').forEach(function(field) {{
    field.disabled = !event.target.checked;
  }});
}});
</script>
"""
    return shell("Speed Tests", body, "Speed Tests")


@app.route("/system", methods=["GET", "POST"])
def system():
    if request.method == "POST":
        ok, _message = start_background_update()
        return redirect("/health?update=started#updateProgress" if ok else "/health?update=failed#updateProgress")

    collector_notice = ""
    if request.args.get("collector") == "restarted":
        collector_notice = '<div class="setup-ok">Collector restart requested.</div>'
    elif request.args.get("collector") == "restart_failed":
        collector_notice = '<div class="setup-warning">Collector restart failed. Check service permissions/logs.</div>'
    timing_rows = ""
    for row in recent_request_timings(20):
        timing_rows += f"""
<tr>
  <td>{h(row.get('ts', ''))}</td>
  <td><b>{h(row.get('ms', ''))} ms</b></td>
  <td>{h(row.get('method', ''))}</td>
  <td><span class="mono">{h(row.get('path', ''))}</span></td>
  <td>{h(row.get('endpoint', ''))}</td>
  <td>{h(row.get('status', ''))}</td>
</tr>"""

    body = f"""
{topbar('Logs')}

{collector_notice}
<div class="related-page logs-page">
<div class="panel related-card logs-table-card" id="performance">
  <h2>Slow Request Timing</h2>
  <p class="sub">NetSpecter records page/API requests that take longer than 750 ms. Use this to see what is causing slow clicks.</p>
  <table>
    <tr><th>Time</th><th>Duration</th><th>Method</th><th>Path</th><th>Endpoint</th><th>Status</th></tr>
    {timing_rows or '<tr><td colspan="6">No slow requests recorded yet.</td></tr>'}
  </table>
</div>
</div>
"""
    return shell("Logs", body, "Logs")


@app.errorhandler(Exception)
def handle_uncaught_error(error):
    if isinstance(error, HTTPException):
        return error

    print(f"Unhandled dashboard error: {error}")
    body = f"""
{topbar('System')}
<div class="panel">
  <h2>NetSpecter hit a recoverable error</h2>
  <p>The dashboard stayed online, but this page could not finish loading.</p>
  <p><b>Error:</b> An internal error occurred while loading this page.</p>
  <p><a href="/system">Open System Health</a></p>
</div>
"""
    return shell("Recoverable Error", body, "System"), 500


if __name__ == "__main__":
    init_db()
    c = cfg()
    app.run(
        host=str(c.get("web_host", "0.0.0.0") or "0.0.0.0"),
        port=int(c.get("web_port", 5050) or 5050),
    )
