#!/usr/bin/env python3
"""
NetSpecter Live Packet Collector

What this file does:
- Installs private nftables bridge counters for each LAN device IP.
- Reads accurate kernel-counted upload and download byte differences.
- Calculates live speed per device.
- Saves live speed into SQLite.
- Saves device details like IP, MAC, vendor and type.
- Saves measured traffic bytes for each collection interval.
- Ignores the gateway/router so it does not appear as the top user.
- Imports AdGuard Home DNS querylog into dns_querylog.
- Imports AdGuard Home client names for friendly device labels.
- Classifies domains into application categories for Top Applications.
- Estimates bytes for selected apps from device-specific delivery DNS answers.

Important:
- Speeds in live_device_speed are stored as BYTES per second.
- live_bps in traffic_intervals is stored as BITS per second.
- dns_querylog powers Top Applications and per-device application views.
"""

import atexit
import fnmatch
import ipaddress
import json
import os
import re
import signal
import socket
import smtplib
import sqlite3
import ssl
import subprocess
import threading
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote, urlsplit

from netspecter_ids import (
    fast_log_alerts_from_text,
    ingest_eve_incremental,
    ids_endpoint_ip,
    is_default_suppressed_signature,
    maybe_vacuum_ids,
    prune_ids_history,
    recent_structured_alerts,
)
from netspecter_anomaly import prune_anomalies, run_anomaly_cycle
from services.microsoft365_endpoints_service import cached_microsoft365_domain_mappings
from netspecter_config_monitor import monitor_once, prune_config_changes
from netspecter_db import init_db as init_shared_db
from netspecter_incidents import build_incidents_once, prune_incidents
from netspecter_incidents import (
    ensure_schema as ensure_incident_schema,
    find_or_create_incident,
    normalize_incident_ip,
    normalize_incident_signature,
    stable_incident_key,
)
from netspecter_internet_quality import collect_quality_summary, insert_quality_summary, maybe_vacuum_quality, prune_quality_history
import netspecter_live_snapshot as live_snapshot
from netspecter_threat_intel import correlate_once, prune_threat_intel, refresh_feeds
from netspecter_config import save_cfg as save_shared_cfg

try:
    import requests
except Exception:
    requests = None

try:
    import fcntl
except Exception:
    fcntl = None

try:
    import paho.mqtt.client as mqtt
except Exception:
    mqtt = None

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception


# ---------------------------------------------------
# File paths
# ---------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent


def configured_path(env_name, default_path, local_path):
    override = os.environ.get(env_name)
    if override:
        return Path(override)

    default = Path(default_path)
    if default.exists() or default.parent.exists():
        return default

    return Path(local_path)


CONFIG_DIR = configured_path("NETSPECTER_CONFIG_ROOT", "/etc/netspecter", BASE_DIR)
DATA_DIR = configured_path("NETSPECTER_DATA_ROOT", "/var/lib/netspecter", BASE_DIR)
CONFIG_PATH = CONFIG_DIR / "config.json"
DB_PATH = DATA_DIR / "netspecter.db"
DNS_DB_PATH = DATA_DIR / "netspecter_dns.db"
TRAFFIC_DB_PATH = DATA_DIR / "netspecter_traffic.db"
OUI_PATH = DATA_DIR / "oui_cache.json"
SYSTEM_OUI_PATH = Path("/usr/share/ieee-data/oui.txt")
SECRET_KEY_PATH = CONFIG_DIR / "secret.key"
COLLECTOR_LOCK_PATH = DATA_DIR / "collector.lock"
SURICATA_FAST_LOG = Path("/var/log/suricata/fast.log")
SURICATA_EVE_LOG = Path("/var/log/suricata/eve.json")
IDS_EMAIL_STATE_PATH = DATA_DIR / "ids_email_state.json"
ENCRYPTED_PREFIX = "enc:"
SENSITIVE_CONFIG_KEYS = {"adguard_pass", "unifi_password", "smtp_password", "snmp_community", "mqtt_password"}
collector_lock_handle = None


# ---------------------------------------------------
# Default settings
# ---------------------------------------------------
# packet_iface:
#   The bridge whose forwarded device traffic is counted by nftables.
#   Example: br0.
#
# ignore_ips:
#   IPs excluded from device totals.
#   Usually your gateway/router.
#
# adguard_url/user/pass:
#   Used to pull /control/querylog from AdGuard Home.
#
# adguard_querylog_interval_seconds:
#   How often AdGuard querylog is imported.
# ---------------------------------------------------

DEFAULT_CONFIG = {
    "lan_prefix": "192.168.1.",
    "packet_iface": "br0",
    "traffic_retention_days": 60,
    "dns_retention_days": 60,
    "gateway_ip": "",
    "ignore_ips": [],
    "remote_map_geo_lookups_per_run": 50,
    "dns_map_geo_lookups_per_run": 10,
    "site_application_mappings": [
        {"application": "Nextcloud", "category": "File Sharing & Storage", "ip": "192.168.99.4"}
    ],
    "site_domain_mappings": [],
    "microsoft365_endpoint_import_enabled": False,
    "microsoft365_endpoint_instance": "worldwide",
    "microsoft365_endpoint_cache_hours": 168,

    "adguard_url": "http://127.0.0.1",
    "adguard_user": "admin",
    "adguard_pass": "",
    "adguard_querylog_interval_seconds": 15,
    "unifi_enabled": False,
    "unifi_connector_url": "",
    "unifi_site_id": "",
    "unifi_username": "",
    "unifi_password": "",
    "unifi_skip_tls_verify": False,
    "ids_unknown_only": False,
    "ids_excluded_ips": [],
    "ids_exceptions": [],
    "ids_banned_ips": [],
    "ids_auto_ban_enabled": False,
    "ids_email_enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_security": "starttls",
    "smtp_username": "",
    "smtp_password": "",
    "smtp_from": "",
    "smtp_to": "",
    "ids_email_cooldown_minutes": 480,
    "ids_alert_retention_days": 45,
    "ids_detail_retention_days": 45,
    "ids_file_retention_days": 45,
    "ids_raw_flow_retention_hours": 0,
    "ids_structured_max_records": 200000,
    "ids_min_free_mb": 512,
    "internet_quality_targets": ["1.1.1.1", "8.8.8.8"],
    "internet_quality_dns_server": "",
    "internet_quality_external_dns_enabled": True,
    "internet_quality_external_dns_server": "1.1.1.1",
    "internet_quality_dns_query": "example.com",
    "internet_quality_interval_seconds": 60,
    "internet_quality_ping_count": 3,
    "internet_quality_ping_timeout_seconds": 2,
    "internet_quality_retention_days": 60,
    "internet_quality_max_rows": 50000,
    "internet_quality_min_free_mb": 512,
    "config_change_monitor_interval_seconds": 300,
    "config_change_retention_days": 180,
    "config_change_max_events": 100000,
    "config_change_min_free_mb": 512,
    "threat_intel_enabled": True,
    "threat_intel_sources": ["spamhaus_drop"],
    "threat_intel_refresh_hours": 24,
    "threat_intel_download_timeout_seconds": 15,
    "threat_intel_max_feed_bytes": 2000000,
    "threat_intel_correlation_days": 14,
    "threat_intel_retention_days": 30,
    "threat_intel_max_correlations": 100000,
    "threat_intel_min_free_mb": 512,
    "incident_trigger_severities": [1, 2],
    "incident_window_minutes": 15,
    "incident_dedupe_minutes": 60,
    "incident_max_per_device_per_day": 20,
    "incident_retention_days": 365,
    "incident_max_records": 50000,
    "incident_min_free_mb": 512,
    "anomaly_learning_only": True,
    "anomaly_min_learning_days": 7,
    "anomaly_recommended_learning_days": 14,
    "anomaly_interval_seconds": 3600,
    "anomaly_upload_min_mb": 250,
    "anomaly_upload_multiplier": 4,
    "anomaly_destination_multiplier": 3,
    "anomaly_dns_multiplier": 4,
    "anomaly_new_ip_min": 25,
    "anomaly_excluded_devices": [],
    "anomaly_device_type_thresholds": {},
    "anomaly_retention_days": 180,
    "anomaly_max_events": 100000,
    "anomaly_min_free_mb": 512,
    "snmp_enabled": False,
    "snmp_targets": "",
    "snmp_version": "2c",
    "snmp_port": 161,
    "snmp_community": "",
    "snmp_poll_seconds": 60,
    "mqtt_enabled": False,
    "mqtt_host": "",
    "mqtt_port": 1883,
    "mqtt_tls": False,
    "mqtt_username": "",
    "mqtt_password": "",
    "mqtt_client_id": "netspecter",
    "mqtt_subscribe_topics": "",
}


# ---------------------------------------------------
# Kernel counter state
# ---------------------------------------------------

imported_dns_keys = set()
db_write_lock = threading.RLock()
nft_config_refresh_event = threading.Event()
adguard_client_names = {}
adguard_client_names_lock = threading.Lock()
adguard_client_names_refreshed_at = 0.0
unifi_clients_refreshed_at = 0.0
UNIFI_SESSION_TTL_SECONDS = 900
UNIFI_RATE_LIMIT_COOLDOWN_SECONDS = 60
unifi_session_cache = {}
NFT_FAMILY = "bridge"
NFT_TABLE = "netspecter"
NFT_CHAIN = "forward"
nft_config_signature = None
nft_previous_counters = {}
nft_previous_estimated_counters = {}
nft_active_ips = set()
live_traffic_today = {"day": "", "downloaded_mb": 0.0, "uploaded_mb": 0.0, "total_mb": 0.0}
estimated_app_targets = {}
estimated_targets_lock = threading.Lock()
last_dns_map_refresh = 0.0
oui_vendor_cache = None
GEOLOCATION_REFRESH_SECONDS = 3600
DNS_MAP_REFRESH_SECONDS = 300
DNS_MAP_DOMAIN_LIMIT = 50
DNS_MAP_IP_LIMIT = 120
DNS_MAP_GEO_LOOKUPS_PER_RUN = 3
ESTIMATED_APP_NFT_TARGET_LIMIT = 100
NFT_SIGNATURE_REFRESH_SECONDS = 900
ADGUARD_CLIENT_REFRESH_SECONDS = 300
UNIFI_CLIENT_REFRESH_SECONDS = 1800
MICROSOFT365_MAPPING_CACHE = {"ts": 0.0, "enabled": None, "items": []}
MONITORED_APP_DOMAIN_KEYS = {
    "Nextcloud": ("nextcloud.com", "owncloud.com"),
    "YouTube": ("googlevideo.com",),
    "Netflix": ("nflxvideo.net", "netflix.com"),
    "TikTok": ("tiktokcdn.com", "tiktokv.com", "byteoversea.com"),
    "Facebook": ("fbcdn.net", "facebook.com"),
    "Instagram": ("cdninstagram.com", "instagram.com"),
    "WhatsApp": ("whatsapp.net", "whatsapp.com"),
    "OneDrive": ("onedrive.com", "onedrive.live.com", "storage.live.com"),
    "SharePoint Documents": ("sharepoint.com", "sharepoint-df.com"),
    "Outlook": ("outlook.office.com", "outlook.office365.com", "outlook.live.com", "outlook.com", "protection.outlook.com"),
    "Microsoft Teams": ("teams.microsoft.com", "teams.live.com", "trouter.teams.microsoft.com", "trouter.io", "skype.com", "lync.com"),
    "Microsoft Defender": ("wdcp.microsoft.com", "wd.microsoft.com", "wdcpalt.microsoft.com", "defender.microsoft.com", "security.microsoft.com", "smartscreen.microsoft.com"),
    "Microsoft Authentication": ("login.microsoftonline.com", "login.live.com", "microsoftonline.com", "msauth.net", "msauthimages.net", "msftauth.net", "aadcdn.microsoftonline-p.com"),
    "Microsoft 365": ("microsoft365.com", "office.com", "office365.com", "office.net", "officeapps.live.com"),
    "Azure": ("azure.com", "azurewebsites.net", "blob.core.windows.net", "queue.core.windows.net", "table.core.windows.net", "file.core.windows.net"),
    "Microsoft CDN": ("msedge.net", "azureedge.net", "akamaized.net"),
    "Windows Update": (
        "windowsupdate.com",
        "windowsupdate.microsoft.com",
        "update.microsoft.com",
        "download.windowsupdate.com",
        "delivery.mp.microsoft.com",
        "dl.delivery.mp.microsoft.com",
        "emdl.ws.microsoft.com",
        "do.dsp.mp.microsoft.com",
        "tsfe.trafficshaping.dsp.mp.microsoft.com",
        "download.microsoft.com",
        "officecdn.microsoft.com",
    ),
    "Spotify": ("spotify.com", "scdn.co", "spotifycdn.com"),
    "Steam": ("steamserver.net", "steamcontent.com", "steampowered.com"),
    "Twitter / X": ("twitter.com", "twimg.com", "x.com"),
    "Snapchat": ("snapchat.com", "sc-cdn.net"),
    "Discord": ("discord.com", "discordapp.com", "discordcdn.com"),
    "Twitch": ("twitch.tv", "ttvnw.net"),
    "Disney+": ("disneyplus.com", "dssott.com", "bamgrid.com"),
    "Prime Video": ("primevideo.com", "aiv-cdn.net"),
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
    "Grok": ("grok.com", "x.ai"),
    "DeepSeek": ("deepseek.com",),
    "Meta AI": ("meta.ai",),
    "Mistral": ("mistral.ai", "chat.mistral.ai"),
    "Qwen": ("qwen.ai", "dashscope.aliyuncs.com"),
    "Kimi AI": ("kimi.com", "moonshot.cn"),
    "Character.AI": ("character.ai",),
    "Poe": ("poe.com",),
    "YouChat": ("you.com",),
    "Hugging Face": ("huggingface.co", "hf.co", "api-inference.huggingface.co"),
    "Replit AI": ("replit.com",),
    "Cursor AI": ("cursor.com", "cursor.sh"),
    "Windsurf": ("windsurf.com",),
    "Continue": ("continue.dev",),
    "Tabnine": ("tabnine.com",),
    "Codeium": ("codeium.com",),
    "Amazon Q": ("amazonq.aws", "qbusiness.aws.dev"),
    "Watsonx": ("watsonx.ai",),
}
SITE_MONITORED_APP_IPS = {
    "Nextcloud": ("192.168.99.4",),
}


def acquire_collector_lock():
    """Allow only one collector writer to update measured traffic."""
    global collector_lock_handle
    if fcntl is None:
        return True
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    handle = COLLECTOR_LOCK_PATH.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        print("Another NetSpecter collector is already running; exiting.")
        return False

    collector_lock_handle = handle
    return True


def load_json(path, default):
    """Safely load a JSON file. If it fails, return the default."""
    try:
        p = Path(path)
        if p.exists():
            return json.loads(p.read_text())
    except Exception as e:
        print(f"JSON load failed for {path}: {e}")

    return default


def cfg():
    """Load config.json and merge it with defaults."""
    data = DEFAULT_CONFIG.copy()
    loaded = load_json(CONFIG_PATH, {})
    if isinstance(loaded, dict):
        data.update(loaded)
    for key in SENSITIVE_CONFIG_KEYS:
        if key in data:
            data[key] = decrypt_config_value(data.get(key))
    return data


def fernet():
    if not Fernet or not SECRET_KEY_PATH.exists():
        return None
    try:
        return Fernet(SECRET_KEY_PATH.read_text().strip().encode())
    except Exception as e:
        print(f"Encryption setup failed: {e}")
        return None


def decrypt_config_value(value):
    text = str(value or "")
    if not text.startswith(ENCRYPTED_PREFIX):
        return text
    f = fernet()
    if not f:
        raise RuntimeError("cryptography package is required to decrypt stored passwords")
    try:
        return f.decrypt(text[len(ENCRYPTED_PREFIX):].encode()).decode()
    except InvalidToken:
        print("Config password decrypt failed: invalid encryption key")
        return ""
    except Exception as e:
        print(f"Config password decrypt failed: {e}")
        return ""


def cfg_list(value):
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value or "").split(",") if x.strip()]


def default_gateway_from_prefix(prefix):
    text = str(prefix or "").strip()
    if text.endswith("."):
        return text + "1"
    return ""


def ignored_ips(config=None):
    c = config or cfg()
    ips = cfg_list(c.get("ignore_ips", []))
    gateway = str(c.get("gateway_ip", "") or "").strip() or default_gateway_from_prefix(c.get("lan_prefix"))
    if gateway and gateway not in ips:
        ips.insert(0, gateway)
    return set(ips)


def ip_identifier(value):
    """Return a normalized device IP, or an empty string for non-IP identifiers."""
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def adguard_name_for_ip(ip):
    with adguard_client_names_lock:
        return adguard_client_names.get(str(ip or "").strip(), "")


def parse_adguard_client_names(payload):
    """Extract client display names from AdGuard persistent and runtime clients."""
    if not isinstance(payload, dict):
        return {}

    names = {}

    def add_name(item, identifiers):
        if not isinstance(item, dict):
            return
        name = str(item.get("name") or "").strip()
        if not name:
            return
        for identifier in identifiers:
            ip = ip_identifier(identifier)
            if ip:
                names[ip] = name

    # Auto-discovered names are useful fallback labels.
    for item in payload.get("auto_clients", []) or []:
        if isinstance(item, dict):
            identifiers = [item.get("ip"), *(item.get("ids") or []), *(item.get("ip_addrs") or [])]
            add_name(item, identifiers)

    # Explicitly configured clients take precedence over runtime discovery.
    for item in payload.get("clients", []) or []:
        if isinstance(item, dict):
            identifiers = [*(item.get("ip_addrs") or []), *(item.get("ids") or [])]
            add_name(item, identifiers)

    return names


def refresh_adguard_client_names(config):
    """Refresh friendly labels infrequently; manual UI overrides remain authoritative."""
    global adguard_client_names, adguard_client_names_refreshed_at
    now_monotonic = time.monotonic()
    if now_monotonic - adguard_client_names_refreshed_at < ADGUARD_CLIENT_REFRESH_SECONDS:
        return

    base = str(config.get("adguard_url", "")).rstrip("/")
    if not base:
        return

    try:
        res = requests.get(
            f"{base}/control/clients",
            auth=(config.get("adguard_user", "admin"), config.get("adguard_pass", "")),
            timeout=10,
        )
        if res.status_code != 200:
            print(f"AdGuard client name import failed: HTTP {res.status_code}")
            return
        names = parse_adguard_client_names(res.json())
    except Exception as e:
        print(f"AdGuard client name import failed: {e}")
        return

    with adguard_client_names_lock:
        adguard_client_names = names
    adguard_client_names_refreshed_at = now_monotonic

    if not names:
        return
    con = None
    lock_acquired = False
    try:
        updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lock_acquired = db_write_lock.acquire(timeout=0.2)
        if not lock_acquired:
            print("AdGuard client name database update skipped: writer busy")
            return
        con = connect_db(timeout=0.5, busy_timeout_ms=250)
        con.executemany(
            "UPDATE devices SET name=? WHERE ip=?",
            [(name, ip) for ip, name in names.items()],
        )
        # Older builds could auto-lock a discovered device while its label was still its IP.
        con.executemany(
            """
            UPDATE device_overrides
            SET name=?, updated_at=?
            WHERE ip=? AND (name IS NULL OR TRIM(name)='' OR name=ip)
            """,
            [(name, updated_at, ip) for ip, name in names.items()],
        )
        con.commit()
    except Exception as e:
        if con:
            con.rollback()
        print(f"AdGuard client name database update failed: {e}")
    finally:
        if con:
            con.close()
        if lock_acquired:
            db_write_lock.release()


def remember_adguard_client_activity(client, ts):
    """Create or label DNS-visible IP clients without overwriting manual UI overrides."""
    ip = ip_identifier(client)
    name = adguard_name_for_ip(ip)
    if not ip or not name:
        return
    run_sql(
        """
        INSERT INTO devices (ip, name, status, first_seen, last_seen)
        VALUES (?, ?, 'Active', ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            name=excluded.name,
            last_seen=CASE
                WHEN devices.last_seen IS NULL OR devices.last_seen < excluded.last_seen
                THEN excluded.last_seen
                ELSE devices.last_seen
            END
        """,
        (ip, name, ts, ts),
    )


def unifi_connector_bases(config):
    base = str(config.get("unifi_connector_url", "") or "").strip().rstrip("/")
    if not base:
        return []
    if "/proxy/network/integration" not in base and "/network/integration" in base:
        base = base.replace("/network/integration", "/proxy/network/integration", 1)
    return [base]


def unifi_legacy_base(base):
    origin = unifi_origin(base)
    if not origin:
        return ""
    return f"{origin}/proxy/network"


def unifi_legacy_site_endpoint(base):
    legacy_base = unifi_legacy_base(base)
    return f"{legacy_base}/api/self/sites" if legacy_base else ""


def unifi_site_name(site):
    if not isinstance(site, dict):
        return ""
    for key in ("name", "site", "site_name"):
        value = str(site.get(key, "") or "").strip()
        if value:
            return value
    return ""


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
    ]
    return any(str(value).strip().lower() == selected for value in values if str(value).strip())


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
        raise RuntimeError("UniFi login is being rate limited. Try again shortly.")
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
        result = session.get(url, params=params, headers=request_headers, timeout=5, verify=verify)
        if result.status_code == 401:
            unifi_session_cache.pop(unifi_session_key(config, base), None)
            session, login = unifi_cached_session(config, base, headers, verify)
            if login is not None:
                return login
            cached = unifi_session_cache.get(unifi_session_key(config, base), {})
            request_headers = dict(headers)
            request_headers.update(unifi_token_headers(cached.get("token")))
            return session.get(url, params=params, headers=request_headers, timeout=5, verify=verify)
        if result.status_code == 429:
            cached = unifi_session_cache.get(unifi_session_key(config, base))
            if cached:
                cached["blocked_until"] = time.monotonic() + UNIFI_RATE_LIMIT_COOLDOWN_SECONDS
        return result
    raise RuntimeError("UniFi credentials are not configured.")


def refresh_unifi_clients(config):
    """Optionally import connected client inventory through the official UniFi API."""
    global unifi_clients_refreshed_at
    if not config.get("unifi_enabled"):
        return
    now_monotonic = time.monotonic()
    if now_monotonic - unifi_clients_refreshed_at < UNIFI_CLIENT_REFRESH_SECONDS:
        return

    bases = unifi_connector_bases(config)
    site_id = quote(str(config.get("unifi_site_id", "") or "").strip(), safe="")
    if not bases or not site_id:
        return

    imported = 0
    named_imported = 0
    device_rows = []
    override_rows = []
    offset = 0
    working_base = None
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        while True:
            payload = None
            failure = ""
            for base in ([working_base] if working_base else bases):
                response = unifi_request(
                    config,
                    base,
                    f"{base}/v1/sites/{site_id}/clients",
                    params={"offset": offset, "limit": 100},
                )
                if response.status_code != 200:
                    legacy_sites = unifi_request(config, base, unifi_legacy_site_endpoint(base))
                    if legacy_sites.status_code != 200:
                        failure = f"HTTP {response.status_code}"
                        continue
                    try:
                        sites_payload = legacy_sites.json()
                    except ValueError:
                        failure = "legacy site response was not JSON"
                        continue
                    sites = sites_payload.get("data", []) if isinstance(sites_payload, dict) else []
                    selected_site = next((site for site in sites if unifi_site_matches(site, config.get("unifi_site_id"))), None)
                    if not selected_site:
                        failure = "legacy site match failed"
                        continue
                    response = unifi_request(
                        config,
                        base,
                        unifi_legacy_client_endpoint(unifi_site_name(selected_site), base),
                    )
                    if response.status_code != 200:
                        failure = f"HTTP {response.status_code}"
                        continue
                try:
                    payload = response.json()
                    working_base = base
                    break
                except ValueError:
                    failure = "response was not JSON"
            if payload is None:
                print(f"UniFi client import failed: {failure}")
                return
            clients = payload.get("data", []) if isinstance(payload, dict) else []
            if not isinstance(clients, list):
                return
            for client in clients:
                if not isinstance(client, dict):
                    continue
                ip = ip_identifier(client.get("ipAddress"))
                if not ip:
                    ip = ip_identifier(client.get("ip"))
                if not ip:
                    continue
                name = str(client.get("name") or client.get("hostname") or ip).strip()
                has_unifi_name = name != ip
                mac = str(client.get("macAddress") or client.get("mac") or "").strip().upper()
                vendor = vendor_from_mac(mac)
                dtype = classify_device(vendor)
                connected = parse_adguard_time(client.get("connectedAt")) if client.get("connectedAt") else now
                device_rows.append((ip, name, mac, vendor, dtype, connected, now))
                if has_unifi_name:
                    named_imported += 1
                    # Replace an automatically locked placeholder, but preserve a user-entered name.
                    override_rows.append((name, now, ip))
                imported += 1
            count = int(payload.get("count", len(clients)) or 0)
            total = int(payload.get("totalCount", count) or count)
            if count <= 0:
                break
            offset += count
            if not clients or offset >= total:
                break
        if device_rows:
            con = None
            try:
                with db_write_lock:
                    con = connect_db(timeout=2, busy_timeout_ms=1000)
                    con.executemany(
                        """
                        INSERT INTO devices (ip, name, mac, vendor, device_type, status, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, 'Active', ?, ?)
                        ON CONFLICT(ip) DO UPDATE SET
                            name=CASE WHEN excluded.name != excluded.ip THEN excluded.name ELSE devices.name END,
                            mac=CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
                            vendor=CASE WHEN excluded.mac != '' THEN excluded.vendor ELSE devices.vendor END,
                            device_type=CASE
                                WHEN devices.device_type IS NULL OR devices.device_type='' OR devices.device_type='Unknown'
                                THEN excluded.device_type ELSE devices.device_type END,
                            last_seen=excluded.last_seen
                        """,
                        device_rows,
                    )
                    if override_rows:
                        con.executemany(
                            """
                            UPDATE device_overrides
                            SET name=?, updated_at=?
                            WHERE ip=? AND (name IS NULL OR TRIM(name)='' OR name=ip)
                            """,
                            override_rows,
                        )
                    con.commit()
            except Exception as error:
                if con:
                    con.rollback()
                print(f"UniFi client database update failed: {error}")
                return
            finally:
                if con:
                    con.close()
        unifi_clients_refreshed_at = now_monotonic
        print(f"UniFi connected clients imported: {imported} ({named_imported} named)")
    except Exception as e:
        print(f"UniFi client import failed: {e}")


def connect_db(timeout=30, busy_timeout_ms=30000):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=timeout)
    con.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    attached = {row[1] for row in con.execute("PRAGMA database_list").fetchall()}
    if "dnsdb" not in attached:
        con.execute(f"ATTACH DATABASE '{str(DNS_DB_PATH).replace(chr(39), chr(39) + chr(39))}' AS dnsdb")
        con.execute("PRAGMA dnsdb.journal_mode=WAL")
        con.execute(f"PRAGMA dnsdb.busy_timeout={int(busy_timeout_ms)}")
    if "trafficdb" not in attached:
        con.execute(f"ATTACH DATABASE '{str(TRAFFIC_DB_PATH).replace(chr(39), chr(39) + chr(39))}' AS trafficdb")
        con.execute("PRAGMA trafficdb.journal_mode=WAL")
        con.execute(f"PRAGMA trafficdb.busy_timeout={int(busy_timeout_ms)}")
    return con


def positive_int(value, default, minimum=1):
    try:
        return max(minimum, int(value or default))
    except Exception:
        return max(minimum, int(default))


def log_slow_loop(name, elapsed, threshold=2.0):
    if elapsed >= threshold:
        print(f"{name} loop took {elapsed:.2f}s")


def run_timed_step(name, func, *args, threshold=2.0):
    started = time.monotonic()
    result = func(*args)
    elapsed = time.monotonic() - started
    if elapsed >= threshold:
        print(f"{name} step took {elapsed:.2f}s")
    return result


def private_mac_address(mac):
    """Return True for locally administered MACs used by mobile privacy features."""
    text = str(mac or "").strip().replace(":", "").replace("-", "")
    try:
        return len(text) >= 2 and bool(int(text[:2], 16) & 0x02)
    except ValueError:
        return False


def load_oui_vendors():
    """Load shipped overrides plus Debian's IEEE OUI list once per collector process."""
    global oui_vendor_cache
    if oui_vendor_cache is not None:
        return oui_vendor_cache

    vendors = load_json(OUI_PATH, {})
    try:
        for line in SYSTEM_OUI_PATH.read_text(errors="ignore").splitlines():
            if "(hex)" not in line:
                continue
            prefix, vendor = line.split("(hex)", 1)
            key = prefix.strip().replace("-", "").upper()
            if len(key) == 6 and vendor.strip():
                vendors.setdefault(key, vendor.strip())
    except Exception:
        pass
    oui_vendor_cache = vendors
    return vendors


def vendor_from_mac(mac):
    """Look up a hardware vendor, without guessing from randomized mobile MACs."""
    if not str(mac or "").strip():
        return "Unknown Vendor"
    if private_mac_address(mac):
        return "Private / Random MAC"
    key = str(mac).upper().replace(":", "").replace("-", "")[:6]
    return load_oui_vendors().get(key, "Unknown Vendor")


def classify_device(vendor=""):
    """
    Basic device classification based on MAC vendor.

    This gives sensible default icons/types before you manually rename devices.
    Manual changes in the web UI are protected by device_overrides and will not
    be overwritten by the collector.
    """
    text = str(vendor or "").lower()

    if any(x in text for x in ["ubiquiti", "unifi", "mikrotik", "tp-link", "netgear", "cisco"]):
        return "Network Device"

    if any(x in text for x in ["dahua", "ezviz", "hikvision", "camera"]):
        return "Camera"

    if any(x in text for x in ["epson", "canon", "brother", "hewlett packard", "hp inc", "printer"]):
        return "Printer"

    if any(x in text for x in ["apple"]):
        return "Apple Device"

    if any(x in text for x in ["xiaomi", "samsung", "huawei", "oppo", "vivo", "oneplus", "honor"]):
        return "Mobile Device"

    if any(x in text for x in ["proxmox", "server"]):
        return "Server"

    if any(x in text for x in ["micro-star", "gigabyte", "intel", "dell", "lenovo", "asustek", "msi"]):
        return "Computer"

    if any(x in text for x in ["google", "chromecast", "roku", "lg", "sony", "hisense", "tv"]):
        return "Media Device"

    if any(x in text for x in ["espressif", "tuya", "sonoff", "shelly"]):
        return "IoT"

    return "Unknown"


def app_from_domain(domain):
    """
    Convert a DNS domain into a friendly app/category name.

    Examples:
    - googlevideo.com -> YouTube
    - tiktokcdn.com -> TikTok
    - steamserver.net -> Steam
    - teams.microsoft.com -> Microsoft Teams
    """
    d = str(domain or "").lower().strip(".")
    if not d:
        return "Other"
    if d == "x.com" or d.endswith(".x.com"):
        return "Twitter / X"
    m365_app = microsoft365_app_from_domain(d)
    if m365_app:
        return m365_app

    mapping = {
        "YouTube": ["youtube", "googlevideo", "ytimg"],
        "TikTok": ["tiktok", "tiktokcdn", "tiktokv", "byteoversea", "bytedance"],
        "Netflix": ["netflix", "nflx", "nrdp"],
        "Spotify": ["spotify", "spclient"],
        "Steam": ["steam", "steampowered", "steamserver"],
        "Roblox": ["roblox"],
        "ChatGPT": ["chatgpt", "chat.openai"],
        "OpenAI API": ["api.openai", "platform.openai"],
        "OpenAI Authentication": ["auth.openai"],
        "OpenAI Static Assets": ["oaistatic"],
        "OpenAI Uploaded Content": ["oaiusercontent"],
        "Sora": ["sora.com"],
        "Microsoft Copilot": ["copilot.microsoft"],
        "GitHub Copilot": ["githubcopilot"],
        "Claude": ["claude.ai", "anthropic"],
        "Gemini": ["gemini.google", "generativelanguage.googleapis"],
        "Perplexity": ["perplexity.ai"],
        "DeepSeek": ["deepseek"],
        "GitHub": ["github"],
        "Facebook": ["facebook", "fbcdn", "messenger"],
        "Instagram": ["instagram", "cdninstagram"],
        "WhatsApp": ["whatsapp"],
        "Twitter / X": ["twitter", "twimg"],
        "Snapchat": ["snapchat", "sc-cdn"],
        "Discord": ["discord", "discordapp", "discordcdn"],
        "Twitch": ["twitch", "ttvnw"],
        "Disney+": ["disneyplus", "dssott", "bamgrid"],
        "Prime Video": ["primevideo", "aiv-cdn"],
        "Nextcloud": ["nextcloud", "owncloud"],
        "OneDrive": ["onedrive", "storage.live"],
        "SharePoint Documents": ["sharepoint", "sharepoint-df"],
        "Outlook": ["outlook", "protection.outlook"],
        "Microsoft Teams": ["teams", "trouter", "skype", "lync"],
        "Microsoft Defender": ["wdcp.microsoft", "wd.microsoft", "wdcpalt.microsoft", "defender.microsoft", "security.microsoft", "smartscreen.microsoft"],
        "Microsoft Authentication": ["login.microsoftonline", "login.live", "microsoftonline", "msauth", "msftauth", "aadcdn.microsoftonline-p"],
        "Microsoft 365": ["microsoft365", "office.com", "office365", "office.net", "officeapps.live"],
        "Azure": ["azure.com", "azurewebsites", "blob.core.windows", "queue.core.windows", "table.core.windows", "file.core.windows"],
        "Windows Update": ["windowsupdate", "update.microsoft", "delivery.mp.microsoft", "emdl.ws.microsoft", "dsp.mp.microsoft", "download.microsoft", "officecdn"],
        "Microsoft CDN": ["msedge", "azureedge", "akamaized"],
        "Microsoft Cloud Services": ["microsoft", "msftconnecttest"],
        "Dell": ["dell.com", "dellcdn", "dellsupport", "delltechnologies"],
        "Lenovo": ["lenovo.com", "thinkbios"],
        "HP": ["hp.com", "hpe.com", "hpcloud.hp"],
        "ASUS": ["asus.com", "asuscomm"],
        "Acer": ["acer.com", "global.acer"],
        "MSI": ["msi.com"],
        "Gigabyte": ["gigabyte.com"],
        "Intel": ["intel.com"],
        "AMD": ["amd.com"],
        "NVIDIA": ["nvidia.com", "geforce.com"],
        "Realtek": ["realtek.com"],
        "Broadcom": ["broadcom.com"],
        "Qualcomm": ["qualcomm.com"],
        "Apple": ["apple", "icloud", "aaplimg"],
        "Google": ["google", "gstatic", "googleapis", "androidtvchannels"],
        "Plex": ["plex"],
        "Samsung": ["samsung"],
        "Cloudflare": ["cloudflare"],
        "Amazon": ["amazon", "aws", "cloudfront"],
        "Mozilla": ["mozilla", "firefox"],
        "Gaming": ["xbox", "playstation", "epicgames", "battle.net"],
        "Security": ["telemetry", "analytics", "logs"],
    }

    for app, keys in mapping.items():
        if any(k in d for k in keys):
            return app

    parts = d.split(".")
    if len(parts) >= 2:
        return parts[-2].title()

    return "Other"


def microsoft365_app_from_domain(domain):
    c = cfg()
    if not c.get("microsoft365_endpoint_import_enabled"):
        return ""
    now = time.time()
    if now - MICROSOFT365_MAPPING_CACHE["ts"] > 300 or MICROSOFT365_MAPPING_CACHE["enabled"] is not True:
        MICROSOFT365_MAPPING_CACHE.update({
            "ts": now,
            "enabled": True,
            "items": cached_microsoft365_domain_mappings(c.get("microsoft365_endpoint_cache_hours", 168)),
        })
    for row in MICROSOFT365_MAPPING_CACHE["items"]:
        if domain_pattern_matches(str(row.get("domain") or ""), domain):
            return str(row.get("application") or "").strip()
    return ""


def is_blocked_reason(reason):
    """
    Return 1 only if AdGuard actually blocked/filtered the query.
    """

    r = str(reason or "").strip().lower()

    if not r:
        return 0

    # AdGuard allowed reasons
    if r.startswith("notfiltered"):
        return 0

    # Actual blocked/filter reasons
    blocked_markers = [
        "filteredblacklist",
        "filteredblockedservice",
        "filteredsafebrowsing",
        "filteredparental",
        "filteredsafesearch",
        "filteredinvalid",
        "blocked",
        "blacklist",
        "blockedservice",
    ]

    return 1 if any(marker in r for marker in blocked_markers) else 0

def parse_adguard_time(value):
    """Convert AdGuard timestamp into YYYY-MM-DD HH:MM:SS."""
    text = str(value or "")

    if not text:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        # AdGuard sometimes has nanosecond precision; Python wants max 6 digits.
        if "." in text:
            left, right = text.split(".", 1)

            if "+" in right:
                frac, tz = right.split("+", 1)
                text = left + "." + frac[:6] + "+" + tz
            elif "-" in right[1:]:
                # Negative timezone offset.
                pos = right[1:].find("-") + 1
                frac = right[:pos]
                tz = right[pos:]
                text = left + "." + frac[:6] + tz

        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    """
    Create required database tables if they do not exist.

    The web app and collector share the same SQLite schema; keep the DDL in
    netspecter_db so installs cannot drift depending on which process starts first.
    """
    init_shared_db()


def run_sql(sql, params=(), timeout=30, busy_timeout_ms=30000, retries=4):
    """Run a database write safely."""
    for attempt in range(retries):
        con = None
        try:
            with db_write_lock:
                con = connect_db(timeout=timeout, busy_timeout_ms=busy_timeout_ms)
                con.execute(sql, params)
                con.commit()
                con.close()
            return
        except sqlite3.OperationalError as e:
            if con:
                con.close()
            if "database is locked" in str(e).lower() and attempt < retries - 1:
                time.sleep(0.25 * (attempt + 1))
                continue
            print(f"DB write failed: {e}")
            return
        except Exception as e:
            if con:
                con.close()
            print(f"DB write failed: {e}")
            return


def store_telemetry(source, target, metric, value):
    run_sql(
        """
        INSERT INTO telemetry_readings (source, target, metric, value, ts)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            str(source or "")[:40],
            str(target or "")[:180],
            str(metric or "")[:180],
            str(value or "")[:1000],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )


def snmpget_value(target, community, oid, port=161):
    command = [
        "snmpget",
        "-v2c",
        "-c",
        str(community),
        "-Oqv",
        f"{target}:{int(port)}",
        oid,
    ]
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return (result.stdout or "").strip().strip('"')
    except FileNotFoundError:
        return "snmpget not installed"
    except Exception as e:
        print(f"SNMP poll failed for {target}: {e}")
        return ""


def poll_snmp_targets(config):
    if not config.get("snmp_enabled"):
        return
    community = str(config.get("snmp_community", "") or "").strip()
    targets = cfg_list(config.get("snmp_targets", ""))
    if not community or not targets:
        return
    port = positive_int(config.get("snmp_port", 161), 161, 1)
    oids = {
        "sys_name": "1.3.6.1.2.1.1.5.0",
        "sys_descr": "1.3.6.1.2.1.1.1.0",
        "sys_uptime": "1.3.6.1.2.1.1.3.0",
    }
    for target in targets:
        for metric, oid in oids.items():
            value = snmpget_value(target, community, oid, port)
            if value:
                store_telemetry("snmp", target, metric, value)


def snmp_poll_loop():
    init_db()
    while True:
        c = cfg()
        interval = positive_int(c.get("snmp_poll_seconds", 60), 60, 10)
        try:
            poll_snmp_targets(c)
        except Exception as e:
            print(f"SNMP telemetry loop failed: {e}")
        time.sleep(interval)


def mqtt_subscription_loop():
    if mqtt is None:
        print("MQTT subscriber disabled: paho-mqtt is not installed")
        return
    while True:
        c = cfg()
        if not c.get("mqtt_enabled") or not str(c.get("mqtt_host", "") or "").strip():
            time.sleep(30)
            continue
        topics = cfg_list(c.get("mqtt_subscribe_topics", ""))
        if not topics:
            time.sleep(30)
            continue
        try:
            client = mqtt.Client(client_id=str(c.get("mqtt_client_id") or "netspecter"))
            username = str(c.get("mqtt_username", "") or "")
            password = str(c.get("mqtt_password", "") or "")
            if username or password:
                client.username_pw_set(username, password)
            if c.get("mqtt_tls"):
                client.tls_set()

            def on_connect(client, _userdata, _flags, rc):
                if rc == 0:
                    for topic in topics:
                        client.subscribe(topic)
                    print(f"MQTT subscriber connected; topics: {', '.join(topics)}")
                else:
                    print(f"MQTT subscriber connect failed: {rc}")

            def on_message(_client, _userdata, message):
                payload = message.payload.decode("utf-8", errors="replace")
                store_telemetry("mqtt", message.topic, "payload", payload)

            client.on_connect = on_connect
            client.on_message = on_message
            client.connect(str(c.get("mqtt_host")), positive_int(c.get("mqtt_port", 1883), 1883, 1), keepalive=60)
            client.loop_forever()
        except Exception as e:
            print(f"MQTT subscriber loop failed: {e}")
            time.sleep(30)


def ids_known_ips():
    try:
        con = connect_db()
        rows = con.execute("SELECT ip FROM devices").fetchall()
        con.close()
        return {str(row[0]) for row in rows}
    except Exception:
        return set()


def send_ids_email(config, alert):
    host = str(config.get("smtp_host", "") or "").strip()
    username = str(config.get("smtp_username", "") or "").strip()
    password = str(config.get("smtp_password", "") or "")
    from_address = str(config.get("smtp_from", "") or username).strip()
    to_address = str(config.get("smtp_to", "") or "").strip()
    security = str(config.get("smtp_security", "starttls") or "starttls").strip().lower()
    if not host or not from_address or not to_address:
        return False
    message = EmailMessage()
    message["Subject"] = f"NetSpecter IDS P{alert['priority']}: {alert['signature']}"
    message["From"] = from_address
    message["To"] = to_address
    message.set_content(
        "NetSpecter detected a new visible IDS alert.\n\n"
        f"Time: {alert['ts']}\n"
        f"Priority: {alert['priority']}\n"
        f"Alert: {alert['signature']}\n"
        f"Classification: {alert['classification']}\n"
        f"Protocol: {alert['protocol']}\n"
        f"Source: {alert['source']}\n"
        f"Destination: {alert['destination']}\n"
    )
    try:
        port = int(config.get("smtp_port", 587) or 587)
        if security == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, timeout=5, context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(host, port, timeout=5)
        with smtp:
            if security == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
        return True
    except Exception as error:
        print(f"IDS email send failed: {error}")
        return False


def ids_alert_recently_notified(con, alert_key, now_ts, cooldown_seconds):
    row = con.execute("SELECT last_sent_ts FROM ids_alert_notifications WHERE alert_key=?", (alert_key,)).fetchone()
    if not row:
        return False
    try:
        return now_ts - int(row[0] or 0) < cooldown_seconds
    except Exception:
        return False


def ids_alert_stable_key(alert):
    return stable_incident_key(alert.get("signature") or "Suricata alert", ids_endpoint_ip(alert.get("source")))


def ids_alert_notification_keys(alert):
    source_ip = ids_endpoint_ip(alert.get("source"))
    signature = alert.get("signature") or "Suricata alert"
    stable_key = ids_alert_stable_key(alert)
    keys = [stable_key]
    sid = str(alert.get("sid") or "").strip()
    source = str(alert.get("source") or "").strip()
    destination = str(alert.get("destination") or "").strip()
    if sid and source and destination:
        keys.append(f"{sid}|{source}|{destination}|{signature}")
        if sid.startswith("1:"):
            keys.append(f"{sid[1:]}|{source}|{destination}|{signature}")
    return [key for key in keys if key]


def ids_any_alert_recently_notified(con, alert_keys, now_ts, cooldown_seconds):
    return any(ids_alert_recently_notified(con, key, now_ts, cooldown_seconds) for key in alert_keys)


def ids_alert_is_fresh(alert, now_dt=None, max_age_minutes=10):
    now_dt = now_dt or datetime.now()
    text = str(alert.get("ts") or "").strip()
    candidates = [text]
    if text and "/" in text and "-" not in text[:5]:
        candidates.append(f"{now_dt.year}/{text}")
    for candidate in candidates:
        normalized = candidate.replace("Z", "+00:00")
        if len(normalized) >= 5 and normalized[-5] in ("+", "-") and normalized[-3] != ":":
            normalized = normalized[:-2] + ":" + normalized[-2:]
        for fmt in (None, "%Y/%m/%d-%H:%M:%S.%f", "%Y/%m/%d-%H:%M:%S"):
            try:
                parsed = datetime.fromisoformat(normalized) if fmt is None else datetime.strptime(normalized, fmt)
                if parsed.tzinfo is not None:
                    parsed = parsed.astimezone().replace(tzinfo=None)
                return timedelta(seconds=-60) <= now_dt - parsed <= timedelta(minutes=max_age_minutes)
            except Exception:
                continue
    return False


def mark_ids_alert_notified(con, alert_key, now_ts):
    con.execute(
        """
        INSERT INTO ids_alert_notifications (alert_key, last_sent_ts)
        VALUES (?, ?)
        ON CONFLICT(alert_key) DO UPDATE SET last_sent_ts=excluded.last_sent_ts
        """,
        (alert_key, int(now_ts)),
    )


def ids_alert_row_for_incident(alert):
    try:
        severity = int(alert.get("priority") or 3)
    except Exception:
        severity = 3
    return {
        "id": alert.get("id") or 0,
        "ts": alert.get("ts") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": ids_endpoint_ip(alert.get("source")),
        "dest_ip": ids_endpoint_ip(alert.get("destination")),
        "flow_id": alert.get("flow_id") or "",
        "signature_id": None,
        "signature": alert.get("signature") or "Suricata alert",
        "severity": severity,
    }


def ids_notification_decision(con, config, alert, now_ts, cooldown_seconds):
    ensure_incident_schema(con)
    incident_id, _was_created = find_or_create_incident(con, ids_alert_row_for_incident(alert), config)
    key = ids_alert_stable_key(alert)
    normalized_signature = normalize_incident_signature(alert.get("signature") or "Suricata alert")
    source_ip = normalize_incident_ip(ids_endpoint_ip(alert.get("source")))
    destination_ip = normalize_incident_ip(ids_endpoint_ip(alert.get("destination")))
    severity = str(alert.get("priority") or 3)
    status = ""
    if incident_id:
        row = con.execute("SELECT status FROM security_incidents WHERE id=?", (incident_id,)).fetchone()
        status = str(row[0] or "").strip().lower() if row else ""
    banned_ips = {normalize_incident_ip(ip) for ip in cfg_list(config.get("ids_banned_ips", []))}
    blocked_statuses = {"under_investigation", "investigating", "resolved", "closed", "banned", "blocked"}
    if source_ip in banned_ips or destination_ip in banned_ips:
        reason = "banned"
    elif status in blocked_statuses:
        reason = status
    elif ids_alert_recently_notified(con, key, now_ts, cooldown_seconds):
        reason = "cooldown"
    else:
        print(
            "IDS_NOTIFY "
            f"decision=sent key={key} incident={incident_id} signature={normalized_signature} "
            f"src={source_ip} dest={destination_ip} severity={severity}"
        )
        return True, "sent", key, incident_id
    print(
        "IDS_NOTIFY "
        f"decision=suppressed reason={reason} key={key} incident={incident_id} signature={normalized_signature} "
        f"src={source_ip} dest={destination_ip} severity={severity}"
    )
    return False, reason, key, incident_id


def ids_notification_last_structured_id(con):
    row = con.execute("SELECT last_sent_ts FROM ids_alert_notifications WHERE alert_key='__last_structured_id'").fetchone()
    try:
        return int(row[0] or 0) if row else 0
    except Exception:
        return 0


def mark_ids_notification_last_structured_id(con, last_id):
    con.execute(
        """
        INSERT INTO ids_alert_notifications (alert_key, last_sent_ts)
        VALUES ('__last_structured_id', ?)
        ON CONFLICT(alert_key) DO UPDATE SET last_sent_ts=MAX(last_sent_ts, excluded.last_sent_ts)
        """,
        (int(last_id or 0),),
    )


def process_ids_email_alerts(config):
    """Email newly appended visible IDS alerts, with signature/source cooldown."""
    if not config.get("ids_email_enabled"):
        return
    state = load_json(IDS_EMAIL_STATE_PATH, {})
    known_ips = ids_known_ips()
    excluded_ips = set(cfg_list(config.get("ids_excluded_ips", [])))
    try:
        cooldown_minutes = max(1, int(config.get("ids_email_cooldown_minutes", 480) or 480))
    except (TypeError, ValueError):
        cooldown_minutes = 480
    cooldown_seconds = cooldown_minutes * 60
    now = time.time()
    now_dt = datetime.now()
    sent = {key: float(ts) for key, ts in state.get("sent", {}).items() if now - float(ts) < cooldown_seconds}
    last_id = int(state.get("last_structured_id", 0) or 0)
    alerts = []
    structured_available = False
    allow_fast_log_fallback = False
    try:
        con = connect_db()
        con.row_factory = sqlite3.Row
        last_id = max(last_id, ids_notification_last_structured_id(con))
        rows = con.execute(
            "SELECT * FROM ids_events WHERE event_type='alert' AND COALESCE(alert_status, 'open')='open' AND id>? ORDER BY id ASC LIMIT 400",
            (last_id,),
        ).fetchall()
        structured_available = True
        con.close()
        for row in rows:
            sid = f"1:{row['signature_id']}:1" if row["signature_id"] else ""
            signature = row["signature"] or "Suricata alert"
            if is_default_suppressed_signature(signature):
                last_id = max(last_id, int(row["id"]))
                continue
            alerts.append({
                "id": row["id"],
                "sid": sid,
                "ts": row["ts"],
                "priority": str(row["severity"] or 3),
                "signature": signature,
                "classification": row["category"] or "",
                "protocol": row["protocol"] or "",
                "source": f"{row['src_ip']}:{row['src_port']}" if row["src_port"] else row["src_ip"],
                "destination": f"{row['dest_ip']}:{row['dest_port']}" if row["dest_port"] else row["dest_ip"],
                "flow_id": row["flow_id"] or "",
            })
            last_id = max(last_id, int(row["id"]))
    except Exception as error:
        print(f"IDS structured email read failed: {error}")
        allow_fast_log_fallback = "no such table: ids_events" in str(error).lower()
    if allow_fast_log_fallback and not structured_available and not alerts and SURICATA_FAST_LOG.exists():
        try:
            result = subprocess.run(
                ["tail", "-n", "400", str(SURICATA_FAST_LOG)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=4,
                check=False,
            )
            alerts = fast_log_alerts_from_text(result.stdout, 400)
        except Exception as error:
            print(f"IDS email log read failed: {error}")
    sent_this_run = 0
    for alert in alerts:
        try:
            if int(alert.get("priority") or 3) > 2:
                continue
        except Exception:
            continue
        source_ip = ids_endpoint_ip(alert.get("source"))
        if not ids_alert_is_fresh(alert, now_dt):
            continue
        if ids_alert_is_excepted(config, alert):
            continue
        if source_ip in excluded_ips or (config.get("ids_unknown_only") and source_ip in known_ips):
            continue
        try:
            con = connect_db()
            should_send, _reason, notify_key, _incident_id = ids_notification_decision(con, config, alert, now, cooldown_seconds)
            if not should_send:
                con.commit()
                con.close()
                continue
            if send_ids_email(config, alert):
                mark_ids_alert_notified(con, notify_key, now)
                con.commit()
                sent[notify_key] = now
                sent_this_run += 1
                print(f"IDS email notification sent: {alert['signature']} from {source_ip}")
                if sent_this_run >= 5:
                    con.close()
                    break
            else:
                con.commit()
                con.close()
                break
            con.close()
        except Exception as error:
            print(f"IDS notification dedupe failed: {error}")
    try:
        con = connect_db()
        mark_ids_notification_last_structured_id(con, last_id)
        con.commit()
        con.close()
    except Exception as error:
        print(f"IDS notification state update failed: {error}")
    IDS_EMAIL_STATE_PATH.write_text(json.dumps({"last_structured_id": last_id, "sent": sent}, indent=2))


def valid_ids_block_ip(value):
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except Exception:
        return False


def ids_alert_matches_exception(alert, exception):
    if not isinstance(exception, dict):
        return False
    source_ip = str(exception.get("source_ip") or "").strip()
    signature = str(exception.get("signature") or "").strip().lower()
    alert_source = ids_endpoint_ip(alert.get("source") or alert.get("src_ip") or "")
    alert_signature = str(alert.get("signature") or "").strip().lower()
    if source_ip and source_ip != alert_source:
        return False
    if signature and signature != alert_signature:
        return False
    return bool(source_ip or signature)


def ids_alert_is_excepted(config, alert):
    exceptions = config.get("ids_exceptions", [])
    if not isinstance(exceptions, list):
        return False
    return any(ids_alert_matches_exception(alert, exception) for exception in exceptions)


def ids_device_name(con, ip):
    try:
        row = con.execute(
            """
            SELECT COALESCE(o.name, d.name, d.ip) AS name
            FROM devices d
            LEFT JOIN device_overrides o ON o.ip=d.ip
            WHERE d.ip=?
            """,
            (ip,),
        ).fetchone()
        if row and row[0]:
            return str(row[0])
    except Exception:
        pass
    return "External / unknown endpoint"


def ids_auto_block_message(ip, device, priority, signature, ts, actor):
    return (
        "NetSpecter IDS Auto Block\n"
        f"IP: {ip}\n"
        f"Device: {device}\n"
        f"Rule: P{priority} {signature}\n"
        f"Reason: IDS priority {priority} automatic block\n"
        f"Time: {ts}\n"
        f"By: {actor}"
    )


def send_ids_telegram_message(config, text):
    if not config.get("telegram_enabled"):
        return False, "Telegram is disabled."
    token = str(config.get("telegram_bot_token", "") or "").strip()
    chat_id = str(config.get("telegram_chat_id", "") or "").strip()
    if not token or not chat_id:
        return False, "Telegram bot token or chat ID is missing."
    if not requests:
        return False, "Python requests package is not installed."
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=12,
        )
        if response.status_code >= 400:
            return False, response.text[:240]
        return True, "Telegram warning sent."
    except Exception as error:
        return False, str(error)


def process_ids_auto_blocks(config):
    """Automatically block P1/P2 IDS endpoints and notify Telegram once."""
    if not config.get("ids_auto_ban_enabled", False):
        return 0
    con = None
    try:
        con = connect_db(timeout=2, busy_timeout_ms=1000)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            """
            SELECT *
            FROM ids_events
            WHERE event_type='alert'
              AND COALESCE(alert_status, 'open')='open'
              AND CAST(COALESCE(severity, 3) AS INTEGER) IN (1, 2)
            ORDER BY id ASC
            LIMIT 100
            """
        ).fetchall()
    except Exception as error:
        print(f"IDS auto block scan failed: {error}")
        if con:
            con.close()
        return 0
    if not rows:
        con.close()
        return 0

    banned = set(ip for ip in cfg_list(config.get("ids_banned_ips", [])) if valid_ids_block_ip(ip))
    changed = False
    blocked_count = 0
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for row in rows:
        signature = row["signature"] or "Suricata alert"
        if is_default_suppressed_signature(signature):
            continue
        priority = int(row["severity"] or 3)
        source_ip = ids_endpoint_ip(row["src_ip"])
        destination_ip = ids_endpoint_ip(row["dest_ip"])
        endpoint_ip = source_ip if valid_ids_block_ip(source_ip) else destination_ip
        if not valid_ids_block_ip(endpoint_ip):
            continue
        if endpoint_ip in banned:
            try:
                con.execute("UPDATE ids_events SET alert_status='banned' WHERE id=?", (row["id"],))
            except Exception:
                pass
            continue

        banned.add(endpoint_ip)
        changed = True
        blocked_count += 1
        event_ts = row["ts"] or now_text
        device = ids_device_name(con, endpoint_ip)
        try:
            con.execute("UPDATE ids_events SET alert_status='banned' WHERE id=?", (row["id"],))
        except Exception as error:
            print(f"IDS auto block status update failed: {error}")
        sent, detail = send_ids_telegram_message(
            config,
            ids_auto_block_message(endpoint_ip, device, priority, signature, event_ts, "Automatic IDS policy"),
        )
        if not sent:
            print(f"IDS auto block Telegram warning failed: {detail}")
        print(f"IDS_AUTO_BLOCK ip={endpoint_ip} priority={priority} signature={signature}")

    try:
        con.commit()
    except Exception as error:
        print(f"IDS auto block commit failed: {error}")
    finally:
        con.close()

    if changed:
        updated = dict(config)
        updated["ids_banned_ips"] = sorted(banned)
        try:
            save_shared_cfg(updated)
            nft_config_refresh_event.set()
        except Exception as error:
            print(f"IDS auto block config update failed: {error}")
    return blocked_count


def import_suricata_eve(config):
    try:
        result = ingest_eve_incremental(connect_db, SURICATA_EVE_LOG)
        if result.get("inserted"):
            print(f"Suricata eve.json imported rows: {result['inserted']}")
        if result.get("bad_json"):
            print(f"Suricata eve.json skipped malformed rows: {result['bad_json']}")
    except Exception as error:
        print(f"Suricata eve.json import failed: {error}")


def write_heartbeat(status="OK", note="", fast=False):
    c = cfg()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    live_snapshot.update_heartbeat(status, note, now)
    run_sql(
        """
        INSERT INTO collector_heartbeat (id, updated_at, packet_iface, status, note)
        VALUES (1, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            updated_at=excluded.updated_at,
            packet_iface=excluded.packet_iface,
            status=excluded.status,
            note=excluded.note
        """,
        (
            now,
            str(c.get("packet_iface") or "br0"),
            status,
            str(note or "")[:300],
        ),
        timeout=0.5 if fast else 30,
        busy_timeout_ms=250 if fast else 30000,
        retries=1 if fast else 4,
    )


def prune_history(config=None):
    """Apply configured history retention without altering today's totals."""
    c = config or cfg()
    traffic_days = positive_int(c.get("traffic_retention_days", 60), 60, 1)
    dns_days = positive_int(c.get("dns_retention_days", 60), 60, 1)
    quality_days = positive_int(c.get("internet_quality_retention_days", 60), 60, 1)
    config_days = positive_int(c.get("config_change_retention_days", 180), 180, 1)
    threat_days = positive_int(c.get("threat_intel_retention_days", 30), 30, 1)
    traffic_cutoff = f"-{traffic_days - 1} days"
    dns_cutoff = f"-{dns_days - 1} days"
    quality_cutoff = f"-{quality_days - 1} days"
    config_cutoff = f"-{config_days - 1} days"
    threat_cutoff = f"-{threat_days - 1} days"

    try:
        con = connect_db()
        con.execute("PRAGMA busy_timeout=1000")
        con.execute(
            "DELETE FROM traffic_intervals WHERE day < date('now', 'localtime', ?)",
            (traffic_cutoff,),
        )
        con.execute(
            "DELETE FROM traffic_samples WHERE day < date('now', 'localtime', ?)",
            (traffic_cutoff,),
        )
        con.execute(
            "DELETE FROM estimated_app_traffic WHERE day < date('now', 'localtime', ?)",
            (traffic_cutoff,),
        )
        con.execute(
            "DELETE FROM remote_traffic_intervals WHERE day < date('now', 'localtime', ?)",
            (traffic_cutoff,),
        )
        con.execute(
            "DELETE FROM dns_querylog WHERE day < date('now', 'localtime', ?)",
            (dns_cutoff,),
        )
        con.execute(
            "DELETE FROM dns_resolved_ips WHERE resolved_ts < datetime('now', 'localtime', ?)",
            (dns_cutoff,),
        )
        con.execute(
            "DELETE FROM remote_ip_locations WHERE lookup_ts < datetime('now', 'localtime', ?)",
            (traffic_cutoff,),
        )
        con.execute(
            "DELETE FROM live_device_speed WHERE updated_at < datetime('now', 'localtime', '-1 day')",
        )
        con.execute(
            "DELETE FROM speed_tests WHERE ts < datetime('now', 'localtime', ?)",
            (quality_cutoff,),
        )
        con.execute(
            "DELETE FROM telemetry_readings WHERE ts < datetime('now', 'localtime', ?)",
            (traffic_cutoff,),
        )
        con.execute(
            "DELETE FROM monitor_events WHERE ts < CAST(strftime('%s', datetime('now', 'localtime', ?)) AS INTEGER)",
            (config_cutoff,),
        )
        con.execute(
            "DELETE FROM classification_audit WHERE ts < datetime('now', 'localtime', ?)",
            (threat_cutoff,),
        )
        con.commit()
        con.execute("PRAGMA wal_checkpoint(PASSIVE)")
        con.close()
        prune_ids_history(connect_db, c)
        prune_quality_history(connect_db, c)
        prune_config_changes(connect_db, c)
        prune_threat_intel(connect_db, c)
        prune_incidents(connect_db, c)
        prune_anomalies(connect_db, c)
    except Exception as e:
        print(f"History retention cleanup failed: {e}")


def retention_cleanup_loop():
    init_db()
    time.sleep(30 * 60)
    while True:
        started = time.monotonic()
        try:
            with db_write_lock:
                prune_history(cfg())
        except Exception as e:
            print(f"Retention cleanup loop failed: {e}")
        log_slow_loop("Retention cleanup", time.monotonic() - started, threshold=5.0)
        time.sleep(24 * 3600)


def lan_network(config=None):
    """Convert the LAN prefix setting into the IPv4 subnet counted by nftables."""
    text = str((config or cfg()).get("lan_prefix", DEFAULT_CONFIG["lan_prefix"]) or "").strip()
    if text.endswith("."):
        text = f"{text}0/24"
    elif "/" not in text:
        text = f"{text}/24"
    network = ipaddress.ip_network(text, strict=False)
    if network.version != 4:
        raise ValueError("LAN Prefix must identify an IPv4 network")
    if network.num_addresses > 1024:
        raise ValueError("LAN Prefix is too large; use a /22 or smaller network")
    return network


def monitored_app_for_domain(domain, config=None):
    """Return an app only when its DNS domain is specific enough for attribution."""
    normalized_domain = str(domain or "").lower().strip(".")
    mappings = (config or cfg()).get("site_domain_mappings")
    if isinstance(mappings, list):
        for row in mappings:
            if not isinstance(row, dict):
                continue
            app_name = str(row.get("application") or "").strip()
            pattern = str(row.get("domain") or row.get("pattern") or "").lower().strip().rstrip(".")
            if app_name and domain_pattern_matches(pattern, normalized_domain):
                return app_name
    for category, keys in MONITORED_APP_DOMAIN_KEYS.items():
        if any(normalized_domain == key or normalized_domain.endswith(f".{key}") for key in keys):
            return category
    return ""


def domain_pattern_matches(pattern, domain):
    if not pattern or not domain or " " in pattern or "/" in pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain == suffix or domain.endswith(f".{suffix}")
    if "*" in pattern:
        return fnmatch.fnmatch(domain, pattern)
    return domain == pattern


def monitored_app_ips(config=None):
    output = {app: set(ips) for app, ips in SITE_MONITORED_APP_IPS.items()}
    mappings = (config or cfg()).get("site_application_mappings")
    if not isinstance(mappings, list):
        return output
    for row in mappings:
        if not isinstance(row, dict):
            continue
        app_name = str(row.get("application") or "").strip()
        ip = str(row.get("ip") or "").strip()
        if not app_name or not ip:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        output.setdefault(app_name, set()).add(ip)
    return output


def remember_estimated_app_targets(config, client, domain, answers, observed_at="", blocked=False):
    """Remember client/destination pairs for explicitly monitored app categories."""
    if blocked:
        return
    category = monitored_app_for_domain(domain, config)
    if not category:
        return
    try:
        client_ip = ipaddress.ip_address(str(client or "").strip())
        network = lan_network(config)
        if client_ip.version != 4 or client_ip not in network:
            return
    except ValueError:
        return

    now = time.time()
    try:
        observed_epoch = datetime.strptime(str(observed_at)[:19], "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        observed_epoch = now
    configured_app_ips = monitored_app_ips(config)
    local_app_ips = configured_app_ips.get(category, set())
    for answer in answers if isinstance(answers, list) else []:
        if not isinstance(answer, dict) or str(answer.get("type") or "").upper() != "A":
            continue
        try:
            destination = ipaddress.ip_address(str(answer.get("value") or "").strip())
        except ValueError:
            continue
        if destination.version != 4 or destination.is_unspecified:
            continue
        if destination in network and str(destination) not in local_app_ips:
            continue
        ttl = positive_int(answer.get("ttl", 900), 900, 1)
        expires = observed_epoch + min(max(ttl, 900), 21600)
        if expires <= now:
            continue
        key = (str(client_ip), str(destination))
        with estimated_targets_lock:
            existing = estimated_app_targets.get(key)
            if not existing or existing[0] == category or existing[1] <= now:
                estimated_app_targets[key] = (category, max(existing[1] if existing and existing[0] == category else 0, expires))


def active_estimated_app_targets():
    """Return unexpired monitored app client/destination pairs for nftables attribution."""
    now = time.time()
    with estimated_targets_lock:
        expired = [key for key, (_category, expires) in estimated_app_targets.items() if expires <= now]
        for key in expired:
            estimated_app_targets.pop(key, None)
        ranked = sorted(
            (
                (expires, category, client, destination)
                for (client, destination), (category, expires) in estimated_app_targets.items()
            ),
            reverse=True,
        )
        return tuple(
            sorted(
                (category, client, destination)
                for _expires, category, client, destination in ranked[:ESTIMATED_APP_NFT_TARGET_LIMIT]
            )
        )


def public_ipv4(value):
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    if ip.version != 4 or not ip.is_global:
        return ""
    return str(ip)


def resolve_domain_ipv4s(domain, limit=2, timeout=1.0):
    domain = str(domain or "").strip().strip(".").lower()
    if not domain or len(domain) > 253 or "." not in domain:
        return []
    literal_ip = public_ipv4(domain)
    if literal_ip:
        return [literal_ip]
    previous_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        _name, _aliases, addresses = socket.gethostbyname_ex(domain)
    except Exception:
        return []
    finally:
        socket.setdefaulttimeout(previous_timeout)
    results = []
    for address in addresses:
        ip = public_ipv4(address)
        if ip and ip not in results:
            results.append(ip)
        if len(results) >= limit:
            break
    return results


def lookup_and_store_remote_location(remote_ip, source_label="Remote destination"):
    remote_ip = public_ipv4(remote_ip)
    if not remote_ip:
        return False
    return False


def update_remote_traffic_locations(config=None):
    """Refresh a few used traffic destination locations per DNS import cycle."""
    c = config or cfg()
    lookup_limit = positive_int(c.get("remote_map_geo_lookups_per_run", 50), 50, 1)
    cutoff = datetime.fromtimestamp(time.time() - GEOLOCATION_REFRESH_SECONDS).strftime("%Y-%m-%d %H:%M:%S")
    con = connect_db()
    rows = con.execute(
        """
        SELECT r.remote_ip, SUM(r.total_mb) AS total_mb
        FROM remote_traffic_intervals r
        LEFT JOIN remote_ip_locations l ON l.remote_ip = r.remote_ip
        WHERE r.day >= date('now', 'localtime', '-1 day')
        GROUP BY r.remote_ip
        HAVING MAX(l.lookup_ts) IS NULL
            OR MAX(l.latitude) IS NULL
            OR MAX(l.longitude) IS NULL
            OR MAX(l.lookup_ts) < ?
        ORDER BY SUM(r.total_mb) DESC, MAX(r.ts) DESC
        LIMIT ?
        """,
        (cutoff, lookup_limit),
    ).fetchall()
    con.close()

    for row in rows:
        lookup_and_store_remote_location(str(row[0]))


def update_one_remote_location():
    """Backward-compatible wrapper for older callers."""
    update_remote_traffic_locations({"remote_map_geo_lookups_per_run": 1})


def update_dns_destination_map_cache(config=None):
    """Resolve top DNS domains and geolocate a few missing IPs outside web requests."""
    global last_dns_map_refresh

    c = config or cfg()
    interval = positive_int(c.get("dns_map_refresh_seconds", DNS_MAP_REFRESH_SECONDS), DNS_MAP_REFRESH_SECONDS, 60)
    now_mono = time.monotonic()
    if now_mono - last_dns_map_refresh < interval:
        return
    last_dns_map_refresh = now_mono

    domain_limit = min(positive_int(c.get("dns_map_domain_limit", DNS_MAP_DOMAIN_LIMIT), DNS_MAP_DOMAIN_LIMIT, 10), 20)
    ip_limit = min(positive_int(c.get("dns_map_ip_limit", DNS_MAP_IP_LIMIT), DNS_MAP_IP_LIMIT, 10), 40)
    lookup_limit = min(positive_int(c.get("dns_map_geo_lookups_per_run", DNS_MAP_GEO_LOOKUPS_PER_RUN), DNS_MAP_GEO_LOOKUPS_PER_RUN, 1), 3)
    deadline = time.monotonic() + 5.0
    cutoff = datetime.fromtimestamp(time.time() - GEOLOCATION_REFRESH_SECONDS).strftime("%Y-%m-%d %H:%M:%S")
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    con = connect_db()
    domains = con.execute(
        """
        SELECT domain
        FROM dns_querylog
        WHERE day >= date('now', 'localtime', '-1 day')
          AND blocked=0
          AND domain <> ''
        GROUP BY domain
        ORDER BY COUNT(*) DESC
        LIMIT ?
        """,
        (domain_limit,),
    ).fetchall()
    con.close()

    resolved_ips = []
    for row in domains:
        if time.monotonic() >= deadline:
            break
        domain = str(row[0] or "").strip().strip(".").lower()
        for remote_ip in resolve_domain_ipv4s(domain, limit=2, timeout=0.75):
            run_sql(
                """
                INSERT INTO dns_resolved_ips (domain, remote_ip, resolved_ts)
                VALUES (?, ?, ?)
                ON CONFLICT(domain, remote_ip) DO UPDATE SET resolved_ts=excluded.resolved_ts
                """,
                (domain, remote_ip, now_text),
            )
            if remote_ip not in resolved_ips:
                resolved_ips.append(remote_ip)
            if len(resolved_ips) >= ip_limit:
                break
        if len(resolved_ips) >= ip_limit:
            break

    if not resolved_ips:
        return

    placeholders = ",".join("?" for _ in resolved_ips)
    con = connect_db()
    missing = con.execute(
        f"""
        SELECT r.remote_ip
        FROM dns_resolved_ips r
        LEFT JOIN remote_ip_locations l ON l.remote_ip = r.remote_ip
        WHERE r.remote_ip IN ({placeholders})
        GROUP BY r.remote_ip
        HAVING MAX(l.lookup_ts) IS NULL OR MAX(l.lookup_ts) < ?
        ORDER BY MAX(r.resolved_ts) DESC
        LIMIT ?
        """,
        (*resolved_ips, cutoff, lookup_limit),
    ).fetchall()
    con.close()

    for row in missing:
        if time.monotonic() >= deadline:
            break
        lookup_and_store_remote_location(str(row[0]), "DNS destination")


def nft_signature(config=None):
    c = config or cfg()
    banned_ips = []
    for value in cfg_list(c.get("ids_banned_ips", [])):
        try:
            if isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address):
                banned_ips.append(value)
        except ValueError:
            continue
    return (
        str(c.get("packet_iface") or "br0"),
        str(lan_network(c)),
        tuple(sorted(ignored_ips(c))),
        tuple(sorted(set(banned_ips))),
        active_estimated_app_targets(),
    )


def install_nft_counters(config=None):
    """Create bridge traffic counters and any configured IDS endpoint drop rules."""
    global nft_config_signature, nft_previous_counters, nft_previous_estimated_counters, nft_active_ips, live_traffic_today
    started = time.monotonic()
    c = config or cfg()
    signature = nft_signature(c)
    interface, network_text, ignored, banned_ips, app_targets = signature
    network = ipaddress.ip_network(network_text)
    ignored_set = set(ignored)
    hosts = [str(ip) for ip in network.hosts() if str(ip) not in ignored_set]

    subprocess.run(
        ["nft", "delete", "table", NFT_FAMILY, NFT_TABLE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    lines = [
        f"table {NFT_FAMILY} {NFT_TABLE} {{",
        "  chain ids_input {",
        "    type filter hook input priority filter; policy accept;",
    ]
    for ip in banned_ips:
        lines.append(
            f'    ip saddr {ip} drop comment "netspecter:ids-ban:input:{ip}"'
        )
    lines.extend([
        "  }",
        "  chain ids_output {",
        "    type filter hook output priority filter; policy accept;",
    ])
    for ip in banned_ips:
        lines.append(
            f'    ip daddr {ip} drop comment "netspecter:ids-ban:output:{ip}"'
        )
    lines.extend([
        "  }",
        f"  chain {NFT_CHAIN} {{",
        "    type filter hook forward priority filter; policy accept;",
    ])
    for ip in banned_ips:
        lines.append(
            f'    ip saddr {ip} drop comment "netspecter:ids-ban:forward-source:{ip}"'
        )
        lines.append(
            f'    ip daddr {ip} drop comment "netspecter:ids-ban:forward-destination:{ip}"'
        )
    for ip in hosts:
        lines.append(
            f'    ip saddr {ip} ip daddr != {network} counter comment "netspecter:tx:{ip}"'
        )
        lines.append(
            f'    ip daddr {ip} ip saddr != {network} counter comment "netspecter:rx:{ip}"'
        )
    for category, client, destination in app_targets:
        lines.append(
            f'    ip saddr {client} ip daddr {destination} counter comment "netspecter:estimated:{category}:tx:{client}:{destination}"'
        )
        lines.append(
            f'    ip daddr {client} ip saddr {destination} counter comment "netspecter:estimated:{category}:rx:{client}:{destination}"'
        )
    lines.extend(["  }", "}"])
    result = subprocess.run(
        ["nft", "-f", "-"],
        input="\n".join(lines) + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"nftables counter setup failed: {result.stderr.strip()}")

    nft_config_signature = signature
    nft_previous_counters = {}
    nft_previous_estimated_counters = {}
    nft_active_ips = set()
    print(
        f"nftables traffic counters installed for {network_text} on bridge traffic ({interface}); "
        f"{len(app_targets)} monitored app attribution target(s); {len(banned_ips)} IDS banned endpoint(s)"
    )
    log_slow_loop("nftables counter install", time.monotonic() - started, threshold=2.0)


def remove_nft_counters():
    """Remove NetSpecter's private counter table during an orderly shutdown."""
    global nft_config_signature, nft_previous_counters, nft_previous_estimated_counters, nft_active_ips, live_traffic_today
    if nft_config_signature is None:
        return
    subprocess.run(
        ["nft", "delete", "table", NFT_FAMILY, NFT_TABLE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    nft_config_signature = None
    nft_previous_counters = {}
    nft_previous_estimated_counters = {}
    nft_active_ips = set()
    print("NetSpecter nftables traffic counters removed")


def shutdown_collector(signum, _frame):
    print(f"Collector shutting down after signal {signum}")
    remove_nft_counters()
    raise SystemExit(0)


def read_nft_counters():
    """Return device totals and DNS-attributed app totals from nftables."""
    result = subprocess.run(
        ["nft", "-j", "list", "chain", NFT_FAMILY, NFT_TABLE, NFT_CHAIN],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"nftables counter read failed: {result.stderr.strip()}")

    payload = json.loads(result.stdout)
    counters = {}
    estimated_counters = {}
    for item in payload.get("nftables", []):
        rule = item.get("rule") if isinstance(item, dict) else None
        if not rule:
            continue
        comment = str(rule.get("comment") or "")
        if not comment.startswith("netspecter:"):
            continue
        total_bytes = 0
        for expr in rule.get("expr", []):
            if isinstance(expr, dict) and isinstance(expr.get("counter"), dict):
                total_bytes = int(expr["counter"].get("bytes", 0) or 0)
                break
        parts = comment.split(":")
        if len(parts) == 3 and parts[1] in ("rx", "tx"):
            counters[(parts[1], parts[2])] = total_bytes
        elif len(parts) == 6 and parts[1] == "estimated" and parts[3] in ("rx", "tx"):
            estimated_counters[(parts[2], parts[3], parts[4], parts[5])] = total_bytes
    return counters, estimated_counters


def read_arp_macs():
    """Use locally known ARP entries when available; traffic counting does not depend on this."""
    macs = {}
    try:
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[3] != "00:00:00:00:00:00":
                macs[fields[0]] = fields[3].upper()
    except Exception:
        pass
    return macs


def flush_loop():
    """
    Kernel-counter database update loop.

    Every few seconds it:
    - Reads per-device byte counter differences from nftables
    - Calculates live RX/TX speed from those differences
    - Updates live_device_speed
    - Updates devices
    - Inserts additive traffic_intervals rows
    """
    global nft_config_signature, nft_previous_counters, nft_previous_estimated_counters, nft_active_ips, live_traffic_today
    init_db()
    last_flush_at = time.monotonic()
    last_signature_check = 0

    while True:
        cycle_started = time.monotonic()
        c = cfg()
        interval = 5
        try:
            now_monotonic = time.monotonic()
            signature_refresh_seconds = NFT_SIGNATURE_REFRESH_SECONDS
            forced_refresh = nft_config_refresh_event.is_set()
            if forced_refresh or nft_config_signature is None or now_monotonic - last_signature_check >= signature_refresh_seconds:
                signature = nft_signature(c)
                last_signature_check = now_monotonic
                if signature != nft_config_signature:
                    install_nft_counters(c)
                nft_config_refresh_event.clear()

            current_counters, current_estimated_counters = read_nft_counters()
            flush_at = time.monotonic()
            elapsed = max(flush_at - last_flush_at, 0.001)
            last_flush_at = flush_at
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            day = datetime.now().strftime("%Y-%m-%d")
            macs = read_arp_macs()
            deltas = {}
            next_previous_counters = dict(nft_previous_counters)
            next_active_ips = set(nft_active_ips)
            for (direction, ip), total_bytes in current_counters.items():
                previous = nft_previous_counters.get((direction, ip), 0)
                delta = max(total_bytes - previous, 0)
                next_previous_counters[(direction, ip)] = total_bytes
                if delta:
                    next_active_ips.add(ip)
                if delta or ip in next_active_ips:
                    deltas.setdefault(ip, {"rx": 0, "tx": 0})
                    deltas[ip][direction] = delta
            estimated_deltas = {}
            remote_destination_deltas = {}
            next_previous_estimated_counters = dict(nft_previous_estimated_counters)
            for (category, direction, ip, destination), total_bytes in current_estimated_counters.items():
                key = (category, direction, ip, destination)
                previous = nft_previous_estimated_counters.get(key, 0)
                delta = max(total_bytes - previous, 0)
                next_previous_estimated_counters[key] = total_bytes
                if delta:
                    estimated_deltas.setdefault((category, ip), {"rx": 0, "tx": 0})
                    estimated_deltas[(category, ip)][direction] += delta
                    remote_destination_deltas.setdefault((category, ip, destination), {"rx": 0, "tx": 0})
                    remote_destination_deltas[(category, ip, destination)][direction] += delta
            write_heartbeat("OK", "nftables counters running", fast=True)
        except Exception as e:
            print(f"nftables traffic collection failed: {e}")
            write_heartbeat("Counter Retry", str(e), fast=True)
            time.sleep(interval)
            continue

        live_rows = []
        interval_downloaded_mb = 0.0
        interval_uploaded_mb = 0.0
        interval_total_mb = 0.0
        for ip, cur in deltas.items():
            rx_Bps = cur["rx"] / elapsed
            tx_Bps = cur["tx"] / elapsed
            interval_downloaded_mb += cur["rx"] / 1024 / 1024
            interval_uploaded_mb += cur["tx"] / 1024 / 1024
            mac = macs.get(ip, "")
            live_rows.append({
                "ip": ip,
                "mac": mac,
                "rx_bps": rx_Bps,
                "tx_bps": tx_Bps,
                "total_bps": rx_Bps + tx_Bps,
                "updated_at": now,
                "name": adguard_name_for_ip(ip) or ip,
            })
        interval_total_mb = interval_downloaded_mb + interval_uploaded_mb
        if live_traffic_today.get("day") != day:
            live_traffic_today = {"day": day, "downloaded_mb": 0.0, "uploaded_mb": 0.0, "total_mb": 0.0}
        live_traffic_today["downloaded_mb"] += interval_downloaded_mb
        live_traffic_today["uploaded_mb"] += interval_uploaded_mb
        live_traffic_today["total_mb"] += interval_total_mb
        live_snapshot.update_live_speeds(live_rows, now)
        live_snapshot.update_summary({
            "download_mbps": round(sum(row["rx_bps"] for row in live_rows) * 8 / 1000000, 3),
            "upload_mbps": round(sum(row["tx_bps"] for row in live_rows) * 8 / 1000000, 3),
            "total_mbps": round(sum(row["total_bps"] for row in live_rows) * 8 / 1000000, 3),
            "total_traffic_today_gb": round(live_traffic_today["total_mb"] / 1024, 3),
            "traffic_today": dict(live_traffic_today),
            "devices": {
                "known": len(next_active_ips),
                "online": sum(1 for row in live_rows if float(row.get("total_bps") or 0) > 0),
                "new_or_unknown": 0,
            },
            "top_talker": max(
                (
                    {"name": row.get("name") or row.get("ip"), "ip": row.get("ip"), "mbps": round(float(row.get("total_bps") or 0) * 8 / 1000000, 3)}
                    for row in live_rows
                ),
                key=lambda item: item["mbps"],
                default={"name": None, "ip": None, "mbps": None},
            ),
        }, now)

        con = None
        lock_acquired = False
        try:
            lock_acquired = db_write_lock.acquire(timeout=0.2)
            if not lock_acquired:
                print("Counter batch skipped: collector database writer busy")
                time.sleep(interval)
                continue
            con = connect_db(timeout=0.5, busy_timeout_ms=250)
            for ip, cur in deltas.items():
                rx_delta = cur["rx"]
                tx_delta = cur["tx"]

                rx_Bps = rx_delta / elapsed
                tx_Bps = tx_delta / elapsed
                total_Bps = rx_Bps + tx_Bps

                mac = macs.get(ip, "")
                vendor = vendor_from_mac(mac)
                dtype = classify_device(vendor)
                name = adguard_name_for_ip(ip) or ip

                con.execute(
                    """
                    INSERT INTO live_device_speed
                        (ip, mac, rx_bps, tx_bps, total_bps, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac=excluded.mac,
                        rx_bps=excluded.rx_bps,
                        tx_bps=excluded.tx_bps,
                        total_bps=excluded.total_bps,
                        updated_at=excluded.updated_at
                    """,
                    (ip, mac, rx_Bps, tx_Bps, total_Bps, now),
                )

                con.execute(
                    """
                    INSERT INTO devices
                        (ip, name, mac, vendor, device_type, status, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, 'Active', ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac=CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
                        vendor=CASE WHEN excluded.mac != '' THEN excluded.vendor ELSE devices.vendor END,
                        device_type=CASE
                            WHEN devices.device_type IS NULL
                              OR devices.device_type=''
                              OR devices.device_type='Unknown'
                            THEN excluded.device_type
                            ELSE devices.device_type
                        END,
                        name=CASE WHEN excluded.name != excluded.ip THEN excluded.name ELSE devices.name END,
                        last_seen=excluded.last_seen
                    """,
                    (ip, name, mac, vendor, dtype, now, now),
                )

                interval_rx_mb = rx_delta / 1024 / 1024
                interval_tx_mb = tx_delta / 1024 / 1024
                interval_total_mb = interval_rx_mb + interval_tx_mb

                if interval_total_mb > 0:
                    con.execute(
                        """
                        INSERT INTO traffic_intervals
                            (ip, name, mac, downloaded_mb, uploaded_mb, total_mb, live_bps, day, ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ip,
                            name,
                            mac,
                            interval_rx_mb,
                            interval_tx_mb,
                            interval_total_mb,
                            (rx_delta + tx_delta) / elapsed * 8,
                            day,
                            now,
                        ),
                    )

            for (category, ip), cur in estimated_deltas.items():
                interval_rx_mb = cur["rx"] / 1024 / 1024
                interval_tx_mb = cur["tx"] / 1024 / 1024
                interval_total_mb = interval_rx_mb + interval_tx_mb
                if interval_total_mb > 0:
                    con.execute(
                        """
                        INSERT INTO estimated_app_traffic
                            (ip, category, downloaded_mb, uploaded_mb, total_mb, day, ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (ip, category, interval_rx_mb, interval_tx_mb, interval_total_mb, day, now),
                    )

            for (category, ip, destination), cur in remote_destination_deltas.items():
                interval_rx_mb = cur["rx"] / 1024 / 1024
                interval_tx_mb = cur["tx"] / 1024 / 1024
                interval_total_mb = interval_rx_mb + interval_tx_mb
                if interval_total_mb > 0:
                    con.execute(
                        """
                        INSERT INTO remote_traffic_intervals
                            (ip, remote_ip, category, downloaded_mb, uploaded_mb, total_mb, day, ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (ip, destination, category, interval_rx_mb, interval_tx_mb, interval_total_mb, day, now),
                    )
            con.commit()
            nft_previous_counters = next_previous_counters
            nft_previous_estimated_counters = next_previous_estimated_counters
            nft_active_ips = next_active_ips
        except sqlite3.OperationalError as e:
            if con:
                con.rollback()
            print(f"Counter batch write failed: {e}")
        except Exception as e:
            if con:
                con.rollback()
            print(f"Counter batch write failed: {e}")
        finally:
            if con:
                con.close()
            if lock_acquired:
                db_write_lock.release()

        log_slow_loop("Packet collector", time.monotonic() - cycle_started, threshold=2.5)
        time.sleep(interval)


def import_adguard_querylog():
    """
    Pull DNS querylog from AdGuard Home and insert into dns_querylog.

    This powers:
    - Top Applications
    - Per-device application data
    - Blocked domains
    """
    c = cfg()

    base = str(c.get("adguard_url", "")).rstrip("/")
    user = c.get("adguard_user", "admin")
    password = c.get("adguard_pass", "")

    if not base:
        return

    try:
        res = requests.get(
            f"{base}/control/querylog",
            auth=(user, password),
            timeout=10,
        )

        if res.status_code != 200:
            print(f"AdGuard querylog import failed: HTTP {res.status_code}")
            return

        payload = res.json()

    except Exception as e:
        print(f"AdGuard querylog import failed: {e}")
        return

    rows = payload.get("data", []) if isinstance(payload, dict) else []

    if not isinstance(rows, list):
        return

    cutoff = ""
    try:
        con = connect_db()
        state = con.execute("SELECT cleared_at FROM dns_import_state WHERE id=1").fetchone()
        con.close()
        cutoff = str(state[0] or "") if state else ""
    except Exception as e:
        print(f"DNS history cutoff read failed: {e}")

    device_updates = {}
    dns_rows = []
    pending_dns_keys = []

    for item in rows:
        if not isinstance(item, dict):
            continue

        question = item.get("question") or {}

        domain = str(question.get("name") or "").strip(".")
        client = str(item.get("client") or "").strip()
        reason = str(item.get("reason") or "")
        ts = parse_adguard_time(item.get("time"))
        day = ts[:10]
        blocked = is_blocked_reason(reason)
        category = app_from_domain(domain)

        if not domain or not client:
            continue

        ip = ip_identifier(client)
        name = adguard_name_for_ip(ip)
        if ip and name:
            current = device_updates.get(ip)
            first_seen = min(current[1], ts) if current else ts
            last_seen = max(current[2], ts) if current else ts
            device_updates[ip] = (name, first_seen, last_seen)
        remember_estimated_app_targets(c, client, domain, item.get("answer") or [], ts, blocked)

        if cutoff and ts <= cutoff:
            continue

        # Fast duplicate protection for this running process.
        key = f"{ts}|{client}|{domain}"
        if key in imported_dns_keys:
            continue

        dns_rows.append((day, ts, client, domain, blocked, category))
        pending_dns_keys.append(key)

    if not device_updates and not dns_rows:
        return

    con = None
    try:
        with db_write_lock:
            con = connect_db(timeout=2, busy_timeout_ms=1000)
            for ip, (name, first_seen, last_seen) in device_updates.items():
                con.execute(
                    """
                    INSERT INTO devices (ip, name, status, first_seen, last_seen)
                    VALUES (?, ?, 'Active', ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        name=excluded.name,
                        last_seen=CASE
                            WHEN devices.last_seen IS NULL OR devices.last_seen < excluded.last_seen
                            THEN excluded.last_seen
                            ELSE devices.last_seen
                        END
                    """,
                    (ip, name, first_seen, last_seen),
                )
            if dns_rows:
                con.executemany(
                    """
                    INSERT OR IGNORE INTO dns_querylog
                        (day, ts, client, domain, blocked, category)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    dns_rows,
                )
            con.commit()
        imported_dns_keys.update(pending_dns_keys)
    except Exception as e:
        if con:
            con.rollback()
        print(f"DNS querylog batch insert failed: {e}")
        return
    finally:
        if con:
            con.close()

    if dns_rows:
        print(f"AdGuard querylog imported rows: {len(dns_rows)}")


def adguard_querylog_loop():
    """Background loop for AdGuard DNS querylog importing."""
    init_db()

    while True:
        started = time.monotonic()
        c = cfg()
        interval = positive_int(c.get("adguard_querylog_interval_seconds", 15), 15, 5)

        try:
            run_timed_step("AdGuard/client names", refresh_adguard_client_names, c)
            run_timed_step("UniFi/client import", refresh_unifi_clients, c)
            run_timed_step("Suricata/eve import", import_suricata_eve, c)
            auto_blocked = run_timed_step("IDS/auto block", process_ids_auto_blocks, c)
            if auto_blocked:
                print(f"IDS automatic blocks applied: {auto_blocked}")
            run_timed_step("IDS/email notify", process_ids_email_alerts, c)
            with db_write_lock:
                created = run_timed_step("Incidents/build", build_incidents_once, connect_db, c)
            if created:
                print(f"Security incidents created: {created}")
            run_timed_step("AdGuard/querylog import", import_adguard_querylog)
            run_timed_step("Remote traffic geo", update_remote_traffic_locations, c)
        except Exception as e:
            print(f"AdGuard querylog loop failed: {e}")

        log_slow_loop("AdGuard/import", time.monotonic() - started, threshold=5.0)
        time.sleep(interval)


def internet_quality_loop():
    """Collect one compact WAN quality summary outside web requests."""
    init_db()

    while True:
        c = cfg()
        interval = positive_int(c.get("internet_quality_interval_seconds", 60), 60, 30)
        started = time.monotonic()
        try:
            summary = collect_quality_summary(c)
            live_snapshot.update_quality(summary)
            with db_write_lock:
                insert_quality_summary(connect_db, summary)
            print(f"Internet quality summary: {summary['status']} - {summary['diagnosis']}")
        except Exception as e:
            print(f"Internet quality collection failed: {e}")
        elapsed = time.monotonic() - started
        time.sleep(max(1, interval - elapsed))


def config_change_monitor_loop():
    """Passively snapshot local configuration and record semantic changes."""
    init_db()

    while True:
        c = cfg()
        interval = positive_int(c.get("config_change_monitor_interval_seconds", 300), 300, 60)
        started = time.monotonic()
        try:
            with db_write_lock:
                result = monitor_once(connect_db, c)
            if result.get("changed"):
                print(f"Config monitor snapshot changed; events={result.get('events', 0)}")
        except Exception as e:
            print(f"Config change monitor failed: {e}")
        elapsed = time.monotonic() - started
        time.sleep(max(1, interval - elapsed))


def threat_intel_loop():
    """Refresh local threat feeds and correlate local observations without cloud lookups."""
    init_db()
    last_refresh = 0

    while True:
        c = cfg()
        if not c.get("threat_intel_enabled", True):
            time.sleep(300)
            continue
        refresh_seconds = positive_int(c.get("threat_intel_refresh_hours", 24), 24, 1) * 3600
        now_monotonic = time.monotonic()
        try:
            if now_monotonic - last_refresh >= refresh_seconds:
                with db_write_lock:
                    results = refresh_feeds(connect_db, c)
                print(f"Threat intel feed refresh: {results}")
                last_refresh = now_monotonic
            with db_write_lock:
                matches = correlate_once(connect_db, c)
            if matches:
                print(f"Threat intel correlations inserted: {matches}")
        except Exception as e:
            print(f"Threat intel loop failed: {e}")
        time.sleep(300)


def anomaly_baseline_loop():
    """Build compact baselines and learning-only anomaly metadata without taking action."""
    init_db()

    while True:
        c = cfg()
        interval = positive_int(c.get("anomaly_interval_seconds", 3600), 3600, 300)
        started = time.monotonic()
        try:
            with db_write_lock:
                created = run_anomaly_cycle(connect_db, c)
            if created:
                print(f"Anomaly baseline events recorded: {created}")
        except Exception as e:
            print(f"Anomaly baseline loop failed: {e}")
        elapsed = time.monotonic() - started
        time.sleep(max(1, interval - elapsed))


if __name__ == "__main__":
    if not acquire_collector_lock():
        raise SystemExit(1)

    atexit.register(remove_nft_counters)
    signal.signal(signal.SIGTERM, shutdown_collector)
    signal.signal(signal.SIGINT, shutdown_collector)

    while True:
        try:
            init_db()
            break
        except Exception as e:
            print(f"Collector startup failed: {e}")
            print("Retrying startup in 10 seconds")
            time.sleep(10)

    # Thread 1: nftables byte counters and traffic totals.
    packet_thread = threading.Thread(target=flush_loop, daemon=True)
    packet_thread.start()

    # Thread 2: AdGuard DNS querylog import.
    dns_thread = threading.Thread(target=adguard_querylog_loop, daemon=True)
    dns_thread.start()

    startup_config = cfg()

    # Thread 3: SNMP telemetry polling, only when explicitly enabled.
    snmp_started = bool(startup_config.get("snmp_enabled"))
    if snmp_started:
        snmp_thread = threading.Thread(target=snmp_poll_loop, daemon=True)
        snmp_thread.start()

    # Thread 4: MQTT telemetry subscription, only when explicitly enabled.
    mqtt_started = bool(startup_config.get("mqtt_enabled") and str(startup_config.get("mqtt_host", "") or "").strip())
    if mqtt_started:
        mqtt_thread = threading.Thread(target=mqtt_subscription_loop, daemon=True)
        mqtt_thread.start()

    # Thread 5: Internet quality summaries.
    quality_thread = threading.Thread(target=internet_quality_loop, daemon=True)
    quality_thread.start()

    # Thread 6: Configuration change monitoring.
    config_monitor_thread = threading.Thread(target=config_change_monitor_loop, daemon=True)
    config_monitor_thread.start()

    # Thread 7: Local threat-intelligence enrichment.
    threat_thread = threading.Thread(target=threat_intel_loop, daemon=True)
    threat_thread.start()

    # Thread 8: Explainable network baseline and anomaly detection.
    anomaly_thread = threading.Thread(target=anomaly_baseline_loop, daemon=True)
    anomaly_thread.start()

    # Thread 9: Slow retention cleanup, kept away from the live packet loop.
    retention_thread = threading.Thread(target=retention_cleanup_loop, daemon=True)
    retention_thread.start()

    interface = str(startup_config.get("packet_iface") or "br0")

    print(f"NetSpecter nftables collector started for bridge: {interface}")
    print(f"Database: {DB_PATH}")
    print("AdGuard DNS querylog importer started")
    print(f"SNMP telemetry collector {'started' if snmp_started else 'disabled'}")
    print(f"MQTT telemetry collector {'started' if mqtt_started else 'disabled'}")
    print("Internet quality monitor started")
    print("Configuration change monitor started")
    print("Threat intelligence enrichment started")
    print("Anomaly baseline monitor started in learning-only mode")
    print("Retention cleanup scheduler started")
    write_heartbeat("OK", "collector started")

    while True:
        time.sleep(3600)
