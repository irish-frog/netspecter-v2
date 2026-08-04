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
- Imports AdGuard Home DNS answers for classification evidence.
- Classifies domains into application categories for Top Applications.
- Estimates bytes for selected apps from device-specific delivery DNS answers.

Important:
- Speeds in live_device_speed are stored as BYTES per second.
- live_bps in traffic_intervals is stored as BITS per second.
- dns_querylog powers Top Applications and per-device application views.
"""

import atexit
from contextlib import contextmanager
import fnmatch
import ipaddress
import json
import os
import re
import signal
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
    reclassify_default_ids_alerts,
)
from netspecter_anomaly import prune_anomalies, run_anomaly_cycle
from services.microsoft365_endpoints_service import cached_microsoft365_domain_mappings
from services.application_classification_service import is_reverse_dns_lookup_domain
from services.classification_resolver_service import (
    Flow,
    classify_flow,
    dns_answer_rows,
    upsert_unknown_traffic,
    write_classified_flow_fact,
)
from services.suricata_classification_service import enrich_from_suricata_metadata, reclassify_unknown_queue
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
    "raw_traffic_retention_hours": 6,
    "dns_retention_days": 60,
    "raw_dns_retention_hours": 24,
    "gateway_ip": "",
    "ignore_ips": [],
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
    "adguard_client_import_enabled": False,
    "device_identity_tracking_enabled": True,
    "device_identity_carry_names": True,
    "device_identity_exclude_private_macs": True,
    "netbios_discovery_enabled": True,
    "netbios_discovery_interval_seconds": 900,
    "netbios_discovery_batch_size": 12,
    "mdns_discovery_enabled": True,
    "snmp_name_discovery_enabled": False,
    "ssdp_discovery_enabled": True,
    "vendor_fallback_names_enabled": True,
    "unifi_enabled": False,
    "unifi_client_import_enabled": False,
    "unifi_connector_url": "",
    "unifi_site_id": "",
    "unifi_username": "",
    "unifi_password": "",
    "unifi_skip_tls_verify": False,
    "ids_unknown_only": False,
    "ids_excluded_ips": [],
    "ids_exceptions": [],
    "ids_banned_ips": [],
    "ids_banned_domains": [],
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
    "suricata_enabled": True,
    "ids_alert_retention_days": 30,
    "ids_ignored_retention_days": 3,
    "ids_low_priority_retention_days": 7,
    "ids_detail_retention_days": 7,
    "ids_file_retention_days": 7,
    "ids_raw_flow_retention_hours": 0,
    "suricata_log_retention_hours": 6,
    "suricata_active_log_max_mb": 64,
    "ids_structured_max_records": 100000,
    "ids_min_free_mb": 2048,
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
db_contention_lock = threading.Lock()
db_contention_until = 0.0
db_contention_failures = 0
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
nft_previous_classification_counters = {}
nft_active_ips = set()
live_traffic_today = {"day": "", "downloaded_mb": 0.0, "uploaded_mb": 0.0, "total_mb": 0.0}
device_inventory_write_cache = {}
estimated_app_targets = {}
estimated_targets_lock = threading.Lock()
last_suricata_import = 0.0
last_ids_default_reclassify = 0.0
last_unknown_reclassify = 0.0
last_unifi_import = 0.0
last_ids_maintenance = 0.0
last_incident_build = 0.0
last_netbios_discovery = 0.0
oui_vendor_cache = None
ESTIMATED_APP_NFT_TARGET_LIMIT = 200
CLASSIFICATION_NFT_TARGET_LIMIT = 300
NFT_SIGNATURE_REFRESH_SECONDS = 900
ADGUARD_CLIENT_REFRESH_SECONDS = 300
UNIFI_CLIENT_REFRESH_SECONDS = 1800
DB_CONTENTION_BACKOFF_BASE_SECONDS = 5
DB_CONTENTION_BACKOFF_MAX_SECONDS = 60
MICROSOFT365_MAPPING_CACHE = {"ts": 0.0, "enabled": None, "items": []}
MONITORED_APP_DOMAIN_KEYS = {
    "Nextcloud": ("nextcloud.com", "owncloud.com"),
    "YouTube": ("googlevideo.com", "youtube.com", "ytimg.com", "youtubei.googleapis.com"),
    "Netflix": ("nflxvideo.net", "netflix.com", "nflxso.net", "nflxext.com"),
    "TikTok": ("tiktokcdn.com", "tiktokv.com", "byteoversea.com", "ibytedtos.com"),
    "Facebook": ("fbcdn.net", "facebook.com", "facebook.net"),
    "Instagram": ("cdninstagram.com", "instagram.com"),
    "WhatsApp": ("whatsapp.net", "whatsapp.com"),
    "Life360": ("life360.com",),
    "Locket": ("locketcamera.com",),
    "OneDrive": ("onedrive.com", "onedrive.live.com", "storage.live.com"),
    "iCloud Drive": ("icloud.com", "icloud-content.com"),
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
    "Apple Update": ("apple.com", "cdn-apple.com", "mzstatic.com", "itunes.apple.com", "gdmf.apple.com"),
    "Android Update": ("android.com", "gvt1.com", "gvt2.com"),
    "Spotify": ("spotify.com", "scdn.co", "spotifycdn.com", "audio-ak-spotify-com.akamaized.net"),
    "Steam": ("steamserver.net", "steamcontent.com", "steampowered.com"),
    "Twitter / X": ("twitter.com", "twimg.com", "x.com"),
    "Snapchat": ("snapchat.com", "sc-cdn.net"),
    "Discord": ("discord.com", "discordapp.com", "discordcdn.com"),
    "Twitch": ("twitch.tv", "ttvnw.net"),
    "Disney+": ("disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com"),
    "Prime Video": ("primevideo.com", "aiv-cdn.net", "media-amazon.com"),
    "HVCDN": ("hvcdn.to",),
    "Xiaomi TV Services": ("tv.global.mi.com", "mitv.tracking.miui.com", "androidtvwatsonfe-pa.googleapis.com"),
    "Akamai CDN": ("akamai.net", "akamaihd.net", "akamaized.net"),
    "Cloudflare CDN": ("cloudflare.net", "cloudflare.com"),
    "Google Cloud": ("googleapis.com", "gstatic.com", "googleusercontent.com", "app-measurement.com", "firebaseio.com", "firebaseapp.com"),
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
    if not config.get("adguard_client_import_enabled"):
        return

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
    try:
        updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with timed_db_write("adguard_client_names") as con:
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
    except Exception as e:
        print(f"AdGuard client name database update failed: {e}")


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
    if not config.get("unifi_enabled") or not config.get("unifi_client_import_enabled"):
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
            try:
                with timed_db_write("unifi_client_import") as con:
                    identity_rows = []
                    for ip, name, mac, vendor, dtype, connected, seen_at in device_rows:
                        normalized_mac = normalize_mac(mac)
                        display_name = apply_device_identity(
                            con, ip, name, normalized_mac, vendor, dtype, seen_at, "unifi", config
                        )
                        identity_rows.append((ip, display_name, normalized_mac, vendor, dtype, connected, seen_at))
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
            except Exception as error:
                print(f"UniFi client database update failed: {error}")
                return
        unifi_clients_refreshed_at = now_monotonic
        print(f"UniFi connected clients imported: {imported} ({named_imported} named)")
    except Exception as e:
        print(f"UniFi client import failed: {e}")


def connect_db(timeout=30, busy_timeout_ms=30000):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    busy_timeout_ms = max(30000, int(busy_timeout_ms or 30000))
    timeout = max(30, float(timeout or 30))
    con = sqlite3.connect(DB_PATH, timeout=timeout)
    con.row_factory = sqlite3.Row
    con.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
    con.execute("PRAGMA journal_mode=WAL")
    attached = {row[1] for row in con.execute("PRAGMA database_list").fetchall()}
    if "dnsdb" not in attached:
        con.execute(f"ATTACH DATABASE '{str(DNS_DB_PATH).replace(chr(39), chr(39) + chr(39))}' AS dnsdb")
        con.execute("PRAGMA dnsdb.journal_mode=WAL")
        con.execute(f"PRAGMA dnsdb.busy_timeout={busy_timeout_ms}")
    if "trafficdb" not in attached:
        con.execute(f"ATTACH DATABASE '{str(TRAFFIC_DB_PATH).replace(chr(39), chr(39) + chr(39))}' AS trafficdb")
        con.execute("PRAGMA trafficdb.journal_mode=WAL")
        con.execute(f"PRAGMA trafficdb.busy_timeout={busy_timeout_ms}")
    return con


def positive_int(value, default, minimum=1):
    try:
        return max(minimum, int(value or default))
    except Exception:
        return max(minimum, int(default))


def database_contention_remaining():
    with db_contention_lock:
        return max(0.0, db_contention_until - time.monotonic())


def note_database_contention(context, error=None):
    global db_contention_failures, db_contention_until
    with db_contention_lock:
        db_contention_failures += 1
        backoff = min(
            DB_CONTENTION_BACKOFF_MAX_SECONDS,
            DB_CONTENTION_BACKOFF_BASE_SECONDS * db_contention_failures,
        )
        db_contention_until = max(db_contention_until, time.monotonic() + backoff)
    detail = f": {error}" if error else ""
    print(f"{context}: database busy; backing off writes for {backoff:.0f}s{detail}")


def note_database_write_success():
    global db_contention_failures, db_contention_until
    with db_contention_lock:
        db_contention_failures = 0
        db_contention_until = 0.0


@contextmanager
def timed_db_write(label, timeout=30, busy_timeout_ms=30000):
    lock_started = time.monotonic()
    db_write_lock.acquire()
    lock_wait = time.monotonic() - lock_started
    con = None
    txn_started = time.monotonic()
    try:
        con = connect_db(timeout=timeout, busy_timeout_ms=busy_timeout_ms)
        yield con
        commit_started = time.monotonic()
        con.commit()
        commit_elapsed = time.monotonic() - commit_started
        total_elapsed = time.monotonic() - txn_started
        if lock_wait >= 0.2 or total_elapsed >= 0.2 or commit_elapsed >= 0.2:
            print(
                f"DB write section {label}: "
                f"lock_wait={lock_wait:.3f}s txn={total_elapsed:.3f}s commit={commit_elapsed:.3f}s"
            )
        note_database_write_success()
    except Exception:
        if con:
            con.rollback()
        raise
    finally:
        if con:
            con.close()
        db_write_lock.release()


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


def normalize_mac(mac):
    text = re.sub(r"[^0-9A-Fa-f]", "", str(mac or ""))
    if len(text) != 12:
        return ""
    return ":".join(text[i:i + 2] for i in range(0, 12, 2)).upper()


def meaningful_device_name(name, ip=""):
    text = str(name or "").strip()
    if not text or text == str(ip or "").strip():
        return ""
    return text


def identity_tracking_enabled(config=None):
    return bool((config or cfg()).get("device_identity_tracking_enabled", True))


def identity_carry_names_enabled(config=None):
    return bool((config or cfg()).get("device_identity_carry_names", True))


def identity_private_mac_excluded(mac, config=None):
    return bool((config or cfg()).get("device_identity_exclude_private_macs", True)) and private_mac_address(mac)


def identity_source_rank(source):
    return {
        "manual": 100,
        "unifi": 90,
        "snmp": 82,
        "dhcp": 80,
        "netbios": 75,
        "mdns": 70,
        "ssdp": 68,
        "adguard": 65,
        "vendor": 25,
        "traffic": 35,
    }.get(str(source or "").lower(), 20)


def identity_key_for_mac(mac):
    normalized = normalize_mac(mac)
    return f"mac:{normalized}" if normalized else ""


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


def apply_device_identity(con, ip, name="", mac="", vendor="", device_type="Unknown", ts="", source="traffic", config=None):
    """Persist stable MAC identity and return the best display name for this IP row."""
    c = config or cfg()
    if not identity_tracking_enabled(c):
        return meaningful_device_name(name, ip) or str(name or ip)
    ip = ip_identifier(ip)
    normalized_mac = normalize_mac(mac)
    observed_name = meaningful_device_name(name, ip)
    ts = ts or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not ip or not normalized_mac:
        return observed_name or str(name or ip)

    is_private = private_mac_address(normalized_mac)
    if identity_private_mac_excluded(normalized_mac, c):
        identity_key = f"private-mac:{normalized_mac}:{ip}"
    else:
        identity_key = identity_key_for_mac(normalized_mac)
    if not identity_key:
        return observed_name or str(name or ip)

    existing = con.execute(
        """
        SELECT display_name, current_ip, source, first_seen, private_mac
        FROM device_identities
        WHERE identity_key=?
        """,
        (identity_key,),
    ).fetchone()
    existing_name = str(existing["display_name"] or "").strip() if existing else ""
    existing_source = str(existing["source"] or "").strip() if existing else ""
    carry_name = existing_name if identity_carry_names_enabled(c) and not is_private else ""
    display_name = observed_name or carry_name or str(name or ip)
    should_update_name = bool(observed_name) and (
        not existing_name or identity_source_rank(source) >= identity_source_rank(existing_source)
    )
    stored_name = observed_name if should_update_name else existing_name or observed_name
    first_seen = min(str(existing["first_seen"] or ts), ts) if existing else ts
    current_ip = str(existing["current_ip"] or "").strip() if existing else ""
    last_ip = current_ip if current_ip and current_ip != ip else str(existing["last_ip"] or "").strip() if existing else ""

    con.execute(
        """
        INSERT INTO device_identities
            (identity_key, mac, hostname, display_name, current_ip, last_ip, vendor, device_type,
             source, confidence, private_mac, first_seen, last_seen, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(identity_key) DO UPDATE SET
            hostname=COALESCE(NULLIF(excluded.hostname, ''), hostname),
            display_name=CASE
                WHEN excluded.display_name IS NOT NULL AND TRIM(excluded.display_name) != ''
                THEN excluded.display_name ELSE display_name END,
            current_ip=excluded.current_ip,
            last_ip=excluded.last_ip,
            vendor=COALESCE(NULLIF(excluded.vendor, ''), vendor),
            device_type=CASE
                WHEN device_type IS NULL OR device_type='' OR device_type='Unknown'
                THEN excluded.device_type ELSE device_type END,
            source=excluded.source,
            confidence=MAX(confidence, excluded.confidence),
            private_mac=excluded.private_mac,
            first_seen=MIN(first_seen, excluded.first_seen),
            last_seen=MAX(last_seen, excluded.last_seen),
            updated_at=excluded.updated_at
        """,
        (
            identity_key,
            normalized_mac,
            observed_name,
            stored_name,
            ip,
            last_ip,
            vendor or "",
            device_type or "Unknown",
            source,
            40 if is_private else max(50, identity_source_rank(source)),
            1 if is_private else 0,
            first_seen,
            ts,
            ts,
        ),
    )
    con.execute(
        """
        INSERT INTO device_ip_history
            (identity_key, ip, mac, hostname, source, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(identity_key, ip) DO UPDATE SET
            hostname=COALESCE(NULLIF(excluded.hostname, ''), hostname),
            source=excluded.source,
            first_seen=MIN(first_seen, excluded.first_seen),
            last_seen=MAX(last_seen, excluded.last_seen)
        """,
        (identity_key, ip, normalized_mac, observed_name, source, ts, ts),
    )
    if carry_name and not observed_name:
        print(f"Device identity carried name {carry_name} from {last_ip or 'previous IP'} to {ip} via {normalized_mac}")
    return display_name


def parse_nmblookup_status(output):
    name = ""
    mac = ""
    for line in str(output or "").splitlines():
        text = line.strip()
        mac_match = re.search(r"MAC Address\s*=\s*([0-9A-Fa-f:-]{17})", text)
        if mac_match:
            mac = normalize_mac(mac_match.group(1))
            continue
        match = re.match(r"^([^\s<]{1,63})\s+<00>\s+-\s+(?:(<GROUP>)\s+)?M\s+<ACTIVE>", text)
        if not match or match.group(2):
            continue
        candidate = match.group(1).strip()
        if candidate and candidate != "__MSBROWSE__":
            name = candidate
    return name, mac


def discover_netbios_name(ip, timeout=3):
    ip = ip_identifier(ip)
    if not ip:
        return "", ""
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return "", ""
    except subprocess.TimeoutExpired:
        return "", ""
    except Exception as error:
        print(f"NetBIOS discovery failed for {ip}: {error}")
        return "", ""
    if result.returncode != 0 and not result.stdout:
        return "", ""
    return parse_nmblookup_status(result.stdout)


def clean_discovered_name(name, ip=""):
    text = str(name or "").strip().strip(".")
    text = re.sub(r"\.local$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    if not text or text == str(ip or "").strip() or text.lower() in {"unknown", "localhost"}:
        return ""
    return text[:80]


def discover_mdns_name(ip, timeout=3):
    ip = ip_identifier(ip)
    if not ip:
        return ""
    for command in (["avahi-resolve-address", ip], ["avahi-resolve", "-a", ip]):
        try:
            result = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception as error:
            print(f"mDNS discovery failed for {ip}: {error}")
            continue
        if result.returncode != 0:
            continue
        text = (result.stdout or "").strip()
        if not text:
            continue
        parts = re.split(r"\s+", text)
        candidate = parts[-1] if parts else ""
        name = clean_discovered_name(candidate, ip)
        if name:
            return name
    return ""


def discover_snmp_name(ip, config=None, timeout=3):
    c = config or cfg()
    if not c.get("snmp_name_discovery_enabled", True):
        return ""
    community = str(c.get("snmp_community") or "public").strip() or "public"
    port = positive_int(c.get("snmp_port", 161), 161, 1)
    value = snmpget_value(ip, community, "1.3.6.1.2.1.1.5.0", port=port, timeout=timeout, quiet=True)
    if value.startswith(("snmpget ", "snmpget failed", "snmpget timed out")):
        return ""
    return clean_discovered_name(value.strip('"'), ip)


def ssdp_location_for_ip(ip, timeout=2):
    ip = ip_identifier(ip)
    if not ip:
        return ""
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(message, ("239.255.255.250", 1900))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, address = sock.recvfrom(4096)
            except socket.timeout:
                break
            if address[0] != ip:
                continue
            text = data.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if line.lower().startswith("location:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        return ""
    finally:
        if sock:
            sock.close()
    return ""


def discover_ssdp_name(ip, timeout=3):
    location = ssdp_location_for_ip(ip, timeout=2)
    if not location or requests is None:
        return ""
    try:
        response = requests.get(location, timeout=timeout)
        if response.status_code != 200:
            return ""
        match = re.search(r"<friendlyName>\s*([^<]+)\s*</friendlyName>", response.text or "", re.IGNORECASE)
        if match:
            return clean_discovered_name(match.group(1), ip)
    except Exception:
        return ""
    return ""


def vendor_fallback_name(ip, vendor="", device_type=""):
    vendor_text = str(vendor or "").strip()
    dtype = str(device_type or "").strip() or classify_device(vendor_text)
    if not vendor_text or vendor_text == "Unknown Vendor":
        return ""
    if vendor_text == "Private / Random MAC":
        return f"Mobile Device - Private MAC"
    short_vendor = re.sub(r"\b(inc|ltd|corp|corporation|co|company)\.?\b", "", vendor_text, flags=re.IGNORECASE)
    short_vendor = re.sub(r"\s+", " ", short_vendor).strip(" .,-")
    if dtype and dtype != "Unknown":
        return f"{dtype} - {short_vendor or vendor_text}"
    return short_vendor or vendor_text


def discover_device_name(ip, mac="", vendor="", device_type="", config=None):
    c = config or cfg()
    if c.get("netbios_discovery_enabled", True):
        name, discovered_mac = discover_netbios_name(ip)
        name = clean_discovered_name(name, ip)
        if name:
            return name, discovered_mac or normalize_mac(mac), "netbios"
        if discovered_mac and not mac:
            mac = discovered_mac
    if c.get("mdns_discovery_enabled", True):
        name = discover_mdns_name(ip)
        if name:
            return name, normalize_mac(mac), "mdns"
    if c.get("snmp_name_discovery_enabled", True):
        name = discover_snmp_name(ip, c)
        if name:
            return name, normalize_mac(mac), "snmp"
    if c.get("ssdp_discovery_enabled", True):
        name = discover_ssdp_name(ip)
        if name:
            return name, normalize_mac(mac), "ssdp"
    if c.get("vendor_fallback_names_enabled", True):
        name = vendor_fallback_name(ip, vendor, device_type)
        if name:
            return name, normalize_mac(mac), "vendor"
    return "", normalize_mac(mac), ""


def netbios_discovery_pass(config=None):
    c = config or cfg()
    if not c.get("netbios_discovery_enabled", True):
        return 0
    batch_size = min(64, positive_int(c.get("netbios_discovery_batch_size", 12), 12, 1))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    try:
        con = connect_db(timeout=2, busy_timeout_ms=1000)
        rows = con.execute(
            """
            SELECT d.ip, d.name, d.mac, d.vendor, d.device_type, o.name AS override_name
            FROM devices d
            LEFT JOIN device_overrides o ON o.ip=d.ip
            WHERE d.last_seen >= ?
              AND d.ip IS NOT NULL AND d.ip != ''
              AND (d.name IS NULL OR TRIM(d.name)='' OR d.name=d.ip OR LOWER(d.name)='unknown')
              AND (o.name IS NULL OR TRIM(o.name)='' OR o.name=o.ip OR LOWER(o.name)='unknown')
            ORDER BY
              d.last_seen DESC
            LIMIT ?
            """,
            (cutoff, batch_size),
        ).fetchall()
        con.close()
    except Exception as error:
        print(f"NetBIOS discovery candidate query failed: {error}")
        return 0

    updates = []
    for row in rows:
        ip = str(row["ip"] or "").strip()
        override_name = str(row["override_name"] or "").strip()
        has_real_override = bool(override_name and override_name != ip)
        discovered_name, discovered_mac, source = discover_device_name(
            ip,
            row["mac"],
            row["vendor"],
            row["device_type"],
            c,
        )
        if not discovered_name and not discovered_mac:
            continue
        vendor = vendor_from_mac(discovered_mac) if discovered_mac else str(row["vendor"] or "Unknown Vendor")
        dtype = classify_device(vendor)
        updates.append((ip, discovered_name, discovered_mac, vendor, dtype, has_real_override, source or "discovery"))

    if not updates:
        return 0

    try:
        with timed_db_write("netbios_discovery") as con:
            applied = 0
            for ip, name, mac, vendor, dtype, has_real_override, source in updates:
                display_name = apply_device_identity(con, ip, name, mac, vendor, dtype, now, source, c)
                device_name = "" if has_real_override else display_name
                con.execute(
                    """
                    INSERT INTO devices (ip, name, mac, vendor, device_type, status, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, 'Active', ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        name=CASE
                            WHEN excluded.name IS NOT NULL AND TRIM(excluded.name) != '' AND excluded.name != excluded.ip
                            THEN excluded.name ELSE devices.name END,
                        mac=CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
                        vendor=CASE WHEN excluded.mac != '' THEN excluded.vendor ELSE devices.vendor END,
                        device_type=CASE
                            WHEN devices.device_type IS NULL OR devices.device_type='' OR devices.device_type='Unknown'
                            THEN excluded.device_type ELSE devices.device_type END,
                        last_seen=CASE
                            WHEN devices.last_seen IS NULL OR devices.last_seen < excluded.last_seen
                            THEN excluded.last_seen ELSE devices.last_seen END
                    """,
                    (ip, device_name, normalize_mac(mac), vendor, dtype, now, now),
                )
                if name:
                    con.execute(
                        """
                        UPDATE device_overrides
                        SET name=?, updated_at=?
                        WHERE ip=? AND (name IS NULL OR TRIM(name)='' OR name=ip)
                        """,
                        (name, now, ip),
                    )
                applied += 1
        if applied:
            print(f"Device name discovery updated: {applied}")
        return applied
    except Exception as error:
        print(f"NetBIOS discovery database update failed: {error}")
        return 0


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
    if is_reverse_dns_lookup_domain(d):
        return "DNS Reverse Lookup"
    if d == "x.com" or d.endswith(".x.com"):
        return "Twitter / X"
    m365_app = microsoft365_app_from_domain(d)
    if m365_app:
        return m365_app

    mapping = {
        "YouTube": ["youtube", "googlevideo", "ytimg"],
        "TikTok": ["tiktok", "tiktokcdn", "tiktokv", "byteoversea", "bytedance", "ibytedtos"],
        "Netflix": ["netflix", "nflx", "nrdp"],
        "Spotify": ["spotify", "spclient", "scdn.co"],
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
        "Facebook": ["facebook", "fbcdn", "facebook.net", "messenger"],
        "Instagram": ["instagram", "cdninstagram"],
        "WhatsApp": ["whatsapp"],
        "Life360": ["life360"],
        "Locket": ["locketcamera"],
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
        "Apple Update": ["cdn-apple", "mzstatic", "itunes.apple", "gdmf.apple"],
        "Android Update": ["android.com", "gvt1", "gvt2"],
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
        "iCloud Drive": ["icloud", "icloud-content"],
        "Apple": ["apple", "aaplimg"],
        "Google Cloud": ["googleusercontent", "app-measurement", "firebaseio", "firebaseapp"],
        "Google": ["google", "gstatic", "googleapis", "androidtvchannels"],
        "Plex": ["plex"],
        "HVCDN": ["hvcdn"],
        "Xiaomi TV Services": ["tv.global.mi.com", "androidtvwatsonfe", "mitv.tracking.miui"],
        "Samsung": ["samsung"],
        "Cloudflare": ["cloudflare"],
        "Akamai CDN": ["akamai", "akamaihd"],
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
    remaining = database_contention_remaining()
    if remaining > 0:
        return

    for attempt in range(retries):
        try:
            with timed_db_write("run_sql", timeout=timeout, busy_timeout_ms=busy_timeout_ms) as con:
                con.execute(sql, params)
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower() and attempt < retries - 1:
                time.sleep(0.25 * (attempt + 1))
                continue
            if "database is locked" in str(e).lower():
                note_database_contention("DB write", e)
                return
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


def snmpget_value(target, community, oid, port=161, timeout=8, quiet=False):
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
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return (result.stdout or "").strip().strip('"')
    except FileNotFoundError:
        return "snmpget not installed"
    except Exception as e:
        if not quiet:
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
    destination_ip = str(exception.get("destination_ip") or "").strip()
    signature = str(exception.get("signature") or "").strip().lower()
    alert_source = ids_endpoint_ip(alert.get("source") or alert.get("src_ip") or "")
    alert_destination = ids_endpoint_ip(alert.get("destination") or alert.get("dest_ip") or "")
    alert_signature = str(alert.get("signature") or "").strip().lower()
    if source_ip and source_ip != alert_source:
        return False
    if destination_ip and destination_ip != alert_destination:
        return False
    if signature and signature != alert_signature:
        return False
    return bool(source_ip or destination_ip or signature)


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
    global last_ids_default_reclassify, last_unknown_reclassify
    if not (config or {}).get("suricata_enabled", True):
        return
    try:
        contention_remaining = database_contention_remaining()
        if contention_remaining > 0:
            print(f"Suricata/eve import skipped: database contention backoff {contention_remaining:.0f}s remaining")
            return

        result = ingest_eve_incremental(connect_db, SURICATA_EVE_LOG)
        if result.get("inserted"):
            print(f"Suricata eve.json imported rows: {result['inserted']}")
            now_mono = time.monotonic()
            reclassify_interval = positive_int(config.get("ids_default_reclassify_interval_seconds", 1800), 1800, 60)
            if now_mono - last_ids_default_reclassify >= reclassify_interval:
                last_ids_default_reclassify = now_mono
                changed = reclassify_default_ids_alerts(connect_db)
                if changed:
                    print(f"Suricata IDS alert severities reclassified: {changed}")
        if result.get("bad_json"):
            print(f"Suricata eve.json skipped malformed rows: {result['bad_json']}")
        enrichment = run_suricata_classification_enrichment()
        if enrichment.get("processed"):
            print(
                "Suricata metadata classification: "
                f"{enrichment['classified']} classified, {enrichment['unknown']} unknown "
                f"from {enrichment['processed']} metadata rows"
            )
        now_mono = time.monotonic()
        unknown_interval = positive_int(config.get("unknown_reclassify_interval_seconds", 300), 300, 30)
        if now_mono - last_unknown_reclassify >= unknown_interval:
            last_unknown_reclassify = now_mono
            reclassified = run_unknown_queue_reclassification()
            if reclassified.get("classified"):
                print(
                    "Unknown traffic reclassification: "
                    f"{reclassified['classified']} classified from {reclassified['processed']} queued destinations"
                )
    except Exception as error:
        if "database is locked" in str(error).lower():
            note_database_contention("Suricata eve.json import", error)
        else:
            print(f"Suricata eve.json import failed: {error}")


def run_suricata_classification_enrichment(batch_size=500):
    try:
        if database_contention_remaining() > 0:
            return {"processed": 0, "classified": 0, "unknown": 0}
        with timed_db_write("suricata_metadata_classification") as con:
            result = enrich_from_suricata_metadata(con, batch_size=batch_size)
        return result
    except Exception as error:
        if "database is locked" in str(error).lower():
            note_database_contention("Suricata metadata classification", error)
            return {"processed": 0, "classified": 0, "unknown": 0, "error": str(error)}
        print(f"Suricata metadata classification failed: {error}")
        return {"processed": 0, "classified": 0, "unknown": 0, "error": str(error)}


def run_unknown_queue_reclassification(batch_size=200):
    try:
        if database_contention_remaining() > 0:
            return {"processed": 0, "classified": 0}
        with timed_db_write("unknown_queue_reclassification") as con:
            result = reclassify_unknown_queue(con, batch_size=batch_size)
        return result
    except Exception as error:
        if "database is locked" in str(error).lower():
            note_database_contention("Unknown traffic reclassification", error)
            return {"processed": 0, "classified": 0, "error": str(error)}
        print(f"Unknown traffic reclassification failed: {error}")
        return {"processed": 0, "classified": 0, "error": str(error)}


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
    quality_days = positive_int(c.get("internet_quality_retention_days", 60), 60, 1)
    config_days = positive_int(c.get("config_change_retention_days", 180), 180, 1)
    threat_days = positive_int(c.get("threat_intel_retention_days", 30), 30, 1)
    traffic_cutoff = f"-{traffic_days - 1} days"
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
        from services.dns_rollup_service import prune_dns_history
        prune_dns_history(con, c)
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
        reclassify_default_ids_alerts(connect_db)
        prune_ids_history(connect_db, c)
        prune_quality_history(connect_db, c)
        prune_config_changes(connect_db, c)
        prune_threat_intel(connect_db, c)
        prune_incidents(connect_db, c)
        prune_anomalies(connect_db, c)
    except Exception as e:
        print(f"History retention cleanup failed: {e}")


def rollup_and_prune_raw_traffic(config=None):
    """Summarise raw traffic rows into hourly rollups, then prune short-lived raw rows."""
    c = config or cfg()
    raw_hours = positive_int(c.get("raw_traffic_retention_hours", 6), 6, 1)
    traffic_days = positive_int(c.get("traffic_retention_days", 60), 60, 1)
    raw_cutoff = f"-{raw_hours} hours"
    rollup_cutoff = f"-{traffic_days - 1} days"
    con = None
    try:
        con = connect_db()
        con.execute("PRAGMA busy_timeout=1000")
        con.execute(
            """
            INSERT INTO traffic_hourly_rollups
                (hour, day, ip, name, mac, downloaded_mb, uploaded_mb, total_mb, avg_live_bps, samples)
            SELECT
                substr(ts, 1, 13) || ':00' AS hour,
                day,
                ip,
                COALESCE(MAX(NULLIF(name, '')), ip) AS name,
                COALESCE(MAX(NULLIF(mac, '')), '') AS mac,
                SUM(downloaded_mb),
                SUM(uploaded_mb),
                SUM(total_mb),
                AVG(live_bps),
                COUNT(*)
            FROM traffic_intervals
            WHERE ts < datetime('now', 'localtime', ?)
            GROUP BY hour, day, ip
            ON CONFLICT(hour, ip) DO UPDATE SET
                name=excluded.name,
                mac=excluded.mac,
                downloaded_mb=excluded.downloaded_mb,
                uploaded_mb=excluded.uploaded_mb,
                total_mb=excluded.total_mb,
                avg_live_bps=excluded.avg_live_bps,
                samples=excluded.samples
            """,
            (raw_cutoff,),
        )
        con.execute(
            """
            INSERT INTO estimated_app_hourly_rollups
                (hour, day, ip, category, downloaded_mb, uploaded_mb, total_mb, samples)
            SELECT
                substr(ts, 1, 13) || ':00' AS hour,
                day,
                ip,
                category,
                SUM(downloaded_mb),
                SUM(uploaded_mb),
                SUM(total_mb),
                COUNT(*)
            FROM estimated_app_traffic
            WHERE ts < datetime('now', 'localtime', ?)
            GROUP BY hour, day, ip, category
            ON CONFLICT(hour, ip, category) DO UPDATE SET
                downloaded_mb=excluded.downloaded_mb,
                uploaded_mb=excluded.uploaded_mb,
                total_mb=excluded.total_mb,
                samples=excluded.samples
            """,
            (raw_cutoff,),
        )
        con.execute(
            """
            INSERT INTO remote_traffic_hourly_rollups
                (hour, day, ip, remote_ip, category, downloaded_mb, uploaded_mb, total_mb, samples)
            SELECT
                substr(ts, 1, 13) || ':00' AS hour,
                day,
                ip,
                remote_ip,
                category,
                SUM(downloaded_mb),
                SUM(uploaded_mb),
                SUM(total_mb),
                COUNT(*)
            FROM remote_traffic_intervals
            WHERE ts < datetime('now', 'localtime', ?)
            GROUP BY hour, day, ip, remote_ip, category
            ON CONFLICT(hour, ip, remote_ip, category) DO UPDATE SET
                downloaded_mb=excluded.downloaded_mb,
                uploaded_mb=excluded.uploaded_mb,
                total_mb=excluded.total_mb,
                samples=excluded.samples
            """,
            (raw_cutoff,),
        )
        con.execute(
            """
            INSERT INTO classified_flow_rollups
                (bucket, day, source_ip, destination_ip, domain, sni, protocol, port,
                 primary_app, primary_category, confidence, bytes_in, bytes_out,
                 total_mb, optional_tags_json, first_seen, last_seen)
            SELECT
                substr(ts, 1, 13) || ':00' AS bucket,
                day,
                local_ip AS source_ip,
                remote_ip AS destination_ip,
                CASE WHEN evidence_source IN ('dns_resolution', 'http_host') THEN application ELSE '' END AS domain,
                CASE WHEN evidence_source='tls_sni' THEN application ELSE '' END AS sni,
                protocol,
                port,
                COALESCE(NULLIF(application, ''), category) AS primary_app,
                category AS primary_category,
                CASE
                    WHEN confidence='high' THEN 90
                    WHEN confidence='medium' THEN 65
                    WHEN confidence='low' THEN 35
                    ELSE 0
                END AS confidence,
                0 AS bytes_in,
                SUM(bytes) AS bytes_out,
                SUM(bytes) / 1024.0 / 1024.0 AS total_mb,
                json_array(evidence_source, confidence) AS optional_tags_json,
                MIN(ts) AS first_seen,
                MAX(ts) AS last_seen
            FROM classified_flow_facts
            WHERE ts < datetime('now', 'localtime', ?)
            GROUP BY bucket, day, source_ip, destination_ip, domain, sni, protocol, port, primary_app, primary_category, confidence
            ON CONFLICT(bucket, source_ip, destination_ip, domain, sni, protocol, port, primary_app) DO UPDATE SET
                primary_category=excluded.primary_category,
                confidence=excluded.confidence,
                bytes_in=excluded.bytes_in,
                bytes_out=excluded.bytes_out,
                total_mb=excluded.total_mb,
                optional_tags_json=excluded.optional_tags_json,
                first_seen=excluded.first_seen,
                last_seen=excluded.last_seen
            """,
            (raw_cutoff,),
        )
        con.execute("DELETE FROM traffic_intervals WHERE ts < datetime('now', 'localtime', ?)", (raw_cutoff,))
        con.execute("DELETE FROM traffic_samples WHERE ts < datetime('now', 'localtime', ?)", (raw_cutoff,))
        con.execute("DELETE FROM classified_flow_facts WHERE ts < datetime('now', 'localtime', ?)", (raw_cutoff,))
        con.execute("DELETE FROM traffic_hourly_rollups WHERE day < date('now', 'localtime', ?)", (rollup_cutoff,))
        con.execute("DELETE FROM estimated_app_hourly_rollups WHERE day < date('now', 'localtime', ?)", (rollup_cutoff,))
        con.execute("DELETE FROM remote_traffic_hourly_rollups WHERE day < date('now', 'localtime', ?)", (rollup_cutoff,))
        con.execute("DELETE FROM classified_flow_rollups WHERE day < date('now', 'localtime', ?)", (rollup_cutoff,))
        con.execute("DELETE FROM classified_flow_facts WHERE day < date('now', 'localtime', ?)", (rollup_cutoff,))
        con.commit()
        con.execute("PRAGMA wal_checkpoint(PASSIVE)")
    except Exception as e:
        if con:
            con.rollback()
        print(f"Traffic rollup cleanup failed: {e}")
    finally:
        if con:
            con.close()


def prune_suricata_raw_logs(config=None):
    """Keep Suricata raw logs bounded; NetSpecter keeps normalized IDS history separately."""
    c = config or cfg()
    retention_hours = positive_int(c.get("suricata_log_retention_hours", 24), 24, 1)
    active_max_mb = positive_int(c.get("suricata_active_log_max_mb", 256), 256, 16)
    log_dir = SURICATA_EVE_LOG.parent
    active_logs = {SURICATA_EVE_LOG.resolve(), SURICATA_FAST_LOG.resolve()}
    cutoff = time.time() - (retention_hours * 3600)
    max_bytes = active_max_mb * 1024 * 1024
    if not log_dir.exists():
        return
    try:
        for path in log_dir.iterdir():
            if not path.is_file():
                continue
            resolved = path.resolve()
            name = path.name.lower()
            if resolved in active_logs:
                try:
                    if path.stat().st_size > max_bytes:
                        path.write_text("")
                        print(f"Suricata active log truncated: {path}")
                except Exception as error:
                    print(f"Suricata active log cleanup failed for {path}: {error}")
                continue
            if not (name.endswith(".log") or name.endswith(".json") or name.endswith(".old") or name.endswith(".gz")):
                continue
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    print(f"Suricata old raw log deleted: {path}")
            except Exception as error:
                print(f"Suricata raw log cleanup failed for {path}: {error}")
    except Exception as error:
        print(f"Suricata raw log cleanup failed: {error}")


def retention_cleanup_loop():
    init_db()
    time.sleep(30 * 60)
    while True:
        started = time.monotonic()
        try:
            with db_write_lock:
                rollup_and_prune_raw_traffic(cfg())
                prune_suricata_raw_logs(cfg())
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
    output = {}
    assigned_ips = set()
    mappings = (config or cfg()).get("site_application_mappings")
    for row in mappings if isinstance(mappings, list) else []:
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
        assigned_ips.add(ip)
    for app_name, ips in SITE_MONITORED_APP_IPS.items():
        for ip in ips:
            if ip in assigned_ips:
                continue
            output.setdefault(app_name, set()).add(ip)
    return output


def remember_estimated_app_targets(config, client, domain, answers, observed_at="", blocked=False):
    """Remember client/destination pairs for explicitly monitored app categories."""
    if blocked:
        return
    category = monitored_app_for_domain(domain, config)
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
    for answer in answers if isinstance(answers, list) else []:
        if not isinstance(answer, dict) or str(answer.get("type") or "").upper() != "A":
            continue
        try:
            destination = ipaddress.ip_address(str(answer.get("value") or "").strip())
        except ValueError:
            continue
        if destination.version != 4 or destination.is_unspecified:
            continue
        target_category = category or monitored_app_for_ip(destination, configured_app_ips)
        if not target_category:
            continue
        local_app_ips = configured_app_ips.get(target_category, set())
        if destination in network and str(destination) not in local_app_ips:
            continue
        ttl = positive_int(answer.get("ttl", 900), 900, 1)
        expires = observed_epoch + min(max(ttl, 900), 21600)
        if expires <= now:
            continue
        key = (str(client_ip), str(destination))
        with estimated_targets_lock:
            existing = estimated_app_targets.get(key)
            if not existing or existing[0] == target_category or existing[1] <= now:
                estimated_app_targets[key] = (target_category, max(existing[1] if existing and existing[0] == target_category else 0, expires))


def monitored_app_for_ip(destination, configured_app_ips=None):
    destination_text = str(destination or "").strip()
    for app_name, ips in (configured_app_ips or monitored_app_ips()).items():
        if destination_text in ips:
            return app_name
    return ""


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


def active_classification_targets(config=None):
    """Return recent DNS client/destination pairs for lightweight byte classification."""
    c = config or cfg()
    try:
        requested_limit = int(c.get("classification_nft_target_limit", CLASSIFICATION_NFT_TARGET_LIMIT))
    except (TypeError, ValueError):
        requested_limit = CLASSIFICATION_NFT_TARGET_LIMIT
    if requested_limit <= 0:
        return tuple()
    limit = min(max(1, requested_limit), 1000)
    try:
        network = lan_network(c)
    except ValueError:
        return tuple()
    rows = []
    con = None
    try:
        con = connect_db(timeout=1, busy_timeout_ms=500)
        rows = con.execute(
            """
            SELECT client_ip, resolved_ip, MAX(expires_at) AS expires_at, MAX(ts) AS last_seen
            FROM dns_resolution_events
            WHERE expires_at >= datetime('now', 'localtime')
              AND client_ip IS NOT NULL AND client_ip != ''
              AND resolved_ip IS NOT NULL AND resolved_ip != ''
            GROUP BY client_ip, resolved_ip
            ORDER BY MAX(ts) DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    except Exception as error:
        print(f"Classification target refresh failed: {error}")
        return tuple()
    finally:
        if con:
            con.close()

    targets = []
    for row in rows:
        client = str(row["client_ip"] if hasattr(row, "keys") else row[0]).strip()
        destination = str(row["resolved_ip"] if hasattr(row, "keys") else row[1]).strip()
        try:
            client_ip = ipaddress.ip_address(client)
            destination_ip = ipaddress.ip_address(destination)
        except ValueError:
            continue
        if client_ip.version != 4 or destination_ip.version != 4:
            continue
        if client_ip not in network:
            continue
        if destination_ip in network or destination_ip.is_unspecified:
            continue
        targets.append((client, destination))
    return tuple(sorted(set(targets)))


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
        active_classification_targets(c),
    )


def install_nft_counters(config=None):
    """Create bridge traffic counters and any configured IDS endpoint drop rules."""
    global nft_config_signature, nft_previous_counters, nft_previous_estimated_counters, nft_previous_classification_counters, nft_active_ips, live_traffic_today, device_inventory_write_cache
    started = time.monotonic()
    c = config or cfg()
    signature = nft_signature(c)
    interface, network_text, ignored, banned_ips, app_targets, classification_targets = signature
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
    app_target_pairs = {(client, destination) for _category, client, destination in app_targets}
    for client, destination in classification_targets:
        if (client, destination) in app_target_pairs:
            continue
        lines.append(
            f'    ip saddr {client} ip daddr {destination} counter comment "netspecter:classify:tx:{client}:{destination}"'
        )
        lines.append(
            f'    ip daddr {client} ip saddr {destination} counter comment "netspecter:classify:rx:{client}:{destination}"'
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
    nft_previous_classification_counters = {}
    nft_active_ips = set()
    device_inventory_write_cache = {}
    print(
        f"nftables traffic counters installed for {network_text} on bridge traffic ({interface}); "
        f"{len(app_targets)} monitored app attribution target(s); "
        f"{len(classification_targets)} classification target(s); {len(banned_ips)} IDS banned endpoint(s)"
    )
    log_slow_loop("nftables counter install", time.monotonic() - started, threshold=2.0)


def remove_nft_counters():
    """Remove NetSpecter's private counter table during an orderly shutdown."""
    global nft_config_signature, nft_previous_counters, nft_previous_estimated_counters, nft_previous_classification_counters, nft_active_ips, live_traffic_today
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
    nft_previous_classification_counters = {}
    nft_active_ips = set()
    print("NetSpecter nftables traffic counters removed")


def shutdown_collector(signum, _frame):
    print(f"Collector shutting down after signal {signum}")
    remove_nft_counters()
    raise SystemExit(0)


def read_nft_counters():
    """Return device totals and lightweight destination totals from nftables."""
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
    classification_counters = {}
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
        elif len(parts) == 5 and parts[1] == "classify" and parts[2] in ("rx", "tx"):
            classification_counters[(parts[2], parts[3], parts[4])] = total_bytes
    return counters, estimated_counters, classification_counters


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


def write_destination_delta(con, ip, destination, cur, day, now, default_category="Unknown"):
    interval_rx_mb = cur["rx"] / 1024 / 1024
    interval_tx_mb = cur["tx"] / 1024 / 1024
    interval_total_mb = interval_rx_mb + interval_tx_mb
    if interval_total_mb <= 0:
        return
    flow = Flow(
        ts=now,
        local_ip=ip,
        remote_ip=destination,
        bytes=int(cur["rx"] + cur["tx"]),
        protocol="tcp",
    )
    classification = classify_flow(con, flow, emit_timing=True)
    category = classification.category if classification else default_category
    con.execute(
        """
        INSERT INTO remote_traffic_intervals
            (ip, remote_ip, category, downloaded_mb, uploaded_mb, total_mb, day, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (ip, destination, category, interval_rx_mb, interval_tx_mb, interval_total_mb, day, now),
    )
    if classification:
        write_started = time.monotonic()
        write_classified_flow_fact(con, flow, classification)
        elapsed = time.monotonic() - write_started
        if elapsed >= 0.05:
            print(f"destination_classify_write: classified_fact={elapsed:.3f}s")
    else:
        write_started = time.monotonic()
        upsert_unknown_traffic(con, flow)
        elapsed = time.monotonic() - write_started
        if elapsed >= 0.05:
            print(f"destination_classify_write: unknown_queue={elapsed:.3f}s")


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
    global nft_config_signature, nft_previous_counters, nft_previous_estimated_counters, nft_previous_classification_counters, nft_active_ips, live_traffic_today
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

            current_counters, current_estimated_counters, current_classification_counters = read_nft_counters()
            flush_at = time.monotonic()
            elapsed = max(flush_at - last_flush_at, 0.001)
            last_flush_at = flush_at
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            day = datetime.now().strftime("%Y-%m-%d")
            device_inventory_interval = positive_int(c.get("traffic_device_update_interval_seconds", 60), 60, 10)
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
            classification_destination_deltas = {}
            next_previous_classification_counters = dict(nft_previous_classification_counters)
            for (direction, ip, destination), total_bytes in current_classification_counters.items():
                key = (direction, ip, destination)
                previous = nft_previous_classification_counters.get(key, 0)
                delta = max(total_bytes - previous, 0)
                next_previous_classification_counters[key] = total_bytes
                if delta:
                    classification_destination_deltas.setdefault((ip, destination), {"rx": 0, "tx": 0})
                    classification_destination_deltas[(ip, destination)][direction] += delta
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

        contention_remaining = database_contention_remaining()
        if contention_remaining > 0:
            print(f"Counter batch skipped: database contention backoff {contention_remaining:.0f}s remaining")
            time.sleep(interval)
            continue

        con = None
        try:
            traffic_detail_started = time.monotonic()
            live_speed_writes = 0
            device_writes = 0
            interval_inserts = 0
            estimated_inserts = 0
            destination_writes = 0
            traffic_step_timings = {
                "prepare": 0.0,
                "live_speed_write": 0.0,
                "device_write": 0.0,
                "traffic_fact_write": 0.0,
                "estimated_write": 0.0,
                "destination_write": 0.0,
            }
            with timed_db_write("traffic_counter_batch") as con:
                live_speed_rows = []
                device_rows = []
                traffic_rows = []
                estimated_rows = []
                step_started = time.monotonic()
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

                    live_speed_rows.append((ip, mac, rx_Bps, tx_Bps, total_Bps, now))
                    live_speed_writes += 1

                    metadata_key = (name, mac, vendor, dtype)
                    last_inventory = device_inventory_write_cache.get(ip)
                    last_inventory_ts = float(last_inventory[0] or 0.0) if last_inventory else 0.0
                    last_metadata_key = last_inventory[1] if last_inventory else None
                    if (
                        last_metadata_key != metadata_key
                        or time.monotonic() - last_inventory_ts >= device_inventory_interval
                    ):
                        device_rows.append((ip, name, mac, vendor, dtype, now, now))
                        device_inventory_write_cache[ip] = (time.monotonic(), metadata_key)
                        device_writes += 1

                    interval_rx_mb = rx_delta / 1024 / 1024
                    interval_tx_mb = tx_delta / 1024 / 1024
                    interval_total_mb = interval_rx_mb + interval_tx_mb

                    if interval_total_mb > 0:
                        traffic_rows.append((
                            ip,
                            name,
                            mac,
                            interval_rx_mb,
                            interval_tx_mb,
                            interval_total_mb,
                            (rx_delta + tx_delta) / elapsed * 8,
                            day,
                            now,
                        ))
                        interval_inserts += 1
                traffic_step_timings["prepare"] += time.monotonic() - step_started

                if live_speed_rows:
                    step_started = time.monotonic()
                    con.executemany(
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
                        live_speed_rows,
                    )
                    traffic_step_timings["live_speed_write"] += time.monotonic() - step_started
                if device_rows:
                    step_started = time.monotonic()
                    identity_rows = []
                    for ip, name, mac, vendor, dtype, first_seen, last_seen in device_rows:
                        normalized_mac = normalize_mac(mac)
                        display_name = apply_device_identity(
                            con, ip, name, normalized_mac, vendor, dtype, last_seen, "traffic", c
                        )
                        identity_rows.append((ip, display_name, normalized_mac, vendor, dtype, first_seen, last_seen))
                    con.executemany(
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
                        identity_rows,
                    )
                    traffic_step_timings["device_write"] += time.monotonic() - step_started
                if traffic_rows:
                    step_started = time.monotonic()
                    con.executemany(
                        """
                        INSERT INTO traffic_intervals
                            (ip, name, mac, downloaded_mb, uploaded_mb, total_mb, live_bps, day, ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        traffic_rows,
                    )
                    traffic_step_timings["traffic_fact_write"] += time.monotonic() - step_started

                step_started = time.monotonic()
                for (category, ip), cur in estimated_deltas.items():
                    interval_rx_mb = cur["rx"] / 1024 / 1024
                    interval_tx_mb = cur["tx"] / 1024 / 1024
                    interval_total_mb = interval_rx_mb + interval_tx_mb
                    if interval_total_mb > 0:
                        estimated_rows.append((ip, category, interval_rx_mb, interval_tx_mb, interval_total_mb, day, now))
                        estimated_inserts += 1
                traffic_step_timings["prepare"] += time.monotonic() - step_started

                if estimated_rows:
                    step_started = time.monotonic()
                    con.executemany(
                        """
                        INSERT INTO estimated_app_traffic
                            (ip, category, downloaded_mb, uploaded_mb, total_mb, day, ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        estimated_rows,
                    )
                    traffic_step_timings["estimated_write"] += time.monotonic() - step_started

                for (category, ip, destination), cur in remote_destination_deltas.items():
                    step_started = time.monotonic()
                    write_destination_delta(con, ip, destination, cur, day, now, category)
                    traffic_step_timings["destination_write"] += time.monotonic() - step_started
                    destination_writes += 1
                for (ip, destination), cur in classification_destination_deltas.items():
                    step_started = time.monotonic()
                    write_destination_delta(con, ip, destination, cur, day, now, "Unknown")
                    traffic_step_timings["destination_write"] += time.monotonic() - step_started
                    destination_writes += 1
            traffic_detail_elapsed = time.monotonic() - traffic_detail_started
            if traffic_detail_elapsed >= 0.2:
                print(
                    "Traffic counter batch detail: "
                    f"devices={len(deltas)} live_speed_writes={live_speed_writes} device_writes={device_writes} "
                    f"traffic_rows={interval_inserts} estimated_rows={estimated_inserts} "
                    f"destination_rows={destination_writes} "
                    f"prepare={traffic_step_timings['prepare']:.3f}s "
                    f"live_speed_write={traffic_step_timings['live_speed_write']:.3f}s "
                    f"device_write={traffic_step_timings['device_write']:.3f}s "
                    f"traffic_fact_write={traffic_step_timings['traffic_fact_write']:.3f}s "
                    f"estimated_write={traffic_step_timings['estimated_write']:.3f}s "
                    f"destination_write={traffic_step_timings['destination_write']:.3f}s "
                    f"total={traffic_detail_elapsed:.3f}s"
                )
            nft_previous_counters = next_previous_counters
            nft_previous_estimated_counters = next_previous_estimated_counters
            nft_previous_classification_counters = next_previous_classification_counters
            nft_active_ips = next_active_ips
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower():
                note_database_contention("Counter batch write", e)
            else:
                print(f"Counter batch write failed: {e}")
        except Exception as e:
            print(f"Counter batch write failed: {e}")

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
    dns_resolution_rows = []
    pending_dns_keys = []
    arp_macs = read_arp_macs()

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
            mac = arp_macs.get(ip, "")
            vendor = vendor_from_mac(mac)
            dtype = classify_device(vendor)
            device_updates[ip] = (name, first_seen, last_seen, mac, vendor, dtype)
        if not is_reverse_dns_lookup_domain(domain):
            remember_estimated_app_targets(c, client, domain, item.get("answer") or [], ts, blocked)
        dns_resolution_rows.extend(dns_answer_rows(ip or client, domain, item.get("answer") or [], ts))

        if cutoff and ts <= cutoff:
            continue

        # Fast duplicate protection for this running process.
        key = f"{ts}|{client}|{domain}"
        if key in imported_dns_keys:
            continue

        dns_rows.append((day, ts, client, domain, blocked, category))
        pending_dns_keys.append(key)

    if not device_updates and not dns_rows and not dns_resolution_rows:
        return

    contention_remaining = database_contention_remaining()
    if contention_remaining > 0:
        print(f"AdGuard querylog write skipped: database contention backoff {contention_remaining:.0f}s remaining")
        return

    try:
        with timed_db_write("adguard_dns_querylog") as con:
            for ip, (name, first_seen, last_seen, mac, vendor, dtype) in device_updates.items():
                normalized_mac = normalize_mac(mac)
                display_name = apply_device_identity(
                    con, ip, name, normalized_mac, vendor, dtype, last_seen, "adguard", c
                )
                con.execute(
                    """
                    INSERT INTO devices (ip, name, mac, vendor, device_type, status, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, 'Active', ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac=CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
                        vendor=CASE WHEN excluded.mac != '' THEN excluded.vendor ELSE devices.vendor END,
                        device_type=CASE
                            WHEN devices.device_type IS NULL OR devices.device_type='' OR devices.device_type='Unknown'
                            THEN excluded.device_type ELSE devices.device_type END,
                        name=excluded.name,
                        last_seen=CASE
                            WHEN devices.last_seen IS NULL OR devices.last_seen < excluded.last_seen
                            THEN excluded.last_seen
                            ELSE devices.last_seen
                        END
                    """,
                    (ip, display_name, normalized_mac, vendor, dtype, first_seen, last_seen),
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
            if dns_resolution_rows:
                con.executemany(
                    """
                    INSERT INTO dns_resolution_events
                        (ts, client_ip, domain, resolved_ip, ttl, expires_at, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    dns_resolution_rows,
                )
        imported_dns_keys.update(pending_dns_keys)
    except Exception as e:
        if "database is locked" in str(e).lower():
            note_database_contention("DNS querylog batch insert", e)
            return
        print(f"DNS querylog batch insert failed: {e}")
        return

    if dns_rows:
        print(f"AdGuard querylog imported rows: {len(dns_rows)}; DNS answers: {len(dns_resolution_rows)}")


def adguard_querylog_loop():
    """Background loop for AdGuard DNS querylog importing."""
    global last_suricata_import, last_unifi_import, last_ids_maintenance, last_incident_build, last_netbios_discovery
    init_db()

    while True:
        started = time.monotonic()
        c = cfg()
        interval = positive_int(c.get("adguard_querylog_interval_seconds", 15), 15, 5)

        try:
            if c.get("adguard_client_import_enabled"):
                run_timed_step("AdGuard/client names", refresh_adguard_client_names, c)
            now_mono = time.monotonic()
            unifi_interval = positive_int(c.get("unifi_import_interval_seconds", 300), 300, 60)
            if now_mono - last_unifi_import >= unifi_interval:
                last_unifi_import = now_mono
                run_timed_step("UniFi/client import", refresh_unifi_clients, c)
            netbios_interval = positive_int(c.get("netbios_discovery_interval_seconds", 900), 900, 60)
            if now_mono - last_netbios_discovery >= netbios_interval:
                last_netbios_discovery = now_mono
                run_timed_step("NetBIOS/device discovery", netbios_discovery_pass, c)
            suricata_interval = positive_int(c.get("suricata_import_interval_seconds", 60), 60, 15)
            if c.get("suricata_enabled", True) and now_mono - last_suricata_import >= suricata_interval:
                last_suricata_import = now_mono
                run_timed_step("Suricata/eve import", import_suricata_eve, c)
            ids_interval = positive_int(c.get("ids_maintenance_interval_seconds", 60), 60, 15)
            if now_mono - last_ids_maintenance >= ids_interval:
                last_ids_maintenance = now_mono
                auto_blocked = run_timed_step("IDS/auto block", process_ids_auto_blocks, c)
                if auto_blocked:
                    print(f"IDS automatic blocks applied: {auto_blocked}")
                run_timed_step("IDS/email notify", process_ids_email_alerts, c)
            incident_interval = positive_int(c.get("incident_build_interval_seconds", 120), 120, 30)
            if now_mono - last_incident_build >= incident_interval:
                last_incident_build = now_mono
                created = run_timed_step("Incidents/build", build_incidents_once, connect_db, c)
                if created:
                    print(f"Security incidents created: {created}")
            run_timed_step("AdGuard/querylog import", import_adguard_querylog)
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
            if database_contention_remaining() <= 0:
                started_write = time.monotonic()
                insert_quality_summary(connect_db, summary)
                elapsed_write = time.monotonic() - started_write
                if elapsed_write >= 0.2:
                    print(f"DB write section internet_quality: txn={elapsed_write:.3f}s")
            print(f"Internet quality summary: {summary['status']} - {summary['diagnosis']}")
        except Exception as e:
            if "database is locked" in str(e).lower():
                note_database_contention("Internet quality collection", e)
            else:
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
            result = run_timed_step("Config monitor", monitor_once, connect_db, c)
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
                results = run_timed_step("Threat intel refresh", refresh_feeds, connect_db, c)
                print(f"Threat intel feed refresh: {results}")
                last_refresh = now_monotonic
            matches = run_timed_step("Threat intel correlate", correlate_once, connect_db, c)
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
            created = run_timed_step("Anomaly baseline", run_anomaly_cycle, connect_db, c)
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
