import json
import ipaddress
import secrets

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception

from netspecter_paths import (
    CONFIG_PATH,
    CONFIG_ROOT,
    DATA_ROOT,
    INSTALL_ROOT,
    SECRET_KEY_PATH,
    SESSION_KEY_PATH,
)


DEFAULT_CONFIG = {
    "app_name": "NetSpecter",
    "tagline": "Monitor | Filter | Protect",
    "adguard_url": "http://127.0.0.1",
    "netspecter_url": "https://127.0.0.1:9443",
    "adguard_user": "admin",
    "adguard_pass": "",
    "packet_iface": "br0",
    "appliance_ip": "",
    "gateway_ip": "",
    "ignore_ips": [],
    "adguard_querylog_interval_seconds": 15,
    "web_host": "127.0.0.1",
    "web_port": 5050,
    "allow_lan_http_5050": False,
    "https_proxy_host": "0.0.0.0",
    "https_proxy_port": 9443,
    "https_proxy_cert_path": "/etc/netspecter/netspecter-https.crt",
    "https_proxy_key_path": "/etc/netspecter/netspecter-https.key",
    "auth_enabled": True,
    "admin_user": "admin",
    "admin_password_hash": "",
    "netlic_enabled": True,
    "netlic_url": "https://netlic.it-inyanga.co.za",
    "netlic_free_registration_key": "FREE",
    "netlic_setup_complete": False,
    "netlic_installation_id": "",
    "netlic_licence_key": "",
    "netlic_signing_secret": "",
    "netlic_appliance_name": "",
    "netlic_last_success_at": "",
    "netlic_last_response": {},
    "netlic_next_check_after": 0,
    "netlic_offline_grace_period_days": 30,
    "lan_prefix": "192.168.1.",
    "traffic_retention_days": 60,
    "dns_retention_days": 60,
    "public_ip_cache_seconds": 1800,
    "remote_map_geo_lookups_per_run": 50,
    "dns_map_geo_lookups_per_run": 10,
    "fast_page_mode": True,
    "site_application_mappings": [
        {"application": "Nextcloud", "category": "File Sharing & Storage", "ip": "192.168.99.4"}
    ],
    "site_domain_mappings": [],
    "microsoft365_endpoint_import_enabled": True,
    "microsoft365_endpoint_instance": "worldwide",
    "microsoft365_endpoint_cache_hours": 168,
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
    "unifi_enabled": False,
    "unifi_connector_url": "",
    "unifi_site_id": "",
    "unifi_username": "",
    "unifi_password": "",
    "unifi_skip_tls_verify": False,
    "scheduled_speedtests_per_day": 0,
    "ids_unknown_only": False,
    "ids_excluded_ips": [],
    "ids_exceptions": [],
    "ids_banned_ips": [],
    "ids_auto_ban_enabled": False,
    "ids_email_enabled": False,
    "ids_telegram_enabled": False,
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
    "gatus_url": "http://127.0.0.1:18080",
    "gatus_monitors": [],
    "beszel_url": "http://127.0.0.1:8090",
    "lcd_displays": [],
    "telegram_enabled": False,
    "telegram_bot_token": "",
    "telegram_chat_id": "",
}

SENSITIVE_CONFIG_KEYS = {"adguard_pass", "unifi_password", "smtp_password", "snmp_community", "mqtt_password", "telegram_bot_token", "netlic_licence_key", "netlic_signing_secret"}
INTEGRATION_SETTINGS_KEYS = {
    "unifi_enabled", "unifi_connector_url", "unifi_site_id",
    "unifi_username", "unifi_password", "unifi_skip_tls_verify", "scheduled_speedtests_per_day",
    "remote_map_geo_lookups_per_run", "dns_map_geo_lookups_per_run",
    "ids_unknown_only", "ids_excluded_ips", "ids_exceptions", "ids_banned_ips", "ids_auto_ban_enabled",
    "ids_email_enabled", "ids_telegram_enabled", "smtp_host", "smtp_port", "smtp_security",
    "smtp_username", "smtp_password", "smtp_from", "smtp_to",
    "ids_email_cooldown_minutes", "ids_alert_retention_days", "ids_detail_retention_days",
    "ids_file_retention_days", "ids_raw_flow_retention_hours", "ids_structured_max_records",
    "ids_min_free_mb", "internet_quality_targets", "internet_quality_dns_server",
    "internet_quality_external_dns_enabled", "internet_quality_external_dns_server",
    "internet_quality_dns_query", "internet_quality_interval_seconds",
    "internet_quality_ping_count", "internet_quality_ping_timeout_seconds",
    "internet_quality_retention_days", "internet_quality_max_rows", "internet_quality_min_free_mb",
    "config_change_monitor_interval_seconds", "config_change_retention_days",
    "config_change_max_events", "config_change_min_free_mb",
    "threat_intel_enabled", "threat_intel_sources", "threat_intel_refresh_hours",
    "threat_intel_download_timeout_seconds", "threat_intel_max_feed_bytes",
    "threat_intel_correlation_days", "threat_intel_retention_days",
    "threat_intel_max_correlations", "threat_intel_min_free_mb",
    "incident_trigger_severities", "incident_window_minutes", "incident_dedupe_minutes",
    "incident_max_per_device_per_day", "incident_retention_days",
    "incident_max_records", "incident_min_free_mb",
    "anomaly_learning_only", "anomaly_min_learning_days", "anomaly_recommended_learning_days",
    "anomaly_interval_seconds", "anomaly_upload_min_mb", "anomaly_upload_multiplier",
    "anomaly_destination_multiplier", "anomaly_dns_multiplier", "anomaly_new_ip_min",
    "anomaly_excluded_devices", "anomaly_device_type_thresholds", "anomaly_retention_days",
    "anomaly_max_events", "anomaly_min_free_mb",
    "gatus_url", "gatus_monitors", "beszel_url", "site_application_mappings", "site_domain_mappings",
    "microsoft365_endpoint_import_enabled", "microsoft365_endpoint_instance", "microsoft365_endpoint_cache_hours",
    "lcd_displays",
    "telegram_enabled", "telegram_bot_token", "telegram_chat_id",
}
ENCRYPTED_PREFIX = "enc:"


def ensure_secure_dir(path):
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except Exception:
        pass


def secure_file_write(path, text):
    ensure_secure_dir(path.parent)
    path.write_text(text)
    try:
        path.chmod(0o600)
    except Exception:
        pass


def write_config_json(data):
    ensure_secure_dir(CONFIG_ROOT)
    stored = config_for_storage(data)
    CONFIG_PATH.write_text(json.dumps(stored, indent=2))
    try:
        CONFIG_PATH.chmod(0o600)
    except Exception:
        pass


def config_for_storage(data):
    stored = {}
    for key, value in data.items():
        if key in SENSITIVE_CONFIG_KEYS:
            stored[key] = encrypt_config_value(value)
        else:
            stored[key] = value
    return stored


def get_or_create_session_secret():
    if SESSION_KEY_PATH.exists():
        return SESSION_KEY_PATH.read_text().strip()
    key = secrets.token_urlsafe(48)
    secure_file_write(SESSION_KEY_PATH, key)
    return key


def get_or_create_encryption_key():
    if SECRET_KEY_PATH.exists():
        return SECRET_KEY_PATH.read_text().strip().encode()
    if not Fernet:
        return b""
    key = Fernet.generate_key()
    secure_file_write(SECRET_KEY_PATH, key.decode())
    return key


def fernet():
    if not Fernet:
        return None
    try:
        return Fernet(get_or_create_encryption_key())
    except Exception as e:
        print(f"Encryption setup failed: {e}")
        return None


def encrypt_config_value(value):
    text = str(value or "")
    if not text or text.startswith(ENCRYPTED_PREFIX):
        return text
    f = fernet()
    if not f:
        raise RuntimeError("cryptography package is required to encrypt stored passwords")
    return ENCRYPTED_PREFIX + f.encrypt(text.encode()).decode()


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


def cfg():
    INSTALL_ROOT.mkdir(parents=True, exist_ok=True)
    ensure_secure_dir(CONFIG_ROOT)
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        write_config_json(DEFAULT_CONFIG)

    try:
        raw_data = json.loads(CONFIG_PATH.read_text())
        data = raw_data.copy()
        if not isinstance(data, dict):
            raise ValueError("config root must be a JSON object")
    except Exception as e:
        print(f"Config load failed, using defaults: {e}")
        data = DEFAULT_CONFIG.copy()
        data["app_name"] = "NetSpecter"
        data["tagline"] = "Monitor | Filter | Protect"
        return data

    unsupported_keys = set(data) - set(DEFAULT_CONFIG)
    changed = bool(unsupported_keys)
    if unsupported_keys:
        data = {key: value for key, value in data.items() if key in DEFAULT_CONFIG}

    for key, value in DEFAULT_CONFIG.items():
        if key not in data:
            data[key] = value
            changed = True

    plaintext_sensitive = False
    for key in SENSITIVE_CONFIG_KEYS:
        if data.get(key) and not str(data.get(key)).startswith(ENCRYPTED_PREFIX):
            plaintext_sensitive = True
        if key in data:
            data[key] = decrypt_config_value(data.get(key))

    data["app_name"] = "NetSpecter"
    data["tagline"] = "Monitor | Filter | Protect"

    if changed or plaintext_sensitive:
        save_cfg(data)

    return data


def save_cfg(data):
    write_config_json(data)


def apply_appliance_ip_urls(config, appliance_ip):
    ip = str(appliance_ip or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    https_port = int(config.get("https_proxy_port") or DEFAULT_CONFIG["https_proxy_port"])
    config["appliance_ip"] = ip
    config["netspecter_url"] = f"https://{ip}:{https_port}"
    config["adguard_url"] = f"http://{ip}"
    config["gatus_url"] = f"http://{ip}:18080"
    config["beszel_url"] = f"http://{ip}:8090"
    return True


def appliance_ip_from_host(host_value):
    host = str(host_value or "").strip()
    if not host or host.startswith("["):
        return ""
    host = host.split(":", 1)[0].strip()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return ""
    if ip.version != 4 or ip.is_loopback or ip.is_unspecified:
        return ""
    return host


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
    return ips
