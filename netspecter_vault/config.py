import json
from pathlib import Path

from .paths import CONFIG_ROOT
from netspecter_config import ENCRYPTED_PREFIX, decrypt_config_value, encrypt_config_value


DEFAULT_VAULT_CONFIG = {
    "schedule_enabled": False,
    "schedule_time": "02:30",
    "retention_daily": 7,
    "retention_weekly": 4,
    "retention_monthly": 6,
    "min_free_mb": 2048,
    "max_archive_mb": 2048,
    "usb_backup_enabled": False,
    "usb_backup_uuid": "",
    "smb_backup_enabled": False,
    "smb_share": "",
    "smb_username": "",
    "smb_password": "",
    "smb_domain": "",
    "smb_options": "vers=3.0",
}

CONFIG_PATH = CONFIG_ROOT / "vault.json"
SENSITIVE_VAULT_CONFIG_KEYS = {"smb_password"}


def load_vault_config():
    data = {}
    if CONFIG_PATH.exists():
        try:
            raw = json.loads(CONFIG_PATH.read_text())
            if isinstance(raw, dict):
                data = raw
        except Exception:
            data = {}
    merged = DEFAULT_VAULT_CONFIG.copy()
    for key in merged:
        if key in data:
            merged[key] = data[key]
    for key in SENSITIVE_VAULT_CONFIG_KEYS:
        if key in merged:
            merged[key] = decrypt_config_value(merged.get(key))
    return normalise_vault_config(merged)


def normalise_vault_config(data):
    out = DEFAULT_VAULT_CONFIG.copy()
    out["schedule_enabled"] = bool(data.get("schedule_enabled"))
    out["schedule_time"] = normalise_time(data.get("schedule_time", out["schedule_time"]))
    for key in ("retention_daily", "retention_weekly", "retention_monthly"):
        out[key] = max(1, int_or_default(data.get(key), out[key]))
    out["min_free_mb"] = max(128, int_or_default(data.get("min_free_mb"), out["min_free_mb"]))
    out["max_archive_mb"] = max(16, int_or_default(data.get("max_archive_mb"), out["max_archive_mb"]))
    out["usb_backup_enabled"] = bool(data.get("usb_backup_enabled"))
    out["usb_backup_uuid"] = str(data.get("usb_backup_uuid", "") or "").strip()
    out["smb_backup_enabled"] = bool(data.get("smb_backup_enabled"))
    out["smb_share"] = str(data.get("smb_share", "") or "").strip()
    out["smb_username"] = str(data.get("smb_username", "") or "").strip()
    out["smb_password"] = str(data.get("smb_password", "") or "")
    out["smb_domain"] = str(data.get("smb_domain", "") or "").strip()
    out["smb_options"] = str(data.get("smb_options", out["smb_options"]) or "vers=3.0").strip()
    return out


def save_vault_config(data):
    config = normalise_vault_config(data)
    stored = vault_config_for_storage(config)
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(stored, indent=2, sort_keys=True))
    try:
        CONFIG_PATH.chmod(0o600)
    except Exception:
        pass
    return config


def vault_config_for_storage(config):
    stored = {}
    for key, value in config.items():
        if key in SENSITIVE_VAULT_CONFIG_KEYS and value:
            stored[key] = encrypt_config_value(value)
        else:
            stored[key] = value
    return stored


def int_or_default(value, default):
    try:
        return int(value)
    except Exception:
        return int(default)


def normalise_time(value):
    text = str(value or "").strip()
    parts = text.split(":")
    if len(parts) != 2:
        return DEFAULT_VAULT_CONFIG["schedule_time"]
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError:
        return DEFAULT_VAULT_CONFIG["schedule_time"]
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return DEFAULT_VAULT_CONFIG["schedule_time"]
    return f"{hour:02d}:{minute:02d}"
