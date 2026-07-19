import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def configured_path(env_name, default_path, local_path):
    override = os.environ.get(env_name)
    if override:
        return Path(override)

    default = Path(default_path)
    if default.exists() or default.parent.exists():
        return default

    return Path(local_path)


INSTALL_ROOT = configured_path("NETSPECTER_INSTALL_ROOT", "/opt/netspecter", BASE_DIR)
CONFIG_ROOT = configured_path("NETSPECTER_CONFIG_ROOT", "/etc/netspecter", BASE_DIR)
DATA_ROOT = configured_path("NETSPECTER_DATA_ROOT", "/var/lib/netspecter", BASE_DIR)
ROOT = Path(os.environ.get("NETSPECTER_APP_ROOT", str(INSTALL_ROOT)))
CONFIG_PATH = CONFIG_ROOT / "config.json"
DB_PATH = DATA_ROOT / "netspecter.db"
DNS_DB_PATH = DATA_ROOT / "netspecter_dns.db"
TRAFFIC_DB_PATH = DATA_ROOT / "netspecter_traffic.db"
SECURITY_DB_PATH = DATA_ROOT / "netspecter_security.db"
CACHE_PATH = DATA_ROOT / "cache.json"
UPDATE_LOG_PATH = DATA_ROOT / "update.log"
UPDATE_STATE_PATH = DATA_ROOT / "update_state"
VAULT_BACKUP_LOG_PATH = DATA_ROOT / "vault" / "manual_backup.log"
VAULT_BACKUP_STATE_PATH = DATA_ROOT / "vault" / "manual_backup_state"
VAULT_RESTORE_LOG_PATH = DATA_ROOT / "vault" / "restore.log"
VAULT_RESTORE_STATE_PATH = DATA_ROOT / "vault" / "restore_state"
REQUEST_TIMING_PATH = DATA_ROOT / "request_timings.log"
LIVE_SNAPSHOT_PATH = DATA_ROOT / "live_snapshot.json"
SECRET_KEY_PATH = CONFIG_ROOT / "secret.key"
SESSION_KEY_PATH = CONFIG_ROOT / "session.key"
SURICATA_FAST_LOG = Path("/var/log/suricata/fast.log")
SURICATA_EVE_LOG = Path("/var/log/suricata/eve.json")
