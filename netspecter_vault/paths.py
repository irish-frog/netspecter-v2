import os
from pathlib import Path


def configured_path(env_name, default_path, local_path):
    override = os.environ.get(env_name)
    if override:
        return Path(override)

    default = Path(default_path)
    if default.exists() or default.parent.exists():
        return default

    return Path(local_path)


BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_ROOT = configured_path("NETSPECTER_CONFIG_ROOT", "/etc/netspecter", BASE_DIR)
DATA_ROOT = configured_path("NETSPECTER_DATA_ROOT", "/var/lib/netspecter", BASE_DIR)
DB_PATH = DATA_ROOT / "netspecter.db"
DEFAULT_VAULT_ROOT = DATA_ROOT / "vault"
DEFAULT_BACKUP_DIR = DEFAULT_VAULT_ROOT / "backups"
DEFAULT_STAGING_DIR = DEFAULT_VAULT_ROOT / "staging"


def vault_root():
    return Path(os.environ.get("NETSPECTER_VAULT_ROOT", str(DEFAULT_VAULT_ROOT)))


def backup_dir():
    return Path(os.environ.get("NETSPECTER_VAULT_BACKUP_DIR", str(vault_root() / "backups")))


def staging_root():
    return Path(os.environ.get("NETSPECTER_VAULT_STAGING_DIR", str(vault_root() / "staging")))

