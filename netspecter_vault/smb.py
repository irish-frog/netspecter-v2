import os
import shutil
from pathlib import Path

from .archive import VaultError, sha256_file
from .history import record_event
from .usb import run_command


MOUNT_ROOT = Path("/mnt/netspecter-vault-smb")


def safe_share_name(share):
    safe = "".join(ch if ch.isalnum() else "-" for ch in str(share or "smb").lower()).strip("-")
    return safe[:64] or "smb"


def mount_path(name):
    return MOUNT_ROOT / safe_share_name(name)


def normalise_share(share):
    text = str(share or "").strip()
    if not text:
        raise VaultError("SMB share path is empty")
    if text.startswith("\\\\"):
        text = "//" + text.lstrip("\\").replace("\\", "/")
    if not text.startswith("//"):
        raise VaultError("SMB share must look like //server/share")
    return text.rstrip("/")


def cifs_option_value(value, field):
    text = str(value or "").strip()
    if any(ch in text for ch in ",\n\r"):
        raise VaultError(f"SMB {field} contains unsupported characters")
    return text


def mount_smb(config):
    share = normalise_share(config.get("smb_share"))
    username = cifs_option_value(config.get("smb_username"), "username")
    password = str(config.get("smb_password") or "")
    domain = cifs_option_value(config.get("smb_domain"), "domain")
    options = str(config.get("smb_options") or "vers=3.0").strip() or "vers=3.0"
    if not username:
        raise VaultError("SMB username is empty")
    if not password:
        raise VaultError("SMB password is empty")

    target = mount_path(share)
    target.mkdir(parents=True, exist_ok=True)
    if os.path.ismount(target):
        return target

    mount_parts = [f"username={username}", "iocharset=utf8", options]
    if domain:
        mount_parts.insert(1, f"domain={domain}")
    mount_options = ",".join(mount_parts)
    env = os.environ.copy()
    env["PASSWD"] = password
    result = run_command(["mount", "-t", "cifs", share, str(target), "-o", mount_options], timeout=30, env=env)
    if result.returncode != 0:
        raise VaultError(result.stderr.strip() or "SMB mount failed")
    return target


def copy_backup_to_smb(config, source):
    source = Path(source)
    if not source.exists() or source.suffix != ".nsbackup":
        raise VaultError("Backup archive not found")
    target_dir = mount_smb(config)
    usage = shutil.disk_usage(target_dir)
    if usage.free < source.stat().st_size + (64 * 1024 * 1024):
        raise VaultError("SMB share does not have enough free space")
    dest = target_dir / source.name
    shutil.copy2(source, dest)
    run_command(["sync"], timeout=60)
    if not dest.exists():
        raise VaultError("SMB copy disappeared before verification")
    if sha256_file(source) != sha256_file(dest):
        raise VaultError("SMB copy checksum verification failed")
    record_event("smb-backup", "ok", "copied and verified on SMB share", archive=source.name, size_bytes=source.stat().st_size, sha256=sha256_file(source))
    return dest
