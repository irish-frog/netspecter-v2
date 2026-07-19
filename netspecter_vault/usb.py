import json
import re
import shutil
import subprocess
from pathlib import Path

from .archive import VaultError, sha256_file
from .history import record_event
from .paths import backup_dir
from .verify import resolve_backup_archive_path


MOUNT_ROOT = Path("/mnt/netspecter-vault")
SUPPORTED_FILESYSTEMS = {"vfat", "exfat", "ext4", "ntfs"}
UUID_PATTERN = r"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$"


def run_command(args, timeout=30, env=None):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, env=env)


def lsblk_json():
    result = run_command([
        "lsblk", "-J", "-o",
        "NAME,PATH,TYPE,SIZE,RM,RO,MODEL,VENDOR,SERIAL,FSTYPE,LABEL,UUID,MOUNTPOINTS",
    ])
    if result.returncode != 0:
        raise VaultError(result.stderr.strip() or "lsblk failed")
    return json.loads(result.stdout)


def flatten_devices(rows, parent=None):
    out = []
    for row in rows:
        merged = dict(row)
        merged["_parent"] = parent or {}
        out.append(merged)
        out.extend(flatten_devices(row.get("children") or [], parent=merged))
    return out


def removable_partitions(lsblk_data=None):
    data = lsblk_data or lsblk_json()
    rows = []
    for row in flatten_devices(data.get("blockdevices") or []):
        if row.get("type") != "part":
            continue
        if not bool(row.get("rm")):
            continue
        if bool(row.get("ro")):
            continue
        if not row.get("uuid"):
            continue
        fstype = str(row.get("fstype") or "").lower()
        if fstype and fstype not in SUPPORTED_FILESYSTEMS:
            continue
        parent = row.get("_parent") or {}
        rows.append({
            "name": row.get("name") or "",
            "path": row.get("path") or "",
            "size": row.get("size") or "",
            "fstype": fstype,
            "label": row.get("label") or "",
            "uuid": row.get("uuid") or "",
            "mountpoints": [m for m in (row.get("mountpoints") or []) if m],
            "model": parent.get("model") or row.get("model") or "",
            "vendor": (parent.get("vendor") or row.get("vendor") or "").strip(),
            "serial": parent.get("serial") or row.get("serial") or "",
        })
    return rows


def validate_usb_uuid(uuid):
    normalized = str(uuid or "").strip()
    if not re.fullmatch(UUID_PATTERN, normalized):
        raise VaultError("USB UUID is not valid")
    return normalized


def usb_by_uuid(uuid):
    uuid = validate_usb_uuid(uuid)
    for row in removable_partitions():
        if row["uuid"] == uuid:
            return row
    raise VaultError("USB device not found or not allowed")


def mount_path(uuid):
    safe = "".join(ch for ch in str(uuid) if ch.isalnum() or ch in "-_")
    if not safe:
        raise VaultError("USB UUID is not valid")
    return MOUNT_ROOT / safe


def mounted_path(device):
    for point in device.get("mountpoints") or []:
        if point and point != "[SWAP]":
            return Path(point)
    return None


def mount_usb(uuid):
    device = usb_by_uuid(uuid)
    trusted_uuid = device["uuid"]
    existing = mounted_path(device)
    if existing:
        return existing
    target = mount_path(trusted_uuid)
    target.mkdir(parents=True, exist_ok=True)
    result = run_command(["mount", "-o", "nosuid,nodev,noexec", f"UUID={trusted_uuid}", str(target)], timeout=20)
    if result.returncode != 0:
        raise VaultError(result.stderr.strip() or "USB mount failed")
    return target


def eject_usb(uuid):
    device = usb_by_uuid(uuid)
    target = mounted_path(device)
    if target and str(target).startswith(str(MOUNT_ROOT)):
        result = run_command(["umount", str(target)], timeout=30)
        if result.returncode != 0:
            raise VaultError(result.stderr.strip() or "USB unmount failed")
    run_command(["sync"], timeout=30)
    record_event("usb-eject", "ok", f"USB {uuid} ejected")
    return True


def latest_backup():
    backups = sorted(backup_dir().glob("*.nsbackup"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not backups:
        raise VaultError("No local Vault backup exists")
    return backups[0]


def resolve_usb_backup_destination(target_dir, archive_name):
    target_root = Path(target_dir).resolve(strict=False)
    candidate = (target_root / archive_name).resolve(strict=False)
    try:
        candidate.relative_to(target_root)
    except ValueError as error:
        raise VaultError("USB backup destination is not valid") from error
    return candidate


def copy_backup_to_usb(uuid, source):
    source_name = str(source or "").strip()
    if source_name != Path(source_name).name:
        raise VaultError("archive path must be a NetSpecter backup archive")
    try:
        source = resolve_backup_archive_path(source_name)
    except ValueError as error:
        raise VaultError(str(error)) from error
    if source is None:
        raise VaultError("Backup archive not found")
    target_dir = mount_usb(uuid)
    usage = shutil.disk_usage(target_dir)
    if usage.free < source.stat().st_size + (64 * 1024 * 1024):
        raise VaultError("USB does not have enough free space")
    dest = resolve_usb_backup_destination(target_dir, source.name)
    shutil.copy2(source, dest)
    run_command(["sync"], timeout=60)
    if not dest.exists():
        raise VaultError("USB copy disappeared before verification")
    if sha256_file(source) != sha256_file(dest):
        raise VaultError("USB copy checksum verification failed")
    record_event("usb-backup", "ok", f"copied and verified on USB {uuid}", archive=source.name, size_bytes=source.stat().st_size, sha256=sha256_file(source))
    return dest


def copy_latest_backup_to_usb(uuid):
    return copy_backup_to_usb(uuid, latest_backup().name)
