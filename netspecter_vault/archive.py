import hashlib
import json
import os
import platform
import shutil
import socket
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import BACKUP_FORMAT_VERSION
from .db_snapshot import snapshot_sqlite_database, sqlite_integrity_ok
from .paths import CONFIG_ROOT, DATA_ROOT, DB_PATH, backup_dir, staging_root
from .verify import _verify_backup_path


ARCHIVE_SUFFIX = ".nsbackup"
MIN_FREE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024

CONFIG_FILES = [
    "config.json",
    "secret.key",
    "session.key",
    "adguard/AdGuardHome.yaml",
    "adguard/AdGuardHome.yaml.generated",
    "gatus/config.yaml",
]

OPTIONAL_SERVICE_FILES = [
    "/etc/systemd/system/netspecter-web.service.d",
    "/etc/systemd/system/netspecter-collector.service.d",
    "/etc/systemd/system/gatus.service.d",
]


class VaultError(RuntimeError):
    pass


def iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def archive_name(created_at=None):
    created_at = created_at or datetime.now()
    return f"NetSpecter-Vault-{created_at.strftime('%Y-%m-%d-%H%M%S')}{ARCHIVE_SUFFIX}"


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_files(root):
    root = Path(root)
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            if rel in ("manifest.json", "checksums.sha256"):
                continue
            files.append(rel)
    return files


def copy_if_exists(source, destination):
    source = Path(source)
    if not source.exists():
        return False
    destination = Path(destination)
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    return True


def os_release():
    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    data = {}
    for line in path.read_text(errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def ensure_free_space(path, required_bytes=MIN_FREE_BYTES):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(path)
    if usage.free < required_bytes:
        raise VaultError(f"not enough free space at {path}: {usage.free} bytes available")


def build_metadata(included_components, encrypted=False):
    return {
        "backup_format_version": BACKUP_FORMAT_VERSION,
        "netspecter_version": os.environ.get("NETSPECTER_VERSION", "unknown"),
        "hostname": socket.gethostname(),
        "appliance_identifier": os.environ.get("NETSPECTER_APPLIANCE_ID", socket.gethostname()),
        "created_at": iso_now(),
        "database_format": "sqlite",
        "encryption": {"enabled": bool(encrypted), "method": None},
        "included_components": included_components,
        "source_os": os_release(),
        "architecture": platform.machine(),
    }


def build_manifest(stage):
    files = relative_files(stage)
    return {
        "backup_format_version": BACKUP_FORMAT_VERSION,
        "files": [{"path": rel, "size": (Path(stage) / rel).stat().st_size} for rel in files],
    }


def write_checksums(stage, manifest):
    lines = []
    for item in manifest["files"]:
        rel = item["path"]
        lines.append(f"{sha256_file(Path(stage) / rel)}  {rel}")
    (Path(stage) / "checksums.sha256").write_text("\n".join(lines) + "\n")


def create_tar_archive(stage, destination):
    with tarfile.open(destination, "w:gz") as tar:
        for path in sorted(Path(stage).rglob("*")):
            if path.is_file():
                tar.add(path, arcname=path.relative_to(stage).as_posix(), recursive=False)


def create_backup(destination_dir=None, min_free_bytes=MIN_FREE_BYTES, max_archive_bytes=MAX_ARCHIVE_BYTES, allow_unencrypted=False):
    if not allow_unencrypted:
        raise VaultError("Phase 1 creates local unencrypted backups only; pass --allow-unencrypted to choose this explicitly.")

    destination_dir = Path(destination_dir) if destination_dir else backup_dir()
    stage_root = staging_root()
    ensure_free_space(destination_dir, min_free_bytes)
    ensure_free_space(stage_root, min_free_bytes)

    destination_dir.mkdir(parents=True, exist_ok=True)
    stage_root.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="vault-", dir=str(stage_root)))
    final_path = destination_dir / archive_name()
    temp_archive = destination_dir / f".{final_path.name}.{uuid.uuid4().hex}.tmp"

    try:
        included = []
        for rel in CONFIG_FILES:
            if copy_if_exists(CONFIG_ROOT / rel, stage / "etc" / "netspecter" / rel):
                included.append(f"/etc/netspecter/{rel}")

        database_dest = stage / "var" / "lib" / "netspecter" / "netspecter.db"
        if snapshot_sqlite_database(DB_PATH, database_dest):
            ok, detail = sqlite_integrity_ok(database_dest)
            if not ok:
                raise VaultError(f"database snapshot failed integrity check: {detail}")
            included.append("/var/lib/netspecter/netspecter.db")

        for service_path in OPTIONAL_SERVICE_FILES:
            service = Path(service_path)
            if copy_if_exists(service, stage / "systemd-overrides" / service.name):
                included.append(service_path)

        metadata = build_metadata(included)
        (stage / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True))
        manifest = build_manifest(stage)
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
        write_checksums(stage, manifest)

        create_tar_archive(stage, temp_archive)
        if temp_archive.stat().st_size <= 0:
            raise VaultError("archive is empty")
        if temp_archive.stat().st_size > max_archive_bytes:
            raise VaultError("archive exceeds configured maximum size")

        result = _verify_backup_path(temp_archive, max_archive_bytes=max_archive_bytes)
        if not result.ok:
            raise VaultError(result.detail)

        temp_archive.replace(final_path)
        return final_path
    finally:
        if temp_archive.exists():
            temp_archive.unlink()
        shutil.rmtree(stage, ignore_errors=True)
