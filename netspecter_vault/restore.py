import json
import os
import shutil
import subprocess
import tarfile
from datetime import datetime
from pathlib import Path

from .archive import VaultError
from .history import record_event
from .verify import _verify_backup_path, resolve_backup_archive_path, safe_member_names


RESTORE_TARGETS = {
    "etc/netspecter/config.json": "/etc/netspecter/config.json",
    "etc/netspecter/secret.key": "/etc/netspecter/secret.key",
    "etc/netspecter/session.key": "/etc/netspecter/session.key",
    "etc/netspecter/adguard/AdGuardHome.yaml": "/etc/netspecter/adguard/AdGuardHome.yaml",
    "etc/netspecter/adguard/AdGuardHome.yaml.generated": "/etc/netspecter/adguard/AdGuardHome.yaml.generated",
    "etc/netspecter/gatus/config.yaml": "/etc/netspecter/gatus/config.yaml",
    "var/lib/netspecter/netspecter.db": "/var/lib/netspecter/netspecter.db",
}

CONFIG_RESTORE_TARGETS = {
    key: value
    for key, value in RESTORE_TARGETS.items()
    if value.startswith("/etc/netspecter/")
}

RESTART_AFTER_CONFIG_RESTORE = [
    "netspecter-collector",
    "gatus",
    "AdGuardHome",
    "netspecter-web",
]

STOP_BEFORE_FULL_RESTORE = [
    "netspecter-web",
    "netspecter-collector",
]

START_AFTER_FULL_RESTORE = [
    "AdGuardHome",
    "gatus",
    "netspecter-collector",
    "netspecter-web",
]


def _read_json_member(tar, name):
    member = tar.getmember(name)
    handle = tar.extractfile(member)
    if not handle:
        raise VaultError(f"backup member cannot be read: {name}")
    return json.loads(handle.read().decode("utf-8"))


def _inspect_backup_path(archive_path):
    archive_path = Path(archive_path)
    result = _verify_backup_path(archive_path)
    if not result.ok:
        raise VaultError(result.detail)

    with tarfile.open(archive_path, "r:gz") as tar:
        files = sorted(safe_member_names(tar))
        names = set(files)
        metadata = _read_json_member(tar, "metadata.json")
        manifest = _read_json_member(tar, "manifest.json")

    targets = []
    for source in files:
        if source in RESTORE_TARGETS:
            targets.append({
                "source": source,
                "target": RESTORE_TARGETS[source],
                "present": True,
            })

    return {
        "archive": archive_path.name,
        "verified": True,
        "detail": result.detail,
        "metadata": metadata,
        "manifest": manifest,
        "files": files,
        "restore_targets": targets,
        "missing_core_targets": sorted(source for source in RESTORE_TARGETS if source not in names),
    }


def inspect_backup(archive_name):
    try:
        archive_path = resolve_backup_archive_path(archive_name)
    except ValueError as error:
        raise VaultError(str(error)) from error
    if archive_path is None:
        raise VaultError("archive does not exist")
    return _inspect_backup_path(archive_path)


def _backup_existing_file(target, safety_root):
    target = Path(target)
    if not target.exists():
        return None
    try:
        relative = target.relative_to("/")
    except ValueError:
        relative = Path(*[part for part in target.parts if part not in (target.anchor, target.drive)])
    backup_path = safety_root / relative
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target, backup_path)
    return backup_path


def _restore_file_from_tar(tar, source, target):
    member = tar.getmember(source)
    handle = tar.extractfile(member)
    if not handle:
        raise VaultError(f"backup member cannot be read: {source}")
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as out:
        shutil.copyfileobj(handle, out)
    _apply_restored_permissions(target)


def _apply_restored_permissions(target):
    target = Path(target)
    runtime_uid = -1
    runtime_gid = -1
    try:
        import grp
        import pwd

        runtime_uid = pwd.getpwnam(os.environ.get("NETSPECTER_RUNTIME_USER", "netspecter")).pw_uid
        runtime_gid = grp.getgrnam(os.environ.get("NETSPECTER_RUNTIME_GROUP", "netspecter")).gr_gid
    except (ImportError, KeyError):
        pass
    try:
        if str(target).startswith("/var/lib/netspecter/"):
            if runtime_uid != -1 and runtime_gid != -1:
                os.chown(target, runtime_uid, runtime_gid)
            target.chmod(0o660 if target.suffix == ".db" else 0o640)
        elif str(target).startswith("/etc/netspecter/"):
            if runtime_gid != -1:
                os.chown(target, 0, runtime_gid)
            target.chmod(0o640)
        else:
            target.chmod(0o644)
    except Exception:
        pass


def systemctl_action(action, services):
    completed = []
    failed = []
    for service in services:
        result = subprocess.run(["systemctl", action, service], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode == 0:
            completed.append(service)
        else:
            failed.append(f"{service}: {result.stderr.strip() or result.stdout.strip() or result.returncode}")
    return completed, failed


def restart_config_services(services=None):
    return systemctl_action("restart", services or RESTART_AFTER_CONFIG_RESTORE)


def restore_config(archive_path, confirmation="", restart_services=True, target_map=None, safety_root=None):
    if str(confirmation or "").strip() != "RESTORE CONFIG":
        raise VaultError("confirmation must be RESTORE CONFIG")

    report = inspect_backup(archive_path)
    archive_path = resolve_backup_archive_path(archive_path)
    if archive_path is None:
        raise VaultError("archive does not exist")
    target_map = target_map or CONFIG_RESTORE_TARGETS
    safety_base = Path(safety_root or os.environ.get("NETSPECTER_VAULT_RESTORE_SAFETY_DIR", "/var/lib/netspecter/vault/restore-safety"))
    safety_root = safety_base / datetime.now().strftime("%Y%m%d-%H%M%S")
    restored = []
    safety = []

    with tarfile.open(archive_path, "r:gz") as tar:
        names = set(safe_member_names(tar))
        for source, target in target_map.items():
            if source not in names:
                continue
            backed_up = _backup_existing_file(target, safety_root)
            if backed_up:
                safety.append(str(backed_up))
            _restore_file_from_tar(tar, source, target)
            restored.append(target)

    if not restored:
        raise VaultError("backup has no config files to restore")

    restarted = []
    failed_restarts = []
    if restart_services:
        restarted, failed_restarts = restart_config_services()

    detail = f"restored {len(restored)} config file(s); safety copy {safety_root}"
    if failed_restarts:
        detail += f"; restart warning: {'; '.join(failed_restarts)}"
    record_event("restore-config", "ok" if not failed_restarts else "warning", detail, archive=archive_path.name)
    return {
        "archive": archive_path.name,
        "report": report,
        "restored": restored,
        "safety_root": str(safety_root),
        "safety_files": safety,
        "restarted": restarted,
        "failed_restarts": failed_restarts,
    }


def restore_full(archive_path, confirmation="", manage_services=True, target_map=None, safety_root=None):
    if str(confirmation or "").strip() != "RESTORE FULL":
        raise VaultError("confirmation must be RESTORE FULL")

    report = inspect_backup(archive_path)
    archive_path = resolve_backup_archive_path(archive_path)
    if archive_path is None:
        raise VaultError("archive does not exist")
    target_map = target_map or RESTORE_TARGETS
    safety_base = Path(safety_root or os.environ.get("NETSPECTER_VAULT_RESTORE_SAFETY_DIR", "/var/lib/netspecter/vault/restore-safety"))
    safety_root = safety_base / datetime.now().strftime("%Y%m%d-%H%M%S-full")
    stopped = []
    failed_stops = []
    started = []
    failed_starts = []
    restored = []
    safety = []

    if manage_services:
        stopped, failed_stops = systemctl_action("stop", STOP_BEFORE_FULL_RESTORE)

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            names = set(safe_member_names(tar))
            for source, target in target_map.items():
                if source not in names:
                    continue
                backed_up = _backup_existing_file(target, safety_root)
                if backed_up:
                    safety.append(str(backed_up))
                _restore_file_from_tar(tar, source, target)
                restored.append(str(target))
    finally:
        if manage_services:
            started, failed_starts = systemctl_action("start", START_AFTER_FULL_RESTORE)

    if not restored:
        raise VaultError("backup has no files to restore")

    failures = failed_stops + failed_starts
    detail = f"restored {len(restored)} file(s); safety copy {safety_root}"
    if failures:
        detail += f"; service warning: {'; '.join(failures)}"
    record_event("restore-full", "ok" if not failures else "warning", detail, archive=archive_path.name)
    return {
        "archive": archive_path.name,
        "report": report,
        "restored": restored,
        "safety_root": str(safety_root),
        "safety_files": safety,
        "stopped": stopped,
        "failed_stops": failed_stops,
        "started": started,
        "failed_starts": failed_starts,
    }
