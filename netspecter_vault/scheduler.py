from datetime import datetime, timedelta

from .archive import VaultError, create_backup, sha256_file
from .config import load_vault_config
from .history import last_successful_scheduled_backup, record_event
from .retention import apply_retention
from .restore import _inspect_backup_path
from .smb import copy_backup_to_smb
from .usb import copy_backup_to_usb


def due_to_run(config=None, now=None):
    config = config or load_vault_config()
    if not config.get("schedule_enabled"):
        return False, "schedule disabled"
    now = now or datetime.now()
    hour, minute = [int(part) for part in str(config.get("schedule_time", "02:30")).split(":", 1)]
    today_run_time = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if now < today_run_time:
        return False, "scheduled time has not arrived"

    last = last_successful_scheduled_backup()
    if last:
        try:
            last_ts = datetime.strptime(str(last.get("ts")), "%Y-%m-%d %H:%M:%S")
            if now - last_ts < timedelta(hours=20):
                return False, "scheduled backup already ran recently"
        except Exception:
            pass
    return True, "due"


def run_scheduled_backup(force=False):
    config = load_vault_config()
    due, reason = due_to_run(config)
    if not force and not due:
        record_event("scheduled-backup", "skipped", reason)
        return False, reason

    try:
        path = create_backup(
            allow_unencrypted=True,
            min_free_bytes=int(config["min_free_mb"]) * 1024 * 1024,
            max_archive_bytes=int(config["max_archive_mb"]) * 1024 * 1024,
        )
        retention = apply_retention(
            daily=config["retention_daily"],
            weekly=config["retention_weekly"],
            monthly=config["retention_monthly"],
        )
        inspection = _inspect_backup_path(path)
        record_event("inspect", "ok", f"automatic dry-run inspection found {len(inspection['restore_targets'])} restore target(s)", archive=path.name)
        usb_detail = ""
        if config.get("usb_backup_enabled") and config.get("usb_backup_uuid"):
            try:
                usb_path = copy_backup_to_usb(config["usb_backup_uuid"], path.name)
                usb_detail = f"; copied to USB {usb_path}"
            except VaultError as error:
                usb_detail = f"; USB copy failed: {error}"
                record_event("usb-backup", "failed", str(error), archive=path.name)
        smb_detail = ""
        if config.get("smb_backup_enabled") and config.get("smb_share"):
            try:
                smb_path = copy_backup_to_smb(config, path)
                smb_detail = f"; copied to SMB {smb_path}"
            except VaultError as error:
                smb_detail = f"; SMB copy failed: {error}"
                record_event("smb-backup", "failed", str(error), archive=path.name)
        detail = f"created {path.name}; deleted {len(retention['deleted'])} old backup(s){usb_detail}{smb_detail}"
        record_event(
            "scheduled-backup",
            "ok",
            detail,
            archive=path.name,
            size_bytes=path.stat().st_size,
            sha256=sha256_file(path),
        )
        return True, detail
    except VaultError as error:
        record_event("scheduled-backup", "failed", str(error))
        return False, str(error)
