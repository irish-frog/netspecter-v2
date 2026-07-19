import argparse
import json
import sys

from .archive import VaultError, create_backup
from .history import record_event
from .retention import apply_retention
from .restore import _inspect_backup_path, inspect_backup, restore_config, restore_full
from .scheduler import run_scheduled_backup
from .usb import copy_latest_backup_to_usb, eject_usb, removable_partitions
from .verify import verify_backup


def build_parser():
    parser = argparse.ArgumentParser(prog="netspecter-vault")
    sub = parser.add_subparsers(dest="command", required=True)

    backup = sub.add_parser("backup", help="create a local NetSpecter Vault backup")
    backup.add_argument("--destination", help="directory to write the backup archive")
    backup.add_argument("--min-free-mb", type=int, default=None, help="minimum free space required before backup")
    backup.add_argument("--max-archive-mb", type=int, default=None, help="maximum allowed backup archive size")
    backup.add_argument(
        "--allow-unencrypted",
        action="store_true",
        help="explicitly allow a local unencrypted Phase 1 backup",
    )

    verify = sub.add_parser("verify", help="verify a NetSpecter Vault backup")
    verify.add_argument("archive")

    inspect = sub.add_parser("inspect", help="verify and inspect a backup without restoring it")
    inspect.add_argument("archive")

    restore_config_parser = sub.add_parser("restore-config", help="restore NetSpecter config files from a backup")
    restore_config_parser.add_argument("archive")
    restore_config_parser.add_argument("--confirm", required=True, help="must be RESTORE CONFIG")
    restore_config_parser.add_argument("--no-restart", action="store_true", help="restore files without restarting services")

    restore_full_parser = sub.add_parser("restore-full", help="restore NetSpecter config and database from a backup")
    restore_full_parser.add_argument("archive")
    restore_full_parser.add_argument("--confirm", required=True, help="must be RESTORE FULL")
    restore_full_parser.add_argument("--no-service-control", action="store_true", help="restore files without stopping or starting services")

    schedule = sub.add_parser("schedule", help="run a scheduled backup if it is due")
    schedule.add_argument("--force", action="store_true", help="run even if the schedule is not due")

    retention = sub.add_parser("retention", help="apply local backup retention")
    retention.add_argument("--daily", type=int, default=7)
    retention.add_argument("--weekly", type=int, default=4)
    retention.add_argument("--monthly", type=int, default=6)
    retention.add_argument("--dry-run", action="store_true")

    usb = sub.add_parser("usb", help="USB backup operations")
    usb_sub = usb.add_subparsers(dest="usb_command", required=True)
    usb_sub.add_parser("list", help="list removable USB backup targets")
    usb_backup = usb_sub.add_parser("backup", help="copy latest local backup to USB")
    usb_backup.add_argument("uuid")
    usb_eject = usb_sub.add_parser("eject", help="unmount a USB device")
    usb_eject.add_argument("uuid")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            min_free_bytes = args.min_free_mb * 1024 * 1024 if args.min_free_mb else None
            max_archive_bytes = args.max_archive_mb * 1024 * 1024 if args.max_archive_mb else None
            kwargs = {"destination_dir": args.destination, "allow_unencrypted": args.allow_unencrypted}
            if min_free_bytes is not None:
                kwargs["min_free_bytes"] = min_free_bytes
            if max_archive_bytes is not None:
                kwargs["max_archive_bytes"] = max_archive_bytes
            path = create_backup(**kwargs)
            inspection = _inspect_backup_path(path)
            record_event("manual-backup", "ok", "created from CLI/background job", archive=path.name, size_bytes=path.stat().st_size)
            record_event("inspect", "ok", f"automatic dry-run inspection found {len(inspection['restore_targets'])} restore target(s)", archive=path.name)
            print(path)
            print(f"backup verified and inspected; {len(inspection['restore_targets'])} restore target(s)")
            return 0
        if args.command == "verify":
            result = verify_backup(args.archive)
            print(result.detail)
            return 0 if result.ok else 1
        if args.command == "inspect":
            print(json.dumps(inspect_backup(args.archive), indent=2, sort_keys=True))
            return 0
        if args.command == "restore-config":
            result = restore_config(args.archive, confirmation=args.confirm, restart_services=not args.no_restart)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "restore-full":
            result = restore_full(args.archive, confirmation=args.confirm, manage_services=not args.no_service_control)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "schedule":
            ok, detail = run_scheduled_backup(force=args.force)
            print(detail)
            return 0 if ok or detail in ("schedule disabled", "scheduled time has not arrived", "scheduled backup already ran recently") else 1
        if args.command == "retention":
            result = apply_retention(daily=args.daily, weekly=args.weekly, monthly=args.monthly, dry_run=args.dry_run)
            print(f"kept {len(result['kept'])}; deleted {len(result['deleted'])}")
            return 0
        if args.command == "usb":
            if args.usb_command == "list":
                for row in removable_partitions():
                    print(f"{row['uuid']}\t{row['path']}\t{row['fstype'] or '-'}\t{row['size']}\t{row['vendor']} {row['model']}".strip())
                return 0
            if args.usb_command == "backup":
                print(copy_latest_backup_to_usb(args.uuid))
                return 0
            if args.usb_command == "eject":
                eject_usb(args.uuid)
                print("USB ejected")
                return 0
    except VaultError as error:
        if getattr(args, "command", "") == "backup":
            record_event("manual-backup", "failed", str(error))
        print(str(error), file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
