#!/usr/bin/env python3
"""Preview or explicitly rebuild collected-history databases while retaining operator state."""
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import sys
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.history_reset_service import preview_reset,discard_recovery,recover_reset,write_journal
from services.history_reset_runtime import coordinated_reset,SystemdController,DataDirectoryProtection,collector_lock,MARKER

DATA_ROOT=Path("/var/lib/netspecter")
RECOVERY_ROOT=Path("/var/backups/netspecter/history-reset")


def secure_recovery_root():
    for path in (RECOVERY_ROOT.parent,RECOVERY_ROOT):
        if path.is_symlink():raise ValueError("Refusing linked recovery directory")
        path.mkdir(mode=0o700,exist_ok=True)
        info=path.stat()
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022:raise ValueError("Recovery directory must be root-owned and not group/world writable")


def validated_recovery(path):
    requested=Path(path)
    if requested.is_symlink():raise ValueError("Refusing linked recovery path")
    result=requested.resolve(strict=True)
    if result.parent!=RECOVERY_ROOT.resolve() or not result.name.startswith("reset-"):
        raise ValueError("Recovery path must be a recorded reset under the protected recovery root")
    info=result.stat()
    if info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o077:raise ValueError("Unsafe recovery directory permissions")
    journal=result/"reset-journal.json"
    if journal.is_symlink():raise ValueError("Refusing linked recovery journal")
    state=json.loads(journal.read_text())
    if state.get("hostname")!=socket.gethostname() or Path(state["data_root"]).resolve()!=DATA_ROOT.resolve():
        raise ValueError("Recovery journal belongs to a different host or data root")
    return result,state


def recover_services(path):
    recovery,state=validated_recovery(path)
    if state.get("status")=="complete":raise ValueError("This reset completed; use --discard-completed to remove its temporary copy")
    protection=DataDirectoryProtection(DATA_ROOT)
    protection.original=state["directory_attributes"]
    controller=SystemdController();states=state["unit_states"]
    protection.protect()
    marker=DATA_ROOT/MARKER
    if marker.is_symlink():raise ValueError("Refusing linked reset marker")
    if not marker.exists():
        descriptor=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(descriptor)
    controller.stop(states)
    with collector_lock(DATA_ROOT):
        if state.get("stage_root"):recover_reset(recovery,writers_stopped=True)
    marker.unlink();protection.restore();controller.start(states)
    write_journal(recovery,{"status":"failed_recovered"})
    return {"status":"recovered","recovery":str(recovery),"note":"Original data and original active services restored. The temporary recovery copy remains for review."}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    action=parser.add_mutually_exclusive_group()
    action.add_argument("--apply",action="store_true")
    action.add_argument("--recover",metavar="RECOVERY_DIRECTORY")
    action.add_argument("--discard-completed",metavar="RECOVERY_DIRECTORY")
    parser.add_argument("--expected-hostname",help="Required for any action; must match this appliance exactly")
    parser.add_argument("--traffic-only",action="store_true",help="Clear traffic measurements/attribution only; retain DNS and other collected history")
    args=parser.parse_args()
    scope="traffic" if args.traffic_only else "all"
    if not (args.apply or args.recover or args.discard_completed):
        print(json.dumps(preview_reset(DATA_ROOT,scope=scope),indent=2));return
    if sys.platform!="linux" or os.geteuid()!=0:parser.error("Apply/recovery requires a root shell on the Linux appliance")
    if args.expected_hostname!=socket.gethostname():parser.error("Supply the exact authorized appliance hostname with --expected-hostname")
    if DATA_ROOT.is_symlink():parser.error("Refusing linked application data directory")
    import fcntl
    secure_recovery_root()
    lock_path=Path("/run/lock/netspecter-history-reset.lock")
    descriptor=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,"r+") as lock:
        if os.fstat(lock.fileno()).st_uid!=0:parser.error("Unsafe reset lock ownership")
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.recover:
            print(json.dumps(recover_services(args.recover),indent=2));return
        if args.discard_completed:
            recovery,_state=validated_recovery(args.discard_completed)
            discard_recovery(recovery);print('{"status":"temporary recovery copy removed"}');return
        configuration=json.loads(Path("/etc/netspecter/config.json").read_text())
        if configuration.get("security_features_enabled") or configuration.get("suricata_enabled"):
            parser.error("Retired IDS collection must be disabled before reset; no data or settings have been changed")
        recovery=RECOVERY_ROOT/("reset-"+uuid.uuid4().hex)
        recovery.mkdir(mode=0o700)
        try:
            result=coordinated_reset(DATA_ROOT,recovery,scope=scope)
        except BaseException:
            print(f"Reset did not complete. Recovery journal (if created): {recovery}/reset-journal.json",file=sys.stderr)
            print(f"Recovery command: python3 {Path(__file__).resolve()} --recover {recovery} --expected-hostname {socket.gethostname()}",file=sys.stderr)
            raise
        discard_recovery(recovery)
        result["recovery"]="Temporary rollback copy removed after successful service verification."
        print(json.dumps(result,indent=2))


if __name__=="__main__":main()
