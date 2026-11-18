"""Systemd coordination for explicit history resets; no automatic update invocation."""
from contextlib import contextmanager,closing
from datetime import datetime
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from services.history_reset_service import prepare_reset,apply_prepared_reset,recover_reset,write_journal,preview_reset,_attributes

WATCHERS=("netspecter-watchdog.timer","netspecter-monitor.timer","netspecter-speedtest.timer","netspecter-db-maintenance.timer","netspecter-vault.timer","netspecter-update.path","netspecter-tls-metadata.socket")
WORKERS=("netspecter-watchdog.service","netspecter-monitor.service","netspecter-speedtest.service","netspecter-db-maintenance.service","netspecter-vault.service","netspecter-tls-inspector.service","netspecter-softflowd.service","netspecter-https.service","netspecter-web.service","netspecter-collector.service")
MARKER="history-reset.in-progress"


class SystemdController:
    def capture(self):
        result={}
        for name in (*WATCHERS,*WORKERS,"netspecter-update.service"):
            completed=subprocess.run(["systemctl","show",name,"--property=LoadState,ActiveState,UnitFileState"],capture_output=True,text=True,timeout=10,check=False)
            values=dict(line.split("=",1) for line in completed.stdout.splitlines() if "=" in line)
            if values.get("LoadState")=="not-found":continue
            if completed.returncode or values.get("LoadState")!="loaded":raise RuntimeError(f"Cannot inspect unit {name}")
            if values.get("ActiveState") in {"activating","deactivating","reloading"}:raise RuntimeError(f"Wait for {name} to finish changing state")
            if name=="netspecter-update.service":
                if values.get("ActiveState")=="active":raise RuntimeError("Wait for the appliance update to finish before resetting history")
                result[name]=values
                continue
            result[name]=values
        return result

    def install_guards(self,marker,states):
        if any(c.isspace() or c in '%"\\' for c in str(marker)):raise ValueError("Unsupported reset guard path")
        content=f'[Unit]\nConditionPathExists=!{marker}\n'
        # Persistent guards also prevent writers starting after a reboot during an interrupted reset.
        for name in states:
            if not name.endswith(".service"):continue
            directory=Path("/etc/systemd/system")/(name+".d")
            if directory.is_symlink():raise ValueError("Refusing linked unit override directory")
            directory.mkdir(mode=0o755,exist_ok=True)
            destination=directory/"netspecter-history-reset.conf"
            if destination.is_symlink():raise ValueError("Refusing linked reset guard")
            if destination.exists() and destination.read_text()!=content:raise ValueError("Existing reset guard differs; review before replacing")
            if not destination.exists():
                descriptor=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
                with os.fdopen(descriptor,"w") as handle:handle.write(content)
        subprocess.run(["systemctl","daemon-reload"],check=True,timeout=30)

    def stop(self,states):
        for name in (*WATCHERS,*WORKERS):
            if name in states:subprocess.run(["systemctl","stop",name],check=True,timeout=60)

    def start(self,states):
        order=("netspecter-tls-metadata.socket","netspecter-collector.service","netspecter-web.service","netspecter-https.service","netspecter-softflowd.service","netspecter-tls-inspector.service",*WORKERS,*WATCHERS)
        done=set()
        for name in order:
            if name in done:continue
            done.add(name)
            if states.get(name,{}).get("ActiveState")=="active":subprocess.run(["systemctl","start",name],check=True,timeout=60)

    def verify(self,states,data_root,cutoff):
        required=[name for name in ("netspecter-collector.service","netspecter-web.service","netspecter-https.service") if states.get(name,{}).get("ActiveState")=="active"]
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            healthy=True
            for name in required:
                result=subprocess.run(["systemctl","is-active","--quiet",name],check=False,timeout=5)
                if result.returncode:healthy=False
            if "netspecter-collector.service" in required:
                try:
                    fresh=False
                    for database in ("netspecter_traffic.db","netspecter.db"):
                        path=(Path(data_root)/database).resolve().as_uri()+"?mode=ro"
                        with closing(sqlite3.connect(path,uri=True,timeout=1)) as con:
                            exists=con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='collector_heartbeat'").fetchone()
                            row=con.execute("SELECT updated_at FROM collector_heartbeat WHERE id=1").fetchone() if exists else None
                        if row and str(row[0] or "")>=cutoff:fresh=True
                    if not fresh:healthy=False
                except sqlite3.Error:healthy=False
            if healthy and "netspecter-https.service" in required:
                try:
                    with socket.create_connection(("127.0.0.1",9443),timeout=1):pass
                except OSError:healthy=False
            if healthy:return
            time.sleep(1)
        raise RuntimeError("Services or fresh collector heartbeat did not recover after reset")


class DataDirectoryProtection:
    def __init__(self,root):self.root=Path(root);self.original=_attributes(self.root.stat())
    def protect(self):
        if self.root.is_symlink():raise ValueError("Refusing linked data root")
        os.chown(self.root,0,self.original["gid"]);os.chmod(self.root,0o750)
    def restore(self):
        os.chown(self.root,self.original["uid"],self.original["gid"]);os.chmod(self.root,self.original["mode"])


@contextmanager
def collector_lock(root):
    import fcntl
    path=Path(root)/"collector.lock"
    if path.is_symlink():raise ValueError("Refusing linked collector lock")
    descriptor=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,"r+") as handle:
        fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:yield
        finally:fcntl.flock(handle.fileno(),fcntl.LOCK_UN)


def _marker_create(path):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,"w") as handle:handle.write("History reset in progress; use the recorded recovery journal if interrupted.\n")


def coordinated_reset(data_root,recovery,controller=None,protection=None,lock_factory=None):
    root=Path(data_root).resolve(strict=True);recovery=Path(recovery).resolve(strict=True)
    controller=controller or SystemdController();protection=protection or DataDirectoryProtection(root)
    lock_factory=lock_factory or collector_lock
    preview_reset(root)
    marker=root/MARKER
    if marker.exists() or marker.is_symlink():raise ValueError("An interrupted reset needs recovery before another reset")
    states=controller.capture()
    write_journal(recovery,{"hostname":socket.gethostname(),"unit_states":states,"directory_attributes":protection.original,"status":"quiescing","data_root":str(root)})
    controller.install_guards(marker,states)
    stopped=False;prepared=False;marker_owned=False
    try:
        protection.protect();_marker_create(marker);marker_owned=True
        print("Pausing NetSpecter data writers; DNS filtering and bridge forwarding remain running.",file=sys.stderr,flush=True)
        stopped=True;controller.stop(states)
        with lock_factory(root):
            plan=prepare_reset(root,recovery,writers_stopped=True,progress=lambda message:print(message,file=sys.stderr,flush=True))
            prepared=True
            apply_prepared_reset(recovery,writers_stopped=True)
        marker.unlink();marker_owned=False;protection.restore()
        print("Fresh databases installed; restarting and verifying collection.",file=sys.stderr,flush=True)
        controller.start(states);controller.verify(states,root,plan["cutoff"])
        write_journal(recovery,{"status":"complete","verified_at":datetime.now().isoformat(timespec="seconds")})
        return {"status":"complete","cleared_history_rows":sum(table["rows"] for tables in plan["inventory"]["databases"].values() for table in tables.values() if table["action"]=="clear collected history"),
                "preserved_rows":{item["name"]:{name:value["rows"] for name,value in item.get("retained",{}).items()} for item in plan["files"] if item["kind"]=="database"},
                "database_bytes_before":sum(item.get("bytes_before",0) for item in plan["files"]),"database_bytes_after":sum(item.get("bytes_after",0) for item in plan["files"]),"recovery":str(recovery)}
    except BaseException:
        if prepared:
            protection.protect()
            if not marker_owned:_marker_create(marker);marker_owned=True
            controller.stop(states)
            with lock_factory(root):recover_reset(recovery,writers_stopped=True)
        # If recovery itself fails, keep the marker/protection and leave writers stopped.
        if marker_owned:marker.unlink()
        protection.restore()
        if stopped:controller.start(states)
        write_journal(recovery,{"status":"failed_recovered" if prepared else "failed_before_swap"})
        raise
