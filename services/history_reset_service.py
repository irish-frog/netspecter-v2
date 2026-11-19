"""Explicit, recoverable rebuild of history databases with retained operator state."""
from datetime import datetime
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
import time
import uuid

DATABASES=("netspecter.db","netspecter_dns.db","netspecter_traffic.db","netspecter_security.db")
REQUIRED=DATABASES[:3]
CACHE_FILES=("cache.json","live_snapshot.json","ids_email_state.json")
KEEP=frozenset({"devices","device_overrides","device_override_unlocks","device_identities","device_identifiers",
    "user_labels","user_device_assignments","application_categories","application_subcategories","application_mappings",
    "application_aliases","application_domain_patterns","application_tags","site_category_overrides","application_signatures",
    "monitor_alert_state"})
MANIFEST_PATH=Path(__file__).resolve().parents[1]/"config"/"history-reset-schema-v1.json"
# Traffic measurement, aggregation and attribution state only. DNS, identity,
# settings, monitoring, speed tests and internet-quality history are retained.
TRAFFIC_TABLES=frozenset({"traffic_samples","traffic_intervals","traffic_hourly_rollups",
    "estimated_app_traffic","estimated_app_hourly_rollups","remote_traffic_intervals",
    "remote_traffic_hourly_rollups","raw_flow_events","destination_identity",
    "hourly_device_usage","daily_device_usage","hourly_app_usage","daily_app_usage",
    "classification_cache","classified_flow_rollups","classified_flow_facts",
    "unknown_traffic_review","unknown_traffic_queue","live_device_speed",
    "tls_connection_metadata","measured_internet_flows","collector_heartbeat"})


def validate_scope(scope):
    if scope not in {"all","traffic"}:raise ValueError("Unsupported history reset scope")



def load_manifest():
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8-sig"))


def _quote(name):
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*",name):raise ValueError("unsupported schema identifier")
    return '"'+name+'"'


def _regular(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
        raise ValueError(f"Refusing non-regular or linked file: {path.name}")
    return info


def _attributes(info):
    return {"uid":info.st_uid,"gid":info.st_gid,"mode":stat.S_IMODE(info.st_mode)}


def _restore_attributes(path,attributes):
    if hasattr(os,"chown"):os.chown(path,attributes["uid"],attributes["gid"])
    os.chmod(path,attributes["mode"])


def _read_database(path):
    _regular(path)
    con=sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True,timeout=5)
    con.execute("PRAGMA query_only=ON")
    con.execute("PRAGMA trusted_schema=OFF")
    con.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,4*1024*1024)
    return con


def inspect_database(path,manifest=None):
    manifest=load_manifest() if manifest is None else manifest
    con=_read_database(Path(path))
    try:
        objects=con.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
        if any(kind not in {"table","index"} for kind,_name,_sql in objects):
            raise ValueError("Views/triggers require explicit reset review")
        report={}
        deadline=time.monotonic()+60
        con.set_progress_handler(lambda: int(time.monotonic()>deadline),10000)
        for kind,name,sql in objects:
            if kind!="table":continue
            if name not in manifest or not sql or "VIRTUAL TABLE" in sql.upper():
                raise ValueError(f"Unrecognized reset table: {name}")
            columns=[row[1] for row in con.execute(f"PRAGMA table_info({_quote(name)})")]
            if name in KEEP and not set(columns).issubset(manifest[name]):
                raise ValueError(f"Unrecognized retained columns in {name}")
            count=con.execute(f"SELECT COUNT(*) FROM {_quote(name)}").fetchone()[0]
            report[name]={"rows":count,"action":"preserve inventory/settings" if name in KEEP else "reset cutoff" if name=="dns_import_state" else "clear collected history"}
        return report
    finally:con.close()


def preview_reset(data_root,manifest=None,*,scope="all"):
    validate_scope(scope)
    root=Path(data_root).resolve(strict=True)
    if not root.is_dir():raise ValueError("Data root is not a directory")
    result={"databases":{},"cache_files":[],"preserves":"Settings, credentials, licences, existing backups, edited names, stable identity inventory, custom classifications and user assignments. Monitor notification deduplication state is retained.",
            "scope":"NetSpecter application history. AdGuard filtering/settings and native query logs, operating system logs and existing backups are not erased."}
    for name in DATABASES:
        path=root/name
        if not path.exists() and not path.is_symlink():
            if name in REQUIRED:raise ValueError(f"Required database missing: {name}")
            continue
        _regular(path)
        result["databases"][name]=inspect_database(path,manifest)
        if scope=="traffic":
            for table,details in result["databases"][name].items():
                details["action"]="clear collected history" if table in TRAFFIC_TABLES else "preserve unchanged"
    for name in (CACHE_FILES if scope=="all" else ("cache.json","live_snapshot.json")):
        path=root/name
        if path.exists() or path.is_symlink():
            _regular(path);result["cache_files"].append(name)
    if scope=="traffic":result["scope"]="Traffic counters/history and attribution metadata only; all other database rows including DNS history are preserved unchanged."
    return result


def _file_digest(path):
    digest=hashlib.sha256()
    with open(path,"rb") as handle:
        for block in iter(lambda:handle.read(1024*1024),b""):digest.update(block)
    return digest.hexdigest()


def write_journal(recovery,updates):
    recovery=Path(recovery)
    destination=recovery/"reset-journal.json"
    data=json.loads(destination.read_text()) if destination.exists() else {}
    data.update(updates)
    temporary=recovery/(".journal-"+uuid.uuid4().hex)
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,"w",encoding="utf-8") as handle:
        json.dump(data,handle,indent=2);handle.write("\n");handle.flush();os.fsync(handle.fileno())
    os.replace(temporary,destination)
    return data


def _clean_inventory(table,columns,row,cutoff):
    values=dict(zip(columns,row))
    if table=="devices":
        for field in ("first_seen","last_seen","last_presence_seen","last_presence_check","last_presence_source"):
            if field in values:values[field]=None
        if "status" in values:values["status"]="Unknown"
    if table=="device_identities":
        for field in ("first_seen","last_seen","updated_at","user_probe_failed_at"):
            if field in values:values[field]=None
        if "user_probe_failure_count" in values:values["user_probe_failure_count"]=0
        if str(values.get("logged_in_user_source") or "").lower()!="manual":
            for field in ("logged_in_user","logged_in_user_source","logged_in_user_updated_at"):
                if field in values:values[field]=None
    if table=="device_identifiers":
        for field in ("first_seen","last_seen"):
            if field in values:values[field]=cutoff
    return tuple(values[column] for column in columns)


def _copy_retained(source,target,table,cutoff):
    info=source.execute(f"PRAGMA table_info({_quote(table)})").fetchall()
    columns=[row[1] for row in info]
    primary=[row[1] for row in sorted(info,key=lambda row:row[5]) if row[5]]
    if not primary:raise ValueError(f"Retained table lacks a stable key: {table}")
    names=",".join(_quote(column) for column in columns)
    order=",".join(_quote(column) for column in primary)
    cursor=source.execute(f"SELECT {names} FROM {_quote(table)} ORDER BY {order}")
    expected=hashlib.sha256();count=0
    while True:
        rows=cursor.fetchmany(32)
        if not rows:break
        cleaned=[]
        for row in rows:
            values=_clean_inventory(table,columns,row,cutoff)
            if table=="device_identities" and {"identity_key","current_ip","last_seen"}.issubset(columns):
                original=dict(zip(columns,row))
                if original["current_ip"]:
                    latest=source.execute("SELECT identity_key FROM device_identities WHERE current_ip=? ORDER BY last_seen DESC,identity_key LIMIT 1",(original["current_ip"],)).fetchone()
                    if latest and latest[0]!=original["identity_key"]:
                        adjusted=dict(zip(columns,values));adjusted["current_ip"]=None
                        values=tuple(adjusted[column] for column in columns)
            cleaned.append(values)
        target.executemany(f"INSERT INTO {_quote(table)} ({names}) VALUES ({','.join('?' for _ in columns)})",cleaned)
        for row in cleaned:expected.update(repr(row).encode("utf-8"));expected.update(b"\n")
        count+=len(cleaned)
    actual=hashlib.sha256()
    for row in target.execute(f"SELECT {names} FROM {_quote(table)} ORDER BY {order}"):
        actual.update(repr(row).encode("utf-8"));actual.update(b"\n")
    if expected.digest()!=actual.digest():raise ValueError(f"Retained state verification failed: {table}")
    return {"rows":count,"digest":actual.hexdigest()}


def _stage_database(snapshot,destination,inventory,cutoff,*,scope="all"):
    source=_read_database(snapshot);target=sqlite3.connect(destination)
    os.chmod(destination,0o600)
    try:
        target.execute("PRAGMA trusted_schema=OFF")
        if scope=="traffic":
            # Copy the complete schema/data first; delete only the reviewed table set.
            # This retains even non-keyed history tables without rewriting identity fields.
            source.backup(target)
            target.execute("PRAGMA journal_mode=DELETE")
            target.execute("PRAGMA synchronous=FULL")
            preserved={}
            for table,details in inventory.items():
                if table in TRAFFIC_TABLES:target.execute(f"DELETE FROM {_quote(table)}")
                else:preserved[table]={"rows":details["rows"]}
            target.commit()
            if target.execute("PRAGMA quick_check(1)").fetchone()[0]!="ok" or target.execute("PRAGMA foreign_key_check").fetchone():
                raise ValueError("Traffic reset integrity verification failed")
            for table,details in inventory.items():
                expected=0 if table in TRAFFIC_TABLES else details["rows"]
                if target.execute(f"SELECT COUNT(*) FROM {_quote(table)}").fetchone()[0]!=expected:
                    raise ValueError("Traffic reset row count verification failed")
            return preserved
        target.execute("PRAGMA journal_mode=DELETE")
        target.execute("PRAGMA synchronous=FULL")
        objects=source.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END,name").fetchall()
        for kind,name,sql in objects:
            if kind=="table":target.execute(sql)
        preserved={}
        for table in inventory:
            if table in KEEP:preserved[table]=_copy_retained(source,target,table,cutoff)
            elif table=="dns_import_state":
                target.execute("INSERT INTO dns_import_state (id,cleared_at) VALUES (1,?)",(cutoff,))
        for kind,name,sql in objects:
            if kind=="index":target.execute(sql)
        target.execute(f"PRAGMA user_version={int(source.execute('PRAGMA user_version').fetchone()[0])}")
        target.commit()
        if target.execute("PRAGMA quick_check(1)").fetchone()[0]!="ok" or target.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("Fresh database integrity verification failed")
        for table in inventory:
            if table not in KEEP and table!="dns_import_state" and target.execute(f"SELECT COUNT(*) FROM {_quote(table)}").fetchone()[0]:
                raise ValueError("Collected history unexpectedly retained")
        return preserved
    finally:source.close();target.close()


def prepare_reset(data_root,recovery,*,writers_stopped=False,cutoff=None,manifest=None,progress=None,scope="all"):
    if not writers_stopped:raise ValueError("Writers must be stopped before preparing reset")
    root=Path(data_root).resolve(strict=True);recovery=Path(recovery).resolve(strict=True)
    if recovery==root or recovery.is_relative_to(root):raise ValueError("Recovery snapshots must be outside the application data directory")
    inventory=preview_reset(root,manifest,scope=scope)
    cutoff=cutoff or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    size=sum((root/name).stat().st_size+(root/(name+"-wal")).stat().st_size if (root/(name+"-wal")).exists() else (root/name).stat().st_size for name in inventory["databases"])
    size+=sum((root/name).stat().st_size for name in inventory["cache_files"])
    required=size+128*1024*1024
    same_device=root.stat().st_dev==recovery.stat().st_dev
    if shutil.disk_usage(root).free<(required+size if same_device else required) or shutil.disk_usage(recovery).free<required:
        raise OSError("Insufficient free space for a protected recovery snapshot and staging")
    stage=Path(tempfile.mkdtemp(prefix=".history-reset-stage-",dir=root));os.chmod(stage,0o700)
    snapshots=recovery/"databases";snapshots.mkdir(mode=0o700)
    cache_backup=recovery/"cache-files";cache_backup.mkdir(mode=0o700)
    plan={"version":1,"data_root":str(root),"stage_root":str(stage),"cutoff":cutoff,"files":[],"applied":[],"replacing":None,"status":"preparing","inventory":inventory,"scope":scope}
    write_journal(recovery,plan)
    for name,tables in inventory["databases"].items():
        path=root/name;attributes=_attributes(_regular(path))
        if progress:progress(f"Preparing {name}: temporary snapshot, fresh schema and retained settings")
        guard=sqlite3.connect(path.resolve().as_uri()+"?mode=rw",uri=True,timeout=5)
        try:
            checkpoint=guard.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint and checkpoint[0]:raise ValueError("Database still has active readers/writers")
            guard.execute("BEGIN IMMEDIATE")
            source=_read_database(path);backup=sqlite3.connect(snapshots/name)
            os.chmod(snapshots/name,0o600)
            try:
                source.backup(backup,pages=1024,sleep=0.01)
                # Backup copies the source journal mode. Keep standalone snapshots
                # in DELETE mode so read-only integrity checks cannot create WAL sidecars.
                if backup.execute("PRAGMA journal_mode=DELETE").fetchone()[0].lower()!="delete":
                    raise ValueError("Cannot finalize standalone recovery snapshot")
            finally:source.close();backup.close()
        finally:guard.rollback();guard.close()
        with closing(_read_database(snapshots/name)) as check:
            if check.execute("PRAGMA quick_check(1)").fetchone()[0]!="ok":raise ValueError("Recovery snapshot integrity failed")
        retained=_stage_database(snapshots/name,stage/name,tables,cutoff,scope=scope)
        _restore_attributes(stage/name,attributes)
        plan["files"].append({"name":name,"kind":"database","attributes":attributes,"backup_sha256":_file_digest(snapshots/name),"retained":retained,"bytes_before":path.stat().st_size,"bytes_after":(stage/name).stat().st_size})
        write_journal(recovery,plan)
    for name in inventory["cache_files"]:
        path=root/name;attributes=_attributes(_regular(path))
        shutil.copyfile(path,cache_backup/name);os.chmod(cache_backup/name,0o600)
        (stage/name).write_text("{}\n",encoding="utf-8");_restore_attributes(stage/name,attributes)
        plan["files"].append({"name":name,"kind":"cache","attributes":attributes,"backup_sha256":_file_digest(cache_backup/name)})
        write_journal(recovery,plan)
    plan["status"]="prepared";write_journal(recovery,plan)
    return plan


def _validated_plan(recovery):
    recovery=Path(recovery).resolve(strict=True)
    journal=recovery/"reset-journal.json";_regular(journal)
    plan=json.loads(journal.read_text())
    if plan.get("version")!=1:raise ValueError("Unsupported recovery journal")
    root=Path(plan["data_root"]).resolve(strict=True)
    stage=Path(plan["stage_root"])
    if stage.is_symlink() or stage.parent.resolve()!=root or not stage.name.startswith(".history-reset-stage-"):
        raise ValueError("Invalid reset staging directory")
    if not stage.exists():stage.mkdir(mode=0o700)
    stage=stage.resolve(strict=True)
    if stage.parent!=root:raise ValueError("Resolved staging directory escapes the data root")
    stage_info=stage.stat()
    if os.name=="posix" and (stage_info.st_uid!=journal.stat().st_uid or stat.S_IMODE(stage_info.st_mode)&0o077):
        raise ValueError("Unsafe reset staging directory ownership or permissions")
    allowed=set(DATABASES+CACHE_FILES)
    if any(item.get("name") not in allowed for item in plan["files"]):raise ValueError("Unexpected reset file")
    return recovery,plan,root,stage


def apply_prepared_reset(recovery,*,writers_stopped=False,fault_hook=None):
    if not writers_stopped:raise ValueError("Writers must be stopped before applying reset")
    recovery,plan,root,stage=_validated_plan(recovery)
    if plan["status"]!="prepared":raise ValueError("Reset is not prepared")
    for item in plan["files"]:
        name=item["name"]
        _regular(root/name);_regular(stage/name)
        if item["kind"]=="database":
            for suffix in ("-wal","-shm"):
                sidecar=root/(name+suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    info=_regular(sidecar)
                    if suffix=="-wal" and info.st_size:raise ValueError("Database writer resumed before reset")
                    sidecar.unlink()
        plan["status"]="applying";plan["replacing"]=name;write_journal(recovery,plan)
        os.replace(stage/name,root/name)
        plan["applied"].append(name);plan["replacing"]=None;write_journal(recovery,plan)
        if fault_hook:fault_hook(name)
    plan["status"]="applied";write_journal(recovery,plan)
    return plan


def recover_reset(recovery,*,writers_stopped=False):
    if not writers_stopped:raise ValueError("Writers must be stopped before recovery")
    recovery,plan,root,stage=_validated_plan(recovery)
    names=set(plan.get("applied",[]))
    if plan.get("replacing"):names.add(plan["replacing"])
    for item in plan["files"]:
        name=item["name"]
        if name not in names:continue
        backup=recovery/("databases" if item["kind"]=="database" else "cache-files")/name
        _regular(backup)
        if _file_digest(backup)!=item["backup_sha256"]:raise ValueError("Recovery snapshot checksum mismatch")
        temporary=stage/("restore-"+name)
        if temporary.exists() or temporary.is_symlink():raise ValueError("Unexpected recovery staging file")
        shutil.copyfile(backup,temporary);_restore_attributes(temporary,item["attributes"])
        for suffix in ("-wal","-shm") if item["kind"]=="database" else ():
            sidecar=root/(name+suffix)
            if sidecar.exists() or sidecar.is_symlink():_regular(sidecar);sidecar.unlink()
        os.replace(temporary,root/name)
    plan["status"]="recovered";write_journal(recovery,plan)
    return plan


def discard_recovery(recovery):
    """Remove only this completed reset's temporary copies, never existing backup directories."""
    recovery,plan,_root,stage=_validated_plan(recovery)
    if plan.get("status")!="complete":raise ValueError("Only a verified completed reset can discard its rollback copy")
    expected={"databases":set(),"cache-files":set()}
    for item in plan["files"]:expected["databases" if item["kind"]=="database" else "cache-files"].add(item["name"])
    # Older completed snapshots may have read-only SQLite WAL/SHM companions.
    # Only exact known database sidecar names, never arbitrary backup contents.
    expected['databases'].update(name+suffix for name in tuple(expected['databases']) for suffix in ('-wal','-shm'))
    if set(path.name for path in recovery.iterdir())-{"databases","cache-files","reset-journal.json"}:
        raise ValueError("Unexpected files in reset recovery directory")
    for directory,names in expected.items():
        folder=recovery/directory
        if folder.is_symlink():raise ValueError("Refusing linked recovery folder")
        if not folder.exists():continue
        files=list(folder.iterdir())
        if any(path.name not in names for path in files):raise ValueError("Unexpected recovery file")
        for path in files:_regular(path)
    if any(stage.iterdir()):raise ValueError("Reset staging is not empty; review before cleanup")
    for directory,names in expected.items():
        folder=recovery/directory
        if not folder.exists():continue
        for name in names:
            path=folder/name
            if path.exists():path.unlink()
        folder.rmdir()
    stage.rmdir()
    (recovery/"reset-journal.json").unlink()
    recovery.rmdir()
