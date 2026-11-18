import json
from contextlib import closing
from pathlib import Path
import sqlite3
import pytest
from services.history_reset_service import preview_reset,prepare_reset,apply_prepared_reset,recover_reset


def fixture(tmp_path):
    data=tmp_path/"data";data.mkdir()
    with closing(sqlite3.connect(data/"netspecter.db")) as con,con:
        con.executescript("""CREATE TABLE devices(ip TEXT PRIMARY KEY,name TEXT,status TEXT,first_seen TEXT,last_seen TEXT);
            CREATE TABLE device_overrides(ip TEXT PRIMARY KEY,name TEXT);
            CREATE TABLE device_identities(identity_key TEXT PRIMARY KEY,device_id TEXT,display_name TEXT,current_ip TEXT,first_seen TEXT,last_seen TEXT,logged_in_user TEXT,logged_in_user_source TEXT);
            CREATE TABLE device_identifiers(id INTEGER PRIMARY KEY,device_id TEXT,identifier_type TEXT,identifier_value TEXT,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL);
            CREATE TABLE user_labels(id INTEGER PRIMARY KEY,display_name TEXT);
            CREATE TABLE monitor_events(id INTEGER PRIMARY KEY,detail TEXT);
            INSERT INTO devices VALUES ('192.168.1.5','Edited device','Active','2020-01-01','2026-01-01');
            INSERT INTO device_overrides VALUES ('192.168.1.5','Edited device');
            INSERT INTO device_identities VALUES ('mac:1','stable','Edited device','192.168.1.5','2020-01-01','2026-01-01','observed-user','windows');
            INSERT INTO device_identifiers VALUES (1,'stable','mac','aa:bb:cc:dd:ee:ff','2020-01-01','2026-01-01');
            INSERT INTO user_labels VALUES (1,'Manual user');""")
        con.execute("INSERT INTO monitor_events VALUES (1,?)",("x"*200000,))
    with closing(sqlite3.connect(data/"netspecter_dns.db")) as con,con:
        con.executescript("""CREATE TABLE dns_querylog(id INTEGER PRIMARY KEY,domain TEXT);
            CREATE TABLE dns_import_state(id INTEGER PRIMARY KEY,cleared_at TEXT);
            INSERT INTO dns_querylog VALUES (1,'old.example.com');""")
    with closing(sqlite3.connect(data/"netspecter_traffic.db")) as con,con:
        con.executescript("""CREATE TABLE traffic_intervals(id INTEGER PRIMARY KEY,total_mb REAL);
            CREATE TABLE application_signatures(id INTEGER PRIMARY KEY,app TEXT,category TEXT);
            INSERT INTO traffic_intervals VALUES (1,123);
            INSERT INTO application_signatures VALUES (1,'Custom service','Business');""")
    (data/"cache.json").write_text('{"old":"history"}')
    config=tmp_path/"config";config.mkdir();(config/"secret.key").write_text("private-key");(config/"config.json").write_text('{"setting":"keep"}')
    recovery=tmp_path/"recovery";recovery.mkdir(mode=0o700)
    return data,recovery,config


def scalar(path,sql):
    with closing(sqlite3.connect(path)) as con,con:return con.execute(sql).fetchone()[0]


def test_preview_is_read_only_and_does_not_remove_names_or_backups(tmp_path):
    data,recovery,config=fixture(tmp_path)
    before=(data/"netspecter.db").read_bytes()
    result=preview_reset(data)
    assert result["databases"]["netspecter.db"]["device_overrides"]["action"].startswith("preserve")
    assert (data/"netspecter.db").read_bytes()==before
    assert not list(recovery.iterdir())


def test_rebuild_clears_history_shrinks_database_and_preserves_operator_state(tmp_path):
    data,recovery,config=fixture(tmp_path)
    old_size=(data/"netspecter.db").stat().st_size
    prepare_reset(data,recovery,writers_stopped=True,cutoff="2026-11-18 22:00:00")
    assert scalar(data/"netspecter.db","SELECT COUNT(*) FROM monitor_events")==1
    apply_prepared_reset(recovery,writers_stopped=True)
    assert scalar(data/"netspecter.db","SELECT COUNT(*) FROM monitor_events")==0
    assert scalar(data/"netspecter.db","SELECT name FROM device_overrides")=="Edited device"
    assert scalar(data/"netspecter.db","SELECT display_name FROM device_identities")=="Edited device"
    assert scalar(data/"netspecter.db","SELECT logged_in_user FROM device_identities") is None
    assert scalar(data/"netspecter.db","SELECT first_seen FROM devices") is None
    assert scalar(data/"netspecter.db","SELECT first_seen FROM device_identifiers")=="2026-11-18 22:00:00"
    assert scalar(data/"netspecter_traffic.db","SELECT app FROM application_signatures")=="Custom service"
    assert scalar(data/"netspecter_traffic.db","SELECT count(*) FROM traffic_intervals")==0
    assert scalar(data/"netspecter_dns.db","SELECT cleared_at FROM dns_import_state")=="2026-11-18 22:00:00"
    assert json.loads((data/"cache.json").read_text())=={}
    assert (data/"netspecter.db").stat().st_size<old_size
    assert (config/"secret.key").read_text()=="private-key" and (config/"config.json").read_text()=='{"setting":"keep"}'
    assert scalar(recovery/"databases/netspecter.db","SELECT count(*) FROM monitor_events")==1


def test_partial_swap_can_restore_coherent_old_databases_and_cache(tmp_path):
    data,recovery,_=fixture(tmp_path);prepare_reset(data,recovery,writers_stopped=True)
    def fail(_name):raise InterruptedError("simulated interrupted swap")
    with pytest.raises(InterruptedError):apply_prepared_reset(recovery,writers_stopped=True,fault_hook=fail)
    recover_reset(recovery,writers_stopped=True)
    assert scalar(data/"netspecter.db","SELECT count(*) FROM monitor_events")==1
    assert scalar(data/"netspecter.db","SELECT name FROM device_overrides")=="Edited device"
    assert scalar(data/"netspecter_dns.db","SELECT count(*) FROM dns_querylog")==1
    assert json.loads((data/"cache.json").read_text())=={"old":"history"}


def test_unknown_schema_and_missing_database_fail_closed(tmp_path):
    data,recovery,_=fixture(tmp_path)
    with closing(sqlite3.connect(data/"netspecter.db")) as con,con:con.execute("CREATE TABLE unknown_custom_state(id INTEGER)")
    with pytest.raises(ValueError,match="Unrecognized reset table"):prepare_reset(data,recovery,writers_stopped=True)
    assert scalar(data/"netspecter.db","SELECT count(*) FROM monitor_events")==1
    (data/"netspecter_dns.db").unlink()
    with pytest.raises(ValueError):preview_reset(data)


def test_unrecognized_edited_state_column_requires_review(tmp_path):
    data,recovery,_=fixture(tmp_path)
    with closing(sqlite3.connect(data/"netspecter.db")) as con,con:con.execute("ALTER TABLE device_overrides ADD COLUMN custom_operator_field TEXT")
    with pytest.raises(ValueError,match="retained columns"):prepare_reset(data,recovery,writers_stopped=True)


def test_reset_refuses_without_writer_stop_and_can_be_repeated(tmp_path):
    data,recovery,_=fixture(tmp_path)
    with pytest.raises(ValueError):prepare_reset(data,recovery)
    prepare_reset(data,recovery,writers_stopped=True);apply_prepared_reset(recovery,writers_stopped=True)
    second=tmp_path/"recovery-two";second.mkdir(mode=0o700)
    prepare_reset(data,second,writers_stopped=True);apply_prepared_reset(second,writers_stopped=True)
    assert scalar(data/"netspecter.db","SELECT name FROM device_overrides")=="Edited device"


def test_temporary_copy_is_discarded_only_after_successful_verification(tmp_path):
    from services.history_reset_service import discard_recovery,write_journal
    data,recovery,_=fixture(tmp_path)
    prepare_reset(data,recovery,writers_stopped=True);apply_prepared_reset(recovery,writers_stopped=True)
    with pytest.raises(ValueError):discard_recovery(recovery)
    write_journal(recovery,{"status":"complete"});discard_recovery(recovery)
    assert not recovery.exists()
    assert scalar(data/"netspecter.db","SELECT name FROM device_overrides")=="Edited device"


def test_insufficient_disk_space_fails_before_snapshot_or_swap(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from services import history_reset_service as reset
    data,recovery,_=fixture(tmp_path)
    monkeypatch.setattr(reset.shutil,"disk_usage",lambda _:SimpleNamespace(free=1))
    with pytest.raises(OSError,match="Insufficient free space"):prepare_reset(data,recovery,writers_stopped=True)
    assert scalar(data/"netspecter.db","SELECT count(*) FROM monitor_events")==1


def test_existing_backup_directory_is_outside_current_reset_cleanup(tmp_path):
    from services.history_reset_service import discard_recovery,write_journal
    data,recovery,_=fixture(tmp_path)
    previous=tmp_path/"old-backup";previous.mkdir();(previous/"keep.txt").write_text("existing backup")
    prepare_reset(data,recovery,writers_stopped=True);apply_prepared_reset(recovery,writers_stopped=True)
    write_journal(recovery,{"status":"complete"});discard_recovery(recovery)
    assert (previous/"keep.txt").read_text()=="existing backup"


def test_coordinator_recovers_data_before_restarting_writers_on_failed_health_check(tmp_path):
    from contextlib import nullcontext
    from services.history_reset_runtime import coordinated_reset,MARKER
    data,recovery,_=fixture(tmp_path);events=[]
    class Protection:
        original={"uid":0,"gid":0,"mode":0o750}
        def protect(self):events.append("protect")
        def restore(self):events.append("permissions restored")
    class Controller:
        def capture(self):return {"netspecter-collector.service":{"ActiveState":"active"}}
        def install_guards(self,*_):events.append("guards")
        def stop(self,*_):events.append("stop")
        def start(self,*_):events.append("start")
        def verify(self,*_):raise RuntimeError("simulated startup failure")
    with pytest.raises(RuntimeError,match="startup failure"):
        coordinated_reset(data,recovery,Controller(),Protection(),lambda _:nullcontext())
    assert scalar(data/"netspecter.db","SELECT count(*) FROM monitor_events")==1
    assert not (data/MARKER).exists()
    assert events.count("stop")==2 and events.count("start")==2
    assert json.loads((recovery/"reset-journal.json").read_text())["status"]=="failed_recovered"


def test_current_address_mapping_survives_cleared_activity_timestamps(tmp_path):
    data,recovery,_=fixture(tmp_path)
    with closing(sqlite3.connect(data/"netspecter.db")) as con,con:
        con.execute("INSERT INTO device_identities VALUES ('mac:older','older-stable','Older edited name','192.168.1.5','2019-01-01','2020-01-01',NULL,NULL)")
    prepare_reset(data,recovery,writers_stopped=True);apply_prepared_reset(recovery,writers_stopped=True)
    assert scalar(data/"netspecter.db","SELECT device_id FROM device_identities WHERE current_ip='192.168.1.5'")=="stable"
    assert scalar(data/"netspecter.db","SELECT display_name FROM device_identities WHERE identity_key='mac:older'")=="Older edited name"
