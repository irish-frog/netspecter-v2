import sqlite3
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from services.alert_history_service import clear_database_history, clear_log_history


def test_cleanup_is_explicit_and_preserves_usage_identity_and_dns(tmp_path):
    path = tmp_path / "netspecter.db"
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE ids_events(id INTEGER PRIMARY KEY, event_type TEXT);
        INSERT INTO ids_events VALUES (1, 'alert'), (2, 'tls');
        CREATE TABLE security_incidents(id INTEGER PRIMARY KEY);
        INSERT INTO security_incidents VALUES (1);
        CREATE TABLE devices(ip TEXT); INSERT INTO devices VALUES ('192.168.1.20');
        CREATE TABLE dns_querylog(domain TEXT); INSERT INTO dns_querylog VALUES ('example.com');
        CREATE TABLE traffic_intervals(bytes INTEGER); INSERT INTO traffic_intervals VALUES (12345);
        CREATE TABLE application_signatures(app TEXT); INSERT INTO application_signatures VALUES ('Example');
    """)
    con.close()
    assert clear_database_history(path)["ids_alerts"] == 1
    con = sqlite3.connect(path)
    assert con.execute("SELECT COUNT(*) FROM ids_events").fetchone()[0] == 2
    con.close()
    assert clear_database_history(path, apply=True)["ids_alerts"] == 1
    con = sqlite3.connect(path)
    assert con.execute("SELECT event_type FROM ids_events").fetchall() == [("tls",)]
    assert con.execute("SELECT COUNT(*) FROM security_incidents").fetchone()[0] == 0
    for table in ("devices", "dns_querylog", "traffic_intervals", "application_signatures"):
        assert con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 1
    con.close()
    assert clear_database_history(path, apply=True)["ids_alerts"] == 0


def test_missing_databases_are_not_created(tmp_path):
    path = tmp_path / "missing.db"
    assert clear_database_history(path, apply=True) == {}
    assert not path.exists()


def test_logs_are_limited_to_suricata_files(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    for name in ("eve.json", "fast.log.1.gz", "dns.log", "config.json"):
        (logs / name).write_text("test")
    assert clear_log_history(logs) == ["eve.json", "fast.log.1.gz"]
    assert (logs / "eve.json").exists()
    clear_log_history(logs, apply=True)
    assert sorted(path.name for path in logs.iterdir()) == ["config.json", "dns.log"]


def test_cleanup_rolls_back_the_entire_database_on_failure(tmp_path):
    path = tmp_path / "history.db"
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE security_incident_notes(id INTEGER);
        INSERT INTO security_incident_notes VALUES (1);
        CREATE TABLE security_incidents(id INTEGER);
        INSERT INTO security_incidents VALUES (1);
        CREATE TRIGGER stop_delete BEFORE DELETE ON security_incidents
        BEGIN SELECT RAISE(ABORT, 'blocked'); END;
    """)
    con.close()
    with pytest.raises(sqlite3.IntegrityError):
        clear_database_history(path, apply=True)
    con = sqlite3.connect(path)
    assert con.execute("SELECT COUNT(*) FROM security_incident_notes").fetchone()[0] == 1
    con.close()


@pytest.mark.parametrize("config,state", [
    ({"security_features_enabled": True}, SimpleNamespace(returncode=3, stdout="inactive")),
    ({"suricata_enabled": True}, SimpleNamespace(returncode=3, stdout="inactive")),
    ({}, SimpleNamespace(returncode=0, stdout="active")),
])
def test_apply_refuses_running_security_collection(tmp_path, monkeypatch, config, state):
    script = Path(__file__).resolve().parents[1] / "scripts" / "clear-alert-history.py"
    spec = importlib.util.spec_from_file_location("alert_cleanup_cli_test", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    monkeypatch.setattr(module.sys, "argv", [str(script), "--apply", "--config", str(config_path)])
    monkeypatch.setattr(module.subprocess, "run", lambda *_args, **_kwargs: state)
    monkeypatch.setattr(module, "clear_database_history", lambda *_args, **_kwargs: pytest.fail("must refuse before deletion"))
    with pytest.raises(SystemExit) as error:
        module.main()
    assert error.value.code == 2
