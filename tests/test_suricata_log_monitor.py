import sqlite3
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

app_stub = types.ModuleType("app")
app_stub.cfg = lambda: {}
app_stub.check_monitor_service = lambda *args, **kwargs: (True, "")
app_stub.connect_db = lambda: None
app_stub.init_db = lambda: None
app_stub.monitor_key = lambda name, url: f"{name}|{url}"
app_stub.normalise_gatus_monitors = lambda config: []
app_stub.recent_suricata_alerts = lambda *args, **kwargs: ([], "")
app_stub.record_monitor_event = lambda *args, **kwargs: None
app_stub.send_telegram_message = lambda *args, **kwargs: (False, "")
sys.modules.setdefault("app", app_stub)

import monitor_sweeper as sweeper
from netspecter_incidents import incident_schema_sql


class SuricataLogMonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.log_dir = self.root / "suricata"
        self.log_dir.mkdir()
        self.config_path = self.root / "logrotate" / "suricata"
        self.config_path.parent.mkdir()
        self.config_path.write_text("daily\n")
        self.db_path = self.root / "incidents.db"

    def tearDown(self):
        self.tmp.cleanup()

    def write_file(self, name, size, mtime=None):
        path = self.log_dir / name
        path.write_bytes(b"x" * size)
        if mtime is not None:
            Path(path).touch()
            import os
            os.utime(path, (mtime, mtime))
        return path

    def connect_db(self):
        con = sqlite3.connect(self.db_path)
        for sql in incident_schema_sql():
            con.execute(sql)
        con.commit()
        return con

    def patch_db(self):
        return patch.multiple(
            sweeper,
            init_db=lambda: None,
            sweeper_db=self.connect_db,
        )

    def test_eve_and_total_thresholds_create_critical_assessment(self):
        self.write_file("eve.json", 1024 * 1024 * 1024)
        self.write_file("fast.log", 10)
        with patch.object(sweeper, "systemctl_state", return_value=("enabled", "active")):
            assessment = sweeper.assess_suricata_logs(log_dir=self.log_dir, logrotate_config=self.config_path)
        self.assertFalse(assessment["ok"])
        self.assertEqual(1, assessment["severity"])
        self.assertEqual("eve.json", assessment["largest_name"])
        self.assertTrue(any("eve.json" in issue for issue in assessment["issues"]))

    def test_missing_rotation_state_is_warning_when_directory_is_large(self):
        self.write_file("stats.log", 2 * 1024 * 1024 * 1024)
        with patch.object(sweeper, "systemctl_state", return_value=("disabled", "inactive")):
            assessment = sweeper.assess_suricata_logs(log_dir=self.log_dir, logrotate_config=self.root / "missing")
        self.assertFalse(assessment["ok"])
        self.assertEqual(1, assessment["severity"])
        self.assertIn("Suricata logrotate configuration is missing", assessment["issues"])
        self.assertTrue(any("logrotate.timer" in issue for issue in assessment["issues"]))
        self.assertTrue(any("No recent rotated" in issue for issue in assessment["issues"]))

    def test_incident_is_deduped_and_resolved(self):
        bad = {
            "ok": False,
            "severity": 1,
            "issues": ["eve.json is 1.2 GB"],
            "largest_name": "eve.json",
            "largest_size": int(1.2 * 1024 * 1024 * 1024),
            "total_size": int(2.8 * 1024 * 1024 * 1024),
            "filesystem": {"percent": 72, "free": 10 * 1024 * 1024 * 1024, "total": 56 * 1024 * 1024 * 1024},
            "logrotate_enabled": "enabled",
            "logrotate_active": "active",
            "logrotate_config_exists": True,
            "rotation_age_hours": 12,
        }
        good = dict(bad, ok=True, issues=[], severity=0)
        with self.patch_db():
            sweeper.upsert_suricata_log_incident(bad)
            sweeper.upsert_suricata_log_incident(bad)
            sweeper.upsert_suricata_log_incident(good)
        con = sqlite3.connect(self.db_path)
        incidents = con.execute("SELECT incident_key, status, severity, title FROM security_incidents").fetchall()
        events = con.execute("SELECT COUNT(*) FROM security_incident_events").fetchone()[0]
        con.close()
        self.assertEqual(1, len(incidents))
        self.assertEqual(sweeper.SURICATA_INCIDENT_KEY, incidents[0][0])
        self.assertEqual("resolved", incidents[0][1])
        self.assertEqual(1, incidents[0][2])
        self.assertEqual(1, events)


if __name__ == "__main__":
    unittest.main()
