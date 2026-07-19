import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import netspecter_anomaly as an


class AnomalyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "anomaly.db"
        con = self.connect_db()
        con.execute("CREATE TABLE devices (ip TEXT PRIMARY KEY, name TEXT, mac TEXT, device_type TEXT)")
        con.execute("CREATE TABLE device_overrides (ip TEXT PRIMARY KEY, device_type TEXT)")
        con.execute("CREATE TABLE traffic_intervals (id INTEGER PRIMARY KEY, day TEXT, ts TEXT, ip TEXT, downloaded_mb REAL, uploaded_mb REAL, total_mb REAL)")
        con.execute("CREATE TABLE remote_traffic_intervals (id INTEGER PRIMARY KEY, day TEXT, ts TEXT, ip TEXT, remote_ip TEXT, category TEXT, total_mb REAL)")
        con.execute("CREATE TABLE remote_ip_locations (remote_ip TEXT PRIMARY KEY, country TEXT, country_code TEXT)")
        con.execute("CREATE TABLE dns_querylog (id INTEGER PRIMARY KEY, day TEXT, ts TEXT, client TEXT, domain TEXT, blocked INTEGER, category TEXT)")
        con.execute("CREATE TABLE ids_events (id INTEGER PRIMARY KEY, day TEXT, ts TEXT, src_ip TEXT, event_type TEXT, dest_port INTEGER, app_proto TEXT, protocol TEXT)")
        an.ensure_schema(con)
        con.commit()
        con.close()

    def tearDown(self):
        self.tmp.cleanup()

    def connect_db(self):
        return sqlite3.connect(self.db_path)

    def seed_day(self, day, ip="192.168.1.10", dtype="Workstation", upload=10, dns=20, dests=3, country="ZA", port=443, proto="tls", hour=10):
        con = self.connect_db()
        con.execute("INSERT OR IGNORE INTO devices VALUES (?, 'dev', '', ?)", (ip, dtype))
        ts = f"{day} {hour:02d}:00:00"
        con.execute("INSERT INTO traffic_intervals (day, ts, ip, downloaded_mb, uploaded_mb, total_mb) VALUES (?, ?, ?, 20, ?, ?)", (day, ts, ip, upload, upload + 20))
        con.execute("INSERT OR REPLACE INTO remote_ip_locations VALUES (?, 'Country', ?)", (f"203.0.113.{dests}", country))
        for i in range(dests):
            remote_ip = f"203.0.{dests}.{i}"
            con.execute("INSERT OR IGNORE INTO remote_ip_locations VALUES (?, 'Country', ?)", (remote_ip, country))
            con.execute("INSERT INTO remote_traffic_intervals (day, ts, ip, remote_ip, category, total_mb) VALUES (?, ?, ?, ?, 'Other', 1)", (day, ts, ip, remote_ip))
        for i in range(dns):
            con.execute("INSERT INTO dns_querylog (day, ts, client, domain, blocked, category) VALUES (?, ?, ?, ?, 0, 'Other')", (day, ts, ip, f"d{i}.test"))
        con.execute("INSERT INTO ids_events (day, ts, src_ip, event_type, dest_port, app_proto, protocol) VALUES (?, ?, ?, 'flow', ?, ?, 'TCP')", (day, ts, ip, port, proto))
        con.commit()
        con.close()

    def seed_baseline(self, days=7, **kwargs):
        start = datetime(2026, 7, 1)
        for i in range(days):
            day = an.day_text(start + timedelta(days=i))
            self.seed_day(day, **kwargs)
            con = self.connect_db()
            an.aggregate_day(con, day)
            con.commit()
            con.close()

    def run_target(self, day="2026-07-12", config=None, **kwargs):
        self.seed_day(day, **kwargs)
        return an.run_anomaly_cycle(self.connect_db, config or {"anomaly_learning_only": False}, day)

    def event_rules(self):
        con = self.connect_db()
        rules = [row[0] for row in con.execute("SELECT rule FROM anomaly_events ORDER BY id").fetchall()]
        con.close()
        return rules

    def test_insufficient_baseline_learning_only(self):
        self.seed_baseline(days=2)
        self.run_target(upload=3000, config={"anomaly_learning_only": False, "anomaly_min_learning_days": 7})
        con = self.connect_db()
        row = con.execute("SELECT learning_only, maturity_days FROM anomaly_events WHERE rule='large_upload'").fetchone()
        con.close()
        self.assertEqual((1, 2), row)

    def test_normal_variation_no_event(self):
        self.seed_baseline(days=7, upload=100, dns=50, dests=5)
        self.run_target(upload=110, dns=55, dests=6)
        self.assertEqual([], self.event_rules())

    def test_large_upload(self):
        self.seed_baseline(days=7, upload=50)
        self.run_target(upload=1000)
        self.assertIn("large_upload", self.event_rules())

    def test_new_country(self):
        self.seed_baseline(days=7, country="ZA")
        self.run_target(country="US", dests=4)
        self.assertIn("new_country", self.event_rules())

    def test_new_port_and_protocol(self):
        self.seed_baseline(days=7, port=443, proto="tls")
        self.run_target(port=4444, proto="ssh")
        rules = self.event_rules()
        self.assertIn("new_port", rules)
        self.assertIn("new_protocol", rules)

    def test_unusual_active_time(self):
        self.seed_baseline(days=7, hour=10)
        self.run_target(hour=3)
        self.assertIn("unusual_active_hour", self.event_rules())

    def test_dns_spike(self):
        self.seed_baseline(days=7, dns=20)
        self.run_target(dns=500)
        self.assertIn("dns_spike", self.event_rules())

    def test_repeated_suppression_by_unique_key(self):
        self.seed_baseline(days=7, upload=50)
        self.run_target(upload=1000)
        self.run_target(upload=1000)
        con = self.connect_db()
        count = con.execute("SELECT COUNT(*) FROM anomaly_events WHERE rule='large_upload'").fetchone()[0]
        con.close()
        self.assertEqual(1, count)

    def test_exclusions(self):
        self.seed_baseline(days=7, upload=50)
        self.run_target(upload=1000, config={"anomaly_learning_only": False, "anomaly_excluded_devices": ["192.168.1.10"]})
        self.assertEqual([], self.event_rules())

    def test_expected_learning_and_poisoning_prevention(self):
        self.seed_baseline(days=7, upload=50)
        self.run_target(upload=1000)
        self.assertTrue(an.mark_expected(self.connect_db, 1, note="expected", learn=False))
        con = self.connect_db()
        learned = con.execute("SELECT learned_at FROM anomaly_events WHERE id=1").fetchone()[0]
        con.close()
        self.assertIsNone(learned)
        self.assertTrue(an.mark_expected(self.connect_db, 1, note="learn this", learn=True))
        con = self.connect_db()
        learned = con.execute("SELECT learned_at FROM anomaly_events WHERE id=1").fetchone()[0]
        con.close()
        self.assertIsNotNone(learned)

    def test_retention_limit(self):
        self.seed_baseline(days=7, upload=50)
        for i in range(3):
            self.run_target(day=f"2026-07-{12+i:02d}", upload=1000 + i)
        an.prune_anomalies(self.connect_db, {"anomaly_max_events": 1, "anomaly_min_free_mb": 0})
        con = self.connect_db()
        count = con.execute("SELECT COUNT(*) FROM anomaly_events").fetchone()[0]
        con.close()
        self.assertEqual(1, count)


if __name__ == "__main__":
    unittest.main()
