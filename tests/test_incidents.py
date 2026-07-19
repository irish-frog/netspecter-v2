import sqlite3
import tempfile
import unittest
from pathlib import Path

import netspecter_incidents as inc


IDS_SCHEMA = """
CREATE TABLE ids_events (
    id INTEGER PRIMARY KEY,
    event_key TEXT,
    event_type TEXT,
    ts TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    app_proto TEXT,
    flow_id TEXT,
    signature_id INTEGER,
    signature TEXT,
    category TEXT,
    severity INTEGER,
    query TEXT,
    hostname TEXT,
    tls_sni TEXT,
    filename TEXT,
    anomaly_event TEXT
)
"""


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "incidents.db"
        con = self.connect_db()
        con.execute(IDS_SCHEMA)
        con.execute("CREATE TABLE devices (ip TEXT PRIMARY KEY, name TEXT, mac TEXT)")
        con.execute("CREATE TABLE dns_querylog (id INTEGER PRIMARY KEY, ts TEXT, client TEXT, domain TEXT, blocked INTEGER, category TEXT)")
        con.execute("CREATE TABLE remote_traffic_intervals (id INTEGER PRIMARY KEY, ip TEXT, remote_ip TEXT, category TEXT, total_mb REAL, ts TEXT)")
        con.execute("CREATE TABLE threat_correlations (id INTEGER PRIMARY KEY, ts TEXT, reputation TEXT, indicator TEXT, source TEXT, reason TEXT, dest_ip TEXT, domain TEXT, device_ip TEXT)")
        con.execute("CREATE TABLE ids_alert_notifications (alert_key TEXT PRIMARY KEY, last_sent_ts INTEGER)")
        inc.ensure_schema(con)
        con.commit()
        con.close()

    def tearDown(self):
        self.tmp.cleanup()

    def connect_db(self):
        return sqlite3.connect(self.db_path)

    def add_alert(self, event_id=1, src="192.168.1.10", dest="203.0.113.5", ts="2026-07-12 10:00:00", severity=1, flow="flow1", sig="Bad thing"):
        con = self.connect_db()
        con.execute(
            """
            INSERT INTO ids_events
            (id, event_key, event_type, ts, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, flow_id,
             signature_id, signature, category, severity, query, hostname, tls_sni, filename, anomaly_event)
            VALUES (?, ?, 'alert', ?, ?, 4444, ?, 443, 'TCP', 'tls', ?, 999001, ?, 'bad', ?, '', '', '', '', '')
            """,
            (event_id, f"k{event_id}", ts, src, dest, flow, sig, severity),
        )
        con.commit()
        con.close()

    def incident_count(self):
        con = self.connect_db()
        count = con.execute("SELECT COUNT(*) FROM security_incidents").fetchone()[0]
        con.close()
        return count

    def test_related_events_grouped_correctly(self):
        self.add_alert()
        con = self.connect_db()
        con.execute("INSERT INTO ids_events VALUES (2, 'k2', 'dns', '2026-07-12 10:01:00', '192.168.1.10', NULL, '203.0.113.5', NULL, 'UDP', 'dns', 'flow1', NULL, NULL, NULL, NULL, 'evil.test', '', '', '', '')")
        con.execute("INSERT INTO dns_querylog VALUES (1, '2026-07-12 10:02:00', '192.168.1.10', 'evil.test', 1, 'Malware')")
        con.execute("INSERT INTO remote_traffic_intervals VALUES (1, '192.168.1.10', '203.0.113.5', 'Other', 1.5, '2026-07-12 10:03:00')")
        con.execute("INSERT INTO threat_correlations VALUES (1, '2026-07-12 10:02:30', 'Malicious', '203.0.113.0/24', 'spamhaus_drop', 'DROP', '203.0.113.5', '', '192.168.1.10')")
        con.commit()
        con.close()
        self.assertEqual(1, inc.build_incidents_once(self.connect_db, {}))
        detail = inc.incident_detail(self.connect_db, 1)
        event_types = {row[3] for row in detail[1]}
        self.assertIn("suricata_alert", event_types)
        self.assertIn("dns_query", event_types)
        self.assertIn("traffic", event_types)
        self.assertIn("threat_intel", event_types)

    def test_unrelated_events_remain_separate(self):
        self.add_alert(1, src="192.168.1.10", dest="203.0.113.5")
        self.add_alert(2, src="192.168.1.11", dest="198.51.100.5", flow="flow2")
        inc.build_incidents_once(self.connect_db, {})
        self.assertEqual(2, self.incident_count())

    def test_duplicate_alerts_deduplicated(self):
        self.add_alert(1)
        self.add_alert(2, ts="2026-07-12 10:05:00")
        inc.build_incidents_once(self.connect_db, {})
        self.assertEqual(1, self.incident_count())

    def test_no_flow_id_still_groups_by_device_destination(self):
        self.add_alert(flow="")
        inc.build_incidents_once(self.connect_db, {})
        self.assertEqual(1, self.incident_count())

    def test_same_destination_different_devices_separate(self):
        self.add_alert(1, src="192.168.1.10", dest="203.0.113.5")
        self.add_alert(2, src="192.168.1.11", dest="203.0.113.5")
        inc.build_incidents_once(self.connect_db, {})
        self.assertEqual(2, self.incident_count())

    def test_expired_source_data_detail_graceful(self):
        self.add_alert()
        inc.build_incidents_once(self.connect_db, {})
        con = self.connect_db()
        con.execute("DELETE FROM ids_events")
        con.commit()
        con.close()
        incident, events, *_ = inc.incident_detail(self.connect_db, 1)
        self.assertIsNotNone(incident)
        self.assertTrue(events)

    def test_acknowledgement_status_closure_and_audit(self):
        self.add_alert()
        inc.build_incidents_once(self.connect_db, {})
        inc.update_incident(self.connect_db, 1, status="acknowledged", assigned_to="gavin", note="checking", actor="gavin")
        inc.update_incident(self.connect_db, 1, status="closed", actor="gavin")
        incident, _, notes, audit_rows, _ = inc.incident_detail(self.connect_db, 1)
        self.assertEqual("closed", incident[8])
        self.assertEqual(1, len(notes))
        self.assertGreaterEqual(len(audit_rows), 4)

    def test_retention_and_record_limit(self):
        for i in range(1, 5):
            self.add_alert(i, src=f"192.168.1.{i}", dest=f"203.0.113.{i}", flow=f"f{i}", ts=f"2026-07-12 10:0{i}:00")
        inc.build_incidents_once(self.connect_db, {})
        inc.prune_incidents(self.connect_db, {"incident_max_records": 2, "incident_min_free_mb": 0})
        self.assertEqual(2, self.incident_count())


if __name__ == "__main__":
    unittest.main()
