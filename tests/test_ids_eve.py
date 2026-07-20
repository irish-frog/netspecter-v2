import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from netspecter_ids import (
    fast_log_alerts_from_text,
    ingest_eve_incremental,
    normalize_eve_event,
    prune_ids_history,
    recent_structured_alerts,
)


IDS_SCHEMA = """
CREATE TABLE ids_eve_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    inode INTEGER DEFAULT 0,
    offset INTEGER DEFAULT 0,
    path TEXT,
    updated_at INTEGER DEFAULT 0
);
CREATE TABLE ids_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    ts TEXT NOT NULL,
    day TEXT,
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
    query_type TEXT,
    rcode TEXT,
    answer_summary TEXT,
    hostname TEXT,
    method TEXT,
    url_path TEXT,
    user_agent TEXT,
    status INTEGER,
    tls_sni TEXT,
    tls_version TEXT,
    cert_subject TEXT,
    cert_issuer TEXT,
    ja3 TEXT,
    ja4 TEXT,
    filename TEXT,
    file_size INTEGER,
    mime_type TEXT,
    hashes TEXT,
    stored INTEGER DEFAULT 0,
    anomaly_event TEXT
);
CREATE INDEX idx_ids_events_ts ON ids_events(ts);
CREATE INDEX idx_ids_events_src_ip ON ids_events(src_ip);
CREATE INDEX idx_ids_events_dest_ip ON ids_events(dest_ip);
CREATE INDEX idx_ids_events_type ON ids_events(event_type);
CREATE INDEX idx_ids_events_signature ON ids_events(signature);
CREATE INDEX idx_ids_events_day_type ON ids_events(day, event_type);
"""


def alert_event(ts="2026-07-12T10:00:00.000000+0200", flow_id=1, signature="Test alert"):
    return {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": "192.168.1.50",
        "src_port": 4444,
        "dest_ip": "8.8.8.8",
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "flow_id": flow_id,
        "alert": {
            "signature_id": 999001,
            "signature": signature,
            "category": "Potentially Bad Traffic",
            "severity": 1,
        },
        "payload": "do not store me",
    }


class EveJsonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "ids.db"
        self.eve_path = self.root / "eve.json"
        con = sqlite3.connect(self.db_path)
        con.executescript(IDS_SCHEMA)
        con.close()

    def tearDown(self):
        self.tmp.cleanup()

    def connect_db(self):
        con = sqlite3.connect(self.db_path)
        con.execute("PRAGMA busy_timeout=30000")
        return con

    def write_events(self, *events):
        with self.eve_path.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")

    def count_events(self):
        con = self.connect_db()
        count = con.execute("SELECT COUNT(*) FROM ids_events").fetchone()[0]
        con.close()
        return count

    def test_normalizes_supported_events_and_caps_payloads(self):
        event = alert_event(signature="x" * 400)
        normalized = normalize_eve_event(event)
        self.assertEqual("alert", normalized["event_type"])
        self.assertEqual(999001, normalized["signature_id"])
        self.assertEqual(260, len(normalized["signature"]))
        self.assertNotIn("payload", normalized)

    def test_incremental_large_file_does_not_reread_previous_rows(self):
        self.write_events(alert_event(flow_id=1), alert_event(flow_id=2))
        first = ingest_eve_incremental(self.connect_db, self.eve_path)
        self.write_events(alert_event(flow_id=3))
        second = ingest_eve_incremental(self.connect_db, self.eve_path)
        self.assertEqual(2, first["inserted"])
        self.assertEqual(1, second["inserted"])
        self.assertEqual(3, self.count_events())

    def test_rotation_or_replacement_reads_new_file_from_start(self):
        self.write_events(alert_event(flow_id=1))
        ingest_eve_incremental(self.connect_db, self.eve_path)
        self.eve_path.unlink()
        self.write_events(alert_event(flow_id=2))
        result = ingest_eve_incremental(self.connect_db, self.eve_path)
        self.assertEqual(1, result["inserted"])
        self.assertEqual(2, self.count_events())

    def test_truncation_reads_from_start_without_crashing(self):
        self.write_events(alert_event(flow_id=1), alert_event(flow_id=2))
        ingest_eve_incremental(self.connect_db, self.eve_path)
        self.eve_path.write_text(json.dumps(alert_event(flow_id=3)) + "\n", encoding="utf-8")
        result = ingest_eve_incremental(self.connect_db, self.eve_path)
        self.assertEqual(1, result["inserted"])

    def test_invalid_json_missing_fields_and_duplicates_are_safe(self):
        self.eve_path.write_text("{bad json\n{}\n", encoding="utf-8")
        self.write_events(alert_event(flow_id=1), alert_event(flow_id=1))
        result = ingest_eve_incremental(self.connect_db, self.eve_path)
        self.assertEqual(1, result["inserted"])
        self.assertEqual(1, result["bad_json"])
        self.assertEqual(1, self.count_events())

    def test_missing_eve_json_reports_without_exception(self):
        result = ingest_eve_incremental(self.connect_db, self.root / "missing.json")
        self.assertEqual(0, result["inserted"])
        self.assertIn("not found", result["error"])

    def test_retention_row_limit_and_indexes(self):
        self.write_events(
            alert_event(ts="2026-01-01T10:00:00.000000+0200", flow_id=1),
            alert_event(ts="2026-07-12T10:00:00.000000+0200", flow_id=2),
            alert_event(ts="2026-07-12T10:01:00.000000+0200", flow_id=3),
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)
        prune_ids_history(self.connect_db, {"ids_alert_retention_days": 60, "ids_structured_max_records": 2, "ids_min_free_mb": 0})
        self.assertLessEqual(self.count_events(), 2)
        con = self.connect_db()
        indexes = {row[1] for row in con.execute("PRAGMA index_list(ids_events)").fetchall()}
        con.close()
        self.assertIn("idx_ids_events_ts", indexes)
        self.assertIn("idx_ids_events_src_ip", indexes)
        self.assertIn("idx_ids_events_dest_ip", indexes)
        self.assertIn("idx_ids_events_type", indexes)
        self.assertIn("idx_ids_events_signature", indexes)

    def test_fast_log_fallback_parser_still_parses_existing_alerts(self):
        text = "07/10/2026-23:01:00.000000 [**] [1:999001:1] NETSPECTER TEST P1 IDS ALERT [**] [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 192.168.1.50:4444 -> 8.8.8.8:443"
        alerts = fast_log_alerts_from_text(text)
        self.assertEqual(1, len(alerts))
        self.assertEqual("1", alerts[0]["priority"])
        self.assertEqual("NETSPECTER TEST P1 IDS ALERT", alerts[0]["signature"])

    def test_recent_alerts_can_sort_highest_severity_first(self):
        self.write_events(
            alert_event(ts="2026-07-12T10:00:00.000000+0200", flow_id=1, signature="Low"),
            alert_event(ts="2026-07-12T10:02:00.000000+0200", flow_id=2, signature="Critical"),
            alert_event(ts="2026-07-12T10:01:00.000000+0200", flow_id=3, signature="High"),
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)
        con = self.connect_db()
        con.execute("UPDATE ids_events SET severity=3 WHERE signature='Low'")
        con.execute("UPDATE ids_events SET severity=2 WHERE signature='High'")
        con.commit()
        con.close()

        alerts = recent_structured_alerts(self.connect_db, filters={"sort": "severity_high"})

        self.assertEqual(["Critical", "High", "Low"], [alert["signature"] for alert in alerts])

    def test_default_truncated_packet_noise_is_hidden_but_raw_view_can_show_it(self):
        self.write_events(
            alert_event(flow_id=1, signature="SURICATA AF-PACKET truncated packet"),
            alert_event(flow_id=2, signature="SURICATA IPv6 truncated packet"),
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)

        normal_alerts = recent_structured_alerts(self.connect_db)
        raw_alerts = recent_structured_alerts(self.connect_db, filters={"show_noise": True})

        self.assertEqual(["SURICATA IPv6 truncated packet"], [alert["signature"] for alert in normal_alerts])
        self.assertEqual(
            ["SURICATA IPv6 truncated packet", "SURICATA AF-PACKET truncated packet"],
            [alert["signature"] for alert in raw_alerts],
        )

    def test_stun_signatures_are_informational_not_medium(self):
        self.write_events(
            alert_event(
                flow_id=1,
                signature="ET INFO Session Traversal Utilities for NAT (STUN Binding Request)",
            )
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)

        alerts = recent_structured_alerts(self.connect_db)

        self.assertEqual(1, len(alerts))
        self.assertEqual("4", alerts[0]["priority"])


if __name__ == "__main__":
    unittest.main()
