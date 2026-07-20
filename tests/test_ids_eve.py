import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from netspecter_ids import (
    fast_log_alerts_from_text,
    ingest_eve_incremental,
    is_default_suppressed_signature,
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
    application TEXT,
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
    anomaly_event TEXT,
    alert_status TEXT DEFAULT 'open',
    first_seen TEXT,
    last_seen TEXT,
    alert_count INTEGER DEFAULT 1
);
CREATE INDEX idx_ids_events_ts ON ids_events(ts);
CREATE INDEX idx_ids_events_src_ip ON ids_events(src_ip);
CREATE INDEX idx_ids_events_dest_ip ON ids_events(dest_ip);
CREATE INDEX idx_ids_events_type ON ids_events(event_type);
CREATE INDEX idx_ids_events_signature ON ids_events(signature);
CREATE INDEX idx_ids_events_day_type ON ids_events(day, event_type);
"""


def alert_event(ts="2026-07-12T10:00:00.000000+0200", flow_id=1, signature="Test alert", severity=1, signature_id=None, dns_query=None):
    event = {
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
            "signature_id": signature_id,
            "signature": signature,
            "category": "Potentially Bad Traffic",
            "severity": severity,
        },
        "payload": "do not store me",
    }
    if dns_query:
        event["app_proto"] = "dns"
        event["dest_port"] = 53
        event["proto"] = "UDP"
        event["dns"] = {"query": dns_query, "type": "query", "rrtype": "A"}
    return event


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
        event = alert_event(signature="x" * 400, signature_id=999001)
        normalized = normalize_eve_event(event)
        self.assertEqual("alert", normalized["event_type"])
        self.assertEqual(999001, normalized["signature_id"])
        self.assertEqual(260, len(normalized["signature"]))
        self.assertNotIn("payload", normalized)

    def test_incremental_large_file_does_not_reread_previous_rows(self):
        self.write_events(alert_event(flow_id=1, signature="Test alert 1"), alert_event(flow_id=2, signature="Test alert 2"))
        first = ingest_eve_incremental(self.connect_db, self.eve_path)
        self.write_events(alert_event(flow_id=3, signature="Test alert 3"))
        second = ingest_eve_incremental(self.connect_db, self.eve_path)
        self.assertEqual(2, first["inserted"])
        self.assertEqual(1, second["inserted"])
        self.assertEqual(3, self.count_events())

    def test_rotation_or_replacement_reads_new_file_from_start(self):
        self.write_events(alert_event(flow_id=1))
        ingest_eve_incremental(self.connect_db, self.eve_path)
        self.eve_path.unlink()
        self.write_events(alert_event(flow_id=2, signature="Rotated alert"))
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
        self.assertEqual(2, result["inserted"])
        self.assertEqual(1, result["bad_json"])
        self.assertEqual(1, self.count_events())

    def test_missing_eve_json_reports_without_exception(self):
        result = ingest_eve_incremental(self.connect_db, self.root / "missing.json")
        self.assertEqual(0, result["inserted"])
        self.assertIn("not found", result["error"])

    def test_retention_row_limit_and_indexes(self):
        self.write_events(
            alert_event(ts="2026-01-01T10:00:00.000000+0200", flow_id=1, signature="Old"),
            alert_event(ts="2026-07-12T10:00:00.000000+0200", flow_id=2, signature="Recent 1"),
            alert_event(ts="2026-07-12T10:01:00.000000+0200", flow_id=3, signature="Recent 2"),
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

    def test_daily_prune_removes_old_ignored_and_medium_alerts_first(self):
        old_day = (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d")
        recent_day = datetime.now().strftime("%Y-%m-%d")
        self.write_events(
            alert_event(ts=f"{old_day}T10:00:00.000000+0200", flow_id=1, signature="Old ignored"),
            alert_event(ts=f"{old_day}T10:01:00.000000+0200", flow_id=2, signature="Old medium"),
            alert_event(ts=f"{recent_day}T10:02:00.000000+0200", flow_id=3, signature="Recent critical"),
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)
        con = self.connect_db()
        con.execute("UPDATE ids_events SET alert_status='ignored' WHERE signature='Old ignored'")
        con.execute("UPDATE ids_events SET severity=3 WHERE signature='Old medium'")
        con.commit()
        con.close()

        prune_ids_history(
            self.connect_db,
            {
                "ids_alert_retention_days": 365,
                "ids_ignored_retention_days": 1,
                "ids_low_priority_retention_days": 1,
                "ids_structured_max_records": 1000,
                "ids_min_free_mb": 0,
            },
        )

        con = self.connect_db()
        remaining = [row[0] for row in con.execute("SELECT signature FROM ids_events ORDER BY id").fetchall()]
        con.close()
        self.assertEqual(["Recent critical"], remaining)

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

        alerts = recent_structured_alerts(self.connect_db, filters={"sort": "severity_high", "show_noise": True})

        self.assertEqual(["Critical", "High", "Low"], [alert["signature"] for alert in alerts])

    def test_default_alert_list_only_shows_critical_and_high(self):
        self.write_events(
            alert_event(flow_id=1, signature="Critical"),
            alert_event(flow_id=2, signature="High"),
            alert_event(flow_id=3, signature="Medium"),
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)
        con = self.connect_db()
        con.execute("UPDATE ids_events SET severity=2 WHERE signature='High'")
        con.execute("UPDATE ids_events SET severity=3 WHERE signature='Medium'")
        con.commit()
        con.close()

        normal_alerts = recent_structured_alerts(self.connect_db)
        expanded_alerts = recent_structured_alerts(self.connect_db, filters={"show_noise": True})

        self.assertEqual(["High", "Critical"], [alert["signature"] for alert in normal_alerts])
        self.assertEqual(["Medium", "High", "Critical"], [alert["signature"] for alert in expanded_alerts])

    def test_ignored_and_suppressed_alerts_do_not_show_by_default(self):
        self.write_events(
            alert_event(flow_id=1, signature="Visible"),
            alert_event(flow_id=2, signature="Ignored"),
            alert_event(flow_id=3, signature="Suppressed"),
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)
        con = self.connect_db()
        con.execute("UPDATE ids_events SET alert_status='ignored' WHERE signature='Ignored'")
        con.execute("UPDATE ids_events SET alert_status='suppressed' WHERE signature='Suppressed'")
        con.commit()
        con.close()

        normal_alerts = recent_structured_alerts(self.connect_db, filters={"show_noise": True})
        ignored_alerts = recent_structured_alerts(self.connect_db, filters={"status": "ignored", "show_noise": True})

        self.assertEqual(["Visible"], [alert["signature"] for alert in normal_alerts])
        self.assertEqual(["Ignored"], [alert["signature"] for alert in ignored_alerts])

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
                signature="ET INFO Session Traversal Utilities for NAT (STUN Keepalive Variant)",
            )
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)

        alerts = recent_structured_alerts(self.connect_db, filters={"show_noise": True})

        self.assertEqual(1, len(alerts))
        self.assertEqual("4", alerts[0]["priority"])

    def test_et_info_external_ip_lookup_is_informational_and_suppressed(self):
        self.write_events(alert_event(
            signature="ET INFO External IP Lookup Domain in DNS Lookup (ipinfo .io)",
            severity=2,
            signature_id=2054168,
            dns_query="ipinfo.io",
        ))
        ingest_eve_incremental(self.connect_db, self.eve_path)

        alerts = recent_structured_alerts(self.connect_db, filters={"show_noise": True})

        self.assertEqual(1, len(alerts))
        self.assertEqual("4", alerts[0]["priority"])
        self.assertEqual("External IP discovery", alerts[0]["classification"])
        self.assertEqual("ipinfo.io", alerts[0]["destination"])
        self.assertTrue(is_default_suppressed_signature(alerts[0]["signature"]))
        self.assertEqual([], recent_structured_alerts(self.connect_db))

    def test_steam_user_agent_is_informational_gaming_and_suppressed(self):
        self.write_events(alert_event(
            signature="ET USER_AGENTS Steam HTTP Client User-Agent",
            severity=1,
            signature_id=2016778,
        ))
        ingest_eve_incremental(self.connect_db, self.eve_path)

        alerts = recent_structured_alerts(self.connect_db, filters={"show_noise": True})

        self.assertEqual(1, len(alerts))
        self.assertEqual("4", alerts[0]["priority"])
        self.assertEqual("Steam", alerts[0]["application"])
        self.assertEqual("Gaming", alerts[0]["classification"])
        self.assertTrue(is_default_suppressed_signature(alerts[0]["signature"]))
        self.assertEqual([], recent_structured_alerts(self.connect_db))

    def test_policy_categories_do_not_force_critical_without_malicious_signature(self):
        self.write_events(alert_event(
            signature="ET USER_AGENTS Generic Browser User-Agent",
            severity=2,
            signature_id=2016779,
        ))
        ingest_eve_incremental(self.connect_db, self.eve_path)

        alerts = recent_structured_alerts(self.connect_db, filters={"show_noise": True})

        self.assertEqual("4", alerts[0]["priority"])
        self.assertEqual("User-Agent observation", alerts[0]["classification"])

    def test_info_tld_observations_are_low_and_keep_full_hostname(self):
        self.write_events(
            alert_event(signature="ET INFO Observed DNS Query to .biz TLD", severity=2, signature_id=2027757, dns_query="updates.example.biz"),
            alert_event(signature="ET INFO Observed DNS Query for Suspicious TLD (.management)", severity=2, signature_id=2047288, dns_query="portal.example.management"),
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)

        alerts = recent_structured_alerts(self.connect_db, filters={"show_noise": True, "sort": "oldest"})

        self.assertEqual(["3", "3"], [alert["priority"] for alert in alerts])
        self.assertEqual(["updates.example.biz", "portal.example.management"], [alert["destination"] for alert in alerts])
        self.assertEqual([], recent_structured_alerts(self.connect_db))

    def test_malware_and_exploit_signatures_remain_actionable(self):
        self.write_events(
            alert_event(signature="ET MALWARE Command and Control Checkin", severity=1, signature_id=2400001),
            alert_event(signature="ET EXPLOIT Known Exploit Attempt", severity=2, signature_id=2400002),
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)

        alerts = recent_structured_alerts(self.connect_db, filters={"sort": "severity_high"})

        self.assertEqual(["ET MALWARE Command and Control Checkin", "ET EXPLOIT Known Exploit Attempt"], [alert["signature"] for alert in alerts])
        self.assertEqual(["1", "2"], [alert["priority"] for alert in alerts])

    def test_duplicate_alerts_aggregate_within_configured_window(self):
        self.write_events(
            alert_event(ts="2026-07-12T10:00:01.000000+0200", flow_id=1, signature="ET MALWARE Repeat", signature_id=2400100),
            alert_event(ts="2026-07-12T10:04:59.000000+0200", flow_id=2, signature="ET MALWARE Repeat", signature_id=2400100),
        )
        ingest_eve_incremental(self.connect_db, self.eve_path)

        con = self.connect_db()
        rows = con.execute("SELECT signature, first_seen, last_seen, alert_count FROM ids_events").fetchall()
        con.close()

        self.assertEqual(1, len(rows))
        self.assertEqual("ET MALWARE Repeat", rows[0][0])
        self.assertEqual("2026-07-12T10:00:01.000000+0200", rows[0][1])
        self.assertEqual("2026-07-12T10:04:59.000000+0200", rows[0][2])
        self.assertEqual(2, rows[0][3])


if __name__ == "__main__":
    unittest.main()
