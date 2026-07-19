import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import netspecter_threat_intel as ti


class ThreatIntelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "ti.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connect_db(self):
        con = sqlite3.connect(self.db_path)
        con.execute("PRAGMA busy_timeout=30000")
        return con

    def init_schema(self):
        con = self.connect_db()
        ti.ensure_schema(con)
        con.commit()
        con.close()

    def test_valid_spamhaus_feed_parses(self):
        rows = ti.parse_spamhaus_drop('[{"cidr":"203.0.113.0/24","sblid":"SBL1"}]')
        self.assertEqual(("203.0.113.0/24", "cidr", "SBL1"), rows[0])

    def test_spamhaus_json_lines_feed_parses(self):
        rows = ti.parse_spamhaus_drop('{"cidr":"203.0.113.0/24","sblid":"SBL1"}\n{"cidr":"198.51.100.0/24","sblid":"SBL2"}')
        self.assertEqual(("203.0.113.0/24", "cidr", "SBL1"), rows[0])
        self.assertEqual(("198.51.100.0/24", "cidr", "SBL2"), rows[1])

    def test_invalid_feed_fails_without_deleting_previous_good(self):
        self.init_schema()
        good = '[{"cidr":"203.0.113.0/24","sblid":"SBL1"}]'
        with patch.object(ti, "download_text", return_value=good):
            ti.refresh_feeds(self.connect_db, {"threat_intel_sources": ["spamhaus_drop"]})
        with patch.object(ti, "download_text", side_effect=ValueError("bad feed")):
            ti.refresh_feeds(self.connect_db, {"threat_intel_sources": ["spamhaus_drop"]})
        con = self.connect_db()
        active = con.execute("SELECT COUNT(*) FROM threat_indicators WHERE active=1").fetchone()[0]
        status = con.execute("SELECT status FROM threat_feed_state WHERE source='spamhaus_drop'").fetchone()[0]
        con.close()
        self.assertEqual(1, active)
        self.assertEqual("failed", status)

    def test_oversized_feed_rejected(self):
        with patch("netspecter_threat_intel.urlopen") as opener:
            opener.return_value.__enter__.return_value.status = 200
            opener.return_value.__enter__.return_value.read.return_value = b"x" * 5
            with self.assertRaises(ValueError):
                ti.download_text("http://example.test/feed", max_bytes=4)

    def test_update_timeout_retains_previous_feed(self):
        self.init_schema()
        with patch.object(ti, "download_text", return_value='[{"cidr":"203.0.113.0/24"}]'):
            ti.refresh_feeds(self.connect_db, {"threat_intel_sources": ["spamhaus_drop"]})
        with patch.object(ti, "download_text", side_effect=TimeoutError("timeout")):
            ti.refresh_feeds(self.connect_db, {"threat_intel_sources": ["spamhaus_drop"]})
        con = self.connect_db()
        count = con.execute("SELECT COUNT(*) FROM threat_indicators WHERE active=1").fetchone()[0]
        con.close()
        self.assertEqual(1, count)

    def test_duplicate_indicators_deduplicate(self):
        self.init_schema()
        con = self.connect_db()
        count = ti.upsert_indicators(
            con,
            "spamhaus_drop",
            ti.FEED_STATUS["spamhaus_drop"],
            [("203.0.113.0/24", "cidr", "a"), ("203.0.113.0/24", "cidr", "b")],
        )
        con.commit()
        stored = con.execute("SELECT COUNT(*) FROM threat_indicators").fetchone()[0]
        con.close()
        self.assertEqual(1, count)
        self.assertEqual(1, stored)

    def test_cidr_and_domain_match(self):
        indicator_rows = [
            ("203.0.113.0/24", "cidr", "spamhaus_drop", "malicious_network", 95, "DROP", "first", "last"),
            ("bad.example", "domain", "urlhaus", "malware_url", 80, "URLhaus", "first", "last"),
        ]
        self.assertEqual("Malicious", ti.reputation_for("203.0.113.5", "", indicator_rows)["reputation"])
        self.assertEqual("Malicious", ti.reputation_for("", "a.bad.example", indicator_rows)["reputation"])

    def test_unknown_is_not_malicious(self):
        self.assertEqual("Unknown", ti.reputation_for("198.51.100.5", "", [])["reputation"])

    def test_expired_indicators_ignored(self):
        self.init_schema()
        con = self.connect_db()
        ti.upsert_indicators(con, "spamhaus_drop", ti.FEED_STATUS["spamhaus_drop"], [("203.0.113.0/24", "cidr", "DROP")])
        con.execute("UPDATE threat_indicators SET expires_at='2000-01-01 00:00:00'")
        con.commit()
        self.assertEqual([], ti.load_active_indicators(con))
        con.close()

    def test_allowlist_false_positive_by_inactive_indicator(self):
        self.init_schema()
        con = self.connect_db()
        ti.upsert_indicators(con, "spamhaus_drop", ti.FEED_STATUS["spamhaus_drop"], [("203.0.113.0/24", "cidr", "DROP")])
        con.execute("UPDATE threat_indicators SET active=0")
        con.commit()
        self.assertEqual([], ti.load_active_indicators(con))
        con.close()

    def test_correlation_deduplication_and_cleanup(self):
        self.init_schema()
        con = self.connect_db()
        con.execute("CREATE TABLE ids_events (id INTEGER PRIMARY KEY, ts TEXT, src_ip TEXT, dest_ip TEXT, query TEXT, hostname TEXT, signature TEXT)")
        con.execute("CREATE TABLE dns_querylog (id INTEGER PRIMARY KEY, ts TEXT, client TEXT, domain TEXT)")
        con.execute("CREATE TABLE remote_traffic_intervals (remote_ip TEXT, ts TEXT, total_mb REAL)")
        con.execute("CREATE TABLE remote_ip_locations (remote_ip TEXT PRIMARY KEY, country TEXT, country_code TEXT)")
        con.execute("INSERT INTO ids_events VALUES (1, '2000-01-01 01:00:00', '192.168.1.2', '203.0.113.5', '', '', 'test')")
        ti.upsert_indicators(con, "spamhaus_drop", ti.FEED_STATUS["spamhaus_drop"], [("203.0.113.0/24", "cidr", "DROP")])
        con.commit()
        con.close()
        self.assertEqual(1, ti.correlate_once(self.connect_db, {"threat_intel_correlation_days": 10000}))
        self.assertEqual(0, ti.correlate_once(self.connect_db, {}))
        ti.prune_threat_intel(self.connect_db, {"threat_intel_retention_days": 0, "threat_intel_min_free_mb": 0})
        con = self.connect_db()
        count = con.execute("SELECT COUNT(*) FROM threat_correlations").fetchone()[0]
        con.close()
        self.assertEqual(0, count)


if __name__ == "__main__":
    unittest.main()
