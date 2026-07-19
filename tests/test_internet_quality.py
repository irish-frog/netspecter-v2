import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import netspecter_internet_quality as iq


class InternetQualityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "quality.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connect_db(self):
        con = sqlite3.connect(self.db_path)
        con.execute("PRAGMA busy_timeout=30000")
        return con

    def test_jitter_is_mean_absolute_consecutive_delta(self):
        self.assertEqual(8.33, iq.calculate_jitter([10, 20, 15, 25]))

    def test_diagnoses_gateway_failure(self):
        status, reason = iq.diagnose(
            {"ok": False, "avg_ms": None, "loss_pct": 100},
            [{"ok": False, "avg_ms": None, "loss_pct": 100}],
            {"ok": False},
        )
        self.assertEqual("down", status)
        self.assertIn("Gateway unavailable", reason)

    def test_diagnoses_isp_failure(self):
        status, reason = iq.diagnose(
            {"ok": True, "avg_ms": 2, "loss_pct": 0},
            [{"ok": False, "loss_pct": 100}, {"ok": False, "loss_pct": 100}],
            {"ok": False},
        )
        self.assertEqual("down", status)
        self.assertIn("ISP/WAN", reason)

    def test_diagnoses_dns_failure_when_internet_is_up(self):
        status, reason = iq.diagnose(
            {"ok": True, "avg_ms": 2, "loss_pct": 0},
            [{"ok": True, "avg_ms": 20, "loss_pct": 0}, {"ok": True, "avg_ms": 22, "loss_pct": 0}],
            {"ok": False},
        )
        self.assertEqual("warn", status)
        self.assertIn("DNS/AdGuard", reason)

    def test_high_jitter_warns(self):
        with patch.object(iq, "ping_target") as ping, patch.object(iq, "dns_query_ms") as dns:
            ping.side_effect = [
                {"ok": True, "avg_ms": 1.0, "loss_pct": 0.0, "latencies": [1, 2, 1]},
                {"ok": True, "avg_ms": 40.0, "loss_pct": 0.0, "latencies": [10, 120, 12]},
                {"ok": True, "avg_ms": 42.0, "loss_pct": 0.0, "latencies": [15, 130, 14]},
            ]
            dns.return_value = {"ok": True, "ms": 12.0, "error": ""}
            summary = iq.collect_quality_summary({
                "gateway_ip": "192.168.1.1",
                "internet_quality_targets": ["1.1.1.1", "8.8.8.8"],
                "internet_quality_external_dns_enabled": False,
            })
        self.assertEqual("warn", summary["status"])
        self.assertIn("ISP-quality", summary["diagnosis"])

    def test_diagnoses_single_target_failure(self):
        status, reason = iq.diagnose(
            {"ok": True, "avg_ms": 2, "loss_pct": 0},
            [{"ok": True, "avg_ms": 20, "loss_pct": 0}, {"ok": False, "loss_pct": 100}],
            {"ok": True},
        )
        self.assertEqual("warn", status)
        self.assertIn("One target fails", reason)

    def test_ping_missing_is_nonfatal(self):
        with patch("shutil.which", return_value=None):
            result = iq.ping_target("1.1.1.1")
        self.assertFalse(result["ok"])
        self.assertEqual("ping missing", result["error"])

    def test_collect_stores_one_summary_row_only(self):
        with patch.object(iq, "ping_target") as ping, patch.object(iq, "dns_query_ms") as dns:
            ping.side_effect = [
                {"ok": True, "avg_ms": 1.0, "loss_pct": 0.0, "latencies": [1, 2, 1]},
                {"ok": True, "avg_ms": 20.0, "loss_pct": 0.0, "latencies": [20, 22, 21]},
                {"ok": True, "avg_ms": 25.0, "loss_pct": 0.0, "latencies": [25, 24, 26]},
            ]
            dns.return_value = {"ok": True, "ms": 12.0, "error": ""}
            iq.collect_and_store_quality(
                self.connect_db,
                {
                    "gateway_ip": "192.168.1.1",
                    "internet_quality_targets": ["1.1.1.1", "8.8.8.8"],
                    "internet_quality_external_dns_enabled": False,
                },
            )
        con = self.connect_db()
        count = con.execute("SELECT COUNT(*) FROM internet_quality").fetchone()[0]
        row = con.execute("SELECT status, targets_ok, targets_total FROM internet_quality").fetchone()
        con.close()
        self.assertEqual(1, count)
        self.assertEqual(("ok", 2, 2), row)

    def test_cleanup_hard_row_limit_and_indexes(self):
        con = self.connect_db()
        iq.ensure_quality_schema(con)
        for index in range(5):
            con.execute(
                "INSERT INTO internet_quality (ts, status) VALUES (?, 'ok')",
                (f"2026-07-12 00:00:0{index}",),
            )
        con.commit()
        con.close()
        iq.prune_quality_history(self.connect_db, {"internet_quality_max_rows": 2, "internet_quality_min_free_mb": 0})
        con = self.connect_db()
        count = con.execute("SELECT COUNT(*) FROM internet_quality").fetchone()[0]
        indexes = {row[1] for row in con.execute("PRAGMA index_list(internet_quality)").fetchall()}
        con.close()
        self.assertEqual(2, count)
        self.assertIn("idx_internet_quality_ts", indexes)
        self.assertIn("idx_internet_quality_status", indexes)

    def test_empty_database_queries_are_safe(self):
        self.assertIsNone(iq.latest_quality(self.connect_db))
        self.assertEqual([], iq.recent_quality(self.connect_db))


if __name__ == "__main__":
    unittest.main()
