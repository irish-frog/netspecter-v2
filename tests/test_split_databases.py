import sqlite3
import tempfile
import unittest
from pathlib import Path

import netspecter_db
import netspecter_internet_quality


class SplitDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.originals = {
            "DATA_ROOT": netspecter_db.DATA_ROOT,
            "DB_PATH": netspecter_db.DB_PATH,
            "DNS_DB_PATH": netspecter_db.DNS_DB_PATH,
            "TRAFFIC_DB_PATH": netspecter_db.TRAFFIC_DB_PATH,
            "CACHE_PATH": netspecter_db.CACHE_PATH,
            "DB_INIT_DONE": netspecter_db.DB_INIT_DONE,
        }
        netspecter_db.DATA_ROOT = self.root
        netspecter_db.DB_PATH = self.root / "netspecter.db"
        netspecter_db.DNS_DB_PATH = self.root / "netspecter_dns.db"
        netspecter_db.TRAFFIC_DB_PATH = self.root / "netspecter_traffic.db"
        netspecter_db.CACHE_PATH = self.root / "cache.json"
        netspecter_db.DB_INIT_DONE = False

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(netspecter_db, name, value)
        self.tempdir.cleanup()

    def table_names(self, path):
        con = sqlite3.connect(path)
        try:
            return {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            con.close()

    def test_dns_tables_live_in_split_database_after_fresh_init(self):
        netspecter_db.init_db(force=True)

        self.assertNotIn("dns_querylog", self.table_names(netspecter_db.DB_PATH))
        self.assertIn("dns_querylog", self.table_names(netspecter_db.DNS_DB_PATH))

        con = netspecter_db.connect_db()
        try:
            con.execute(
                """
                INSERT INTO dns_querylog(day, ts, client, domain, blocked, category)
                VALUES ('2026-07-17', '2026-07-17 21:00:00', '192.168.99.10', 'example.test', 0, 'Other')
                """
            )
            con.commit()
        finally:
            con.close()

        dns_con = sqlite3.connect(netspecter_db.DNS_DB_PATH)
        try:
            count = dns_con.execute("SELECT COUNT(*) FROM dns_querylog").fetchone()[0]
        finally:
            dns_con.close()

        self.assertEqual(1, count)
        rows = netspecter_db.query("SELECT COUNT(*) AS total FROM dns_querylog")
        self.assertEqual(1, rows[0]["total"])

    def test_traffic_tables_live_in_split_database_after_fresh_init(self):
        netspecter_db.init_db(force=True)

        main_tables = self.table_names(netspecter_db.DB_PATH)
        traffic_tables = self.table_names(netspecter_db.TRAFFIC_DB_PATH)
        self.assertNotIn("traffic_intervals", main_tables)
        self.assertNotIn("internet_quality", main_tables)
        self.assertIn("traffic_intervals", traffic_tables)
        self.assertIn("estimated_app_traffic", traffic_tables)
        self.assertIn("remote_traffic_intervals", traffic_tables)
        self.assertIn("internet_quality", traffic_tables)

        con = netspecter_db.connect_db()
        try:
            con.execute(
                """
                INSERT INTO traffic_intervals(day, ts, ip, downloaded_mb, uploaded_mb, total_mb)
                VALUES ('2026-07-17', '2026-07-17 21:00:00', '192.168.99.10', 5, 2, 7)
                """
            )
            con.execute(
                """
                INSERT INTO internet_quality(ts, status, internet_latency_ms)
                VALUES ('2026-07-17 21:00:00', 'ok', 4.2)
                """
            )
            con.commit()
        finally:
            con.close()

        traffic_con = sqlite3.connect(netspecter_db.TRAFFIC_DB_PATH)
        try:
            count = traffic_con.execute("SELECT COUNT(*) FROM traffic_intervals").fetchone()[0]
            quality_count = traffic_con.execute("SELECT COUNT(*) FROM internet_quality").fetchone()[0]
        finally:
            traffic_con.close()

        self.assertEqual(1, count)
        self.assertEqual(1, quality_count)
        rows = netspecter_db.query("SELECT COALESCE(SUM(total_mb), 0) AS total FROM traffic_intervals")
        self.assertEqual(7, rows[0]["total"])

    def test_quality_schema_helper_uses_split_traffic_database(self):
        netspecter_db.init_db(force=True)

        con = netspecter_db.connect_db()
        try:
            netspecter_internet_quality.ensure_quality_schema(con)
            con.commit()
        finally:
            con.close()

        self.assertNotIn("internet_quality", self.table_names(netspecter_db.DB_PATH))
        self.assertIn("internet_quality", self.table_names(netspecter_db.TRAFFIC_DB_PATH))


if __name__ == "__main__":
    unittest.main()
