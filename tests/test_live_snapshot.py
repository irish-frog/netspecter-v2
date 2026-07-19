import tempfile
import threading
import unittest
from pathlib import Path

import netspecter_live_snapshot as live_snapshot


class LiveSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original_path = live_snapshot.LIVE_SNAPSHOT_PATH
        live_snapshot.LIVE_SNAPSHOT_PATH = Path(self.tmp.name) / "live_snapshot.json"
        live_snapshot.clear()

    def tearDown(self):
        live_snapshot.clear()
        live_snapshot.LIVE_SNAPSHOT_PATH = self.original_path
        self.tmp.cleanup()

    def test_update_and_read_speed_snapshot(self):
        live_snapshot.update_live_speeds([
            {"ip": "192.0.2.10", "rx_bps": 100, "tx_bps": 50, "total_bps": 150, "name": "Laptop"}
        ], "2026-07-16 12:00:00")

        speeds = live_snapshot.speeds()
        self.assertEqual("Laptop", speeds["192.0.2.10"]["name"])
        self.assertEqual(150, speeds["192.0.2.10"]["total_bps"])
        self.assertTrue(live_snapshot.LIVE_SNAPSHOT_PATH.exists())

    def test_file_snapshot_is_used_after_memory_clear(self):
        live_snapshot.update_summary({"devices": {"known": 3, "online": 2}}, "2026-07-16 12:00:00")
        with live_snapshot._LOCK:
            live_snapshot._SNAPSHOT["updated_at"] = ""
            live_snapshot._SNAPSHOT["summary"] = {}

        summary = live_snapshot.summary()

        self.assertEqual(3, summary["devices"]["known"])
        self.assertIsNotNone(summary["snapshot_age_seconds"])

    def test_concurrent_read_write_is_safe(self):
        errors = []

        def writer():
            for index in range(50):
                live_snapshot.update_live_speeds([
                    {"ip": "192.0.2.10", "rx_bps": index, "tx_bps": index, "total_bps": index * 2}
                ])

        def reader():
            try:
                for _ in range(100):
                    live_snapshot.speeds()
                    live_snapshot.summary()
            except Exception as error:
                errors.append(error)

        threads = [threading.Thread(target=writer)] + [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual([], errors)


if __name__ == "__main__":
    unittest.main()
