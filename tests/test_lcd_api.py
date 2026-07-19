import time
import tempfile
import unittest
from pathlib import Path
from datetime import datetime

import app as netspecter


class FakePsutil:
    @staticmethod
    def boot_time():
        return time.time() - 3600

    @staticmethod
    def cpu_percent(interval=None):
        return 18

    @staticmethod
    def virtual_memory():
        return type("Memory", (), {"percent": 42})()

    @staticmethod
    def disk_usage(_path):
        return type("Disk", (), {"percent": 31, "free": 200 * 1024 * 1024 * 1024})()

    @staticmethod
    def net_if_addrs():
        return {"br0": []}


class LcdApiTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.token = "ns_lcd_test_token"
        self.display = {
            "id": "office",
            "name": "Office LCD",
            "token_hash": netspecter.lcd_token_hash(self.token),
            "token_preview": "ns_lcd...token",
            "revoked_at": "",
        }
        self.config = dict(netspecter.DEFAULT_CONFIG)
        self.config.update({
            "admin_password_hash": "test",
            "appliance_ip": "192.168.99.6",
            "lan_prefix": "192.168.99.",
            "packet_iface": "br0",
            "lcd_displays": [self.display],
        })
        self.originals = {
            "cfg": netspecter.cfg,
            "cached_query": netspecter.cached_query,
            "latest_quality": netspecter.latest_quality,
            "live_network_speed": netspecter.live_network_speed,
            "system_health_snapshot": netspecter.system_health_snapshot,
            "system_health_live_only": netspecter.system_health_live_only,
            "psutil": netspecter.psutil,
            "DB_PATH": netspecter.DB_PATH,
            "run_sql": netspecter.run_sql,
            "LIVE_SNAPSHOT_PATH": netspecter.live_snapshot.LIVE_SNAPSHOT_PATH,
        }
        netspecter.live_snapshot.LIVE_SNAPSHOT_PATH = Path(self.tempdir.name) / "live_snapshot.json"
        netspecter.live_snapshot.clear()
        netspecter.LCD_LAST_SEEN.clear()
        netspecter.LCD_TRAFFIC_HISTORY["download_mbps"] = []
        netspecter.LCD_TRAFFIC_HISTORY["upload_mbps"] = []
        netspecter.cfg = lambda: dict(self.config)
        netspecter.cached_query = self.cached_query
        netspecter.latest_quality = lambda _connect_db: {
            "status": "ok",
            "wan_up": 1,
            "internet_latency_ms": 14,
            "internet_loss_pct": 0,
            "jitter_ms": 2,
            "dns_ms": 12,
        }
        netspecter.live_network_speed = lambda: {"rx_bps": 84_000_000, "tx_bps": 12_000_000, "total_bps": 96_000_000}
        netspecter.live_snapshot.update_quality({
            "ts": "2026-07-16 12:00:00",
            "status": "ok",
            "wan_up": 1,
            "internet_latency_ms": 14,
            "internet_loss_pct": 0,
            "jitter_ms": 2,
            "dns_ms": 12,
        })
        netspecter.live_snapshot.update_heartbeat("OK", "test", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        netspecter.live_snapshot.update_summary({
            "total_traffic_today_gb": 101.8,
            "devices": {"known": 48, "online": 42, "new_or_unknown": 0},
            "active_alerts": 0,
            "top_talker": {"name": "Xiaomi TV Box", "mbps": 28.0},
            "top_application": {"name": "Video Streaming", "mbps": None},
            "last_speed_test": {
                "completed_at": "2026-07-16 12:00:00",
                "download_mbps": 256.17,
                "upload_mbps": 266.37,
                "ping_ms": 4,
                "status": "completed",
            },
        }, "2026-07-16 12:00:00")
        netspecter.system_health_snapshot = lambda *args, **kwargs: {
            "cpu": 18,
            "mem": 42,
            "disk": 31,
            "collector_state": "OK",
            "last_seen": "recent",
        }
        netspecter.psutil = FakePsutil
        netspecter.DB_PATH = type("FakePath", (), {"exists": staticmethod(lambda: True)})()
        netspecter.run_sql = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("LCD endpoint must not write SQL"))
        netspecter.app.config["TESTING"] = True
        self.client = netspecter.app.test_client()

    def tearDown(self):
        netspecter.live_snapshot.clear()
        for name, value in self.originals.items():
            if name == "LIVE_SNAPSHOT_PATH":
                netspecter.live_snapshot.LIVE_SNAPSHOT_PATH = value
            else:
                setattr(netspecter, name, value)
        netspecter.LCD_LAST_SEEN.clear()
        netspecter.LCD_TRAFFIC_HISTORY["download_mbps"] = []
        netspecter.LCD_TRAFFIC_HISTORY["upload_mbps"] = []
        self.tempdir.cleanup()

    def cached_query(self, key, _max_age, _sql, _params=()):
        if key.startswith("lcd_today_traffic"):
            return [{"total": 104.2 * 1024}]
        if key == "lcd_devices":
            return [{"known": 48, "online": 42, "unknowns": 0}]
        if key == "lcd_active_alerts":
            return [{"total": 0}]
        if key == "lcd_top_talker":
            return [{"ip": "192.168.99.51", "name": "Xiaomi TV Box", "total_bps": 3_500_000}]
        if key.startswith("lcd_top_application"):
            return [{"category": "Video Streaming", "mb": 1234}]
        if key == "lcd_last_speed_test":
            return [{
                "ts": "2026-07-16 12:00:00",
                "latency_ms": 4,
                "download_mbps": 256.17,
                "upload_mbps": 266.37,
                "success": 1,
            }]
        return []

    def get_summary(self, token=None, remote_addr="192.168.99.20"):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        return self.client.get("/api/lcd/summary", headers=headers, environ_base={"REMOTE_ADDR": remote_addr})

    def test_unauthenticated_access_is_rejected(self):
        response = self.get_summary()
        self.assertEqual(401, response.status_code)

    def test_invalid_token_is_rejected(self):
        response = self.get_summary("wrong-token")
        self.assertEqual(401, response.status_code)

    def test_valid_token_returns_summary_and_records_last_seen(self):
        response = self.get_summary(self.token)
        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual("online", payload["internet_status"])
        self.assertEqual("secure", payload["status"])
        self.assertEqual("healthy", payload["services"]["dns"])
        self.assertEqual("healthy", payload["services"]["bridge"])
        self.assertEqual(84.0, payload["download_mbps"])
        self.assertEqual(12.0, payload["upload_mbps"])
        self.assertEqual("completed", payload["last_speed_test"]["status"])
        self.assertIn("office", netspecter.LCD_LAST_SEEN)
        self.assertEqual("192.168.99.20", netspecter.LCD_LAST_SEEN["office"]["last_ip"])

    def test_revoked_token_is_rejected(self):
        self.config["lcd_displays"][0]["revoked_at"] = "2026-07-16T12:00:00Z"
        response = self.get_summary(self.token)
        self.assertEqual(401, response.status_code)

    def test_lcd_token_does_not_grant_other_api_access(self):
        response = self.client.get(
            "/api/update-status",
            headers={"Authorization": f"Bearer {self.token}"},
            environ_base={"REMOTE_ADDR": "192.168.99.20"},
        )
        self.assertEqual(401, response.status_code)

    def test_refresh_rate_is_limited_without_database_writes(self):
        first = self.get_summary(self.token)
        second = self.get_summary(self.token)
        self.assertEqual(200, first.status_code)
        self.assertEqual(429, second.status_code)

    def test_missing_snapshot_alert_count_keeps_ids_healthy(self):
        netspecter.live_snapshot.clear()
        netspecter.live_snapshot.update_quality({
            "ts": "2026-07-16 12:00:00",
            "status": "ok",
            "wan_up": 1,
            "internet_latency_ms": 14,
            "internet_loss_pct": 0,
            "jitter_ms": 2,
            "dns_ms": 12,
        })
        netspecter.live_snapshot.update_heartbeat("OK", "test", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        netspecter.live_snapshot.update_summary({
            "total_traffic_today_gb": 101.8,
            "last_speed_test": {"status": "completed"},
        }, "2026-07-16 12:00:00")

        response = self.get_summary(self.token)

        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual(0, payload["active_alerts"])
        self.assertEqual("healthy", payload["services"]["ids"])

    def test_lcd_speed_test_falls_back_to_saved_history(self):
        netspecter.live_snapshot.clear()
        netspecter.live_snapshot.update_quality({
            "ts": "2026-07-16 12:00:00",
            "status": "ok",
            "wan_up": 1,
            "internet_latency_ms": 14,
            "internet_loss_pct": 0,
            "jitter_ms": 2,
            "dns_ms": 12,
        })
        netspecter.live_snapshot.update_heartbeat("OK", "test", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        netspecter.live_snapshot.update_summary({
            "total_traffic_today_gb": 101.8,
            "active_alerts": 0,
        }, "2026-07-16 12:00:00")

        response = self.get_summary(self.token)

        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual("completed", payload["last_speed_test"]["status"])
        self.assertEqual(256.17, payload["last_speed_test"]["download_mbps"])
        self.assertEqual(266.37, payload["last_speed_test"]["upload_mbps"])
        self.assertEqual(4.0, payload["last_speed_test"]["ping_ms"])

    def test_lcd_current_speed_falls_back_to_snapshot_summary(self):
        netspecter.live_network_speed = lambda: {"rx_bps": 0, "tx_bps": 0, "total_bps": 0}
        netspecter.live_snapshot.update_summary({
            "download_mbps": 37.42,
            "upload_mbps": 9.81,
        }, "2026-07-16 12:00:00")

        response = self.get_summary(self.token)

        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual(37.42, payload["download_mbps"])
        self.assertEqual(9.81, payload["upload_mbps"])

    def test_lcd_stale_collector_is_watch_not_alert(self):
        netspecter.system_health_live_only = lambda *args, **kwargs: {
            "cpu": 18,
            "mem": 42,
            "disk": 31,
            "collector_state": "Stale",
            "last_seen": "older",
        }

        response = self.get_summary(self.token)

        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual("warning", payload["services"]["collector"])
        self.assertEqual("watch", payload["status"])

    def test_lcd_current_values_prefer_memory_snapshot(self):
        netspecter.live_network_speed = self.originals["live_network_speed"]
        netspecter.live_snapshot.clear()
        netspecter.live_snapshot.update_quality({
            "ts": "2026-07-16 12:00:00",
            "status": "ok",
            "wan_up": 1,
            "internet_latency_ms": 14,
            "internet_loss_pct": 0,
            "jitter_ms": 2,
            "dns_ms": 12,
        })
        netspecter.live_snapshot.update_heartbeat("OK", "test", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        netspecter.live_snapshot.update_summary({
            "total_traffic_today_gb": 101.8,
            "active_alerts": 0,
            "last_speed_test": {
                "completed_at": "2026-07-16 12:00:00",
                "download_mbps": 256.17,
                "upload_mbps": 266.37,
                "ping_ms": 4,
                "status": "completed",
            },
        }, "2026-07-16 12:00:00")
        netspecter.live_snapshot.update_live_speeds([
            {
                "ip": "192.168.99.51",
                "name": "Desk PC",
                "rx_bps": 10_000_000,
                "tx_bps": 2_000_000,
                "total_bps": 12_000_000,
                "updated_at": "2026-07-16 12:00:00",
            },
            {
                "ip": "192.168.99.52",
                "name": "Camera",
                "rx_bps": 0,
                "tx_bps": 0,
                "total_bps": 0,
                "updated_at": "2026-07-16 12:00:00",
            },
        ])

        response = self.get_summary(self.token)

        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual(80.0, payload["download_mbps"])
        self.assertEqual(16.0, payload["upload_mbps"])
        self.assertEqual(2, payload["devices"]["known"])
        self.assertEqual(1, payload["devices"]["online"])
        self.assertEqual("Desk PC", payload["top_talker"]["name"])


if __name__ == "__main__":
    unittest.main()
