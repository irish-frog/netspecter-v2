import sqlite3
import unittest

from live_packet_collector import (
    apply_device_identity,
    classify_device,
    identity_key_for_mac,
    update_logged_in_user,
    windows_user_probe_eligible,
)


SCHEMA = """
CREATE TABLE device_identities (
    identity_key TEXT PRIMARY KEY,
    mac TEXT,
    hostname TEXT,
    display_name TEXT,
    current_ip TEXT,
    last_ip TEXT,
    vendor TEXT,
    device_type TEXT DEFAULT 'Unknown',
    source TEXT,
    confidence INTEGER DEFAULT 0,
    private_mac INTEGER DEFAULT 0,
    logged_in_user TEXT,
    logged_in_user_source TEXT,
    logged_in_user_updated_at TEXT,
    user_probe_failed_at TEXT,
    user_probe_failure_count INTEGER DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    updated_at TEXT
);
CREATE TABLE device_ip_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_key TEXT NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    source TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(identity_key, ip)
);
"""


class DeviceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.con = sqlite3.connect(":memory:")
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)
        self.config = {
            "device_identity_tracking_enabled": True,
            "device_identity_carry_names": True,
            "device_identity_exclude_private_macs": True,
            "windows_user_discovery_enabled": False,
            "windows_user_discovery_interval_seconds": 1800,
        }

    def tearDown(self):
        self.con.close()

    def identity(self, key):
        return self.con.execute("SELECT * FROM device_identities WHERE identity_key=?", (key,)).fetchone()

    def test_apply_device_identity_selects_last_ip_and_carries_name(self):
        mac = "04:BF:1B:89:83:8A"
        key = identity_key_for_mac(mac)
        first = apply_device_identity(
            self.con,
            "192.168.1.105",
            "DESKTOP-5S814F2",
            mac,
            "Dell Inc.",
            "Computer",
            "2026-08-04 16:00:00",
            "netbios",
            self.config,
        )
        second = apply_device_identity(
            self.con,
            "192.168.1.176",
            "",
            mac,
            "Dell Inc.",
            "Computer",
            "2026-08-04 16:30:00",
            "traffic",
            self.config,
        )

        row = self.identity(key)
        self.assertEqual("DESKTOP-5S814F2", first)
        self.assertEqual("DESKTOP-5S814F2", second)
        self.assertEqual("192.168.1.176", row["current_ip"])
        self.assertEqual("192.168.1.105", row["last_ip"])
        self.assertEqual("DESKTOP-5S814F2", row["display_name"])

    def test_private_mac_identity_is_not_persistent_across_ips(self):
        mac = "02:11:22:33:44:55"
        apply_device_identity(self.con, "192.168.1.10", "Phone", mac, "", "Mobile Device", source="traffic", config=self.config)
        apply_device_identity(self.con, "192.168.1.20", "", mac, "", "Mobile Device", source="traffic", config=self.config)

        rows = self.con.execute("SELECT identity_key, current_ip FROM device_identities ORDER BY current_ip").fetchall()
        self.assertEqual(["private-mac:02:11:22:33:44:55:192.168.1.10", "private-mac:02:11:22:33:44:55:192.168.1.20"], [r["identity_key"] for r in rows])

    def test_device_type_classification_excludes_non_windows_from_user_probe(self):
        enabled = dict(self.config, windows_user_discovery_enabled=True)

        self.assertEqual("VoIP Phone", classify_device("Yealink Network Technology"))
        self.assertEqual("Printer", classify_device("RICOH COMPANY, LTD."))
        self.assertEqual("Camera", classify_device("Hikvision Digital Technology"))
        self.assertFalse(windows_user_probe_eligible("Yealink", "VoIP Phone", "Phone", "00:15:65:00:00:01", True, enabled))
        self.assertFalse(windows_user_probe_eligible("RICOH", "Printer", "RICOH Printer", "58:38:79:BE:67:20", True, enabled))
        self.assertTrue(windows_user_probe_eligible("Dell Inc.", "Computer", "DESKTOP-5S814F2", "04:BF:1B:89:83:8A", True, enabled))

    def test_logged_in_user_is_stored_separately_and_unchanged_user_is_not_rewritten(self):
        mac = "04:BF:1B:89:83:8A"
        key = identity_key_for_mac(mac)
        apply_device_identity(
            self.con,
            "192.168.1.105",
            "DESKTOP-5S814F2",
            mac,
            "Dell Inc.",
            "Computer",
            "2026-08-04 16:00:00",
            "netbios",
            self.config,
        )

        self.assertTrue(update_logged_in_user(self.con, key, "gavinr", "windows", "2026-08-04 16:05:00"))
        self.assertFalse(update_logged_in_user(self.con, key, "gavinr", "windows", "2026-08-04 16:06:00"))
        row = self.identity(key)
        self.assertEqual("DESKTOP-5S814F2", row["display_name"])
        self.assertEqual("gavinr", row["logged_in_user"])
        self.assertEqual("2026-08-04 16:05:00", row["logged_in_user_updated_at"])


if __name__ == "__main__":
    unittest.main()
