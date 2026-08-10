import sqlite3
import unittest
from datetime import datetime
from unittest.mock import patch

from services import device_presence_service as presence


def make_db():
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute(
        """
        CREATE TABLE devices (
            ip TEXT PRIMARY KEY,
            name TEXT,
            last_seen TEXT,
            last_presence_seen TEXT,
            last_presence_source TEXT,
            last_presence_check TEXT
        )
        """
    )
    return con


def add_device(con, ip, seen=None, source=None, check=None):
    con.execute(
        """
        INSERT INTO devices (ip, name, last_presence_seen, last_presence_source, last_presence_check)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ip, ip, seen, source, check),
    )


def states(con, now, max_checks=0):
    rows = con.execute("SELECT * FROM devices ORDER BY ip").fetchall()
    return presence.resolve_presence_states(con, rows, now=now, max_checks=max_checks)


class DevicePresenceTests(unittest.TestCase):
    def test_recent_traffic_is_online(self):
        con = make_db()
        now = datetime(2026, 8, 10, 12, 0, 0)
        add_device(con, "192.168.1.10", "2026-08-10 11:59:00", "traffic")

        result = states(con, now)

        self.assertEqual(presence.ONLINE, result["192.168.1.10"].state)
        self.assertEqual("traffic", result["192.168.1.10"].evidence)

    def test_recent_neighbour_observation_is_online(self):
        con = make_db()
        now = datetime(2026, 8, 10, 12, 0, 0)
        add_device(con, "192.168.1.11")

        with patch.object(presence, "read_neighbour_ips", return_value={"192.168.1.11"}):
            result = states(con, now)

        self.assertEqual(presence.ONLINE, result["192.168.1.11"].state)
        self.assertEqual("neighbour", result["192.168.1.11"].evidence)

    def test_recent_discovery_observation_is_online(self):
        con = make_db()
        now = datetime(2026, 8, 10, 12, 0, 0)
        add_device(con, "192.168.1.12", "2026-08-10 11:58:00", "mdns")

        result = states(con, now)

        self.assertEqual(presence.ONLINE, result["192.168.1.12"].state)
        self.assertEqual("mdns", result["192.168.1.12"].evidence)

    def test_quiet_but_reachable_device_is_online(self):
        con = make_db()
        now = datetime(2026, 8, 10, 12, 0, 0)
        add_device(con, "192.168.1.13")

        with patch.object(presence, "read_neighbour_ips", return_value=set()):
            with patch.object(presence, "ping_once", side_effect=lambda ip: ip == "192.168.1.13"):
                result = states(con, now, max_checks=1)

        self.assertEqual(presence.ONLINE, result["192.168.1.13"].state)
        self.assertEqual("reachability", result["192.168.1.13"].evidence)

    def test_no_presence_evidence_beyond_timeout_is_offline(self):
        con = make_db()
        now = datetime(2026, 8, 10, 12, 0, 0)
        add_device(con, "192.168.1.14", "2026-08-10 11:00:00", "traffic")

        with patch.object(presence, "read_neighbour_ips", return_value=set()):
            result = states(con, now, max_checks=0)

        self.assertEqual(presence.OFFLINE, result["192.168.1.14"].state)

    def test_device_with_no_reliable_evidence_is_unknown(self):
        con = make_db()
        now = datetime(2026, 8, 10, 12, 0, 0)
        add_device(con, "192.168.1.15")

        with patch.object(presence, "read_neighbour_ips", return_value=set()):
            result = states(con, now, max_checks=0)

        self.assertEqual(presence.UNKNOWN, result["192.168.1.15"].state)

    def test_online_counts_match_individual_device_states(self):
        con = make_db()
        now = datetime(2026, 8, 10, 12, 0, 0)
        add_device(con, "192.168.1.20", "2026-08-10 11:59:00", "traffic")
        add_device(con, "192.168.1.21", "2026-08-10 10:00:00", "traffic")
        add_device(con, "192.168.1.22")

        with patch.object(presence, "read_neighbour_ips", return_value=set()):
            result = states(con, now, max_checks=0)

        self.assertEqual({"online": 1, "offline": 1, "unknown": 1}, presence.count_states(result))


if __name__ == "__main__":
    unittest.main()
