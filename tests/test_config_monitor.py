import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import netspecter_config_monitor as cm


class ConfigMonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "config.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connect_db(self):
        return sqlite3.connect(self.db_path)

    def store_snapshot_pair(self, first, second):
        with patch.object(cm, "collect_snapshot", side_effect=[first, second]):
            one = cm.monitor_once(self.connect_db, {})
            two = cm.monitor_once(self.connect_db, {})
        return one, two

    def event_rows(self):
        con = self.connect_db()
        rows = con.execute("SELECT component, field, severity, previous_value, new_value FROM config_change_events ORDER BY id").fetchall()
        con.close()
        return rows

    def test_no_change_stores_no_repeated_snapshot_or_events(self):
        snapshot = {"bridge": {"members": ["eth0", "eth1"]}}
        with patch.object(cm, "collect_snapshot", return_value=snapshot):
            first = cm.monitor_once(self.connect_db, {})
            second = cm.monitor_once(self.connect_db, {})
        con = self.connect_db()
        snapshots = con.execute("SELECT COUNT(*) FROM config_snapshots").fetchone()[0]
        events = con.execute("SELECT COUNT(*) FROM config_change_events").fetchone()[0]
        con.close()
        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])
        self.assertEqual(1, snapshots)
        self.assertEqual(0, events)

    def test_bridge_member_change_detected(self):
        self.store_snapshot_pair({"bridge": {"members": ["eth0", "eth1"]}}, {"bridge": {"members": ["eth0"]}})
        rows = self.event_rows()
        self.assertTrue(any("bridge.members" in row[1] for row in rows))

    def test_nic_speed_change_detected(self):
        self.store_snapshot_pair({"nics": {"eth0": {"speed": "1000"}}}, {"nics": {"eth0": {"speed": "100"}}})
        rows = self.event_rows()
        self.assertTrue(any(row[1] == "nics.eth0.speed" and row[2] == "warning" for row in rows))

    def test_gateway_change_detected(self):
        self.store_snapshot_pair({"default_gateway": ["default via 192.168.1.1 dev br0"]}, {"default_gateway": ["default via 192.168.1.254 dev br0"]})
        rows = self.event_rows()
        self.assertTrue(any(row[0] == "default_gateway" for row in rows))

    def test_route_reorder_is_not_a_change(self):
        one = cm.fingerprint({"routes": cm.normalize_routes("10.0.0.0/24 dev br0\n192.168.1.0/24 dev br0")})
        two = cm.fingerprint({"routes": cm.normalize_routes("192.168.1.0/24 dev br0\n10.0.0.0/24 dev br0")})
        self.assertEqual(one, two)

    def test_nft_counter_only_change_is_not_a_change(self):
        a = '{"nftables":[{"rule":{"expr":[{"counter":{"packets":1,"bytes":10}},{"accept":null}],"handle":4}}]}'
        b = '{"nftables":[{"rule":{"expr":[{"counter":{"packets":99,"bytes":9999}},{"accept":null}],"handle":5}}]}'
        self.assertEqual(cm.normalize_nftables(a), cm.normalize_nftables(b))

    def test_nft_json_fallback_handle_change_is_not_a_change(self):
        a = '[{"nftables":[{"table":{"family":"bridge","name":"netspecter","handle":7241}},{"chain":{"family":"bridge","table":"netspecter","name":"ids_input","handle":1}}]}'
        b = '[{"nftables":[{"table":{"family":"bridge","name":"netspecter","handle":7256}},{"chain":{"family":"bridge","table":"netspecter","name":"ids_input","handle":1}}]}'
        self.assertEqual(cm.normalize_nftables(a), cm.normalize_nftables(b))

    def test_nft_wrapper_shape_change_is_not_a_change(self):
        a = '{"nftables":[{"metainfo":{"version":"1.1.3"}},{"table":{"family":"bridge","name":"netspecter","handle":7241}}]}'
        b = '[{"nftables":[{"metainfo":{"version":"1.1.3"}},{"table":{"family":"bridge","name":"netspecter","handle":7256}}]}]'
        self.assertEqual(cm.normalize_nftables(a), cm.normalize_nftables(b))

    def test_netspecter_runtime_nft_table_is_ignored(self):
        a = '{"nftables":[{"table":{"family":"bridge","name":"netspecter"}},{"chain":{"family":"bridge","table":"netspecter","name":"traffic"}},{"rule":{"family":"bridge","table":"netspecter","chain":"traffic","expr":[{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.168.99.10"}},{"counter":{"packets":1,"bytes":10}}],"comment":"netspecter:tx:192.168.99.10"}}]}'
        b = '{"nftables":[{"table":{"family":"bridge","name":"netspecter"}},{"chain":{"family":"bridge","table":"netspecter","name":"traffic"}},{"rule":{"family":"bridge","table":"netspecter","chain":"traffic","expr":[{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.168.99.55"}},{"counter":{"packets":99,"bytes":999}}],"comment":"netspecter:tx:192.168.99.55"}}]}'
        self.assertEqual([], cm.normalize_nftables(a))
        self.assertEqual(cm.normalize_nftables(a), cm.normalize_nftables(b))

    def test_malformed_json_nft_output_is_not_stored_as_config(self):
        output = '"{\\"nftables\\": [{\\"table\\": {\\"family\\": \\"bridge\\", \\"name\\": \\"netspecter\\"}}, {\\"chain\\": '
        self.assertEqual([], cm.normalize_nftables(output))

    def test_nft_metainfo_only_is_ignored(self):
        output = '{"nftables":[{"metainfo":{"version":"1.1.3","release_name":"Commodore Bullmoose #4","json_schema_version":1}}]}'
        self.assertEqual([], cm.normalize_nftables(output))

    def test_collect_snapshot_uses_large_nft_stdout_limit(self):
        with patch.object(cm, "run_command", return_value={"stdout": "", "stderr": "", "ok": True, "returncode": 0}) as run:
            cm.collect_snapshot({"packet_iface": "br0"})
        nft_calls = [call for call in run.call_args_list if call.args[0] == ["nft", "-j", "list", "ruleset"]]
        self.assertEqual(1, len(nft_calls))
        self.assertGreaterEqual(nft_calls[0].kwargs["stdout_limit"], 250000)

    def test_real_firewall_rule_change_detected(self):
        a = '{"nftables":[{"rule":{"expr":[{"accept":null}]}}]}'
        b = '{"nftables":[{"rule":{"expr":[{"drop":null}]}}]}'
        self.assertNotEqual(cm.normalize_nftables(a), cm.normalize_nftables(b))

    def test_adguard_disabled_detected(self):
        self.store_snapshot_pair({"adguard": {"status": {"protection_enabled": True}}}, {"adguard": {"status": {"protection_enabled": False}}})
        rows = self.event_rows()
        self.assertTrue(any(row[2] == "critical" and "protection_enabled" in row[1] for row in rows))

    def test_suricata_stopped_detected(self):
        self.store_snapshot_pair({"suricata": {"service": {"active": "active"}}}, {"suricata": {"service": {"active": "inactive"}}})
        rows = self.event_rows()
        self.assertTrue(any(row[2] == "critical" and "suricata.service.active" in row[1] for row in rows))

    def test_secret_redaction(self):
        snapshot = cm.redact({"adguard_pass": "secret", "nested": {"api_token": "abc"}, "safe": "value"})
        self.assertEqual(cm.SECRET_MARKER, snapshot["adguard_pass"])
        self.assertEqual(cm.SECRET_MARKER, snapshot["nested"]["api_token"])
        self.assertEqual("value", snapshot["safe"])

    def test_retention_cleanup_hard_limit(self):
        con = self.connect_db()
        cm.ensure_schema(con)
        for i in range(5):
            con.execute(
                "INSERT INTO config_change_events (ts, component, field, severity) VALUES (?, 'bridge', 'bridge.members', 'warning')",
                (f"2026-07-12 00:00:0{i}",),
            )
        con.commit()
        con.close()
        cm.prune_config_changes(self.connect_db, {"config_change_max_events": 2, "config_change_min_free_mb": 0})
        con = self.connect_db()
        count = con.execute("SELECT COUNT(*) FROM config_change_events").fetchone()[0]
        con.close()
        self.assertEqual(2, count)


if __name__ == "__main__":
    unittest.main()
