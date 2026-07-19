import contextlib
import importlib.util
import io
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]


class IdsNotificationDecisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.original_env = {
            key: os.environ.get(key)
            for key in ("NETSPECTER_CONFIG_ROOT", "NETSPECTER_DATA_ROOT")
        }
        os.environ["NETSPECTER_CONFIG_ROOT"] = str(root / "config")
        os.environ["NETSPECTER_DATA_ROOT"] = str(root / "data")
        spec = importlib.util.spec_from_file_location("collector_notify_test", SOURCE_DIR / "live_packet_collector.py")
        self.collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.collector)
        self.collector.init_db()
        self.send_attempts = []
        self.collector.send_ids_email = lambda _config, alert: self.send_attempts.append(alert["signature"]) or True

    def tearDown(self):
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tmp.cleanup()

    def insert_alert(self, event_id, ts=None):
        ts = ts or datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        con = self.collector.connect_db()
        con.execute(
            """
            INSERT INTO ids_events
                (event_key, event_type, ts, day, src_ip, src_port, dest_ip, dest_port, protocol,
                 app_proto, flow_id, signature_id, signature, category, severity)
            VALUES (?, 'alert', ?, ?, '192.168.1.50', 4444, '8.8.8.8', 443, 'TCP',
                    'tls', ?, 999001, 'NETSPECTER TEST P1 IDS ALERT',
                    'A Network Trojan was Detected', 1)
            """,
            (f"event-{event_id}", ts, ts[:10], f"flow-{event_id}"),
        )
        con.commit()
        con.close()

    def process_and_logs(self, config):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.collector.process_ids_email_alerts(config)
        return output.getvalue()

    def incident_state(self):
        con = self.collector.connect_db()
        con.row_factory = sqlite3.Row
        incidents = [dict(row) for row in con.execute(
            "SELECT id, incident_key, status, severity, device_ip, title FROM security_incidents ORDER BY id"
        )]
        notifications = [dict(row) for row in con.execute(
            "SELECT alert_key, last_sent_ts FROM ids_alert_notifications WHERE alert_key <> '__last_structured_id' ORDER BY alert_key"
        )]
        con.close()
        return incidents, notifications

    def update_status(self, status):
        con = self.collector.connect_db()
        con.execute("UPDATE security_incidents SET status=? WHERE id=1", (status,))
        con.commit()
        con.close()

    def test_identical_p1_alerts_are_central_deduped_and_status_gated(self):
        config = {"ids_email_enabled": True, "ids_email_cooldown_minutes": 1440, "ids_banned_ips": []}
        logs = ""
        for event_id in (1, 2, 3):
            self.insert_alert(event_id)
            logs += self.process_and_logs(config)

        self.assertEqual(1, len(self.send_attempts))
        self.assertEqual(1, logs.count("IDS_NOTIFY decision=sent"))
        self.assertEqual(2, logs.count("IDS_NOTIFY decision=suppressed reason=cooldown"))
        self.assertIn("key=ids|netspecter test p1 ids alert|192.168.1.50 incident=1", logs)

        incidents, notifications = self.incident_state()
        self.assertEqual(1, len(incidents))
        self.assertEqual("ids|netspecter test p1 ids alert|192.168.1.50", incidents[0]["incident_key"])
        self.assertEqual(1, len(notifications))

        self.insert_alert(4)
        restart_logs = self.process_and_logs(config)
        self.assertIn("IDS_NOTIFY decision=suppressed reason=cooldown key=ids|netspecter test p1 ids alert|192.168.1.50 incident=1", restart_logs)

        self.update_status("under_investigation")
        self.insert_alert(5)
        under_investigation_logs = self.process_and_logs(config)
        self.assertIn("IDS_NOTIFY decision=suppressed reason=under_investigation key=ids|netspecter test p1 ids alert|192.168.1.50 incident=1", under_investigation_logs)

        self.update_status("closed")
        self.insert_alert(6)
        closed_logs = self.process_and_logs(config)
        self.assertIn("IDS_NOTIFY decision=suppressed reason=closed key=ids|netspecter test p1 ids alert|192.168.1.50 incident=1", closed_logs)

        self.update_status("new")
        self.insert_alert(7)
        banned_logs = self.process_and_logs({**config, "ids_banned_ips": ["192.168.1.50"]})
        self.assertIn("IDS_NOTIFY decision=suppressed reason=banned key=ids|netspecter test p1 ids alert|192.168.1.50 incident=1", banned_logs)
        self.assertEqual(1, len(self.send_attempts))


if __name__ == "__main__":
    unittest.main()
