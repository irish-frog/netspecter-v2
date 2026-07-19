import importlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


class VaultScheduleTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.original_env = {
            key: os.environ.get(key)
            for key in (
                "NETSPECTER_CONFIG_ROOT",
                "NETSPECTER_DATA_ROOT",
                "NETSPECTER_VAULT_BACKUP_DIR",
                "NETSPECTER_VAULT_STAGING_DIR",
                "NETSPECTER_VAULT_ROOT",
            )
        }
        os.environ["NETSPECTER_CONFIG_ROOT"] = str(self.root / "config")
        os.environ["NETSPECTER_DATA_ROOT"] = str(self.root / "data")
        os.environ["NETSPECTER_VAULT_BACKUP_DIR"] = str(self.root / "backups")
        os.environ["NETSPECTER_VAULT_STAGING_DIR"] = str(self.root / "staging")
        os.environ["NETSPECTER_VAULT_ROOT"] = str(self.root / "vault")

        import netspecter_vault.config as config
        import netspecter_vault.history as history
        import netspecter_vault.retention as retention
        import netspecter_vault.scheduler as scheduler
        self.config = importlib.reload(config)
        self.history = importlib.reload(history)
        self.retention = importlib.reload(retention)
        self.scheduler = importlib.reload(scheduler)

    def tearDown(self):
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_config_normalises_schedule_values(self):
        saved = self.config.save_vault_config({
            "schedule_enabled": True,
            "schedule_time": "7:5",
            "retention_daily": "0",
            "retention_weekly": "bad",
            "retention_monthly": "2",
            "min_free_mb": "1",
            "max_archive_mb": "2",
            "usb_backup_enabled": True,
            "usb_backup_uuid": "9CB0-6FD8",
            "smb_backup_enabled": True,
            "smb_share": " //server/backups ",
            "smb_username": " backup ",
            "smb_password": "secret",
            "smb_domain": " WORKGROUP ",
            "smb_options": "",
        })
        self.assertTrue(saved["schedule_enabled"])
        self.assertEqual("07:05", saved["schedule_time"])
        self.assertEqual(1, saved["retention_daily"])
        self.assertEqual(4, saved["retention_weekly"])
        self.assertEqual(2, saved["retention_monthly"])
        self.assertEqual(128, saved["min_free_mb"])
        self.assertEqual(16, saved["max_archive_mb"])
        self.assertTrue(saved["usb_backup_enabled"])
        self.assertEqual("9CB0-6FD8", saved["usb_backup_uuid"])
        self.assertTrue(saved["smb_backup_enabled"])
        self.assertEqual("//server/backups", saved["smb_share"])
        self.assertEqual("backup", saved["smb_username"])
        self.assertEqual("secret", saved["smb_password"])
        stored = json.loads(self.config.CONFIG_PATH.read_text())
        self.assertNotEqual("secret", stored["smb_password"])
        self.assertTrue(str(stored["smb_password"]).startswith("enc:"))
        loaded = self.config.load_vault_config()
        self.assertEqual("secret", loaded["smb_password"])
        self.assertEqual("WORKGROUP", saved["smb_domain"])
        self.assertEqual("vers=3.0", saved["smb_options"])

    def test_retention_always_keeps_newest(self):
        backups = [
            {"path": Path(f"backup-{idx}.nsbackup"), "created": datetime(2026, 7, 11 - idx, tzinfo=timezone.utc)}
            for idx in range(5)
        ]
        keep = self.retention.retention_keep_set(backups, daily=1, weekly=1, monthly=1)
        self.assertIn(Path("backup-0.nsbackup"), keep)

    def test_schedule_disabled_skips_without_creating_backup(self):
        self.config.save_vault_config({"schedule_enabled": False})
        ok, detail = self.scheduler.run_scheduled_backup()
        self.assertFalse(ok)
        self.assertEqual("schedule disabled", detail)
        events = self.history.recent_events()
        self.assertEqual("skipped", events[0]["status"])


if __name__ == "__main__":
    unittest.main()
