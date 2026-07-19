import importlib
import json
import os
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path


class VaultBackupTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.config_root = self.root / "config"
        self.data_root = self.root / "data"
        self.backup_root = self.root / "backups"
        self.staging_root = self.root / "staging"
        self.original_env = {
            key: os.environ.get(key)
            for key in (
                "NETSPECTER_CONFIG_ROOT",
                "NETSPECTER_DATA_ROOT",
                "NETSPECTER_VAULT_BACKUP_DIR",
                "NETSPECTER_VAULT_STAGING_DIR",
            )
        }
        os.environ["NETSPECTER_CONFIG_ROOT"] = str(self.config_root)
        os.environ["NETSPECTER_DATA_ROOT"] = str(self.data_root)
        os.environ["NETSPECTER_VAULT_BACKUP_DIR"] = str(self.backup_root)
        os.environ["NETSPECTER_VAULT_STAGING_DIR"] = str(self.staging_root)

        self.config_root.mkdir(parents=True)
        self.data_root.mkdir(parents=True)
        (self.config_root / "config.json").write_text(json.dumps({"app_name": "NetSpecter"}))
        (self.config_root / "secret.key").write_text("not-a-real-test-secret")
        (self.config_root / "adguard").mkdir()
        (self.config_root / "adguard" / "AdGuardHome.yaml").write_text("dns:\n  bind_hosts: []\n")
        (self.config_root / "gatus").mkdir()
        (self.config_root / "gatus" / "config.yaml").write_text("endpoints: []\n")

        con = sqlite3.connect(self.data_root / "netspecter.db")
        con.execute("CREATE TABLE devices (ip TEXT PRIMARY KEY, name TEXT)")
        con.execute("INSERT INTO devices VALUES (?, ?)", ("192.0.2.10", "Test Device"))
        con.commit()
        con.close()

        import netspecter_vault.paths as paths
        import netspecter_vault.archive as archive
        import netspecter_vault.cli as cli
        import netspecter_vault.restore as restore
        import netspecter_vault.verify as verify
        self.paths = importlib.reload(paths)
        self.verify = importlib.reload(verify)
        self.archive = importlib.reload(archive)
        self.cli = importlib.reload(cli)
        self.restore = importlib.reload(restore)

    def tearDown(self):
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_backup_creates_verified_archive_with_expected_contents(self):
        backup = self.archive.create_backup(min_free_bytes=1, allow_unencrypted=True)
        self.assertTrue(backup.exists())
        self.assertTrue(backup.name.startswith("NetSpecter-Vault-"))
        self.assertTrue(backup.name.endswith(".nsbackup"))

        with tarfile.open(backup, "r:gz") as tar:
            names = set(tar.getnames())

        self.assertIn("metadata.json", names)
        self.assertIn("manifest.json", names)
        self.assertIn("checksums.sha256", names)
        self.assertIn("etc/netspecter/config.json", names)
        self.assertIn("etc/netspecter/adguard/AdGuardHome.yaml", names)
        self.assertIn("etc/netspecter/gatus/config.yaml", names)
        self.assertIn("var/lib/netspecter/netspecter.db", names)
        self.assertFalse(any("suricata" in name.lower() for name in names))
        self.assertFalse(any("cache" in name.lower() for name in names))

        result = self.verify.verify_backup(backup.name)
        self.assertTrue(result.ok, result.detail)

    def test_backup_sqlite_snapshot_is_consistent(self):
        backup = self.archive.create_backup(min_free_bytes=1, allow_unencrypted=True)
        extract_dir = self.root / "extract"
        extract_dir.mkdir()
        with tarfile.open(backup, "r:gz") as tar:
            tar.extractall(extract_dir)

        snapshot = extract_dir / "var" / "lib" / "netspecter" / "netspecter.db"
        con = sqlite3.connect(snapshot)
        try:
            integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
            row = con.execute("SELECT name FROM devices WHERE ip=?", ("192.0.2.10",)).fetchone()
        finally:
            con.close()
        self.assertEqual("ok", integrity)
        self.assertEqual("Test Device", row[0])

    def test_verify_rejects_tampered_archive(self):
        backup = self.archive.create_backup(min_free_bytes=1, allow_unencrypted=True)
        tamper_stage = self.root / "tamper"
        tamper_stage.mkdir()
        with tarfile.open(backup, "r:gz") as tar:
            tar.extractall(tamper_stage)
        (tamper_stage / "metadata.json").write_text("{}")
        tampered = self.root / "tampered.nsbackup"
        with tarfile.open(tampered, "w:gz") as tar:
            for path in tamper_stage.rglob("*"):
                if path.is_file():
                    tar.add(path, arcname=path.relative_to(tamper_stage).as_posix())

        result = self.verify._verify_backup_path(tampered)
        self.assertFalse(result.ok)

    def test_verify_rejects_archive_paths(self):
        result = self.verify.verify_backup("../NetSpecter-Vault-2026-07-18-120000.nsbackup")
        self.assertFalse(result.ok)
        self.assertEqual("archive path must be a NetSpecter backup archive", result.detail)

    def test_verify_allows_archive_name_inside_custom_safe_root(self):
        result = self.verify.verify_backup("NetSpecter-Vault-2026-07-18-120000.nsbackup", safe_root=self.root)
        self.assertFalse(result.ok)
        self.assertEqual("archive does not exist", result.detail)

    def test_cli_backup_and_verify(self):
        self.assertEqual(1, self.cli.main(["backup", "--destination", str(self.backup_root)]))
        self.assertEqual(0, self.cli.main(["backup", "--destination", str(self.backup_root), "--allow-unencrypted"]))
        backups = list(self.backup_root.glob("*.nsbackup"))
        self.assertEqual(1, len(backups))
        self.assertEqual(0, self.cli.main(["verify", backups[0].name]))
        self.assertEqual(0, self.cli.main(["inspect", backups[0].name]))

    def test_inspect_backup_reports_restore_targets(self):
        backup = self.archive.create_backup(min_free_bytes=1, allow_unencrypted=True)
        report = self.restore.inspect_backup(backup.name)
        targets = {row["target"] for row in report["restore_targets"]}
        self.assertTrue(report["verified"])
        self.assertIn("/etc/netspecter/config.json", targets)
        self.assertIn("/var/lib/netspecter/netspecter.db", targets)
        self.assertIn("metadata.json", report["files"])

    def test_restore_config_requires_confirmation_and_safety_copies(self):
        backup = self.archive.create_backup(min_free_bytes=1, allow_unencrypted=True)
        live_config = self.root / "live" / "config.json"
        live_config.parent.mkdir(parents=True)
        live_config.write_text('{"old": true}')

        with self.assertRaises(self.archive.VaultError):
            self.restore.restore_config(
                backup.name,
                confirmation="NOPE",
                restart_services=False,
                target_map={"etc/netspecter/config.json": str(live_config)},
                safety_root=self.root / "safety",
            )

        result = self.restore.restore_config(
            backup.name,
            confirmation="RESTORE CONFIG",
            restart_services=False,
            target_map={"etc/netspecter/config.json": str(live_config)},
            safety_root=self.root / "safety",
        )
        self.assertEqual({"app_name": "NetSpecter"}, json.loads(live_config.read_text()))
        self.assertEqual(1, len(result["safety_files"]))
        self.assertTrue(Path(result["safety_files"][0]).exists())

    def test_restore_full_requires_confirmation_and_restores_database(self):
        backup = self.archive.create_backup(min_free_bytes=1, allow_unencrypted=True)
        live_config = self.root / "live-full" / "config.json"
        live_db = self.root / "live-full" / "netspecter.db"
        live_config.parent.mkdir(parents=True)
        live_config.write_text('{"old": true}')
        con = sqlite3.connect(live_db)
        con.execute("CREATE TABLE devices (ip TEXT PRIMARY KEY, name TEXT)")
        con.execute("INSERT INTO devices VALUES (?, ?)", ("198.51.100.20", "Old Device"))
        con.commit()
        con.close()

        with self.assertRaises(self.archive.VaultError):
            self.restore.restore_full(
                backup.name,
                confirmation="RESTORE CONFIG",
                manage_services=False,
                target_map={
                    "etc/netspecter/config.json": str(live_config),
                    "var/lib/netspecter/netspecter.db": str(live_db),
                },
                safety_root=self.root / "safety-full",
            )

        result = self.restore.restore_full(
            backup.name,
            confirmation="RESTORE FULL",
            manage_services=False,
            target_map={
                "etc/netspecter/config.json": str(live_config),
                "var/lib/netspecter/netspecter.db": str(live_db),
            },
            safety_root=self.root / "safety-full",
        )
        self.assertEqual({"app_name": "NetSpecter"}, json.loads(live_config.read_text()))
        con = sqlite3.connect(live_db)
        try:
            row = con.execute("SELECT name FROM devices WHERE ip=?", ("192.0.2.10",)).fetchone()
        finally:
            con.close()
        self.assertEqual("Test Device", row[0])
        self.assertEqual(2, len(result["safety_files"]))


if __name__ == "__main__":
    unittest.main()
