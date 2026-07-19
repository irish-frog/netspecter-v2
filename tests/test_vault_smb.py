import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netspecter_vault.smb import copy_backup_to_smb, normalise_share


class VaultSmbTests(unittest.TestCase):
    def test_normalise_windows_share_path(self):
        self.assertEqual("//server/share", normalise_share(r"\\server\share"))

    def test_copy_backup_mounts_and_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "test.nsbackup"
            source.write_text("backup")
            target = root / "mount"
            target.mkdir()
            config = {
                "smb_share": "//server/backups",
                "smb_username": "backup",
                "smb_password": "secret",
                "smb_domain": "",
                "smb_options": "vers=3.0",
            }
            with patch("netspecter_vault.smb.MOUNT_ROOT", root), \
                    patch("netspecter_vault.smb.os.path.ismount", return_value=False), \
                    patch("netspecter_vault.smb.mount_path", return_value=target), \
                    patch("netspecter_vault.smb.run_command") as run_command:
                run_command.return_value.returncode = 0
                dest = copy_backup_to_smb(config, source)
            self.assertEqual(target / source.name, dest)
            self.assertTrue(dest.exists())
            mount_call = run_command.call_args_list[0].args[0]
            self.assertEqual("mount", mount_call[0])
            self.assertEqual("-t", mount_call[1])
            self.assertEqual("cifs", mount_call[2])
            self.assertEqual("//server/backups", mount_call[3])
            self.assertNotIn("secret", " ".join(mount_call))
            self.assertEqual("secret", run_command.call_args_list[0].kwargs["env"]["PASSWD"])
            self.assertEqual([], list(root.glob("*.cred")))


if __name__ == "__main__":
    unittest.main()
