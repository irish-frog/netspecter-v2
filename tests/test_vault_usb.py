import unittest
from unittest.mock import patch

from netspecter_vault.archive import VaultError
from netspecter_vault.cli import build_parser
from netspecter_vault.usb import copy_backup_to_usb, eject_usb, mount_usb, removable_partitions, resolve_usb_backup_destination, validate_usb_uuid


class VaultUsbTests(unittest.TestCase):
    def test_only_removable_uuid_partitions_are_listed(self):
        data = {
            "blockdevices": [
                {
                    "name": "sda", "path": "/dev/sda", "type": "disk", "size": "59.6G",
                    "rm": False, "ro": False, "model": "TS64GMTS400SD", "vendor": "ATA",
                    "serial": "E195688186", "children": [
                        {"name": "sda1", "path": "/dev/sda1", "type": "part", "size": "56.5G",
                         "rm": False, "ro": False, "fstype": "ext4", "label": None,
                         "uuid": "d56097ce-6043-436a-8f41-0d97d9564e12", "mountpoints": ["/"]}
                    ],
                },
                {
                    "name": "sdb", "path": "/dev/sdb", "type": "disk", "size": "14.6G",
                    "rm": True, "ro": False, "model": "ProductCode", "vendor": "VendorCo",
                    "serial": "4980961250188619533", "children": [
                        {"name": "sdb1", "path": "/dev/sdb1", "type": "part", "size": "14.6G",
                         "rm": True, "ro": False, "fstype": "vfat", "label": "DEBIAN 13_5",
                         "uuid": "9CB0-6FD8", "mountpoints": []}
                    ],
                },
            ]
        }
        devices = removable_partitions(data)
        self.assertEqual(1, len(devices))
        self.assertEqual("9CB0-6FD8", devices[0]["uuid"])
        self.assertEqual("/dev/sdb1", devices[0]["path"])
        self.assertEqual("ProductCode", devices[0]["model"])

    def test_unsupported_filesystem_is_hidden(self):
        data = {"blockdevices": [{"name": "sdb", "type": "disk", "rm": True, "children": [
            {"name": "sdb1", "path": "/dev/sdb1", "type": "part", "rm": True, "ro": False,
             "fstype": "crypto_LUKS", "uuid": "bad", "mountpoints": []}
        ]}]}
        self.assertEqual([], removable_partitions(data))

    def test_cli_does_not_offer_format(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["usb", "format", "9CB0-6FD8"])

    def test_eject_unmounted_usb_is_ok(self):
        data = {"blockdevices": [{"name": "sdb", "type": "disk", "rm": True, "children": [
            {"name": "sdb1", "path": "/dev/sdb1", "type": "part", "rm": True, "ro": False,
             "fstype": "ext4", "uuid": "d56097ce-6043-436a-8f41-0d97d9564e12", "mountpoints": []}
        ]}]}
        with patch("netspecter_vault.usb.lsblk_json", return_value=data), \
                patch("netspecter_vault.usb.run_command") as run_command:
            self.assertTrue(eject_usb("d56097ce-6043-436a-8f41-0d97d9564e12"))
        calls = [call.args[0] for call in run_command.call_args_list]
        self.assertNotIn(["umount", "/mnt/netspecter-vault/d56097ce-6043-436a-8f41-0d97d9564e12"], calls)
        self.assertIn(["sync"], calls)

    def test_rejects_non_canonical_usb_uuid(self):
        with self.assertRaises(VaultError):
            validate_usb_uuid("0649-222D; touch /tmp/pwned")

    def test_mount_uses_trusted_uuid_from_device_lookup(self):
        uuid = "d56097ce-6043-436a-8f41-0d97d9564e12"
        data = {"blockdevices": [{"name": "sdb", "type": "disk", "rm": True, "children": [
            {"name": "sdb1", "path": "/dev/sdb1", "type": "part", "rm": True, "ro": False,
             "fstype": "ext4", "uuid": uuid, "mountpoints": []}
        ]}]}
        with patch("netspecter_vault.usb.lsblk_json", return_value=data), \
                patch("netspecter_vault.usb.MOUNT_ROOT", self._test_mount_root()), \
                patch("netspecter_vault.usb.run_command") as run_command:
            run_command.return_value.returncode = 0
            run_command.return_value.stderr = ""
            mount_usb(f"  {uuid}  ")

        calls = [call.args[0] for call in run_command.call_args_list]
        self.assertIn(["mount", "-o", "nosuid,nodev,noexec", f"UUID={uuid}", str(self._test_mount_root() / uuid)], calls)

    def test_copy_backup_rejects_source_outside_backup_dir(self):
        outside = self._test_mount_root() / "outside.nsbackup"
        outside.write_bytes(b"backup")
        with self.assertRaises(VaultError):
            copy_backup_to_usb("d56097ce-6043-436a-8f41-0d97d9564e12", outside)

    def test_usb_backup_destination_stays_inside_target_dir(self):
        with self.assertRaises(VaultError):
            resolve_usb_backup_destination(self._test_mount_root(), "../outside.nsbackup")

    def _test_mount_root(self):
        from pathlib import Path
        import tempfile

        root = Path(tempfile.gettempdir()) / "netspecter-vault-test"
        root.mkdir(parents=True, exist_ok=True)
        return root


if __name__ == "__main__":
    unittest.main()
