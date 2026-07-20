import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
SCRIPT = SOURCE_DIR / "scripts" / "configure-ids-interfaces.sh"


class IdsInterfaceScriptTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which("bash"):
            self.skipTest("bash is not available")
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write_command(self, name, body):
        path = self.bin / name
        path.write_text("#!/usr/bin/env bash\n" + textwrap.dedent(body), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def run_script(self, *args):
        env = os.environ.copy()
        env["PATH"] = str(self.bin) + os.pathsep + env.get("PATH", "")
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )

    def test_detects_multiple_predictable_bridge_members(self):
        self.write_command(
            "bridge",
            """
            echo '2: enp11s0f0: <BROADCAST,MULTICAST,UP,LOWER_UP> master br0 state forwarding'
            echo '3: enp11s0f1@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> master br0 state forwarding'
            """,
        )
        self.write_command(
            "ethtool",
            """
            if [ "$1" = "-k" ]; then
              echo 'tcp-segmentation-offload: off'
              echo 'generic-segmentation-offload: off'
              echo 'generic-receive-offload: off'
              exit 0
            fi
            exit 0
            """,
        )

        result = self.run_script("br0")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Detected bridge members: enp11s0f0 enp11s0f1", result.stdout)
        self.assertIn("Disabling GRO on enp11s0f0", result.stdout)
        self.assertIn("Disabling TSO on enp11s0f1", result.stdout)

    def test_no_members_returns_nonzero(self):
        self.write_command("bridge", "exit 0\n")
        self.write_command("ethtool", "exit 0\n")

        result = self.run_script("br0")

        self.assertNotEqual(0, result.returncode)
        self.assertIn("no interfaces are currently attached to bridge", result.stderr)

    def test_unsupported_offload_setting_does_not_abort_script(self):
        self.write_command("bridge", "echo '5: eth0: <UP> master br0 state forwarding'\n")
        self.write_command(
            "ethtool",
            """
            if [ "$1" = "-K" ] && [ "$3" = "gso" ]; then
              exit 95
            fi
            if [ "$1" = "-k" ]; then
              echo 'tcp-segmentation-offload: off'
              echo 'generic-segmentation-offload: on'
              echo 'generic-receive-offload: off'
              exit 0
            fi
            exit 0
            """,
        )

        result = self.run_script("br0")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Disabling GRO on eth0", result.stdout)
        self.assertIn("Disabling GSO on eth0", result.stdout)
        self.assertIn("Disabling TSO on eth0", result.stdout)
        self.assertIn("does not support changing GSO", result.stderr)


if __name__ == "__main__":
    unittest.main()
