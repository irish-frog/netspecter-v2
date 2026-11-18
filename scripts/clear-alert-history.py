#!/usr/bin/env python3
"""Preview or explicitly delete retired security-alert history."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.alert_history_service import clear_database_history, clear_log_history


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Permanently delete the displayed alert history")
    parser.add_argument("--data-dir", default="/var/lib/netspecter")
    parser.add_argument("--log-dir", default="/var/log/suricata")
    parser.add_argument("--config", default="/etc/netspecter/config.json")
    args = parser.parse_args()
    if args.apply:
        config = json.loads(Path(args.config).read_text())
        if config.get("security_features_enabled") or config.get("suricata_enabled"):
            parser.error("Disable security collection before clearing alert history")
        state = subprocess.run(["systemctl", "is-active", "suricata"], capture_output=True, text=True, timeout=5, check=False)
        if state.returncode not in (3, 4) or state.stdout.strip() not in {"inactive", "failed", "unknown"}:
            parser.error("Suricata must be confirmed stopped before clearing its history")
    result = {"applied": args.apply, "databases": {}}
    for name in ("netspecter.db", "netspecter_security.db"):
        result["databases"][name] = clear_database_history(Path(args.data_dir) / name, apply=args.apply)
    result["suricata_logs"] = clear_log_history(args.log_dir, apply=args.apply)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
