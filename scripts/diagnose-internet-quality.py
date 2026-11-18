#!/usr/bin/env python3
"""Read-only appliance, bridge and DNS checks. Does not run a speed test."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from netspecter_internet_quality import dns_query_ms, dns_server_from_config, ping_target, quality_targets


def interface_stats(interface):
    root = Path("/sys/class/net") / interface / "statistics"
    return {
        name: int((root / name).read_text().strip())
        for name in ("rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped")
        if (root / name).exists()
    }


def check(config, samples=3, interval=5):
    bridge = str(config.get("packet_iface") or "br0")
    if Path(bridge).name != bridge or bridge in (".", ".."):
        raise ValueError("Invalid bridge interface")
    members = Path("/sys/class/net") / bridge / "brif"
    interfaces = [bridge] + (sorted(path.name for path in members.iterdir()) if members.is_dir() else [])
    previous = {name: interface_stats(name) for name in interfaces}
    reports = []
    for index in range(samples):
        if index:
            time.sleep(interval)
        started = time.monotonic()
        probes = []
        gateway = str(config.get("gateway_ip") or "").strip()
        if gateway:
            probes.append({"role": "gateway", "target": gateway, **ping_target(gateway, count=3, timeout=2)})
        probes.extend({"role": "internet", "target": target, **ping_target(target, count=3, timeout=2)} for target in quality_targets(config))
        dns = {}
        for external, role in ((False, "configured_dns"), (True, "external_dns")):
            server = dns_server_from_config(config, external=external)
            dns[role] = {"server": server, **dns_query_ms(server, config.get("internet_quality_dns_query") or "example.com")}
        current = {name: interface_stats(name) for name in interfaces}
        delta = {
            name: {key: max(0, value - previous[name].get(key, value)) for key, value in counters.items()}
            for name, counters in current.items()
        }
        previous = current
        services = subprocess.run(
            ["systemctl", "show", "netspecter-web", "netspecter-collector", "netspecter-https", "AdGuardHome",
             "--property=Id,ActiveState,NRestarts,MemoryCurrent,CPUUsageNSec"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        report = {
            "sample": index + 1,
            "observed_at": time.strftime("%Y-%m-%d %H:%M:%S %z"),
            "duration_seconds": round(time.monotonic() - started, 2),
            "load_average": os.getloadavg(),
            "logical_cpus": os.cpu_count(),
            "memory": [line for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith(("MemAvailable:", "SwapFree:"))],
            "interface_counter_delta": delta,
            "probes": probes,
            "dns": dns,
            "services": services.stdout.strip() or services.stderr.strip(),
        }
        reports.append(report)
        print(json.dumps(report, indent=2), flush=True)
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/netspecter/config.json")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    check(config, samples=max(1, min(10, args.samples)), interval=max(1, min(60, args.interval)))


if __name__ == "__main__":
    main()
