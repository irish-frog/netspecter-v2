"""Parse completed speed-test measurements and validate reported success."""

import json
import math
import re


def number(value):
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if math.isfinite(parsed) and parsed >= 0 else None


def metrics_complete(latency, download, upload):
    return all(number(value) is not None for value in (latency, download, upload))


def parse_metrics(output):
    try:
        payload = json.loads(output or "")
    except (TypeError, ValueError):
        payload = None
    if isinstance(payload, dict):
        latency = payload.get("ping")
        if latency is None:
            latency = payload.get("latency")
        if isinstance(latency, dict):
            latency = latency.get("latency", latency.get("value"))

        def bandwidth(value):
            if isinstance(value, dict):
                rate = number(value.get("bandwidth"))
                return rate * 8 / 1_000_000 if rate is not None else None
            rate = number(value)
            return rate / 1_000_000 if rate is not None else None

        return number(latency), bandwidth(payload.get("download")), bandwidth(payload.get("upload"))

    def matched(pattern):
        match = re.search(pattern, output or "", re.IGNORECASE)
        return number(match.group(1)) if match else None

    return (
        matched(r"(?:Latency|Ping):\s*([0-9.]+)\s*ms"),
        matched(r"Download:\s*([0-9.]+)\s*(?:Mbit/s|Mbps)"),
        matched(r"Upload:\s*([0-9.]+)\s*(?:Mbit/s|Mbps)"),
    )
