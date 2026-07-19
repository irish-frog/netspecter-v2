#!/usr/bin/env python3
import html
import ipaddress
import os
from datetime import datetime


def env_minutes(name, default):
    try:
        return max(0, float(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return float(default)


def h(value):
    return html.escape(str(value or ""), quote=True)


def fmt_mb(value):
    """Format megabytes as MB, GB, or TB."""
    try:
        mb = float(value or 0)
    except Exception:
        mb = 0.0

    if abs(mb) >= 1024 * 1024:
        return f"{mb / (1024 * 1024):.2f} TB"

    if abs(mb) >= 1000:
        return f"{mb / 1024:.2f} GB"

    return f"{mb:.2f} MB"


def fmt_bps(value):
    """Format bits-per-second values cleanly for live speed displays."""
    try:
        bps = float(value or 0)
    except Exception:
        bps = 0.0

    if abs(bps) >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"

    if abs(bps) >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"

    if abs(bps) >= 1_000:
        return f"{bps / 1_000:.1f} Kbps"

    return "0.0 Kbps" if bps == 0 else f"{bps:.0f} bps"


def fmt_bytes_per_sec(value):
    """Format bytes-per-second as KB/s, MB/s, GB/s or TB/s."""
    try:
        bps = float(value or 0)
    except Exception:
        bps = 0.0

    if abs(bps) >= 1024 ** 4:
        return f"{bps / (1024 ** 4):.2f} TB/s"

    if abs(bps) >= 1024 ** 3:
        return f"{bps / (1024 ** 3):.2f} GB/s"

    if abs(bps) >= 1024 ** 2:
        return f"{bps / (1024 ** 2):.2f} MB/s"

    if abs(bps) >= 1024:
        return f"{bps / 1024:.2f} KB/s"

    return "0 B/s" if bps == 0 else f"{bps:.0f} B/s"


def fmt_bits_as_bytes(value):
    """Display collector throughput, stored as bits/sec, in byte-rate units."""
    try:
        bits = float(value or 0)
    except Exception:
        bits = 0.0

    return fmt_bytes_per_sec(bits / 8)


def parse_local_dt(value):
    """Parse a NetSpecter timestamp safely. Returns None if invalid."""
    try:
        if not value:
            return None
        return datetime.strptime(str(value)[:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def device_age_seconds(value):
    """Return age in seconds from a timestamp to now. Returns None if unknown."""
    dt = parse_local_dt(value)
    if not dt:
        return None
    return (datetime.now() - dt).total_seconds()


def device_lifecycle_badges(first_seen, last_seen):
    """Build New/Offline/Online badges for the Devices page."""
    badges = []

    first_age = device_age_seconds(first_seen)
    last_age = device_age_seconds(last_seen)

    if first_age is not None and first_age <= 86400:
        badges.append('<span class="badge-new">New</span>')

    if last_age is None:
        badges.append('<span class="badge-unknown">Unknown</span>')
    elif last_age > 300:
        badges.append('<span class="badge-offline">Offline</span>')
    else:
        badges.append('<span class="badge-online">Online</span>')

    return " ".join(badges)


def valid_lan_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def valid_ipv4_ip(ip):
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except Exception:
        return False


def public_ipv4(value):
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    if ip.version != 4:
        return ""
    if not ip.is_global:
        return ""
    return str(ip)
