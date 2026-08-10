import ipaddress
import platform
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta


ONLINE = "online"
OFFLINE = "offline"
UNKNOWN = "unknown"

PRESENCE_TIMEOUT_SECONDS = 900
REACHABILITY_CHECK_INTERVAL_SECONDS = 900
MAX_REACHABILITY_CHECKS = 8


@dataclass(frozen=True)
class PresenceState:
    state: str
    online: bool
    evidence: str = ""
    seen_at: str = ""

    @property
    def label(self):
        return "Online" if self.state == ONLINE else "Offline" if self.state == OFFLINE else "Unknown"


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_ts(value):
    if not value:
        return None
    text = str(value)[:19]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except Exception:
            pass
    return None


def age_seconds(value, now=None):
    dt = parse_ts(value)
    if not dt:
        return None
    return max(0, int(((now or datetime.now()) - dt).total_seconds()))


def valid_lan_ip(ip):
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
        return addr.version == 4 and addr.is_private and not addr.is_loopback and not addr.is_multicast
    except Exception:
        return False


def ensure_presence_columns(con):
    for stmt in [
        "ALTER TABLE devices ADD COLUMN last_presence_seen TEXT",
        "ALTER TABLE devices ADD COLUMN last_presence_source TEXT",
        "ALTER TABLE devices ADD COLUMN last_presence_check TEXT",
    ]:
        try:
            con.execute(stmt)
        except Exception as error:
            if "duplicate column name" not in str(error).lower():
                raise
    con.execute("CREATE INDEX IF NOT EXISTS idx_devices_presence_seen ON devices(last_presence_seen)")


def mark_presence(con, ip, source, seen_at=None, check_at=None):
    if not valid_lan_ip(ip):
        return
    ensure_presence_columns(con)
    ts = seen_at or now_text()
    con.execute(
        """
        UPDATE devices
        SET last_presence_seen=CASE
                WHEN last_presence_seen IS NULL OR last_presence_seen < ? THEN ? ELSE last_presence_seen END,
            last_presence_source=?,
            last_presence_check=COALESCE(?, last_presence_check)
        WHERE ip=?
        """,
        (ts, ts, source, check_at, ip),
    )


def mark_presence_many(con, rows, source):
    ts = now_text()
    ensure_presence_columns(con)
    con.executemany(
        """
        UPDATE devices
        SET last_presence_seen=CASE
                WHEN last_presence_seen IS NULL OR last_presence_seen < ? THEN ? ELSE last_presence_seen END,
            last_presence_source=?,
            last_presence_check=COALESCE(last_presence_check, ?)
        WHERE ip=?
        """,
        [(ts, ts, source, ts, str(ip)) for ip in rows if valid_lan_ip(ip)],
    )


def read_neighbour_ips():
    commands = [["ip", "neigh"], ["arp", "-an"]]
    seen = set()
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        except Exception:
            continue
        if result.returncode != 0:
            continue
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", result.stdout or ""):
            if valid_lan_ip(ip):
                seen.add(ip)
        if seen:
            break
    return seen


def ping_once(ip, timeout=1):
    if not valid_lan_ip(ip):
        return False
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(max(1, int(timeout * 1000))), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max(2, timeout + 1))
        return result.returncode == 0
    except Exception:
        return False


def state_from_timestamp(seen_at, source="", now=None, timeout_seconds=PRESENCE_TIMEOUT_SECONDS):
    if age_seconds(seen_at, now) is not None and age_seconds(seen_at, now) <= timeout_seconds:
        return PresenceState(ONLINE, True, source or "presence", str(seen_at or ""))
    if seen_at:
        return PresenceState(OFFLINE, False, source or "stale_presence", str(seen_at or ""))
    return PresenceState(UNKNOWN, False)


def resolve_presence_states(con, devices, now=None, timeout_seconds=PRESENCE_TIMEOUT_SECONDS, max_checks=MAX_REACHABILITY_CHECKS):
    ensure_presence_columns(con)
    now = now or datetime.now()
    rows = [dict(row) for row in devices]
    states = {}
    stale_or_unknown = []

    for row in rows:
        ip = str(row.get("ip") or "").strip()
        presence = row.get("last_presence_seen")
        source = row.get("last_presence_source") or ""
        if age_seconds(presence, now) is not None and age_seconds(presence, now) <= timeout_seconds:
            states[ip] = PresenceState(ONLINE, True, source or "presence", presence)
        elif valid_lan_ip(ip):
            stale_or_unknown.append(row)
        else:
            states[ip] = PresenceState(UNKNOWN, False)

    neighbour_ips = read_neighbour_ips()
    for row in list(stale_or_unknown):
        ip = str(row.get("ip") or "").strip()
        if ip in neighbour_ips:
            ts = now.strftime("%Y-%m-%d %H:%M:%S")
            mark_presence(con, ip, "neighbour", ts, ts)
            states[ip] = PresenceState(ONLINE, True, "neighbour", ts)
            stale_or_unknown.remove(row)

    checks = 0
    check_cutoff = now - timedelta(seconds=REACHABILITY_CHECK_INTERVAL_SECONDS)
    for row in stale_or_unknown:
        ip = str(row.get("ip") or "").strip()
        last_check = parse_ts(row.get("last_presence_check"))
        if checks >= max_checks or (last_check and last_check > check_cutoff):
            states[ip] = state_from_timestamp(row.get("last_presence_seen"), row.get("last_presence_source"), now, timeout_seconds)
            continue
        checks += 1
        checked_at = now.strftime("%Y-%m-%d %H:%M:%S")
        if ping_once(ip):
            mark_presence(con, ip, "reachability", checked_at, checked_at)
            states[ip] = PresenceState(ONLINE, True, "reachability", checked_at)
        else:
            con.execute("UPDATE devices SET last_presence_check=? WHERE ip=?", (checked_at, ip))
            states[ip] = state_from_timestamp(row.get("last_presence_seen"), row.get("last_presence_source"), now, timeout_seconds)

    con.commit()
    return states


def count_states(states):
    online = sum(1 for state in states.values() if state.state == ONLINE)
    unknown = sum(1 for state in states.values() if state.state == UNKNOWN)
    offline = sum(1 for state in states.values() if state.state == OFFLINE)
    return {"online": online, "offline": offline, "unknown": unknown}
