import hashlib
import json
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from netspecter_paths import DATA_ROOT

try:
    import requests
except Exception:
    requests = None


SECRET_MARKER = "[redacted]"
VOLATILE_KEYS = {"updated_at", "last_seen", "first_seen", "ts", "timestamp", "counter", "packets", "bytes"}
SECRET_RE = re.compile(r"(pass(word)?|token|secret|key|credential|authorization|cookie|api[_-]?key)", re.IGNORECASE)


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_command(command, timeout=3, stdout_limit=20000):
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "ok": result.returncode == 0,
            "stdout": (result.stdout or "")[:stdout_limit],
            "stderr": (result.stderr or "")[:1000],
            "returncode": result.returncode,
        }
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": f"{command[0]} missing", "returncode": 127}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "timeout", "returncode": 124}
    except Exception as error:
        return {"ok": False, "stdout": "", "stderr": str(error)[:500], "returncode": 1}


def redact(value, key=""):
    if SECRET_RE.search(str(key or "")):
        return SECRET_MARKER
    if isinstance(value, dict):
        return {str(k): redact(v, k) for k, v in sorted(value.items()) if str(k) not in VOLATILE_KEYS}
    if isinstance(value, list):
        return [redact(item, key) for item in value]
    text = str(value) if value is not None else ""
    if SECRET_RE.search(text):
        return SECRET_MARKER
    return text[:500]


def stable_json(value):
    return json.dumps(redact(value), sort_keys=True, separators=(",", ":"))


def fingerprint(snapshot):
    return hashlib.sha256(stable_json(snapshot).encode("utf-8")).hexdigest()


def normalize_lines(text):
    return sorted(line.strip() for line in str(text or "").splitlines() if line.strip())


def normalize_routes(text):
    lines = []
    for line in normalize_lines(text):
        line = re.sub(r"\s+", " ", line)
        lines.append(line)
    return sorted(lines)


def strip_nft_counters(value):
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            if key in ("counter", "packets", "bytes", "handle"):
                continue
            out[key] = strip_nft_counters(child)
        return out
    if isinstance(value, list):
        return [strip_nft_counters(item) for item in value]
    return value


def canonical_nftables_items(value):
    if isinstance(value, dict):
        items = value.get("nftables")
        if isinstance(items, list):
            return items
        return [value]
    if isinstance(value, list):
        flattened = []
        for item in value:
            flattened.extend(canonical_nftables_items(item))
        return flattened
    return []


def is_netspecter_runtime_nft_item(value):
    if not isinstance(value, dict):
        return False
    if "metainfo" in value:
        return True
    table = value.get("table")
    if isinstance(table, dict):
        return table.get("family") == "bridge" and table.get("name") == "netspecter"
    chain = value.get("chain")
    if isinstance(chain, dict):
        return chain.get("family") == "bridge" and chain.get("table") == "netspecter"
    rule = value.get("rule")
    if isinstance(rule, dict):
        return rule.get("family") == "bridge" and rule.get("table") == "netspecter"
    return False


def normalize_nftables(output):
    try:
        payload = json.loads(output or "{}")
        cleaned = [
            strip_nft_counters(item)
            for item in canonical_nftables_items(payload)
            if not is_netspecter_runtime_nft_item(item)
        ]
        return sorted((json.loads(stable_json(item)) for item in cleaned), key=stable_json)
    except Exception:
        raw_output = str(output or "")
        if '"nftables"' in raw_output or '\\"nftables\\"' in raw_output:
            return []
        lines = []
        for line in normalize_lines(output):
            line = re.sub(r"\bcounter\s+packets\s+\d+\s+bytes\s+\d+", "counter", line)
            line = re.sub(r"\bpackets\s+\d+\s+bytes\s+\d+", "", line)
            line = re.sub(r"\s+#\s+handle\s+\d+", "", line)
            line = re.sub(r',?\s*"handle"\s*:\s*\d+', "", line)
            lines.append(re.sub(r"\s+", " ", line).strip())
        return sorted(lines)


def systemd_state(service):
    active = run_command(["systemctl", "is-active", service], timeout=2)
    enabled = run_command(["systemctl", "is-enabled", service], timeout=2)
    return {
        "active": (active["stdout"].strip() or active["stderr"].strip() or "unknown")[:80],
        "enabled": (enabled["stdout"].strip() or enabled["stderr"].strip() or "unknown")[:80],
    }


def bridge_snapshot(config):
    bridge = str(config.get("packet_iface") or "br0").strip() or "br0"
    state_path = Path("/sys/class/net") / bridge / "operstate"
    members = []
    member_root = Path("/sys/class/net") / bridge / "brif"
    if member_root.exists():
        members = sorted(path.name for path in member_root.iterdir())
    return {
        "name": bridge,
        "exists": (Path("/sys/class/net") / bridge).exists(),
        "state": state_path.read_text().strip() if state_path.exists() else "missing",
        "members": members,
    }


def nic_snapshot(config):
    names = set(bridge_snapshot(config).get("members") or [])
    iface = str(config.get("packet_iface") or "").strip()
    if iface:
        names.add(iface)
    rows = {}
    for name in sorted(names):
        root = Path("/sys/class/net") / name
        if not root.exists():
            rows[name] = {"exists": False}
            continue
        def read_file(child):
            path = root / child
            try:
                return path.read_text().strip()
            except Exception:
                return ""
        rows[name] = {
            "exists": True,
            "carrier": read_file("carrier"),
            "speed": read_file("speed"),
            "duplex": read_file("duplex"),
            "operstate": read_file("operstate"),
        }
    return rows


def resolver_snapshot():
    path = Path("/etc/resolv.conf")
    if not path.exists():
        return []
    servers = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("nameserver "):
                servers.append(line.split(None, 1)[1])
    except Exception:
        pass
    return sorted(set(servers))


def adguard_snapshot(config):
    state = systemd_state("AdGuardHome")
    base = str(config.get("adguard_url") or "").rstrip("/")
    status = {}
    if base:
        if requests is None:
            status = {"http": "requests missing"}
        else:
            try:
                res = requests.get(
                    f"{base}/control/status",
                    auth=(config.get("adguard_user", "admin"), config.get("adguard_pass", "")),
                    timeout=3,
                )
                if res.status_code == 200:
                    payload = res.json()
                    status = {
                        "protection_enabled": bool(payload.get("protection_enabled")),
                        "filtering_enabled": bool(payload.get("filtering_enabled", payload.get("protection_enabled"))),
                    }
                else:
                    status = {"http": f"HTTP {res.status_code}"}
            except Exception as error:
                status = {"http": str(error)[:160]}
    ports = run_command(["ss", "-lntup"], timeout=3)
    listening = [line for line in normalize_lines(ports["stdout"]) if "AdGuardHome" in line or ":53 " in line or ":80 " in line]
    return {"service": state, "status": status, "listening": listening}


def unifi_snapshot(config):
    if not config.get("unifi_enabled"):
        return {"enabled": False}
    url = str(config.get("unifi_connector_url") or "").strip()
    if not url:
        return {"enabled": True, "connectivity": "url missing"}
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=3):
            return {"enabled": True, "connectivity": "reachable", "host": host, "port": port}
    except Exception as error:
        return {"enabled": True, "connectivity": str(error)[:160]}


def installed_version_snapshot():
    version_file = Path("/opt/netspecter/VERSION")
    if version_file.exists():
        try:
            return version_file.read_text().strip()[:120]
        except Exception:
            return "unreadable"
    git = run_command(["git", "rev-parse", "--short", "HEAD"], timeout=3)
    return git["stdout"].strip()[:40] if git["ok"] else "unknown"


def collect_snapshot(config):
    route_default = run_command(["ip", "route", "show", "default"], timeout=3)
    routes = run_command(["ip", "route", "show"], timeout=3)
    nft_json = run_command(["nft", "-j", "list", "ruleset"], timeout=5, stdout_limit=250000)
    suricata_config = run_command(["suricata", "--dump-config"], timeout=5)
    return {
        "bridge": bridge_snapshot(config),
        "nics": nic_snapshot(config),
        "default_gateway": normalize_routes(route_default["stdout"]),
        "dns_resolvers": resolver_snapshot(),
        "routes": normalize_routes(routes["stdout"]),
        "nftables": normalize_nftables(nft_json["stdout"]),
        "adguard": adguard_snapshot(config),
        "suricata": {
            "service": systemd_state("suricata"),
            "interface_config": normalize_lines(suricata_config["stdout"]),
        },
        "unifi": unifi_snapshot(config),
        "version": installed_version_snapshot(),
        "services": {
            "netspecter-web": systemd_state("netspecter-web"),
            "netspecter-collector": systemd_state("netspecter-collector"),
            "gatus": systemd_state("gatus"),
            "netspecter-vault.service": systemd_state("netspecter-vault.service"),
            "netspecter-vault.timer": systemd_state("netspecter-vault.timer"),
            "netspecter-monitor.timer": systemd_state("netspecter-monitor.timer"),
        },
    }


def flatten(value, prefix=""):
    rows = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            rows.update(flatten(child, path))
    elif isinstance(value, list):
        rows[prefix] = json.dumps(value, sort_keys=True, separators=(",", ":"))
    else:
        rows[prefix] = "" if value is None else str(value)
    return rows


def severity_for(component, field, previous, new):
    text = f"{component}.{field}".lower()
    if any(token in text for token in ("service.active", "protection_enabled", "filtering_enabled", "gateway", "default_gateway")):
        return "critical" if str(new).lower() in ("inactive", "failed", "false", "", "[]") else "warning"
    if "speed" in text and previous and new:
        try:
            return "warning" if int(float(new)) < int(float(previous)) else "info"
        except Exception:
            return "warning"
    if any(token in text for token in ("bridge.members", "routes", "nftables", "dns_resolvers")):
        return "warning"
    if "version" in text:
        return "info"
    return "info"


def diff_snapshots(previous, current):
    prev = flatten(redact(previous))
    curr = flatten(redact(current))
    changes = []
    for field in sorted(set(prev) | set(curr)):
        old = prev.get(field, "")
        new = curr.get(field, "")
        if old == new:
            continue
        component = field.split(".", 1)[0]
        changes.append({
            "component": component,
            "field": field,
            "previous_value": old[:1000],
            "new_value": new[:1000],
            "severity": severity_for(component, field, old, new),
        })
    return changes


def ensure_schema(con):
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS config_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            snapshot_json TEXT NOT NULL,
            is_baseline INTEGER DEFAULT 0
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS config_change_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            component TEXT NOT NULL,
            field TEXT NOT NULL,
            severity TEXT NOT NULL,
            previous_value TEXT,
            new_value TEXT,
            snapshot_id INTEGER,
            status TEXT DEFAULT 'new'
        )
        """
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_snapshots_ts ON config_snapshots(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_snapshots_fingerprint ON config_snapshots(fingerprint)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_events_ts ON config_change_events(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_events_component ON config_change_events(component)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_events_severity ON config_change_events(severity)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_events_status ON config_change_events(status)")


def monitor_once(connect_db, config):
    snapshot = redact(collect_snapshot(config))
    fp = fingerprint(snapshot)
    con = connect_db()
    ensure_schema(con)
    con.row_factory = None
    latest = con.execute("SELECT id, fingerprint, snapshot_json FROM config_snapshots ORDER BY id DESC LIMIT 1").fetchone()
    if latest and latest[1] == fp:
        con.close()
        return {"changed": False, "fingerprint": fp, "events": 0}
    ts = now_text()
    cur = con.execute(
        "INSERT OR IGNORE INTO config_snapshots (ts, fingerprint, snapshot_json, is_baseline) VALUES (?, ?, ?, ?)",
        (ts, fp, stable_json(snapshot), 0 if latest else 1),
    )
    snapshot_id = cur.lastrowid or con.execute("SELECT id FROM config_snapshots WHERE fingerprint=?", (fp,)).fetchone()[0]
    changes = []
    if latest:
        previous = json.loads(latest[2])
        changes = diff_snapshots(previous, snapshot)
        con.executemany(
            """
            INSERT INTO config_change_events
                (ts, component, field, severity, previous_value, new_value, snapshot_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'new')
            """,
            [(ts, c["component"], c["field"], c["severity"], c["previous_value"], c["new_value"], snapshot_id) for c in changes],
        )
    con.commit()
    con.close()
    return {"changed": True, "fingerprint": fp, "events": len(changes)}


def prune_config_changes(connect_db, config):
    days = int(config.get("config_change_retention_days", 180) or 180)
    max_events = int(config.get("config_change_max_events", 100000) or 100000)
    min_free_mb = int(config.get("config_change_min_free_mb", 512) or 512)
    con = connect_db()
    ensure_schema(con)
    con.execute("DELETE FROM config_change_events WHERE ts < datetime('now', 'localtime', ?)", (f"-{days} days",))
    count = con.execute("SELECT COUNT(*) FROM config_change_events").fetchone()[0]
    if count > max_events:
        con.execute(
            "DELETE FROM config_change_events WHERE id IN (SELECT id FROM config_change_events ORDER BY ts ASC LIMIT ?)",
            (count - max_events,),
        )
    latest = con.execute("SELECT id FROM config_snapshots ORDER BY id DESC LIMIT 1").fetchone()
    baseline = con.execute("SELECT id FROM config_snapshots WHERE is_baseline=1 ORDER BY id DESC LIMIT 1").fetchone()
    keep = {row[0] for row in (latest, baseline) if row}
    if keep:
        placeholders = ",".join("?" for _ in keep)
        con.execute(f"DELETE FROM config_snapshots WHERE id NOT IN ({placeholders}) AND ts < datetime('now', 'localtime', ?)", (*keep, f"-{days} days"))
    try:
        free_mb = shutil.disk_usage(str(DATA_ROOT)).free / 1024 / 1024
    except Exception:
        free_mb = min_free_mb + 1
    if free_mb < min_free_mb:
        con.execute("DELETE FROM config_change_events WHERE id IN (SELECT id FROM config_change_events ORDER BY ts ASC LIMIT 500)")
    con.commit()
    con.close()


def latest_snapshot(connect_db):
    con = connect_db()
    con.row_factory = None
    ensure_schema(con)
    row = con.execute("SELECT id, ts, fingerprint, snapshot_json FROM config_snapshots ORDER BY id DESC LIMIT 1").fetchone()
    con.close()
    return row


def recent_events(connect_db, limit=200):
    con = connect_db()
    con.row_factory = None
    ensure_schema(con)
    rows = con.execute(
        """
        SELECT id, ts, component, field, severity, previous_value, new_value, status
        FROM config_change_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(limit),),
    ).fetchall()
    con.close()
    return rows


def event_summary(connect_db):
    con = connect_db()
    ensure_schema(con)
    total = con.execute("SELECT COUNT(*) FROM config_change_events").fetchone()[0]
    open_count = con.execute("SELECT COUNT(*) FROM config_change_events WHERE status='new'").fetchone()[0]
    critical = con.execute("SELECT COUNT(*) FROM config_change_events WHERE severity='critical' AND status='new'").fetchone()[0]
    con.close()
    return {"total": total, "open": open_count, "critical": critical}


def update_event_status(connect_db, event_id, status):
    if status not in ("acknowledged", "expected", "new"):
        return False
    con = connect_db()
    ensure_schema(con)
    cur = con.execute("UPDATE config_change_events SET status=? WHERE id=?", (status, int(event_id)))
    con.commit()
    con.close()
    return cur.rowcount > 0


def use_latest_as_baseline(connect_db):
    con = connect_db()
    ensure_schema(con)
    row = con.execute("SELECT id FROM config_snapshots ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        con.close()
        return False
    con.execute("UPDATE config_snapshots SET is_baseline=0")
    con.execute("UPDATE config_snapshots SET is_baseline=1 WHERE id=?", (row[0],))
    con.execute("UPDATE config_change_events SET status='expected' WHERE status='new'")
    con.commit()
    con.close()
    return True
