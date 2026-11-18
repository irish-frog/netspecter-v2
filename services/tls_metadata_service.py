"""Bounded, authenticated local intake for passive TLS connection metadata."""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
import re
import socket
import struct
import time

SOCKET_PATH = "/run/netspecter-metadata/tls.sock"
MAX_LINE = 4096
HOSTNAME = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


@dataclass(frozen=True)
class TlsMetadata:
    metadata_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    started_ms: int
    observed_ms: int
    hostname: str | None
    ech_present: bool


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid integer field")
    return value


def validate_metadata(line, now_ms=None):
    if not isinstance(line, bytes) or len(line) > MAX_LINE:
        raise ValueError("oversized metadata")
    def invalid_constant(_value):
        raise ValueError("invalid JSON constant")
    item = json.loads(line, object_pairs_hook=_unique_object, parse_constant=invalid_constant)
    fields = {"schema_version", "event_type", "observed_at_unix_ms", "connection_started_at_unix_ms", "connection", "hostname", "ech_present"}
    if not isinstance(item, dict) or set(item) != fields or type(item["schema_version"]) is not int or item["schema_version"] != 1 or item["event_type"] != "tls_client_hello":
        raise ValueError("unsupported metadata schema")
    connection = item["connection"]
    if not isinstance(connection, dict) or set(connection) != {"source", "destination", "source_port", "destination_port"}:
        raise ValueError("invalid connection")
    if any(not isinstance(connection[key], str) or len(connection[key]) > 45 or "%" in connection[key] for key in ("source", "destination")):
        raise ValueError("invalid address encoding")
    source = ipaddress.ip_address(connection["source"])
    destination = ipaddress.ip_address(connection["destination"])
    if source.version != destination.version or source.is_unspecified or destination.is_unspecified or source.is_multicast or destination.is_multicast:
        raise ValueError("invalid connection addresses")
    source_port = _integer(connection["source_port"], 1, 65535)
    destination_port = _integer(connection["destination_port"], 1, 65535)
    now = int(time.time() * 1000) if now_ms is None else now_ms
    observed = _integer(item["observed_at_unix_ms"], max(0, now - 120_000), now + 5000)
    started = _integer(item["connection_started_at_unix_ms"], max(0, observed - 30_000), observed)
    if type(item["ech_present"]) is not bool:
        raise ValueError("invalid ECH flag")
    hostname = item["hostname"]
    if hostname is not None:
        if not isinstance(hostname, str) or not HOSTNAME.fullmatch(hostname):
            raise ValueError("invalid hostname")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("hostname cannot be an IP address")
    if item["ech_present"] and hostname is not None:
        raise ValueError("ECH outer name cannot be application evidence")
    identity = json.dumps([str(source), str(destination), source_port, destination_port, started, hostname, item["ech_present"]], separators=(",", ":"))
    return TlsMetadata(hashlib.sha256(identity.encode()).hexdigest(), str(source), str(destination), source_port, destination_port, started, observed, hostname, item["ech_present"])


def metadata_table(con):
    attached = {row[1] for row in con.execute("PRAGMA database_list")}
    return "trafficdb.tls_connection_metadata" if "trafficdb" in attached else "tls_connection_metadata"


def ensure_metadata_schema(con):
    con.execute("""CREATE TABLE IF NOT EXISTS tls_connection_metadata (
        metadata_id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL,
        source_port INTEGER NOT NULL, destination_port INTEGER NOT NULL, started_ms INTEGER NOT NULL,
        observed_ms INTEGER NOT NULL, hostname TEXT, ech_present INTEGER NOT NULL DEFAULT 0
    )""")
    con.execute("""CREATE INDEX IF NOT EXISTS idx_tls_connection_match ON tls_connection_metadata
        (source_ip, destination_ip, source_port, destination_port, started_ms, observed_ms)""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_tls_observed ON tls_connection_metadata(observed_ms)")


def store_metadata(con, rows):
    if len(rows) > 200:
        raise ValueError("metadata batch too large")
    con.executemany(f"INSERT OR IGNORE INTO {metadata_table(con)} VALUES (?,?,?,?,?,?,?,?,?)", [
        (r.metadata_id, r.source_ip, r.destination_ip, r.source_port, r.destination_port, r.started_ms, r.observed_ms, r.hostname, int(r.ech_present)) for r in rows
    ])


def inherited_listener(environ=None, expected_path=SOCKET_PATH):
    environment = os.environ if environ is None else environ
    if environment.get("LISTEN_PID") != str(os.getpid()) or environment.get("LISTEN_FDS") != "1":
        return None
    listener = socket.socket(fileno=os.dup(3))
    if listener.family != socket.AF_UNIX or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or listener.getsockname() != expected_path or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
        listener.close()
        raise ValueError("invalid inherited metadata listener")
    listener.set_inheritable(False)
    return listener


def peer_is_allowed(connection, expected_uid):
    if not hasattr(socket, "SO_PEERCRED"):
        return False
    _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    return uid == expected_uid


def serve_metadata(listener, expected_uid, write_batch, stop_event):
    """One authenticated sensor stream, bounded buffers/batches; never binds a public socket."""
    listener.settimeout(1)
    pending = []
    last_flush = time.monotonic()
    rejected = 0
    def flush():
        nonlocal last_flush
        if pending:
            write_batch(pending[:])
            pending.clear()
        last_flush = time.monotonic()
    while not stop_event.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            if pending:
                flush()
            continue
        with connection:
            if not peer_is_allowed(connection, expected_uid):
                rejected += 1
                continue
            connection.settimeout(1)
            buffer = bytearray()
            count = 0
            window = time.monotonic()
            while not stop_event.is_set():
                try:
                    chunk = connection.recv(8192)
                except socket.timeout:
                    flush()
                    continue
                if not chunk:
                    break
                buffer.extend(chunk)
                while b"\n" in buffer:
                    line, _, remainder = buffer.partition(b"\n")
                    buffer = bytearray(remainder)
                    now = time.monotonic()
                    if now - window >= 1:
                        count, window = 0, now
                    count += 1
                    if count > 2048:
                        raise ValueError("metadata rate limit exceeded")
                    try:
                        pending.append(validate_metadata(bytes(line)))
                    except (ValueError, TypeError, KeyError, RecursionError):
                        rejected += 1
                    if len(pending) >= 200 or now - last_flush >= 1:
                        flush()
                if len(buffer) > MAX_LINE:
                    rejected += 1
                    break
            flush()
    flush()
    return {"rejected": rejected}
