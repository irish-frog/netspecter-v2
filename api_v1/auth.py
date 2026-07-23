import hashlib
import hmac
import os
import time
from functools import wraps

from flask import g, jsonify, request

from netspecter_config import cfg
from netspecter_db import connect_db


RATE_BUCKETS = {}
DEFAULT_RATE_LIMIT_PER_MINUTE = 60
READ_SCOPE = "read"


def hash_api_key(key):
    return hashlib.sha256(str(key or "").encode("utf-8")).hexdigest()


def request_api_key():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.headers.get("X-API-Key", "").strip()


def configured_api_keys():
    entries = []
    for item in cfg().get("api_keys", []) or []:
        if not isinstance(item, dict) or item.get("enabled") is False:
            continue
        key_hash = str(item.get("key_hash") or "").strip()
        if key_hash:
            entries.append({
                "id": str(item.get("id") or item.get("name") or "api-key")[:80],
                "name": str(item.get("name") or item.get("id") or "API key")[:120],
                "key_hash": key_hash,
                "roles": item.get("roles") or ["reader"],
                "scopes": item.get("scopes") or [READ_SCOPE],
                "rate_limit_per_minute": int(item.get("rate_limit_per_minute") or DEFAULT_RATE_LIMIT_PER_MINUTE),
            })
    env_key = os.environ.get("NETSPECTER_API_KEY", "").strip()
    if env_key:
        entries.append({
            "id": "env",
            "name": "Environment API key",
            "key_hash": hash_api_key(env_key),
            "roles": ["reader"],
            "scopes": [READ_SCOPE],
            "rate_limit_per_minute": DEFAULT_RATE_LIMIT_PER_MINUTE,
        })
    return entries


def require_api_key(scope=READ_SCOPE):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                return api_error("read_only_api", 405)
            supplied = request_api_key()
            if not supplied:
                return api_error("missing_api_key", 401)
            supplied_hash = hash_api_key(supplied)
            for entry in configured_api_keys():
                if hmac.compare_digest(supplied_hash, entry["key_hash"]):
                    if scope not in set(entry.get("scopes") or []):
                        return api_error("insufficient_scope", 403)
                    limited = rate_limited(entry)
                    if limited:
                        return limited
                    g.api_key = entry
                    return func(*args, **kwargs)
            return api_error("invalid_api_key", 401)
        return wrapper
    return decorator


def rate_limited(entry):
    now = int(time.time())
    window = now // 60
    key = (entry["id"], window)
    RATE_BUCKETS[key] = RATE_BUCKETS.get(key, 0) + 1
    for old_key in list(RATE_BUCKETS):
        if old_key[1] < window - 1:
            RATE_BUCKETS.pop(old_key, None)
    limit = max(1, int(entry.get("rate_limit_per_minute") or DEFAULT_RATE_LIMIT_PER_MINUTE))
    if RATE_BUCKETS[key] > limit:
        response = jsonify({"error": "rate_limited", "limit_per_minute": limit})
        response.status_code = 429
        response.headers["Retry-After"] = "60"
        return response
    return None


def api_error(code, status):
    response = jsonify({"error": code})
    response.status_code = status
    return response


def ensure_api_schema():
    con = connect_db()
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS api_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                api_key_id TEXT,
                method TEXT,
                path TEXT,
                remote_addr TEXT,
                user_agent TEXT,
                status_code INTEGER,
                elapsed_ms REAL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_api_audit_ts ON api_audit_log(ts)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_api_audit_key_ts ON api_audit_log(api_key_id, ts)")
        con.commit()
    finally:
        con.close()


def audit_api_request(status_code, elapsed_ms):
    if not request.path.startswith("/api/v1/"):
        return
    try:
        ensure_api_schema()
        con = connect_db()
        try:
            api_key = getattr(g, "api_key", {}) or {}
            con.execute(
                """
                INSERT INTO api_audit_log
                    (ts, api_key_id, method, path, remote_addr, user_agent, status_code, elapsed_ms)
                VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    api_key.get("id", ""),
                    request.method,
                    request.full_path.rstrip("?"),
                    request.remote_addr or "",
                    request.headers.get("User-Agent", "")[:300],
                    int(status_code or 0),
                    float(elapsed_ms or 0),
                ),
            )
            con.commit()
        finally:
            con.close()
    except Exception as error:
        print(f"API audit log failed: {error}")
