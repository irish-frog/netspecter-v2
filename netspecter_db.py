import json
import sqlite3
import time
from pathlib import Path

from netspecter_paths import CACHE_PATH, DATA_ROOT, DB_PATH, DNS_DB_PATH, TRAFFIC_DB_PATH
from netspecter_anomaly import schema_sql as anomaly_schema_sql
from netspecter_incidents import incident_schema_sql


DB_INIT_DONE = False


def query(sql, params=()):
    for attempt in range(4):
        con = None
        try:
            init_db()
            con = connect_db()
            con.row_factory = sqlite3.Row
            rows = con.execute(sql, params).fetchall()
            con.close()
            return rows
        except sqlite3.OperationalError as e:
            if con:
                con.close()
            if "database is locked" in str(e).lower() and attempt < 3:
                time.sleep(0.25 * (attempt + 1))
                continue
            print(f"DB query failed: {e}")
            return []
        except Exception as e:
            if con:
                con.close()
            print(f"DB query failed: {e}")
            return []


def run_sql(sql, params=()):
    for attempt in range(4):
        con = None
        try:
            init_db()
            con = connect_db()
            cur = con.execute(sql, params)
            con.commit()
            con.close()
            return cur.rowcount
        except sqlite3.OperationalError as e:
            if con:
                con.close()
            if "database is locked" in str(e).lower() and attempt < 3:
                time.sleep(0.25 * (attempt + 1))
                continue
            print(f"DB write failed: {e}")
            return 0
        except Exception as e:
            if con:
                con.close()
            print(f"DB write failed: {e}")
            return 0


def load_json(path, default):
    try:
        p = Path(path)
        return json.loads(p.read_text()) if p.exists() else default
    except Exception:
        return default


def save_json(path, data):
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2))
    except Exception as e:
        print(f"JSON save failed for {path}: {e}")


def _sqlite_path(path):
    return str(Path(path)).replace("'", "''")


def attach_history_dbs(con):
    DNS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    TRAFFIC_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    attached = {row[1] for row in con.execute("PRAGMA database_list").fetchall()}
    if "dnsdb" not in attached:
        con.execute(f"ATTACH DATABASE '{_sqlite_path(DNS_DB_PATH)}' AS dnsdb")
        con.execute("PRAGMA dnsdb.journal_mode=WAL")
        con.execute("PRAGMA dnsdb.busy_timeout=30000")
    if "trafficdb" not in attached:
        con.execute(f"ATTACH DATABASE '{_sqlite_path(TRAFFIC_DB_PATH)}' AS trafficdb")
        con.execute("PRAGMA trafficdb.journal_mode=WAL")
        con.execute("PRAGMA trafficdb.busy_timeout=30000")


def connect_db():
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("PRAGMA busy_timeout=30000")
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA temp_store=MEMORY")
    con.execute("PRAGMA mmap_size=134217728")
    con.execute("PRAGMA wal_autocheckpoint=1000")
    attach_history_dbs(con)
    return con


def init_dns_db():
    DNS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DNS_DB_PATH, timeout=30)
    con.execute("PRAGMA busy_timeout=30000")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS dns_querylog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            day TEXT,
            ts TEXT,
            client TEXT,
            domain TEXT,
            blocked INTEGER DEFAULT 0,
            category TEXT DEFAULT 'Other'
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_day ON dns_querylog(day)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_client ON dns_querylog(client)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_day_category ON dns_querylog(day, category)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_day_domain ON dns_querylog(day, domain)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_day_blocked_domain ON dns_querylog(day, blocked, domain)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_day_category_client_domain ON dns_querylog(day, category, client, domain)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_ts_client ON dns_querylog(ts, client)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_client_ts ON dns_querylog(client, ts)")
    con.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_unique
        ON dns_querylog(ts, client, domain)
        """
    )
    con.execute("""
        CREATE TABLE IF NOT EXISTS dns_resolved_ips (
            domain TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            resolved_ts TEXT,
            PRIMARY KEY (domain, remote_ip)
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_resolved_domain ON dns_resolved_ips(domain)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_resolved_remote_ip ON dns_resolved_ips(remote_ip)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS dns_import_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            cleared_at TEXT
        )
    """)
    con.commit()
    con.close()


def init_traffic_db():
    TRAFFIC_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(TRAFFIC_DB_PATH, timeout=30)
    con.execute("PRAGMA busy_timeout=30000")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS traffic_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            name TEXT,
            mac TEXT,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            total_mb REAL DEFAULT 0,
            live_bps REAL DEFAULT 0,
            day TEXT,
            ts TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_day_ip ON traffic_samples(day, ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_ip_ts ON traffic_samples(ip, ts)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS traffic_intervals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            name TEXT,
            mac TEXT,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            total_mb REAL DEFAULT 0,
            live_bps REAL DEFAULT 0,
            day TEXT,
            ts TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_intervals_day_ip ON traffic_intervals(day, ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_intervals_ip_ts ON traffic_intervals(ip, ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_intervals_ts ON traffic_intervals(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_intervals_day_totals ON traffic_intervals(day, downloaded_mb, uploaded_mb, total_mb)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_intervals_ip_day_totals ON traffic_intervals(ip, day, downloaded_mb, uploaded_mb, total_mb)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_intervals_day_ip_totals ON traffic_intervals(day, ip, total_mb, downloaded_mb, uploaded_mb)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS estimated_app_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            category TEXT NOT NULL,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            total_mb REAL DEFAULT 0,
            day TEXT,
            ts TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_estimated_app_day_ip ON estimated_app_traffic(day, category, ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_estimated_app_day_category ON estimated_app_traffic(day, category, ip, total_mb, downloaded_mb, uploaded_mb)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS remote_traffic_intervals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            category TEXT NOT NULL,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            total_mb REAL DEFAULT 0,
            day TEXT,
            ts TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_remote_traffic_day_ip ON remote_traffic_intervals(day, remote_ip, category)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_remote_traffic_ts_ip ON remote_traffic_intervals(ts, ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_remote_traffic_ts_ip_remote ON remote_traffic_intervals(ts, ip, remote_ip)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS remote_ip_locations (
            remote_ip TEXT PRIMARY KEY,
            city TEXT,
            region TEXT,
            country TEXT,
            country_code TEXT,
            latitude REAL,
            longitude REAL,
            lookup_ts TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS live_device_speed (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            rx_bps REAL DEFAULT 0,
            tx_bps REAL DEFAULT 0,
            total_bps REAL DEFAULT 0,
            updated_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS collector_heartbeat (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            updated_at TEXT,
            packet_iface TEXT,
            status TEXT,
            note TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS speed_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            latency_ms REAL,
            download_mbps REAL,
            upload_mbps REAL,
            result_text TEXT,
            success INTEGER DEFAULT 0
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_speed_tests_ts ON speed_tests(ts)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS internet_quality (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            status TEXT NOT NULL,
            diagnosis TEXT,
            gateway_ip TEXT,
            gateway_latency_ms REAL,
            gateway_loss_pct REAL,
            internet_latency_ms REAL,
            internet_loss_pct REAL,
            jitter_ms REAL,
            dns_ms REAL,
            external_dns_ms REAL,
            wan_up INTEGER DEFAULT 0,
            targets_ok INTEGER DEFAULT 0,
            targets_total INTEGER DEFAULT 0,
            public_ip TEXT,
            isp_name TEXT,
            asn TEXT,
            isp_org TEXT,
            details TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_internet_quality_ts ON internet_quality(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_internet_quality_status ON internet_quality(status)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_internet_quality_isp ON internet_quality(asn, isp_name, public_ip)")
    con.commit()
    con.close()


def init_db(force=False):
    """Create the minimum database schema required by the web UI and collector."""
    global DB_INIT_DONE
    if DB_INIT_DONE and DB_PATH.exists() and DNS_DB_PATH.exists() and TRAFFIC_DB_PATH.exists() and not force:
        return

    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    init_dns_db()
    init_traffic_db()
    con = connect_db()
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            name TEXT,
            mac TEXT,
            vendor TEXT,
            device_type TEXT DEFAULT 'Unknown',
            status TEXT DEFAULT 'Active',
            first_seen TEXT,
            last_seen TEXT,
            owner TEXT,
            location TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS device_overrides (
            ip TEXT PRIMARY KEY,
            name TEXT,
            vendor TEXT,
            device_type TEXT,
            status TEXT,
            updated_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS device_override_unlocks (
            ip TEXT PRIMARY KEY,
            updated_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS user_labels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT NOT NULL,
            department TEXT,
            email TEXT,
            notes TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS user_device_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_ip TEXT NOT NULL,
            friendly_name TEXT,
            shared_device INTEGER DEFAULT 0,
            notes TEXT,
            assigned_from TEXT NOT NULL,
            assigned_to TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_user_labels_active ON user_labels(active, display_name)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_assignments_device_period ON user_device_assignments(device_ip, assigned_from, assigned_to)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_assignments_user_period ON user_device_assignments(user_id, assigned_from, assigned_to)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS application_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            slug TEXT NOT NULL UNIQUE,
            usage_group TEXT,
            description TEXT,
            icon TEXT,
            display_order INTEGER DEFAULT 999,
            enabled INTEGER DEFAULT 1,
            created_at TEXT,
            updated_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS application_subcategories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            slug TEXT NOT NULL,
            display_order INTEGER DEFAULT 999,
            enabled INTEGER DEFAULT 1,
            created_at TEXT,
            updated_at TEXT,
            UNIQUE(category_id, slug)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS application_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_name TEXT NOT NULL,
            category_id INTEGER,
            subcategory TEXT,
            primary_domain TEXT,
            risk_level TEXT DEFAULT 'normal',
            enabled INTEGER DEFAULT 1,
            created_at TEXT,
            updated_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS application_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mapping_id INTEGER NOT NULL,
            alias TEXT NOT NULL,
            created_at TEXT,
            UNIQUE(mapping_id, alias)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS application_domain_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mapping_id INTEGER,
            category_id INTEGER,
            domain_pattern TEXT NOT NULL,
            priority INTEGER DEFAULT 100,
            enabled INTEGER DEFAULT 1,
            created_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS application_tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mapping_id INTEGER NOT NULL,
            tag TEXT NOT NULL,
            created_at TEXT,
            UNIQUE(mapping_id, tag)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS site_category_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id TEXT DEFAULT 'default',
            application_name TEXT,
            domain_pattern TEXT,
            original_category_id INTEGER,
            override_category_id INTEGER,
            business_relevance TEXT,
            policy_status TEXT,
            reason TEXT,
            created_by TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS classification_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            application_name TEXT,
            domain TEXT,
            destination_ip TEXT,
            category TEXT,
            usage_group TEXT,
            classification_source TEXT,
            detail TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_app_categories_slug ON application_categories(slug)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_app_mappings_name ON application_mappings(application_name)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_app_mappings_category ON application_mappings(category_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_app_aliases_alias ON application_aliases(alias)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_app_domain_patterns_pattern ON application_domain_patterns(domain_pattern)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_site_overrides_site ON site_category_overrides(site_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_classification_audit_ts ON classification_audit(ts)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            metric TEXT NOT NULL,
            value TEXT,
            ts TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_source_target ON telemetry_readings(source, target, ts)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS monitor_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            monitor_key TEXT,
            name TEXT,
            url TEXT,
            state TEXT,
            ts INTEGER
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_monitor_events_key_ts ON monitor_events(monitor_key, ts)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS config_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            snapshot_json TEXT NOT NULL,
            is_baseline INTEGER DEFAULT 0
        )
    """)
    con.execute("""
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
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_snapshots_ts ON config_snapshots(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_snapshots_fingerprint ON config_snapshots(fingerprint)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_events_ts ON config_change_events(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_events_component ON config_change_events(component)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_events_severity ON config_change_events(severity)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_config_events_status ON config_change_events(status)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS threat_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            source TEXT NOT NULL,
            category TEXT,
            confidence INTEGER DEFAULT 50,
            reason TEXT,
            first_seen TEXT,
            last_seen TEXT,
            expires_at TEXT,
            active INTEGER DEFAULT 1,
            UNIQUE(indicator, indicator_type, source)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS threat_feed_state (
            source TEXT PRIMARY KEY,
            url TEXT,
            status TEXT,
            licence_status TEXT,
            fetched_at TEXT,
            indicator_count INTEGER DEFAULT 0,
            error TEXT,
            content_hash TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS threat_correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            ts TEXT NOT NULL,
            reputation TEXT NOT NULL,
            indicator TEXT,
            indicator_type TEXT,
            source TEXT,
            category TEXT,
            confidence INTEGER DEFAULT 0,
            reason TEXT,
            src_ip TEXT,
            dest_ip TEXT,
            domain TEXT,
            device_ip TEXT,
            country TEXT,
            asn TEXT,
            provider TEXT,
            first_seen TEXT,
            last_seen TEXT,
            total_mb REAL DEFAULT 0
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicators_indicator ON threat_indicators(indicator, indicator_type)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicators_active ON threat_indicators(active, expires_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_threat_corr_ts ON threat_correlations(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_threat_corr_reputation ON threat_correlations(reputation)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_threat_corr_indicator ON threat_correlations(indicator)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS ids_alert_notifications (
            alert_key TEXT PRIMARY KEY,
            last_sent_ts INTEGER
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS ids_eve_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            inode INTEGER DEFAULT 0,
            offset INTEGER DEFAULT 0,
            path TEXT,
            updated_at INTEGER DEFAULT 0
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS ids_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            ts TEXT NOT NULL,
            day TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            app_proto TEXT,
            flow_id TEXT,
            signature_id INTEGER,
            signature TEXT,
            category TEXT,
            application TEXT,
            severity INTEGER,
            query TEXT,
            query_type TEXT,
            rcode TEXT,
            answer_summary TEXT,
            hostname TEXT,
            method TEXT,
            url_path TEXT,
            user_agent TEXT,
            status INTEGER,
            tls_sni TEXT,
            tls_version TEXT,
            cert_subject TEXT,
            cert_issuer TEXT,
            ja3 TEXT,
            ja4 TEXT,
            filename TEXT,
            file_size INTEGER,
            mime_type TEXT,
            hashes TEXT,
            stored INTEGER DEFAULT 0,
            anomaly_event TEXT,
            alert_status TEXT DEFAULT 'open',
            first_seen TEXT,
            last_seen TEXT,
            alert_count INTEGER DEFAULT 1
        )
    """)
    for sql in (
        "ALTER TABLE ids_events ADD COLUMN alert_status TEXT DEFAULT 'open'",
        "ALTER TABLE ids_events ADD COLUMN first_seen TEXT",
        "ALTER TABLE ids_events ADD COLUMN last_seen TEXT",
        "ALTER TABLE ids_events ADD COLUMN alert_count INTEGER DEFAULT 1",
        "ALTER TABLE ids_events ADD COLUMN application TEXT",
    ):
        try:
            con.execute(sql)
        except sqlite3.OperationalError:
            pass
    con.execute("UPDATE ids_events SET first_seen=COALESCE(first_seen, ts), last_seen=COALESCE(last_seen, ts), alert_count=COALESCE(alert_count, 1)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_ts ON ids_events(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_src_ip ON ids_events(src_ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_dest_ip ON ids_events(dest_ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_type ON ids_events(event_type)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_signature ON ids_events(signature)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_application ON ids_events(application)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_day_type ON ids_events(day, event_type)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_alert_status ON ids_events(alert_status)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_alert_rollup ON ids_events(signature_id, src_ip, dest_ip, query, protocol)")
    con.execute(
        """
        INSERT OR IGNORE INTO ids_alert_notifications (alert_key, last_sent_ts)
        SELECT '__last_structured_id', COALESCE(MAX(id), 0)
        FROM ids_events
        WHERE event_type='alert'
        """
    )
    for sql in incident_schema_sql():
        con.execute(sql)
    con.execute("CREATE INDEX IF NOT EXISTS idx_incidents_last_event ON security_incidents(last_event_ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_incident_notes_incident_ts ON security_incident_notes(incident_id, ts)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS investigation_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            client_site TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT,
            assigned_technician TEXT,
            status TEXT DEFAULT 'Open',
            priority TEXT DEFAULT 'Standard',
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            selected_users TEXT,
            selected_devices TEXT,
            filters_json TEXT,
            findings_json TEXT,
            report_snapshot TEXT,
            notes TEXT,
            conclusion TEXT,
            recommended_actions TEXT,
            resolution TEXT,
            closed_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS investigation_case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            author TEXT,
            note TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_cases_status_created ON investigation_cases(status, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_cases_period ON investigation_cases(period_start, period_end)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_case_notes_case_ts ON investigation_case_notes(case_id, ts)")
    for sql in anomaly_schema_sql():
        con.execute(sql)
    con.commit()
    try:
        con.execute("PRAGMA optimize")
    except sqlite3.OperationalError:
        pass
    con.close()
    DB_INIT_DONE = True


def cache_get(key, max_age):
    data = load_json(CACHE_PATH, {})
    item = data.get(key)

    if not item:
        return None

    if time.time() - item.get("ts", 0) > max_age:
        return None

    return item.get("value")


def cache_value(key):
    item = load_json(CACHE_PATH, {}).get(key)
    return item.get("value") if isinstance(item, dict) else None


def cache_set(key, value):
    data = load_json(CACHE_PATH, {})
    data[key] = {"ts": time.time(), "value": value}
    save_json(CACHE_PATH, data)


def cache_delete_prefix(prefix):
    data = load_json(CACHE_PATH, {})
    changed = False
    for key in list(data.keys()):
        if str(key).startswith(prefix):
            data.pop(key, None)
            changed = True
    if changed:
        save_json(CACHE_PATH, data)


def cached_query(key, max_age, sql, params=()):
    """Cache short-lived page query results to make navigation feel lighter."""
    cached = cache_get(f"query:{key}", max_age)
    if cached is not None:
        return cached

    rows = [dict(row) for row in query(sql, params)]
    cache_set(f"query:{key}", rows)
    return rows
