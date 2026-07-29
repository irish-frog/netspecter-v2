def _positive_int(value, default, minimum=1):
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    return max(minimum, parsed)


def summary_retention_days(config):
    return _positive_int((config or {}).get("dns_retention_days", 60), 60, 1)


def raw_retention_hours(config):
    return _positive_int((config or {}).get("raw_dns_retention_hours", 24), 24, 1)


def ensure_dns_daily_rollup_schema(con):
    attached = {row[1] for row in con.execute("PRAGMA database_list").fetchall()}
    schema = "dnsdb." if "dnsdb" in attached else ""
    con.execute(f"""
        CREATE TABLE IF NOT EXISTS {schema}dns_daily_rollups (
            day TEXT NOT NULL,
            client TEXT NOT NULL,
            domain TEXT NOT NULL,
            category TEXT DEFAULT 'Other',
            request_count INTEGER DEFAULT 0,
            blocked_count INTEGER DEFAULT 0,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            total_mb REAL DEFAULT 0,
            PRIMARY KEY (day, client, domain)
        )
    """)
    index_schema = "dnsdb." if "dnsdb" in attached else ""
    con.execute(f"CREATE INDEX IF NOT EXISTS {index_schema}idx_dns_daily_day_client ON dns_daily_rollups(day, client)")
    con.execute(f"CREATE INDEX IF NOT EXISTS {index_schema}idx_dns_daily_day_domain ON dns_daily_rollups(day, domain)")
    con.execute(f"CREATE INDEX IF NOT EXISTS {index_schema}idx_dns_daily_day_category ON dns_daily_rollups(day, category)")
    return f"{schema}dns_daily_rollups"


def refresh_dns_daily_rollups(con, config=None):
    """Build compact daily DNS/app rows before raw DNS is pruned."""
    rollup_table = ensure_dns_daily_rollup_schema(con)
    days = summary_retention_days(config)
    day_cutoff = f"-{days - 1} days"

    con.execute(
        f"""
        INSERT INTO {rollup_table}
            (day, client, domain, category, request_count, blocked_count,
             downloaded_mb, uploaded_mb, total_mb)
        SELECT
            day,
            client,
            domain,
            COALESCE(MAX(NULLIF(category, '')), 'Other') AS category,
            COUNT(*) AS request_count,
            SUM(CASE WHEN blocked=1 THEN 1 ELSE 0 END) AS blocked_count,
            0 AS downloaded_mb,
            0 AS uploaded_mb,
            0 AS total_mb
        FROM dns_querylog
        WHERE day >= date('now', 'localtime', ?)
          AND client IS NOT NULL AND client != ''
          AND domain IS NOT NULL AND domain != ''
        GROUP BY day, client, domain
        HAVING 1=1
        ON CONFLICT(day, client, domain) DO UPDATE SET
            category=excluded.category,
            request_count=excluded.request_count,
            blocked_count=excluded.blocked_count
        """,
        (day_cutoff,),
    )

    # Best-effort site bandwidth: match remote traffic intervals to client DNS
    # resolution evidence. Request counts stay exact even when bytes cannot be
    # attributed to a domain.
    con.execute(
        f"""
        WITH matched AS (
            SELECT DISTINCT
                r.id,
                r.day,
                r.ip AS client,
                e.domain,
                COALESCE(NULLIF(r.category, ''), 'Other') AS category,
                r.downloaded_mb,
                r.uploaded_mb,
                r.total_mb
            FROM remote_traffic_intervals r
            JOIN dns_resolution_events e
              ON e.client_ip=r.ip
             AND e.resolved_ip=r.remote_ip
             AND e.ts <= r.ts
             AND COALESCE(e.expires_at, datetime(e.ts, '+1 hour')) >= r.ts
            WHERE r.day >= date('now', 'localtime', ?)
              AND e.domain IS NOT NULL AND e.domain != ''
        ),
        usage AS (
            SELECT
                day,
                client,
                domain,
                COALESCE(MAX(NULLIF(category, '')), 'Other') AS category,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb
            FROM matched
            GROUP BY day, client, domain
        )
        INSERT INTO {rollup_table}
            (day, client, domain, category, request_count, blocked_count,
             downloaded_mb, uploaded_mb, total_mb)
        SELECT
            day,
            client,
            domain,
            category,
            0 AS request_count,
            0 AS blocked_count,
            COALESCE(downloaded_mb, 0),
            COALESCE(uploaded_mb, 0),
            COALESCE(total_mb, 0)
        FROM usage
        WHERE 1=1
        ON CONFLICT(day, client, domain) DO UPDATE SET
            downloaded_mb=excluded.downloaded_mb,
            uploaded_mb=excluded.uploaded_mb,
            total_mb=excluded.total_mb,
            category=CASE
                WHEN category IS NULL OR category=''
                THEN excluded.category
                ELSE category
            END
        """,
        (day_cutoff,),
    )


def prune_dns_history(con, config=None):
    refresh_dns_daily_rollups(con, config)
    rollup_table = ensure_dns_daily_rollup_schema(con)
    raw_hours = raw_retention_hours(config)
    days = summary_retention_days(config)
    raw_cutoff = f"-{raw_hours} hours"
    day_cutoff = f"-{days - 1} days"

    con.execute("DELETE FROM dns_querylog WHERE ts < datetime('now', 'localtime', ?)", (raw_cutoff,))
    con.execute("DELETE FROM dns_resolution_events WHERE ts < datetime('now', 'localtime', ?)", (raw_cutoff,))
    con.execute(f"DELETE FROM {rollup_table} WHERE day < date('now', 'localtime', ?)", (day_cutoff,))
    con.execute("DELETE FROM dns_resolved_ips WHERE resolved_ts < datetime('now', 'localtime', ?)", (day_cutoff,))
