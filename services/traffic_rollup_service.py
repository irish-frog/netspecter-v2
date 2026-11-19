"""Bridge history: atomically move disjoint raw batches into additive rollups."""


def bridge_history_source_sql(ignore_ip_filter='1=1'):
    # Rolled rows have been removed from raw in the same transaction. A global
    # MAX(hour) filter hides late arrivals and does not represent that invariant.
    return f"""
        SELECT ip,name,mac,downloaded_mb,uploaded_mb,total_mb,avg_live_bps AS live_bps,
               day,hour AS ts,hour FROM traffic_hourly_rollups WHERE {ignore_ip_filter}
        UNION ALL
        SELECT ip,name,mac,downloaded_mb,uploaded_mb,total_mb,live_bps,day,ts,
               substr(ts,1,13)||':00' AS hour FROM traffic_intervals WHERE {ignore_ip_filter}
    """


def compact_bridge_intervals(con,cutoff):
    """Start a transaction if needed; caller commits/rolls back both statements."""
    if getattr(con,'autocommit',None) is True:
        raise ValueError('Bridge compaction requires caller-managed commit/rollback')
    if not con.in_transaction:con.execute('BEGIN')
    con.execute("""INSERT INTO traffic_hourly_rollups
        (hour,day,ip,name,mac,downloaded_mb,uploaded_mb,total_mb,avg_live_bps,samples)
        SELECT substr(ts,1,13)||':00',day,ip,COALESCE(MAX(NULLIF(name,'')),ip),
               COALESCE(MAX(NULLIF(mac,'')),''),COALESCE(SUM(downloaded_mb),0),COALESCE(SUM(uploaded_mb),0),COALESCE(SUM(total_mb),0),
               CASE WHEN COUNT(live_bps)=COUNT(*) THEN AVG(live_bps) ELSE NULL END,COUNT(*)
        FROM traffic_intervals WHERE ts<? GROUP BY substr(ts,1,13)||':00',day,ip
        ON CONFLICT(hour,ip) DO UPDATE SET
            name=excluded.name,mac=CASE WHEN excluded.mac!='' THEN excluded.mac ELSE mac END,
            downloaded_mb=COALESCE(traffic_hourly_rollups.downloaded_mb,0)+excluded.downloaded_mb,
            uploaded_mb=COALESCE(traffic_hourly_rollups.uploaded_mb,0)+excluded.uploaded_mb,
            total_mb=COALESCE(traffic_hourly_rollups.total_mb,0)+excluded.total_mb,
            avg_live_bps=CASE WHEN traffic_hourly_rollups.samples IS NULL THEN NULL
                WHEN traffic_hourly_rollups.samples=0 THEN excluded.avg_live_bps
                ELSE (traffic_hourly_rollups.avg_live_bps*traffic_hourly_rollups.samples+
                      excluded.avg_live_bps*excluded.samples)/(traffic_hourly_rollups.samples+excluded.samples) END,
            samples=COALESCE(traffic_hourly_rollups.samples,0)+excluded.samples""",(cutoff,))
    con.execute('DELETE FROM traffic_intervals WHERE ts<?',(cutoff,))
