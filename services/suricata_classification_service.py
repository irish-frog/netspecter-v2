from datetime import datetime

from services.classification_resolver_service import (
    Flow,
    classify_flow,
    upsert_unknown_traffic,
    write_classified_flow_fact,
)


SOURCE_KEY = "suricata_metadata"
SUPPORTED_TYPES = ("tls", "http", "alert")


def enrich_from_suricata_metadata(con, batch_size=500):
    state = con.execute(
        "SELECT last_id FROM classification_enrichment_state WHERE source=?",
        (SOURCE_KEY,),
    ).fetchone()
    last_id = int(state["last_id"] if state else 0)
    limit = max(1, min(5000, int(batch_size or 500)))
    rows = con.execute(
        f"""
        SELECT id, event_type, ts, src_ip, src_port, dest_ip, dest_port, protocol,
               app_proto, flow_id, tls_sni, hostname
        FROM ids_events
        WHERE id > ?
          AND event_type IN ({",".join(["?"] * len(SUPPORTED_TYPES))})
          AND src_ip IS NOT NULL
          AND TRIM(src_ip) != ''
          AND dest_ip IS NOT NULL
          AND TRIM(dest_ip) != ''
        ORDER BY id ASC
        LIMIT ?
        """,
        (last_id, *SUPPORTED_TYPES, limit),
    ).fetchall()
    if not rows:
        return {"processed": 0, "classified": 0, "unknown": 0, "last_id": last_id}

    processed = classified_count = unknown_count = 0
    max_id = last_id
    for row in rows:
        max_id = max(max_id, int(row["id"]))
        flow = _flow_from_event(row)
        if not flow:
            continue
        classification = classify_flow(con, flow)
        if classification:
            write_classified_flow_fact(con, flow, classification)
            _update_matching_unknowns(con, flow)
            classified_count += 1
        else:
            upsert_unknown_traffic(con, flow)
            unknown_count += 1
        processed += 1

    con.execute(
        """
        INSERT INTO classification_enrichment_state (source, last_id, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
            last_id=MAX(last_id, excluded.last_id),
            updated_at=excluded.updated_at
        """,
        (SOURCE_KEY, max_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    return {"processed": processed, "classified": classified_count, "unknown": unknown_count, "last_id": max_id}


def reclassify_unknown_queue(con, batch_size=200):
    limit = max(1, min(1000, int(batch_size or 200)))
    rows = con.execute(
        """
        SELECT id, first_seen, last_seen, local_ip, remote_ip, port, protocol,
               total_bytes, asn, provider, sample_sni, sample_http_host
        FROM unknown_traffic_queue
        WHERE status IN ('new', 'review', 'enriched')
        ORDER BY total_bytes DESC, last_seen DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    processed = classified_count = 0
    for row in rows:
        flow = Flow(
            ts=str(row["last_seen"] or row["first_seen"]),
            local_ip=str(row["local_ip"] or "").strip(),
            remote_ip=str(row["remote_ip"] or "").strip(),
            port=row["port"],
            protocol=str(row["protocol"] or "").strip().lower(),
            bytes=int(row["total_bytes"] or 0),
            tls_sni=str(row["sample_sni"] or "").strip(),
            http_host=str(row["sample_http_host"] or "").strip(),
            asn=str(row["asn"] or "").strip(),
            provider=str(row["provider"] or "").strip(),
            flow_id=f"unknown:{row['id']}:{row['last_seen']}",
        )
        classification = classify_flow(con, flow)
        if classification:
            write_classified_flow_fact(con, flow, classification)
            con.execute(
                """
                UPDATE unknown_traffic_queue
                SET status='classified'
                WHERE id=?
                """,
                (row["id"],),
            )
            classified_count += 1
        processed += 1
    return {"processed": processed, "classified": classified_count}


def _flow_from_event(row):
    tls_sni = str(row["tls_sni"] or "").strip()
    http_host = str(row["hostname"] or "").strip()
    app_proto = str(row["app_proto"] or "").strip()
    if not (tls_sni or http_host or app_proto):
        return None
    return Flow(
        ts=_normalise_ts(row["ts"]),
        local_ip=str(row["src_ip"] or "").strip(),
        remote_ip=str(row["dest_ip"] or "").strip(),
        port=row["dest_port"],
        protocol=str(row["protocol"] or "").strip().lower(),
        tls_sni=tls_sni,
        http_host=http_host,
        app_proto=app_proto,
        flow_id=str(row["flow_id"] or f"ids:{row['id']}").strip(),
    )


def _update_matching_unknowns(con, flow):
    con.execute(
        """
        UPDATE unknown_traffic_queue
        SET sample_sni=COALESCE(NULLIF(?, ''), sample_sni),
            sample_http_host=COALESCE(NULLIF(?, ''), sample_http_host),
            status=CASE WHEN status='new' THEN 'enriched' ELSE status END
        WHERE local_ip=?
          AND remote_ip=?
          AND (port IS NULL OR port=?)
          AND (protocol IS NULL OR protocol='' OR protocol=?)
        """,
        (
            flow.tls_sni,
            flow.http_host,
            flow.local_ip,
            flow.remote_ip,
            flow.port,
            flow.protocol or flow.app_proto,
        ),
    )


def _normalise_ts(value):
    text = str(value or "").strip()
    if "T" in text:
        text = text.replace("T", " ")
    if "+" in text:
        text = text.split("+", 1)[0]
    if "." in text:
        text = text.split(".", 1)[0]
    return text[:19] if len(text) >= 19 else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
