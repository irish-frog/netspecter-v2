import inspect
import json
import sqlite3
import subprocess

import live_packet_collector
from services import report_context_service
from services.classification_resolver_service import (
    Flow,
    classify_flow,
    dns_answer_rows,
    upsert_unknown_traffic,
    write_classified_flow_fact,
)
from services import application_signature_service
from services.application_signature_service import create_application_signature
from services.suricata_classification_service import enrich_from_suricata_metadata, reclassify_unknown_queue


def memory_db():
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute(
        """
        CREATE TABLE dns_resolution_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            domain TEXT NOT NULL,
            resolved_ip TEXT NOT NULL,
            ttl INTEGER,
            expires_at TEXT,
            source TEXT DEFAULT 'adguard'
        )
        """
    )
    con.execute(
        """
        CREATE TABLE classified_flow_facts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            day TEXT NOT NULL,
            local_ip TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            port INTEGER,
            protocol TEXT,
            bytes INTEGER NOT NULL,
            category TEXT NOT NULL,
            application TEXT,
            evidence_source TEXT NOT NULL,
            confidence TEXT NOT NULL,
            flow_id TEXT
        )
        """
    )
    con.execute(
        """
        CREATE TABLE remote_traffic_intervals (
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
        """
    )
    con.execute(
        """
        CREATE TABLE unknown_traffic_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            local_ip TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            port INTEGER,
            protocol TEXT,
            total_bytes INTEGER DEFAULT 0,
            flow_count INTEGER DEFAULT 0,
            asn TEXT,
            provider TEXT,
            sample_sni TEXT,
            sample_http_host TEXT,
            status TEXT DEFAULT 'new',
            UNIQUE(local_ip, remote_ip, port, protocol)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE ids_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            ts TEXT NOT NULL,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            app_proto TEXT,
            flow_id TEXT,
            tls_sni TEXT,
            hostname TEXT
        )
        """
    )
    con.execute(
        """
        CREATE TABLE classification_enrichment_state (
            source TEXT PRIMARY KEY,
            last_id INTEGER DEFAULT 0,
            updated_at TEXT
        )
        """
    )
    return con


def test_dns_answer_rows_preserve_client_ip_ttl_and_expiry():
    rows = dns_answer_rows(
        "192.168.99.50",
        "e7a37f2d.hvcdn.to",
        [{"type": "A", "value": "203.0.113.10", "ttl": 120}, {"type": "TXT", "value": "skip"}],
        "2026-07-24 10:00:00",
    )

    assert rows == [(
        "2026-07-24 10:00:00",
        "192.168.99.50",
        "e7a37f2d.hvcdn.to",
        "203.0.113.10",
        120,
        "2026-07-24 10:02:00",
        "adguard",
    )]


def test_classify_flow_prefers_dns_resolution_before_sni(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-07-24 10:00:00', '192.168.99.50', 'e7a37f2d.hvcdn.to', '203.0.113.10', 900, '2026-07-24 10:15:00')
        """
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", **_kwargs: {"primary_category": "Video Streaming", "category": "Video Streaming"},
    )

    result = classify_flow(con, Flow(
        ts="2026-07-24 10:01:00",
        local_ip="192.168.99.50",
        remote_ip="203.0.113.10",
        tls_sni="different.example",
        bytes=2048,
    ))

    assert result.category == "Video Streaming"
    assert result.application == "e7a37f2d.hvcdn.to"
    assert result.evidence_source == "dns_resolution"
    assert result.confidence == "high"


def test_unknown_queue_merges_by_local_remote_port_protocol():
    con = memory_db()
    flow = Flow(
        ts="2026-07-24 10:01:00",
        local_ip="192.168.99.88",
        remote_ip="203.0.113.44",
        port=443,
        protocol="tcp",
        bytes=100,
        tls_sni="",
    )
    upsert_unknown_traffic(con, flow)
    upsert_unknown_traffic(con, Flow(**{**flow.__dict__, "ts": "2026-07-24 10:02:00", "bytes": 50, "http_host": "later.example"}))

    row = con.execute("SELECT * FROM unknown_traffic_queue").fetchone()
    assert row["total_bytes"] == 150
    assert row["flow_count"] == 2
    assert row["first_seen"] == "2026-07-24 10:01:00"
    assert row["last_seen"] == "2026-07-24 10:02:00"
    assert row["sample_http_host"] == "later.example"


def test_write_classified_flow_fact_uses_precomputed_classification():
    con = memory_db()
    flow = Flow(ts="2026-07-24 10:01:00", local_ip="192.168.99.50", remote_ip="203.0.113.10", bytes=2048, port=443, protocol="tcp")
    classification = classify_flow(con, Flow(**{**flow.__dict__, "tls_sni": "www.youtube.com"}))
    write_classified_flow_fact(con, flow, classification)

    row = con.execute("SELECT * FROM classified_flow_facts").fetchone()
    assert row["day"] == "2026-07-24"
    assert row["evidence_source"] == "tls_sni"
    assert row["confidence"] == "high"


def test_report_context_reads_precomputed_tables_without_reverse_dns():
    source = inspect.getsource(report_context_service.classified_flow_summary)
    source += inspect.getsource(report_context_service.top_unknown_destinations)
    source += inspect.getsource(report_context_service.unknown_traffic_trend)
    source += inspect.getsource(report_context_service.classified_flow_source_sql)

    assert "gethostbyaddr" not in source
    assert "dns_resolution_events" not in source
    assert "classified_flow_facts" in source
    assert "unknown_traffic_queue" in source


def test_classified_flow_source_includes_rollups_without_correlation_tables():
    source = report_context_service.classified_flow_source_sql()

    assert "classified_flow_facts" in source
    assert "classified_flow_rollups" in source
    assert "dns_resolution_events" not in source
    assert "gethostbyaddr" not in source


def test_suricata_metadata_enrichment_classifies_tls_sni(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO ids_events (
            event_type, ts, src_ip, src_port, dest_ip, dest_port, protocol,
            app_proto, flow_id, tls_sni, hostname
        )
        VALUES ('tls', '2026-07-24T10:01:00.000000+0200', '192.168.99.50', 51500,
                '203.0.113.10', 443, 'TCP', 'tls', 'flow-1', 'e7a37f2d.hvcdn.to', '')
        """
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", **_kwargs: {"primary_category": "Video Streaming", "category": "Video Streaming"},
    )

    result = enrich_from_suricata_metadata(con)

    assert result["processed"] == 1
    assert result["classified"] == 1
    fact = con.execute("SELECT * FROM classified_flow_facts").fetchone()
    assert fact["application"] == "e7a37f2d.hvcdn.to"
    assert fact["evidence_source"] == "tls_sni"
    state = con.execute("SELECT last_id FROM classification_enrichment_state WHERE source='suricata_metadata'").fetchone()
    assert state["last_id"] == 1


def test_suricata_metadata_enrichment_updates_unknown_with_later_http_host(monkeypatch):
    con = memory_db()
    upsert_unknown_traffic(con, Flow(
        ts="2026-07-24 10:00:00",
        local_ip="192.168.99.88",
        remote_ip="203.0.113.44",
        port=80,
        protocol="tcp",
        bytes=500,
    ))
    con.execute(
        """
        INSERT INTO ids_events (
            event_type, ts, src_ip, src_port, dest_ip, dest_port, protocol,
            app_proto, flow_id, tls_sni, hostname
        )
        VALUES ('http', '2026-07-24 10:01:00', '192.168.99.88', 51500,
                '203.0.113.44', 80, 'TCP', 'http', 'flow-2', '', 'example.com')
        """
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", **_kwargs: {"primary_category": "Web Browsing", "category": "Web Browsing"},
    )

    result = enrich_from_suricata_metadata(con)

    assert result["classified"] == 1
    row = con.execute("SELECT * FROM unknown_traffic_queue").fetchone()
    assert row["sample_http_host"] == "example.com"
    assert row["status"] == "enriched"


def test_builtin_provider_fallback_classifies_common_asn():
    result = classify_flow(memory_db(), Flow(
        ts="2026-07-24 10:00:00",
        local_ip="192.168.99.99",
        remote_ip="1.1.1.1",
        port=443,
        protocol="tcp",
        provider="Cloudflare",
    ))

    assert result.category == "Cloud Infrastructure"
    assert result.application == "Cloudflare"
    assert result.evidence_source == "asn_provider"
    assert result.confidence == "medium"


def test_unknown_queue_reclassification_promotes_provider_match():
    con = memory_db()
    upsert_unknown_traffic(con, Flow(
        ts="2026-07-24 10:00:00",
        local_ip="192.168.99.88",
        remote_ip="1.1.1.1",
        port=443,
        protocol="tcp",
        bytes=4096,
        provider="Cloudflare",
    ))

    result = reclassify_unknown_queue(con)

    assert result["classified"] == 1
    queue_row = con.execute("SELECT status FROM unknown_traffic_queue").fetchone()
    assert queue_row["status"] == "classified"
    fact = con.execute("SELECT category, evidence_source, bytes FROM classified_flow_facts").fetchone()
    assert fact["category"] == "Cloud Infrastructure"
    assert fact["evidence_source"] == "asn_provider"
    assert fact["bytes"] == 4096


def test_operator_signature_helper_stores_rule_payload(monkeypatch):
    calls = []
    monkeypatch.setattr(application_signature_service, "run_sql", lambda sql, params=(): calls.append((sql, params)))

    create_application_signature(
        "Plex CDN",
        "Video Streaming",
        domains=["*.hvcdn.to"],
        destination_ips=["203.0.113.10"],
        ports=["443"],
        protocols=["TCP"],
        tags=["Operator rule"],
    )

    _sql, params = calls[0]
    assert params[0] == "Plex CDN"
    assert params[1] == "Video Streaming"
    assert params[2] == '["*.hvcdn.to"]'
    assert params[4] == '["203.0.113.10"]'
    assert params[5] == '["443"]'
    assert params[6] == '["tcp"]'
    assert params[7] == '["Operator rule"]'


def test_read_nft_counters_parses_classification_counters(monkeypatch):
    payload = {
        "nftables": [
            {"rule": {"comment": "netspecter:classify:tx:192.168.99.50:203.0.113.10", "expr": [{"counter": {"bytes": 100}}]}},
            {"rule": {"comment": "netspecter:classify:rx:192.168.99.50:203.0.113.10", "expr": [{"counter": {"bytes": 250}}]}},
        ]
    }

    monkeypatch.setattr(
        live_packet_collector.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, json.dumps(payload), ""),
    )

    _device, _estimated, classification = live_packet_collector.read_nft_counters()

    assert classification[("tx", "192.168.99.50", "203.0.113.10")] == 100
    assert classification[("rx", "192.168.99.50", "203.0.113.10")] == 250


def test_write_destination_delta_records_fact_or_unknown(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-07-24 10:00:00', '192.168.99.50', 'e7a37f2d.hvcdn.to', '203.0.113.10', 900, '2026-07-24 10:15:00')
        """
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", **_kwargs: {"primary_category": "Video Streaming", "category": "Video Streaming"},
    )

    live_packet_collector.write_destination_delta(
        con,
        "192.168.99.50",
        "203.0.113.10",
        {"rx": 1024, "tx": 1024},
        "2026-07-24",
        "2026-07-24 10:01:00",
    )

    fact = con.execute("SELECT * FROM classified_flow_facts").fetchone()
    remote = con.execute("SELECT * FROM remote_traffic_intervals").fetchone()
    assert fact["application"] == "e7a37f2d.hvcdn.to"
    assert remote["category"] == "Video Streaming"
