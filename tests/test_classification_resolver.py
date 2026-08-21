import inspect
import json
import sqlite3
import subprocess

import live_packet_collector
from services import report_context_service
from services.classification_resolver_service import (
    Classification,
    Flow,
    classify_flow,
    dns_resolution_table_name,
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
        CREATE UNIQUE INDEX idx_dns_resolution_unique_event
        ON dns_resolution_events(client_ip, domain, resolved_ip, ts, expires_at)
        """
    )
    con.execute(
        """
        CREATE TABLE estimated_app_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
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
        CREATE TABLE traffic_intervals (
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


def test_classify_flow_ignores_expired_or_other_client_dns_mapping(monkeypatch):
    con = memory_db()
    con.executemany(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            ("2026-07-24 10:00:00", "192.168.99.50", "expired.example", "203.0.113.10", 60, "2026-07-24 10:01:00"),
            ("2026-07-24 10:02:00", "192.168.99.51", "other-client.example", "203.0.113.10", 900, "2026-07-24 10:17:00"),
        ],
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", **_kwargs: {"primary_category": "Video Streaming", "category": "Video Streaming"} if domain else {"primary_category": "Unknown", "category": "Unknown"},
    )

    result = classify_flow(con, Flow(
        ts="2026-07-24 10:05:00",
        local_ip="192.168.99.50",
        remote_ip="203.0.113.10",
    ))

    assert result is None


def test_classify_flow_uses_most_recent_valid_dns_mapping(monkeypatch):
    con = memory_db()
    con.executemany(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            ("2026-07-24 10:00:00", "192.168.99.50", "old.example", "203.0.113.10", 900, "2026-07-24 10:15:00"),
            ("2026-07-24 10:03:00", "192.168.99.50", "new.example", "203.0.113.10", 900, "2026-07-24 10:18:00"),
        ],
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", **_kwargs: {"primary_category": "File Sharing & Storage", "category": "File Sharing & Storage"} if domain else {"primary_category": "Unknown", "category": "Unknown"},
    )

    result = classify_flow(con, Flow(
        ts="2026-07-24 10:05:00",
        local_ip="192.168.99.50",
        remote_ip="203.0.113.10",
    ))

    assert result.application == "new.example"
    assert result.evidence_source == "dns_resolution"


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


def test_operator_signature_helper_invalidates_signature_cache(monkeypatch):
    application_signature_service._SIGNATURE_CACHE.update({
        "expires_at": 999999.0,
        "category_key": "cached",
        "signatures": [{"app": "Old"}],
    })
    monkeypatch.setattr(application_signature_service, "run_sql", lambda sql, params=(): None)

    create_application_signature("Microsoft Updates", "Software Updates", destination_ips=["13.107.136.10"])

    assert application_signature_service._SIGNATURE_CACHE["expires_at"] == 0.0
    assert application_signature_service._SIGNATURE_CACHE["category_key"] == ""
    assert application_signature_service._SIGNATURE_CACHE["signatures"] == []


def test_reclassify_unknown_queue_uses_destination_ip_signature_after_unknown_dns(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-08-06 13:20:00', '192.168.1.89', 'unknown.example', '13.107.136.10', 900, '2026-08-06 13:35:00')
        """
    )
    upsert_unknown_traffic(con, Flow(
        ts="2026-08-06 13:21:24",
        local_ip="192.168.1.89",
        remote_ip="13.107.136.10",
        port=None,
        protocol="tcp",
        bytes=61761126,
    ))

    def fake_classify_application(domain="", destination_ip="", **_kwargs):
        if domain:
            return {"primary_category": "Unknown", "category": "Unknown"}
        if destination_ip == "13.107.136.10":
            return {
                "primary_category": "Software Updates",
                "category": "Software Updates",
                "primary_app": "Microsoft Updates",
            }
        return {"primary_category": "Unknown", "category": "Unknown"}

    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        fake_classify_application,
    )

    result = reclassify_unknown_queue(con)

    assert result["classified"] == 1
    queue_row = con.execute("SELECT status FROM unknown_traffic_queue").fetchone()
    assert queue_row["status"] == "classified"
    fact = con.execute("SELECT category, application, evidence_source FROM classified_flow_facts").fetchone()
    assert fact["category"] == "Software Updates"
    assert fact["application"] == "Microsoft Updates"
    assert fact["evidence_source"] == "destination_signature"


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

    _device, _estimated, classification, _visibility = live_packet_collector.read_nft_counters()

    assert classification[("tx", "192.168.99.50", "203.0.113.10")] == 100
    assert classification[("rx", "192.168.99.50", "203.0.113.10")] == 250


def test_read_nft_counters_parses_visibility_counters(monkeypatch):
    payload = {
        "nftables": [
            {"rule": {"comment": "netspecter:visible:tx:192.168.99.50:203.0.113.10", "expr": [{"counter": {"bytes": 100}}]}},
            {"rule": {"comment": "netspecter:visible:rx:192.168.99.50:203.0.113.10", "expr": [{"counter": {"bytes": 250}}]}},
        ]
    }

    monkeypatch.setattr(
        live_packet_collector.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, json.dumps(payload), ""),
    )

    _device, _estimated, _classification, visibility = live_packet_collector.read_nft_counters()

    assert visibility[("tx", "192.168.99.50", "203.0.113.10")] == 100
    assert visibility[("rx", "192.168.99.50", "203.0.113.10")] == 250


def test_configured_local_app_ip_creates_estimated_target_from_dns_answer():
    config = {
        "lan_prefix": "192.168.99.",
        "site_application_mappings": [
            {"application": "Customer File Server", "category": "File Sharing & Storage", "ip": "192.168.99.4"}
        ],
    }
    live_packet_collector.estimated_app_targets.clear()

    live_packet_collector.remember_estimated_app_targets(
        config,
        "192.168.99.50",
        "fileserver.lan",
        [{"type": "A", "value": "192.168.99.4", "ttl": 900}],
        "",
        False,
    )

    assert (
        "Customer File Server",
        "192.168.99.50",
        "192.168.99.4",
    ) in live_packet_collector.active_estimated_app_targets()


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
    estimated = con.execute("SELECT * FROM estimated_app_traffic").fetchone()
    assert fact["application"] == "e7a37f2d.hvcdn.to"
    assert remote["category"] == "Video Streaming"
    assert estimated["ip"] == "192.168.99.50"
    assert estimated["category"] == "Video Streaming"
    assert estimated["total_mb"] == 2048 / 1024 / 1024


def test_adguard_sharepoint_destination_bytes_reach_estimated_app_traffic_once(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-08-07 10:00:00', '192.168.1.44', 'wslcoza-my.sharepoint.com', '13.107.136.10', 177, '2026-08-07 10:02:57')
        """
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", **_kwargs: {"primary_category": "File Sharing & Storage", "category": "File Sharing & Storage"} if domain else {"primary_category": "Unknown", "category": "Unknown"},
    )

    live_packet_collector.write_destination_delta(
        con,
        "192.168.1.44",
        "13.107.136.10",
        {"rx": 4096, "tx": 1024},
        "2026-08-07",
        "2026-08-07 10:01:00",
    )

    estimated_rows = con.execute("SELECT * FROM estimated_app_traffic").fetchall()
    fact = con.execute("SELECT * FROM classified_flow_facts").fetchone()
    remote = con.execute("SELECT * FROM remote_traffic_intervals").fetchone()
    assert len(estimated_rows) == 1
    assert estimated_rows[0]["ip"] == "192.168.1.44"
    assert estimated_rows[0]["category"] == "File Sharing & Storage"
    assert estimated_rows[0]["total_mb"] == 5120 / 1024 / 1024
    assert fact["application"] == "wslcoza-my.sharepoint.com"
    assert fact["evidence_source"] == "dns_resolution"
    assert remote["remote_ip"] == "13.107.136.10"
    assert remote["category"] == "File Sharing & Storage"


def test_destination_delta_writes_attached_trafficdb_tables(monkeypatch):
    con = memory_db()
    con.execute("ATTACH DATABASE ':memory:' AS trafficdb")
    con.execute(
        """
        CREATE TABLE trafficdb.estimated_app_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
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
        CREATE TABLE trafficdb.remote_traffic_intervals (
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
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-08-07 10:00:00', '192.168.1.44', 'wslcoza-my.sharepoint.com', '13.107.136.10', 177, '2026-08-07 10:02:57')
        """
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", **_kwargs: {"primary_category": "File Sharing & Storage", "category": "File Sharing & Storage"} if domain else {"primary_category": "Unknown", "category": "Unknown"},
    )

    live_packet_collector.write_destination_delta(
        con,
        "192.168.1.44",
        "13.107.136.10",
        {"rx": 4096, "tx": 1024},
        "2026-08-07",
        "2026-08-07 10:01:00",
    )

    assert con.execute("SELECT COUNT(*) FROM estimated_app_traffic").fetchone()[0] == 0
    assert con.execute("SELECT COUNT(*) FROM remote_traffic_intervals").fetchone()[0] == 0
    assert con.execute("SELECT COUNT(*) FROM trafficdb.estimated_app_traffic").fetchone()[0] == 1
    assert con.execute("SELECT COUNT(*) FROM trafficdb.remote_traffic_intervals").fetchone()[0] == 1


def test_active_classification_targets_reads_valid_adguard_client_destination(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-08-07 10:00:00', '192.168.1.44', 'wslcoza-my.sharepoint.com', '13.107.136.10', 177, datetime('now', 'localtime', '+2 minutes'))
        """
    )
    monkeypatch.setattr(live_packet_collector, "connect_db", lambda *args, **_kwargs: con)

    targets = live_packet_collector.active_classification_targets({
        "lan_prefix": "192.168.1.",
        "classification_nft_target_limit": 10,
    })

    assert ("192.168.1.44", "13.107.136.10") in targets


def test_conntrack_classification_targets_extracts_lan_external_pairs():
    network = live_packet_collector.lan_network({"lan_prefix": "192.168.1."})
    lines = [
        "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.142 dst=169.1.36.238 sport=54321 dport=443 src=169.1.36.238 dst=165.255.241.41 sport=443 dport=54321 [ASSURED]",
        "ipv4 2 udp 17 29 src=169.1.36.238 dst=192.168.1.142 sport=443 dport=54321 src=192.168.1.142 dst=169.1.36.238 sport=54321 dport=443",
        "ipv4 2 tcp 6 11 src=192.168.1.1 dst=192.168.1.142 sport=1 dport=1",
    ]

    targets = [
        live_packet_collector.conntrack_lan_external_pair(line, network)
        for line in lines
    ]

    assert targets[0] == ("192.168.1.142", "169.1.36.238")
    assert targets[1] == ("192.168.1.142", "169.1.36.238")
    assert targets[2] is None


def test_active_classification_targets_includes_bounded_conntrack_pairs(monkeypatch):
    monkeypatch.setattr(live_packet_collector, "dns_classification_targets", lambda *_args: tuple())
    monkeypatch.setattr(
        live_packet_collector,
        "iter_conntrack_lines",
        lambda _limit: iter([
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.142 dst=169.1.36.238 sport=54321 dport=443 src=169.1.36.238 dst=165.255.241.41 sport=443 dport=54321 [ASSURED]",
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.142 dst=169.1.36.237 sport=54322 dport=443 src=169.1.36.237 dst=165.255.241.41 sport=443 dport=54322 [ASSURED]",
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.142 dst=169.1.36.236 sport=54323 dport=443 src=169.1.36.236 dst=165.255.241.41 sport=443 dport=54323 [ASSURED]",
        ]),
    )

    targets = live_packet_collector.active_classification_targets({
        "lan_prefix": "192.168.1.",
        "classification_nft_target_limit": 2,
        "destination_attribution_conntrack_enabled": True,
        "classification_conntrack_per_device_limit": 2,
    })

    assert targets == (
        ("192.168.1.142", "169.1.36.237"),
        ("192.168.1.142", "169.1.36.238"),
    )


def test_active_classification_targets_global_cap_wins_over_per_device_conntrack_limit(monkeypatch):
    monkeypatch.setattr(live_packet_collector, "dns_classification_targets", lambda *_args: tuple())

    lines = []
    for device in range(1, 101):
        for dest in range(1, 6):
            lines.append(
                "ipv4 2 tcp 6 431999 ESTABLISHED "
                f"src=192.168.1.{device} dst=169.1.{device}.{dest} sport=5{device:02d}{dest} dport=443 "
                f"src=169.1.{device}.{dest} dst=165.255.241.41 sport=443 dport=5{device:02d}{dest} [ASSURED]"
            )
    monkeypatch.setattr(live_packet_collector, "iter_conntrack_lines", lambda _limit: iter(lines))

    targets = live_packet_collector.active_classification_targets({
        "lan_prefix": "192.168.1.",
        "classification_nft_target_limit": 300,
        "destination_attribution_conntrack_enabled": True,
        "classification_conntrack_per_device_limit": 5,
    })

    assert len(targets) == 300
    assert len(set(targets)) == 300


def test_conntrack_classification_targets_disappear_when_conntrack_source_disappears(monkeypatch):
    monkeypatch.setattr(live_packet_collector, "dns_classification_targets", lambda *_args: tuple())
    config = {
        "lan_prefix": "192.168.1.",
        "classification_nft_target_limit": 300,
        "destination_attribution_conntrack_enabled": True,
    }

    monkeypatch.setattr(
        live_packet_collector,
        "iter_conntrack_lines",
        lambda _limit: iter([
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.142 dst=169.1.36.238 sport=54321 dport=443 src=169.1.36.238 dst=165.255.241.41 sport=443 dport=54321 [ASSURED]",
        ]),
    )
    first_signature = live_packet_collector.nft_signature(config)

    monkeypatch.setattr(live_packet_collector, "iter_conntrack_lines", lambda _limit: iter([]))
    second_signature = live_packet_collector.nft_signature(config)

    assert ("192.168.1.142", "169.1.36.238") in first_signature[-1]
    assert ("192.168.1.142", "169.1.36.238") not in second_signature[-1]
    assert second_signature[-1] == tuple()


def test_active_classification_targets_keeps_recent_expired_dns_destination(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES (datetime('now', 'localtime', '-2 hours'), '192.168.1.44', 'wslcoza-my.sharepoint.com', '13.107.136.10', 177, datetime('now', 'localtime', '-90 minutes'))
        """
    )
    monkeypatch.setattr(live_packet_collector, "connect_db", lambda *args, **_kwargs: con)

    targets = live_packet_collector.active_classification_targets({
        "lan_prefix": "192.168.1.",
        "classification_nft_target_limit": 10,
        "classification_dns_target_lookback_hours": 6,
    })

    assert ("192.168.1.44", "13.107.136.10") in targets


def test_low_visibility_devices_selects_high_volume_under_visible_devices(monkeypatch):
    con = memory_db()
    con.executemany(
        """
        INSERT INTO traffic_intervals (ip, total_mb, day, ts)
        VALUES (?, ?, date('now', 'localtime'), datetime('now', 'localtime'))
        """,
        [
            ("192.168.1.67", 1000.0),
            ("192.168.1.153", 120.0),
            ("192.168.1.10", 10.0),
        ],
    )
    con.executemany(
        """
        INSERT INTO remote_traffic_intervals (ip, remote_ip, category, total_mb, day, ts)
        VALUES (?, ?, ?, ?, date('now', 'localtime'), datetime('now', 'localtime'))
        """,
        [
            ("192.168.1.67", "203.0.113.10", "Unknown", 150.0),
            ("192.168.1.153", "203.0.113.20", "Social Media", 100.0),
        ],
    )
    monkeypatch.setattr(live_packet_collector, "connect_db", lambda *args, **_kwargs: con)

    devices = live_packet_collector.low_visibility_devices({
        "destination_visibility_device_limit": 10,
        "destination_visibility_min_total_mb": 50,
        "destination_visibility_max_visible_pct": 50,
    }, 10)

    assert devices == ("192.168.1.67",)


def test_active_visibility_targets_uses_conntrack_for_under_visible_devices(monkeypatch):
    monkeypatch.setattr(live_packet_collector, "low_visibility_devices", lambda *_args: ("192.168.1.67",))
    monkeypatch.setattr(
        live_packet_collector,
        "iter_conntrack_lines",
        lambda _limit: iter([
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.67 dst=142.251.216.74 sport=54321 dport=443 src=142.251.216.74 dst=165.255.241.41 sport=443 dport=54321 [ASSURED]",
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.67 dst=102.132.104.23 sport=54322 dport=443 src=102.132.104.23 dst=165.255.241.41 sport=443 dport=54322 [ASSURED]",
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.39 dst=108.177.15.207 sport=54323 dport=443 src=108.177.15.207 dst=165.255.241.41 sport=443 dport=54323 [ASSURED]",
        ]),
    )

    targets = live_packet_collector.active_visibility_targets({
        "lan_prefix": "192.168.1.",
        "destination_visibility_probe_enabled": True,
        "destination_visibility_nft_target_limit": 10,
        "destination_visibility_per_device_limit": 12,
    }, excluded_pairs={("192.168.1.67", "102.132.104.23")})

    assert targets == (("192.168.1.67", "142.251.216.74"),)


def test_active_visibility_targets_falls_back_to_recent_destination_rows(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO remote_traffic_intervals
            (ip, remote_ip, category, total_mb, day, ts)
        VALUES
            ('192.168.1.67', '142.251.216.74', 'Google Cloud', 110, date('now', 'localtime'), datetime('now', 'localtime')),
            ('192.168.1.67', '102.132.104.23', 'Social Media', 30, date('now', 'localtime'), datetime('now', 'localtime')),
            ('192.168.1.39', '108.177.15.207', 'Cloud Infrastructure', 100, date('now', 'localtime'), datetime('now', 'localtime'))
        """
    )
    monkeypatch.setattr(live_packet_collector, "connect_db", lambda *args, **_kwargs: con)
    monkeypatch.setattr(live_packet_collector, "low_visibility_devices", lambda *_args: ("192.168.1.67",))
    monkeypatch.setattr(live_packet_collector, "iter_conntrack_lines", lambda _limit: iter([]))

    targets = live_packet_collector.active_visibility_targets({
        "lan_prefix": "192.168.1.",
        "destination_visibility_probe_enabled": True,
        "destination_visibility_nft_target_limit": 10,
        "destination_visibility_per_device_limit": 12,
        "destination_visibility_recent_lookback_minutes": 60,
    }, excluded_pairs={("192.168.1.67", "102.132.104.23")})

    assert targets == (("192.168.1.67", "142.251.216.74"),)


def test_tcpdump_sampler_extracts_lan_external_pairs():
    network = live_packet_collector.lan_network({"lan_prefix": "192.168.1."})
    output = "\n".join([
        "1787314682.123 IP 192.168.1.57.51514 > 40.104.14.210.443: tcp 0 length 1460",
        "1787314682.124 IP 40.104.14.210.443 > 192.168.1.57.51514: tcp 0 length 1200",
        "1787314682.125 IP 192.168.1.121.44444 > 192.168.1.1.53: UDP, length 40",
    ])

    pairs = live_packet_collector.sample_pairs_from_tcpdump(
        output,
        {"192.168.1.57", "192.168.1.121"},
        network,
    )

    assert pairs[("192.168.1.57", "40.104.14.210")] == 2660
    assert ("192.168.1.121", "192.168.1.1") not in pairs


def test_tcpdump_sampler_uses_packet_size_fallback_without_length():
    network = live_packet_collector.lan_network({"lan_prefix": "192.168.1."})
    output = "\n".join([
        "1787314682.123 IP 192.168.1.57.51514 > 40.104.14.210.443: tcp",
        "1787314682.124 IP 40.104.14.210.443 > 192.168.1.57.51514: tcp",
    ])

    pairs = live_packet_collector.sample_pairs_from_tcpdump(
        output,
        {"192.168.1.57"},
        network,
    )

    assert pairs[("192.168.1.57", "40.104.14.210")] == 3000


def test_active_classification_targets_prefers_attached_dnsdb_over_empty_main(monkeypatch):
    con = memory_db()
    con.execute("ATTACH DATABASE ':memory:' AS dnsdb")
    con.execute(
        """
        CREATE TABLE dnsdb.dns_resolution_events (
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
        INSERT INTO dnsdb.dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-08-07 10:00:00', '192.168.1.44', 'wslcoza-my.sharepoint.com', '13.107.136.10', 177, datetime('now', 'localtime', '+2 minutes'))
        """
    )
    assert dns_resolution_table_name(con) == "dnsdb.dns_resolution_events"
    monkeypatch.setattr(live_packet_collector, "connect_db", lambda *args, **_kwargs: con)

    targets = live_packet_collector.active_classification_targets({
        "lan_prefix": "192.168.1.",
        "classification_nft_target_limit": 10,
    })

    assert ("192.168.1.44", "13.107.136.10") in targets


def test_classify_flow_prefers_attached_dnsdb_resolution_over_empty_main(monkeypatch):
    con = memory_db()
    con.execute("ATTACH DATABASE ':memory:' AS dnsdb")
    con.execute(
        """
        CREATE TABLE dnsdb.dns_resolution_events (
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
        INSERT INTO dnsdb.dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-08-07 10:00:00', '192.168.1.44', 'wslcoza-my.sharepoint.com', '13.107.136.10', 177, '2026-08-07 10:02:57')
        """
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", **_kwargs: {"primary_category": "File Sharing & Storage", "category": "File Sharing & Storage"} if domain else {"primary_category": "Unknown", "category": "Unknown"},
    )

    result = classify_flow(con, Flow(
        ts="2026-08-07 10:01:00",
        local_ip="192.168.1.44",
        remote_ip="13.107.136.10",
    ))

    assert result.application == "wslcoza-my.sharepoint.com"
    assert result.evidence_source == "dns_resolution"


def test_dns_classification_refresh_request_is_throttled():
    live_packet_collector.nft_config_refresh_event.clear()
    live_packet_collector.last_dns_classification_refresh_request = 0.0

    assert live_packet_collector.request_dns_classification_target_refresh("test", now_monotonic=100.0) is True
    assert live_packet_collector.nft_config_refresh_event.is_set()
    live_packet_collector.nft_config_refresh_event.clear()
    assert live_packet_collector.request_dns_classification_target_refresh("test", now_monotonic=110.0) is False
    assert not live_packet_collector.nft_config_refresh_event.is_set()
    assert live_packet_collector.request_dns_classification_target_refresh("test", now_monotonic=131.0) is True


def test_write_destination_delta_does_not_double_count_existing_estimated_target(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-07-24 10:00:00', '192.168.99.50', 'outlook.office365.com', '203.0.113.10', 900, '2026-07-24 10:15:00')
        """
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", **_kwargs: {"primary_category": "Email", "category": "Email"} if domain else {"primary_category": "Unknown", "category": "Unknown"},
    )

    live_packet_collector.write_destination_delta(
        con,
        "192.168.99.50",
        "203.0.113.10",
        {"rx": 1024, "tx": 1024},
        "2026-07-24",
        "2026-07-24 10:01:00",
        default_category="Outlook",
    )

    assert con.execute("SELECT COUNT(*) FROM estimated_app_traffic").fetchone()[0] == 0


def test_same_bytes_with_dns_and_destination_classification_create_one_attribution_record(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-07-24 10:00:00', '192.168.99.50', 'outlook.office365.com', '203.0.113.10', 900, '2026-07-24 10:15:00')
        """
    )
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda domain="", destination_ip="", **_kwargs: (
            {"primary_category": "Email", "category": "Email", "primary_app": "Outlook"}
            if domain or destination_ip == "203.0.113.10"
            else {"primary_category": "Unknown", "category": "Unknown"}
        ),
    )
    cur = {"rx": 4096, "tx": 4096}

    con.execute(
        """
        INSERT INTO estimated_app_traffic
            (ip, category, downloaded_mb, uploaded_mb, total_mb, day, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "192.168.99.50",
            "Outlook",
            cur["rx"] / 1024 / 1024,
            cur["tx"] / 1024 / 1024,
            (cur["rx"] + cur["tx"]) / 1024 / 1024,
            "2026-07-24",
            "2026-07-24 10:01:00",
        ),
    )
    live_packet_collector.write_destination_delta(
        con,
        "192.168.99.50",
        "203.0.113.10",
        cur,
        "2026-07-24",
        "2026-07-24 10:01:00",
        default_category="Outlook",
    )

    rows = con.execute("SELECT category, total_mb FROM estimated_app_traffic").fetchall()
    assert len(rows) == 1
    assert rows[0]["category"] == "Outlook"
    assert rows[0]["total_mb"] == (cur["rx"] + cur["tx"]) / 1024 / 1024


def test_write_destination_delta_does_not_promote_low_confidence_port_protocol(monkeypatch):
    con = memory_db()
    monkeypatch.setattr(
        live_packet_collector,
        "classify_flow",
        lambda _con, _flow, emit_timing=False: Classification("Web Browsing", "HTTPS", "port_protocol", "low"),
    )

    live_packet_collector.write_destination_delta(
        con,
        "192.168.99.50",
        "203.0.113.10",
        {"rx": 1024, "tx": 1024},
        "2026-07-24",
        "2026-07-24 10:01:00",
        default_category="Unknown",
    )

    remote = con.execute("SELECT category FROM remote_traffic_intervals").fetchone()
    assert remote["category"] == "Web Browsing"
    assert con.execute("SELECT COUNT(*) FROM estimated_app_traffic").fetchone()[0] == 0


def test_dns_resolution_event_upsert_avoids_identical_duplicates_and_refreshes_ttl():
    con = memory_db()
    rows = [
        ("2026-07-24 10:00:00", "192.168.99.50", "outlook.office365.com", "203.0.113.10", 6, "2026-07-24 10:00:06", "adguard"),
        ("2026-07-24 10:00:00", "192.168.99.50", "outlook.office365.com", "203.0.113.10", 8, "2026-07-24 10:00:06", "adguard"),
        ("2026-07-24 10:00:02", "192.168.99.50", "outlook.office365.com", "203.0.113.10", 8, "2026-07-24 10:00:10", "adguard"),
    ]
    con.executemany(
        """
        INSERT INTO dns_resolution_events
            (ts, client_ip, domain, resolved_ip, ttl, expires_at, source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(client_ip, domain, resolved_ip, ts, expires_at) DO UPDATE SET
            ttl=excluded.ttl,
            source=excluded.source
        """,
        rows,
    )

    stored = con.execute(
        """
        SELECT ts, ttl, expires_at
        FROM dns_resolution_events
        ORDER BY ts
        """
    ).fetchall()
    assert len(stored) == 2
    assert stored[0]["ttl"] == 8
    assert stored[1]["expires_at"] == "2026-07-24 10:00:10"


def test_operator_signature_has_priority_over_dns(monkeypatch):
    con = memory_db()
    con.execute(
        """
        INSERT INTO dns_resolution_events (ts, client_ip, domain, resolved_ip, ttl, expires_at)
        VALUES ('2026-07-24 10:00:00', '192.168.99.50', 'generic-cdn.example', '203.0.113.10', 900, '2026-07-24 10:15:00')
        """
    )

    def fake_classify_application(domain="", destination_ip="", **_kwargs):
        if destination_ip == "203.0.113.10":
            return {
                "primary_category": "Email",
                "category": "Email",
                "primary_app": "Operator Outlook Rule",
                "confidence": 90,
            }
        if domain:
            return {"primary_category": "Cloud Infrastructure", "category": "Cloud Infrastructure"}
        return {"primary_category": "Unknown", "category": "Unknown"}

    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        fake_classify_application,
    )

    result = classify_flow(con, Flow(
        ts="2026-07-24 10:01:00",
        local_ip="192.168.99.50",
        remote_ip="203.0.113.10",
    ))

    assert result.application == "Operator Outlook Rule"
    assert result.evidence_source == "operator_signature"


def test_destination_signature_accepts_category_without_primary_category(monkeypatch):
    monkeypatch.setattr(
        "services.classification_resolver_service.classify_application",
        lambda destination_ip="", **_kwargs: {"category": "Cloud Infrastructure", "primary_app": "Google"},
    )

    result = classify_flow(memory_db(), Flow(
        ts="2026-08-07 11:45:00",
        local_ip="192.168.1.10",
        remote_ip="172.217.170.131",
    ))

    assert result.category == "Cloud Infrastructure"
    assert result.application == "Google"
    assert result.evidence_source == "destination_signature"
