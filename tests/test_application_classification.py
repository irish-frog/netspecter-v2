import inspect
import sqlite3

from services import reporting_service
from services import application_classification_service
from services.application_classification_service import categories, category_summary, classify_application, display_application_name
from services import ai_attribution_service
from services.ai_attribution_service import ai_attribution_summary, ai_service_for_domain, dns_time_window_correlations
from services.report_pdf_service import reporting_pdf_response
from services.report_export_service import structured_report_text
from netspecter_config import DEFAULT_CONFIG, appliance_ip_from_host, apply_appliance_ip_urls
from live_packet_collector import monitored_app_for_domain


def category_for(app_name):
    return classify_application(app_name)["category"]


def test_appliance_ip_sync_derives_service_urls():
    config = {"web_port": 5050, "https_proxy_port": 9443}

    assert apply_appliance_ip_urls(config, "192.168.99.6")
    assert config["appliance_ip"] == "192.168.99.6"
    assert config["netspecter_url"] == "https://192.168.99.6:9443"
    assert config["adguard_url"] == "http://192.168.99.6"
    assert config["gatus_url"] == "http://192.168.99.6:18080"
    assert config["beszel_url"] == "http://192.168.99.6:8090"

    assert not apply_appliance_ip_urls(config, "not-an-ip")


def test_microsoft365_endpoint_import_is_default_enabled():
    assert DEFAULT_CONFIG["microsoft365_endpoint_import_enabled"] is True


def test_default_site_domain_mappings_stay_user_visible_only():
    assert DEFAULT_CONFIG["site_domain_mappings"] == []
    assert monitored_app_for_domain("outlook.office365.com", DEFAULT_CONFIG) == "Outlook"
    assert monitored_app_for_domain("teams.microsoft.com", DEFAULT_CONFIG) == "Microsoft Teams"
    assert monitored_app_for_domain("office.com", DEFAULT_CONFIG) == "Microsoft 365"


def test_https_proxy_defaults_to_public_9443():
    assert DEFAULT_CONFIG["https_proxy_port"] == 9443
    assert DEFAULT_CONFIG["netspecter_url"] == "https://127.0.0.1:9443"
    assert DEFAULT_CONFIG["web_host"] == "127.0.0.1"
    assert DEFAULT_CONFIG["allow_lan_http_5050"] is False




def test_appliance_ip_infers_from_browser_host():
    assert appliance_ip_from_host("192.168.99.6:5050") == "192.168.99.6"
    assert appliance_ip_from_host("127.0.0.1:5050") == ""
    assert appliance_ip_from_host("localhost:5050") == ""
    assert appliance_ip_from_host("[::1]:5050") == ""


def test_streaming_and_social_mappings():
    assert category_for("Netflix") == "Video Streaming"
    assert category_for("YouTube") == "Video Streaming"
    assert category_for("Netflix") != "Social Media"
    assert category_for("Facebook") == "Social Media"


def test_microsoft_service_mappings_are_functional():
    assert category_for("OneDrive") == "File Sharing & Storage"
    assert category_for("SharePoint Documents") == "File Sharing & Storage"
    assert category_for("Microsoft Teams") == "Communication & Collaboration"
    assert category_for("Outlook") == "Email"
    assert category_for("Exchange Online") == "Email"
    assert category_for("Windows Update") == "Software Updates"
    assert category_for("Microsoft Defender") == "Security Services"
    assert category_for("Azure") == "Cloud Infrastructure"
    assert category_for("Microsoft Authentication") == "Microsoft Cloud Services"
    assert category_for("Microsoft CDN") == "Content Delivery Networks"
    assert category_for("Microsoft Cloud Services") == "Microsoft Cloud Services"
    assert category_for("Microsoft Services - Unresolved") == "Microsoft Cloud Services"
    assert display_application_name("Microsoft Services - Unresolved") == "Microsoft Services (General)"
    assert category_for("Microsoft") != "File Sharing & Storage"


def test_windows_update_is_software_updates():
    assert category_for("Windows Update") == "Software Updates"
    assert classify_application(domain="download.windowsupdate.com")["category"] == "Software Updates"
    assert classify_application(domain="update.microsoft.com")["category"] == "Software Updates"
    assert classify_application(domain="dl.delivery.mp.microsoft.com")["category"] == "Software Updates"
    assert classify_application(domain="officecdn.microsoft.com")["category"] == "Software Updates"


def test_microsoft_domains_use_specific_categories():
    assert classify_application(domain="wdcp.microsoft.com")["category"] == "Security Services"
    assert classify_application(domain="defender.microsoft.com")["category"] == "Security Services"
    assert classify_application(domain="login.microsoftonline.com")["category"] == "Microsoft Cloud Services"
    assert classify_application(domain="aadcdn.microsoftonline-p.com")["category"] == "Microsoft Cloud Services"
    assert classify_application(domain="officeapps.live.com")["category"] == "Office & Productivity"
    assert classify_application(domain="onedrive.live.com")["category"] == "File Sharing & Storage"
    assert classify_application(domain="teams.live.com")["category"] == "Communication & Collaboration"
    assert classify_application(domain="outlook.office365.com")["category"] == "Email"
    assert classify_application(domain="blob.core.windows.net")["category"] == "Cloud Infrastructure"


def test_hardware_vendor_domains_are_not_unknown():
    assert classify_application(domain="downloads.dell.com")["category"] == "Hardware Vendor Services"
    assert classify_application(domain="pcsupport.lenovo.com")["category"] == "Hardware Vendor Services"
    assert classify_application(domain="downloadcenter.intel.com")["category"] == "Hardware Vendor Services"
    assert classify_application(domain="download.nvidia.com")["category"] == "Hardware Vendor Services"


def test_messaging_is_not_email():
    assert category_for("Discord") == "Communication & Collaboration"
    assert category_for("WhatsApp") == "Communication & Collaboration"
    assert category_for("Slack") == "Communication & Collaboration"


def test_ai_services_are_first_class_category():
    assert category_for("ChatGPT") == "AI Services"
    assert category_for("Microsoft Copilot") == "AI Services"
    assert category_for("GitHub Copilot") == "AI Services"
    assert category_for("Claude") == "AI Services"
    assert category_for("Gemini") == "AI Services"
    assert category_for("DeepSeek") == "AI Services"
    assert classify_application(domain="chatgpt.com")["category"] == "AI Services"
    assert classify_application(domain="claude.ai")["category"] == "AI Services"
    assert classify_application(domain="perplexity.ai")["category"] == "AI Services"
    assert classify_application(domain="github.com")["category"] != "AI Services"


def test_chatgpt_detected_from_dns_evidence():
    assert ai_service_for_domain("chatgpt.com") == "ChatGPT"
    assert ai_service_for_domain("chat.openai.com") == "ChatGPT"
    assert ai_service_for_domain("api.openai.com") == "OpenAI API"
    assert ai_service_for_domain("openai.com") == ""


def test_ai_services_metadata_is_loaded():
    ai_category = next(row for row in categories() if row["name"] == "AI Services")
    services = ai_category["services"]
    assert any(row["vendor"] == "OpenAI" and row["service"] == "ChatGPT" for row in services)
    assert any(row["vendor"] == "Microsoft" and row["service"] == "GitHub Copilot" for row in services)
    assert "Coding" in ai_category["tags"]


def test_identity_authentication_is_not_client_category():
    assert all(row["name"] != "Identity & Authentication" for row in categories())


def test_nextcloud_site_mapping():
    assert category_for("Nextcloud") == "File Sharing & Storage"
    assert classify_application(destination_ip="192.168.99.4")["category"] == "File Sharing & Storage"


def test_site_domain_mapping_classifies_wildcard_domain(monkeypatch):
    monkeypatch.setattr(
        application_classification_service,
        "site_domain_mappings",
        lambda: [{"application": "Plex CDN", "category": "Video Streaming", "domain": "*.hvcdn.to"}],
    )
    result = classify_application(domain="edge.hvcdn.to")
    assert result["category"] == "Video Streaming"
    assert result["source"] == "Site category mapping"


def test_applications_have_single_primary_category():
    seen = {}
    duplicates = {}
    for category in categories():
        for app in category.get("applications", []):
            key = app.strip().lower()
            if key in seen:
                duplicates.setdefault(app, {seen[key]}).add(category["name"])
            else:
                seen[key] = category["name"]
    assert duplicates == {}


def test_top_users_does_not_fallback_to_device_names():
    source = inspect.getsource(reporting_service.get_top_users)
    assert "COALESCE(NULLIF(d.owner" not in source
    assert "o.name" not in source
    assert "d.name" not in source
    assert "JOIN user_labels" in source
    assert "user_device_assignments" in source


def test_site_device_mapping_adds_nextcloud_to_category_summary(monkeypatch):
    def fake_query(sql, params=()):
        if "FROM estimated_app_traffic" in sql and "GROUP BY category" in sql:
            return []
        if "FROM traffic_intervals" in sql:
            return [{"downloaded_mb": 80.0, "uploaded_mb": 20.0, "total_mb": 100.0, "devices": 1}]
        if "FROM estimated_app_traffic" in sql and "ip=?" in sql:
            return [{"downloaded_mb": 10.0, "uploaded_mb": 5.0, "total_mb": 15.0}]
        return []

    monkeypatch.setattr(application_classification_service, "query", fake_query)
    monkeypatch.setattr(
        application_classification_service,
        "site_application_mappings",
        lambda: [{"application": "Nextcloud", "category": "File Sharing & Storage", "ip": "192.168.99.4"}],
    )
    summary = category_summary("2026-07-13", "2026-07-14", total_network_mb=200.0)

    file_sharing = next(row for row in summary["rows"] if row["category"] == "File Sharing & Storage")
    unclassified = next(row for row in summary["rows"] if row["category"] == "Unclassified / Other Network Traffic")
    assert file_sharing["total_mb"] == 85.0
    assert file_sharing["application_names"] == ["Nextcloud"]
    assert summary["classification_coverage_pct"] == 42.5
    assert unclassified["total_mb"] == 115.0


def test_ai_services_are_not_grouped_into_other(monkeypatch):
    apps = ["OneDrive", "Outlook", "Microsoft Teams", "Microsoft 365", "Sage", "Facebook", "Netflix", "Spotify"]
    app_rows = [
        {"application_name": app, "downloaded_mb": 10.0, "uploaded_mb": 0.0, "total_mb": 10.0, "devices": 1}
        for app in apps
    ]
    app_rows.append({"application_name": "ChatGPT", "downloaded_mb": 1.0, "uploaded_mb": 0.0, "total_mb": 1.0, "devices": 1})

    def fake_query(sql, params=()):
        if "FROM estimated_app_traffic" in sql and "GROUP BY category" in sql:
            return app_rows
        return []

    monkeypatch.setattr(application_classification_service, "query", fake_query)
    monkeypatch.setattr(application_classification_service, "site_application_mappings", lambda: [])
    summary = category_summary("2026-07-13", "2026-07-14", total_network_mb=100.0)

    categories_seen = [row["category"] for row in summary["rows"]]
    assert "AI Services" in categories_seen
    assert not any(
        row["category"] != "AI Services" and "ChatGPT" in row.get("application_names", [])
        for row in summary["rows"]
    )


def test_social_media_is_not_grouped_into_other(monkeypatch):
    app_rows = [
        {"application_name": app, "downloaded_mb": 10.0, "uploaded_mb": 0.0, "total_mb": 10.0, "devices": 1}
        for app in ["OneDrive", "Outlook", "Microsoft Teams", "Microsoft 365", "Sage", "Netflix", "Spotify"]
    ]
    app_rows.extend([
        {"application_name": "Facebook", "downloaded_mb": 0.4, "uploaded_mb": 0.0, "total_mb": 0.4, "devices": 1},
        {"application_name": "TikTok", "downloaded_mb": 0.3, "uploaded_mb": 0.0, "total_mb": 0.3, "devices": 1},
    ])

    def fake_query(sql, params=()):
        if "FROM estimated_app_traffic" in sql and "GROUP BY category" in sql:
            return app_rows
        return []

    monkeypatch.setattr(application_classification_service, "query", fake_query)
    monkeypatch.setattr(application_classification_service, "site_application_mappings", lambda: [])
    summary = category_summary("2026-07-13", "2026-07-14", limit=3, total_network_mb=110.0)
    social = next(row for row in summary["rows"] if row["category"] == "Social Media")
    other = next(row for row in summary["rows"] if row["category"] == "Other")

    assert social["total_mb"] == 0.7
    assert social["application_names"] == ["Facebook", "TikTok"]
    assert "Facebook" not in other["application_names"]
    assert "TikTok" not in other["application_names"]


def test_application_filtered_report_traffic_uses_application_totals(monkeypatch):
    def fake_query(sql, params=()):
        assert "FROM estimated_app_traffic" in sql
        assert "category IN (?)" in sql
        assert params == ("2026-07-13", "2026-07-14", "ChatGPT")
        return [{"downloaded_mb": 20.0, "uploaded_mb": 1.0, "total_mb": 21.0}]

    monkeypatch.setattr(reporting_service, "query", fake_query)
    traffic = reporting_service.get_traffic_summary({"application": "ChatGPT"}, "2026-07-13", "2026-07-14")

    assert traffic == {"downloaded_mb": 20.0, "uploaded_mb": 1.0, "total_mb": 21.0}


def test_application_filtered_top_devices_use_application_rows(monkeypatch):
    def fake_query(sql, params=()):
        assert "FROM estimated_app_traffic t" in sql
        assert "t.category IN (?)" in sql
        assert params == ("2026-07-13", "2026-07-14", "ChatGPT", 5)
        return [{"name": "Gavin Pc", "ip": "192.168.99.58", "mac": "aa:bb", "downloaded_mb": 20.0, "uploaded_mb": 1.0, "total_mb": 21.0, "last_seen": "2026-07-14"}]

    monkeypatch.setattr(reporting_service, "query", fake_query)
    rows = reporting_service.get_top_devices({"application": "ChatGPT"}, "2026-07-13", "2026-07-14", 5)

    assert len(rows) == 1
    assert rows[0]["name"] == "Gavin Pc"
    assert rows[0]["total_mb"] == 21.0


def test_application_filtered_top_sites_use_dns_category(monkeypatch):
    def fake_query(sql, params=()):
        assert "FROM dns_querylog" in sql
        assert "category IN (?)" in sql
        assert params == ("2026-07-13", "2026-07-14", "ChatGPT", 5)
        return [{"domain": "chatgpt.com", "category": "ChatGPT", "blocked": 0, "requests": 12, "clients": 1}]

    monkeypatch.setattr(reporting_service, "query", fake_query)
    rows = reporting_service.get_dns_summary({"application": "ChatGPT"}, "2026-07-13", "2026-07-14", 5)

    assert rows[0]["domain"] == "chatgpt.com"
    assert rows[0]["requests"] == 12


def test_application_filtered_destinations_use_remote_category(monkeypatch):
    def fake_query(sql, params=()):
        assert "FROM remote_traffic_intervals r" in sql
        assert "r.category IN (?)" in sql
        assert params == ("2026-07-13", "2026-07-14", "ChatGPT", 5)
        return [{"remote_ip": "203.0.113.10", "country": "US", "category": "ChatGPT", "downloaded_mb": 20.0, "uploaded_mb": 1.0, "total_mb": 21.0, "devices": 1}]

    monkeypatch.setattr(reporting_service, "query", fake_query)
    rows = reporting_service.get_destination_summary({"application": "ChatGPT"}, "2026-07-13", "2026-07-14", 5)

    assert rows[0]["remote_ip"] == "203.0.113.10"
    assert rows[0]["total_mb"] == 21.0


def test_pdf_export_accepts_sqlite_rows():
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE top_devices (name TEXT, ip TEXT, total_mb REAL, uploaded_mb REAL, downloaded_mb REAL)")
    con.execute("INSERT INTO top_devices VALUES ('Laptop', '192.168.1.10', 100, 20, 80)")
    device_row = con.execute("SELECT * FROM top_devices").fetchone()
    context = {
        "start_time": "2026-07-13 00:00:00",
        "end_time": "2026-07-14 00:00:00",
        "overview": {"total_mb": 100, "downloaded_mb": 80, "uploaded_mb": 20, "active_devices": 1, "applications": 1, "unique_destinations": 1},
        "category_rows": [{"category": "AI Services", "color": "#a68bff", "share_total_pct": 10, "total_mb": 10}],
        "category_report": {"classification_coverage_pct": 10},
        "findings": {"rating": "Low", "score": 0, "reasons": []},
        "top_devices": [device_row],
        "top_users": [],
    }
    _filename, data = reporting_pdf_response(context)
    assert data.startswith(b"%PDF-")


def test_report_uses_attributed_traffic_language():
    context = {
        "start_time": "2026-07-13 00:00:00",
        "end_time": "2026-07-14 00:00:00",
        "overview": {"devices": 1, "active_devices": 1, "dns_total": 1, "total_mb": 100.0, "uploaded_mb": 10.0, "downloaded_mb": 90.0, "applications": 1, "unique_destinations": 1},
        "findings": {"rating": "Low", "score": 0, "reasons": [], "findings": [], "recommendations": []},
        "category_rows": [{"category": "AI Services", "total_mb": 1.61, "share_total_pct": 1.6, "share_classified_pct": 100, "application_names": ["ChatGPT"]}],
        "category_report": {"classification_coverage_pct": 1.6, "classified_application_mb": 1.61, "total_network_mb": 100.0},
        "top_devices": [],
        "top_users": [],
        "ai_summary": {
            "services_detected": 1,
            "services_with_attributed_traffic": 1,
            "attributed_mb": 1.61,
            "devices": ["192.168.1.10"],
            "attribution_coverage": "Partial",
            "services": [{
                "service": "ChatGPT",
                "service_detected": True,
                "service_detection_confidence": "High",
                "attributed_mb": 1.61,
                "traffic_attribution_status": "Partial",
                "evidence_summary": "DNS",
            }],
        },
    }
    report = structured_report_text(context)
    assert "Confidently attributed traffic: 1.61 MB" in report
    assert "ChatGPT usage was 1.61 MB" not in report


def test_ai_attribution_summary_handles_attributed_rows(monkeypatch):
    def fake_query(sql, params=()):
        if "FROM remote_traffic_intervals" in sql:
            return []
        if "FROM dns_querylog" in sql:
            return [{"domain": "chatgpt.com", "client": "192.168.1.10", "requests": 2, "first_seen": "2026-07-14 08:00:00", "last_seen": "2026-07-14 09:00:00"}]
        if "FROM estimated_app_traffic" in sql:
            return [{"category": "ChatGPT", "ip": "192.168.1.10", "downloaded_mb": 1.2, "uploaded_mb": 0.4, "total_mb": 1.6, "first_seen": "2026-07-14 08:00:00", "last_seen": "2026-07-14 09:00:00"}]
        return []

    monkeypatch.setattr(ai_attribution_service, "query", fake_query)
    summary = ai_attribution_summary({}, "2026-07-14 00:00:00", "2026-07-14 23:59:59")
    assert summary["services_detected"] == 1
    assert summary["attributed_mb"] == 1.6
    assert summary["services"][0]["traffic_attribution_status"] == "Partial"


def test_dns_time_window_correlation_requires_service_specific_domain(monkeypatch):
    rows = [
        {"ip": "192.168.1.10", "remote_ip": "203.0.113.10", "domain": "chatgpt.com", "downloaded_mb": 5.0, "uploaded_mb": 1.0, "total_mb": 6.0, "first_seen": "2026-07-14 08:00:00", "last_seen": "2026-07-14 08:05:00"},
        {"ip": "192.168.1.10", "remote_ip": "203.0.113.11", "domain": "openai.com", "downloaded_mb": 50.0, "uploaded_mb": 1.0, "total_mb": 51.0, "first_seen": "2026-07-14 08:00:00", "last_seen": "2026-07-14 08:05:00"},
        {"ip": "192.168.1.10", "remote_ip": "203.0.113.12", "domain": "cloudflare.com", "downloaded_mb": 100.0, "uploaded_mb": 1.0, "total_mb": 101.0, "first_seen": "2026-07-14 08:00:00", "last_seen": "2026-07-14 08:05:00"},
    ]

    monkeypatch.setattr(ai_attribution_service, "query", lambda sql, params=(): rows)
    correlated = dns_time_window_correlations({}, "2026-07-14 00:00:00", "2026-07-14 23:59:59")
    assert [row["service"] for row in correlated] == ["ChatGPT"]
    assert correlated[0]["total_mb"] == 6.0


def test_ai_summary_keeps_dns_correlation_separate_from_attributed_bytes(monkeypatch):
    def fake_query(sql, params=()):
        if "FROM dns_querylog" in sql and "GROUP BY domain, client" in sql:
            return [{"domain": "chatgpt.com", "client": "192.168.1.10", "requests": 1, "first_seen": "2026-07-14 08:00:00", "last_seen": "2026-07-14 08:01:00"}]
        if "FROM estimated_app_traffic" in sql:
            return []
        if "FROM remote_traffic_intervals" in sql:
            return [{"ip": "192.168.1.10", "remote_ip": "203.0.113.10", "domain": "chatgpt.com", "downloaded_mb": 5.0, "uploaded_mb": 1.0, "total_mb": 6.0, "first_seen": "2026-07-14 08:00:00", "last_seen": "2026-07-14 08:05:00"}]
        return []

    monkeypatch.setattr(ai_attribution_service, "query", fake_query)
    summary = ai_attribution_summary({}, "2026-07-14 00:00:00", "2026-07-14 23:59:59", include_dns_correlation=True)
    service = summary["services"][0]
    assert summary["attributed_mb"] == 0
    assert service["dns_correlated_mb"] == 6.0
    assert service["traffic_attribution_status"] == "Partial"
    assert "DNS time-window correlation" in service["classification_sources"]
