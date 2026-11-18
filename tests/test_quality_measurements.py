import json
import socket
import sqlite3
from types import SimpleNamespace

import pytest

import netspecter_internet_quality as iq
import scheduled_speedtest
from services import reporting_service
from services.speedtest_result_service import metrics_complete, parse_metrics


def test_jitter_never_compares_round_trips_from_different_hosts():
    targets = [{"latencies": [5, 5, 5]}, {"latencies": [150, 150, 150]}]
    assert iq.calculate_target_jitter(targets) == 0
    assert iq.calculate_target_jitter([{"latencies": [5]}, {"latencies": [150]}]) is None


def test_dns_missing_tool_cannot_pass_using_another_resolver_or_change_global_timeout(monkeypatch):
    timeout = socket.getdefaulttimeout()
    monkeypatch.setattr(iq.shutil, "which", lambda _name: None)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args: pytest.fail("must test the selected DNS server"))
    result = iq.dns_query_ms("192.168.1.4")
    assert not result["ok"]
    assert result["unavailable"]
    assert socket.getdefaulttimeout() == timeout


@pytest.mark.parametrize("external, fragment", [
    ({"ok": True}, "AdGuard DNS probe failed"),
    ({"ok": False}, "Both local and external DNS probes failed"),
    (None, "DNS/AdGuard probe failed"),
])
def test_dns_diagnosis_uses_external_probe_evidence(external, fragment):
    targets = [{"ok": True, "avg_ms": 20, "loss_pct": 0}] * 2
    status, reason = iq.diagnose({"ok": True, "avg_ms": 2, "loss_pct": 0}, targets, {"ok": False}, external)
    assert status == "warn"
    assert fragment in reason


def test_slow_gateway_is_not_misdiagnosed_as_a_dns_only_failure():
    status, reason = iq.diagnose(
        {"ok": True, "avg_ms": 210, "loss_pct": 0},
        [{"ok": True, "avg_ms": 230, "loss_pct": 0}] * 2,
        {"ok": False}, {"ok": True},
    )
    assert status == "warn"
    assert "Gateway latency high" in reason


@pytest.mark.parametrize("payload, expected", [
    ({"ping": 0, "download": 98_300_000, "upload": 82_000_000}, (0, 98.3, 82)),
    ({"ping": {"latency": 6.2}, "download": {"bandwidth": 12_287_500}, "upload": {"bandwidth": 10_250_000}}, (6.2, 98.3, 82)),
    ({"ping": 5, "download": 2000, "upload": 1000}, (5, 0.002, 0.001)),
    ({"ping": "bad", "download": {}, "upload": -1}, (None, None, None)),
])
def test_speedtest_json_units_and_invalid_metrics(payload, expected):
    assert parse_metrics(json.dumps(payload)) == expected


@pytest.mark.parametrize("metrics", [(None, None, None), (5, 10, None), (float("nan"), 10, 10), (5, -1, 10)])
def test_speedtest_cannot_be_successful_with_missing_or_invalid_metrics(metrics):
    assert not metrics_complete(*metrics)


def test_scheduled_process_exit_zero_without_measurements_is_not_success(monkeypatch):
    monkeypatch.setattr(scheduled_speedtest, "load_config", lambda: {})
    monkeypatch.setattr(scheduled_speedtest, "speedtest_command", lambda _config: ["fake-speedtest"])
    monkeypatch.setattr(scheduled_speedtest.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="{}"))
    output, latency, download, upload, success = scheduled_speedtest.run_test()
    assert not success
    assert "incomplete" in output
    assert (latency, download, upload) == (None, None, None)


def test_historical_empty_success_rows_are_not_reported_as_ok(monkeypatch):
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE speed_tests(ts TEXT, source TEXT, latency_ms REAL, download_mbps REAL, upload_mbps REAL, success INTEGER)")
    con.executemany("INSERT INTO speed_tests VALUES (?, 'scheduled', ?, ?, ?, 1)", [
        ("2026-11-18 12:00:00", None, None, None),
        ("2026-11-17 12:00:00", 6.2, 98.3, 82),
    ])
    monkeypatch.setattr(reporting_service, "_timed_query", lambda sql, params, _label: con.execute(sql, params).fetchall())
    rows = reporting_service.get_speedtest_summary("2026-11-01", "2026-12-01")
    assert [row["success"] for row in rows] == [0, 1]
    con.close()
