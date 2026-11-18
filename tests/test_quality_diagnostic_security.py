import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace


def test_diagnostic_does_not_print_credentials_or_run_shell_commands(monkeypatch, capsys):
    path = Path(__file__).resolve().parents[1] / "scripts" / "diagnose-internet-quality.py"
    spec = importlib.util.spec_from_file_location("quality_diagnostic_security_test", path)
    diagnostic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(diagnostic)
    monkeypatch.setattr(diagnostic, "interface_stats", lambda _interface: {"rx_errors": 0})
    monkeypatch.setattr(Path, "is_dir", lambda _path: False)
    monkeypatch.setattr(Path, "read_text", lambda _path: "MemAvailable: 1000 kB\nSwapFree: 2000 kB\n")
    monkeypatch.setattr(diagnostic.os, "getloadavg", lambda: (0.1, 0.1, 0.1), raising=False)
    monkeypatch.setattr(diagnostic, "ping_target", lambda *_args, **_kwargs: {"ok": True, "avg_ms": 2})
    monkeypatch.setattr(diagnostic, "dns_query_ms", lambda *_args, **_kwargs: {"ok": True, "ms": 2})
    calls = []

    def run(args, **kwargs):
        assert not kwargs.get("shell")
        assert args[:2] == ["systemctl", "show"]
        calls.append(args)
        return SimpleNamespace(stdout="ActiveState=active", stderr="")

    monkeypatch.setattr(diagnostic.subprocess, "run", run)
    diagnostic.check({
        "adguard_url": "http://admin:PRIVATE-TEST-PASSWORD@192.168.1.4",
        "adguard_pass": "PRIVATE-TEST-PASSWORD",
        "smtp_password": "PRIVATE-TEST-SMTP-SECRET",
        "gateway_ip": "192.168.1.1",
    }, samples=1)
    output = capsys.readouterr().out
    assert "PRIVATE-TEST" not in output
    assert json.loads(output)["dns"]["configured_dns"]["server"] == "192.168.1.4"
    assert len(calls) == 1
