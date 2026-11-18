from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_updates_do_not_install_start_or_validate_suricata():
    for name in ("install.sh", "scripts/post-update-maintenance.sh"):
        source = (ROOT / name).read_text()
        assert "apt install -y suricata" not in source
        assert "suricata -T" not in source
        assert "suricata-update" not in source
        assert "systemctl enable --now suricata" not in source
        assert "disable_suricata_safely" in source


def test_maintenance_restarts_collector_even_after_script_failure():
    source = (ROOT / "systemd/netspecter-db-maintenance.service").read_text()
    assert "ExecStopPost=-/bin/systemctl start netspecter-collector.service" in source
    assert "ExecStart=/bin/bash /opt/netspecter/scripts/daily-db-maintenance.sh" in source
    assert "ExecStartPost=" not in source


def test_updater_does_not_depend_on_script_execute_permission():
    source = (ROOT / "systemd/netspecter-update.service").read_text()
    assert "ExecStart=/bin/bash /opt/netspecter/scripts/run-ui-update.sh" in source
