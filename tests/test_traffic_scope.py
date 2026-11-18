from types import SimpleNamespace

import pytest

import live_packet_collector as collector
from services.traffic_scope_service import internal_ipv4_networks, is_internal_destination


CONFIG = {"lan_prefix": "192.168.1.", "internal_networks": ["10.20.30.0/24"]}


def test_lan_server_and_vpn_are_internal_but_internet_is_not():
    networks = internal_ipv4_networks(CONFIG)
    assert is_internal_destination("192.168.1.10", networks)
    assert is_internal_destination("10.20.30.9", networks)
    assert not is_internal_destination("1.1.1.1", networks)
    assert not is_internal_destination("10.20.31.9", networks)


@pytest.mark.parametrize("value", [
    "garbage", "0.0.0.0/0", "::/0", "10.20.30.0/33",
    "10.20.30.0/24; reboot", "10.20.30.0/24 } drop", "$(id)",
])
def test_invalid_internal_ranges_are_rejected(value):
    with pytest.raises(ValueError):
        internal_ipv4_networks({**CONFIG, "internal_networks": [value]})


def test_internal_range_input_can_use_commas_and_normalises_host_bits():
    networks = internal_ipv4_networks({**CONFIG, "internal_networks": "10.20.30.9/24, 10.20.31.0/24"})
    assert tuple(map(str, networks)) == ("10.20.30.0/23", "192.168.1.0/24")


def test_every_counter_path_excludes_internal_and_ignored_endpoints(monkeypatch):
    pairs = (
        ("192.168.1.20", "192.168.1.10"),
        ("192.168.1.10", "10.20.30.9"),
        ("192.168.1.20", "1.1.1.1"),
        ("192.168.1.30", "8.8.8.8"),
    )
    monkeypatch.setattr(collector, "active_estimated_app_targets", lambda: tuple(("Files", *pair) for pair in pairs))
    monkeypatch.setattr(collector, "active_classification_targets", lambda _config: pairs)
    monkeypatch.setattr(collector, "active_visibility_targets", lambda *_args: pairs)
    config = {**CONFIG, "ignore_ips": ["192.168.1.30"]}
    signature = collector.nft_signature(config)
    assert signature[-3] == (("Files", "192.168.1.20", "1.1.1.1"),)
    assert signature[-2] == signature[-1] == (("192.168.1.20", "1.1.1.1"),)

    calls = []
    monkeypatch.setattr(collector.subprocess, "run", lambda *args, **kwargs: (calls.append(kwargs.get("input", "")) or SimpleNamespace(returncode=0, stderr="")))
    collector.install_nft_counters(config)
    rules = calls[-1]
    internal_set = "{ 10.20.30.0/24, 192.168.1.0/24 }"
    assert f'ip saddr 192.168.1.10 ip daddr != {internal_set} counter' in rules
    assert f'ip daddr 192.168.1.10 ip saddr != {internal_set} counter' in rules
    assert "netspecter:estimated:Files:tx:192.168.1.20:192.168.1.10" not in rules
    assert "netspecter:estimated:Files:tx:192.168.1.10:10.20.30.9" not in rules


def test_vpn_range_change_invalidates_counter_signature(monkeypatch):
    monkeypatch.setattr(collector, "active_estimated_app_targets", lambda: ())
    monkeypatch.setattr(collector, "active_classification_targets", lambda _config: ())
    monkeypatch.setattr(collector, "active_visibility_targets", lambda *_args: ())
    assert collector.nft_signature(CONFIG) != collector.nft_signature({**CONFIG, "internal_networks": []})


def test_saturated_dns_budget_still_captures_other_active_connections(monkeypatch):
    dns = tuple(("192.168.1.20", f"203.0.113.{i}") for i in range(1, 9))
    active = tuple(("192.168.1.21", f"198.51.100.{i}") for i in range(1, 4))
    monkeypatch.setattr(collector, "dns_classification_targets", lambda *_args: dns)
    monkeypatch.setattr(collector, "conntrack_classification_targets", lambda *_args: active)
    targets = collector.active_classification_targets({**CONFIG, "classification_nft_target_limit": 8})
    assert len(targets) == 8
    assert len(set(targets) & set(active)) == 2
    assert len(set(targets) & set(dns)) == 6


def test_conntrack_duplicates_do_not_waste_reserved_slots(monkeypatch):
    dns = tuple(("192.168.1.20", f"203.0.113.{i}") for i in range(1, 9))
    monkeypatch.setattr(collector, "dns_classification_targets", lambda *_args: dns)
    monkeypatch.setattr(collector, "conntrack_classification_targets", lambda *_args: dns)
    assert collector.active_classification_targets({**CONFIG, "classification_nft_target_limit": 8}) == tuple(sorted(dns))
