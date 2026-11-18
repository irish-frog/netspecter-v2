from datetime import datetime,timedelta
from types import SimpleNamespace
import live_packet_collector as collector


def test_old_or_malformed_dns_cannot_repopulate_any_learned_state(monkeypatch):
    cutoff=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    old=(datetime.now()-timedelta(days=7)).astimezone().isoformat()
    data=[{"question":{"name":"old.example.com"},"client":"192.168.1.5","time":value,"answer":[{"type":"A","value":"8.8.8.8","ttl":600}]} for value in (old,"invalid",None)]
    class Connection:
        def execute(self,*_):return SimpleNamespace(fetchone=lambda:(cutoff,))
        def close(self):pass
    monkeypatch.setattr(collector,"cfg",lambda:{"adguard_url":"http://127.0.0.1","adguard_user":"test","adguard_pass":"test"})
    monkeypatch.setattr(collector,"connect_db",lambda:Connection())
    monkeypatch.setattr(collector,"requests",SimpleNamespace(get=lambda *a,**k:SimpleNamespace(status_code=200,json=lambda:{"data":data})))
    monkeypatch.setattr(collector,"read_arp_macs",lambda:{})
    def unexpected(*_args,**_kwargs):raise AssertionError("Old DNS reached classification or learned state")
    for name in ("app_from_domain","remember_estimated_app_targets","dns_answer_rows","apply_device_identity"):
        monkeypatch.setattr(collector,name,unexpected)
    collector.import_adguard_querylog()


def test_failed_cutoff_read_does_not_import_old_data(monkeypatch):
    monkeypatch.setattr(collector,"cfg",lambda:{"adguard_url":"http://127.0.0.1"})
    monkeypatch.setattr(collector,"requests",SimpleNamespace(get=lambda *a,**k:SimpleNamespace(status_code=200,json=lambda:{"data":[]})))
    def unavailable():raise RuntimeError("database unavailable")
    monkeypatch.setattr(collector,"connect_db",unavailable)
    monkeypatch.setattr(collector,"read_arp_macs",lambda:(_ for _ in ()).throw(AssertionError("Import continued without cutoff")))
    collector.import_adguard_querylog()


def test_strict_time_parser_rejects_missing_and_invalid_timestamp():
    assert collector.parse_adguard_time(None,strict=True)==""
    assert collector.parse_adguard_time("invalid",strict=True)==""
