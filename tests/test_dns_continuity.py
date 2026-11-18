import subprocess
import pytest
from services import dns_continuity_service as dns


def test_dns_failure_blocks_deployment(monkeypatch):
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:subprocess.CompletedProcess(a,0,stdout=';; status: SERVFAIL,',stderr=''))
    with pytest.raises(RuntimeError,match='probe failed'):dns.probe_dns()


def test_both_dns_transports_checked(monkeypatch):
    calls=[]
    def run(args,**kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args,0,stdout=';; status: NOERROR,',stderr='')
    monkeypatch.setattr(subprocess,'run',run)
    dns.probe_dns()
    assert len(calls)==2 and '+tcp' not in calls[0] and '+tcp' in calls[1]


def test_configuration_change_refuses_cleanup(monkeypatch,tmp_path):
    path=tmp_path/'AdGuardHome.yaml';path.write_text('saved settings')
    before=dns.config_hashes((path,));path.write_text('changed settings')
    hashes=dns.config_hashes
    monkeypatch.setattr(dns,'config_hashes',lambda:hashes((path,)))
    with pytest.raises(RuntimeError,match='configuration changed'):
        dns.verify({'adguard_was_active':False,'configuration_hashes':before})
