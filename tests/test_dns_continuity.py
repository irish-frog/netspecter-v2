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



def install_listener_fixture(monkeypatch,v4,v6='',pid='1014'):
    calls=[]
    def run(args,**kwargs):
        calls.append(args)
        if args[0]=='systemctl':output=pid if 'show' in args else ''
        elif args[0]=='ss':output=v4 if '-4' in args else v6
        else:output=';; status: NOERROR,'
        return subprocess.CompletedProcess(args,0,stdout=output,stderr='')
    monkeypatch.setattr(subprocess,'run',run)
    monkeypatch.setattr(dns,'config_hashes',lambda:{})
    return calls


def listener(protocol,address,pid=1014):
    return f'{protocol} UNCONN 0 0 {address}:53 0.0.0.0:* users:(("AdGuardHome",pid={pid},fd=7))\n'


def test_lan_only_adguard_is_probed_on_same_address_before_and_after(monkeypatch):
    calls=install_listener_fixture(monkeypatch,listener('udp','192.168.1.4')+listener('tcp','192.168.1.4'))
    state=dns.snapshot();dns.verify(state)
    assert state['dns_server']=='192.168.1.4'
    probes=[args for args in calls if args[0]=='dig']
    assert len(probes)==4 and all(args[1]=='@192.168.1.4' for args in probes)
    assert sum('+tcp' in args for args in probes)==2


@pytest.mark.parametrize('udp,tcp,expected',[
 ('0.0.0.0','0.0.0.0','127.0.0.1'),
 ('0.0.0.0','192.168.1.4','192.168.1.4'),
 ('192.168.1.4','0.0.0.0','192.168.1.4'),
 ('127.0.0.1','127.0.0.1','127.0.0.1'),
])
def test_ipv4_wildcard_and_specific_binding_intersection(monkeypatch,udp,tcp,expected):
    install_listener_fixture(monkeypatch,listener('udp',udp)+listener('tcp',tcp))
    assert dns.adguard_dns_servers()[0]==expected


def test_ipv6_wildcard_uses_ipv6_loopback(monkeypatch):
    install_listener_fixture(monkeypatch,'',listener('udp','[::]')+listener('tcp','[::]'))
    assert dns.adguard_dns_servers()==['::1']


@pytest.mark.parametrize('text',[
 listener('udp','192.168.1.4'),
 listener('udp','192.168.1.4',10140)+listener('tcp','192.168.1.4',10140),
 listener('udp','192.168.1.4')+listener('tcp','127.0.0.1'),
])
def test_missing_transport_or_other_process_never_satisfies_guard(monkeypatch,text):
    install_listener_fixture(monkeypatch,text)
    with pytest.raises(RuntimeError,match='listener'):dns.adguard_dns_servers()


def test_verification_does_not_fall_back_to_a_different_working_address(monkeypatch):
    install_listener_fixture(monkeypatch,listener('udp','127.0.0.1')+listener('tcp','127.0.0.1'))
    with pytest.raises(RuntimeError,match='disappeared'):
        dns.verify({'adguard_was_active':True,'configuration_hashes':{},'dns_server':'192.168.1.4'})


def test_query_timeout_is_reported_as_guard_failure(monkeypatch):
    def fail(*args,**kwargs):raise subprocess.CalledProcessError(9,args)
    monkeypatch.setattr(subprocess,'run',fail)
    with pytest.raises(RuntimeError,match='192.168.1.4 over UDP'):dns.probe_dns('192.168.1.4')



def test_concrete_ipv6_owned_listener_and_mixed_families(monkeypatch):
    install_listener_fixture(monkeypatch,'',listener('udp','[2001:db8::4]')+listener('tcp','[2001:db8::4]'))
    assert dns.adguard_dns_servers()==['2001:db8::4']
    install_listener_fixture(monkeypatch,listener('udp','0.0.0.0'),listener('tcp','[::]'))
    with pytest.raises(RuntimeError,match='listener'):dns.adguard_dns_servers()


@pytest.mark.parametrize('pid',['','0','1014x'])
def test_invalid_service_pid_fails_closed(monkeypatch,pid):
    install_listener_fixture(monkeypatch,listener('udp','192.168.1.4')+listener('tcp','192.168.1.4'),pid=pid)
    with pytest.raises(RuntimeError,match='identify'):dns.adguard_dns_servers()


def test_udp_probe_cannot_silently_retry_over_tcp(monkeypatch):
    calls=install_listener_fixture(monkeypatch,'')
    dns.probe_dns('192.168.1.4')
    assert '+ignore' in calls[0] and '+tcp' not in calls[0] and '+tcp' in calls[1]
