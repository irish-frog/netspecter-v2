import pytest
from services.classification_resolver_service import dns_answer_rows


def rows(answers,**overrides):
    return dns_answer_rows(overrides.get('client','192.168.1.5'),overrides.get('domain','Example.COM.'),answers,overrides.get('time','2026-11-19 12:00:00'))


@pytest.mark.parametrize('ttl',[0,-1,'invalid',None,True,float('inf')])
def test_noncacheable_or_malformed_ttl_cannot_become_fifteen_minutes(ttl):
    assert rows([{'type':'A','value':'8.8.8.8','ttl':ttl}])==[]


def test_cname_chain_and_duplicate_address_use_shortest_lifetime():
    result=rows([{'type':'CNAME','value':'first.example.net.','ttl':30},
                 {'type':'CNAME','value':'second.example.net.','ttl':10},
                 {'type':'A','value':'8.8.8.8','ttl':300},
                 {'type':'A','value':'8.8.8.8','ttl':5}])
    assert len(result)==1
    assert result[0][1:6]==('192.168.1.5','example.com','8.8.8.8',5,'2026-11-19 12:00:05')


def test_zero_ttl_cname_cannot_leave_long_lived_address_evidence():
    assert rows([{'type':'CNAME','value':'cdn.example.net','ttl':0},
                 {'type':'A','value':'8.8.8.8','ttl':600}])==[]


def test_answer_ip_type_and_ipv6_canonicalization():
    result=rows([{'type':'A','value':'not-an-address','ttl':300},
                 {'type':'AAAA','value':'8.8.8.8','ttl':300},
                 {'type':'A','value':'2001:4860:4860::8888','ttl':300},
                 {'type':'AAAA','value':'2001:4860:4860:0:0:0:0:8888','ttl':300}])
    assert len(result)==1 and result[0][3]=='2001:4860:4860::8888'


@pytest.mark.parametrize('overrides',[{'client':'not-an-ip'},{'time':'invalid'},{'domain':''}])
def test_invalid_observation_cannot_supply_dns_evidence(overrides):
    assert rows([{'type':'A','value':'8.8.8.8','ttl':120}],**overrides)==[]
