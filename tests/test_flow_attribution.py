import json
import sqlite3
import pytest
from services.flow_attribution_service import Attributor,ensure_flow_schema,persist_measurements
from services.tls_metadata_service import ensure_metadata_schema,store_metadata,validate_metadata

NOW=1_800_000_000_000
CONFIG={"lan_prefix":"192.168.1.","internal_networks":["10.20.30.0/24"]}


def database():
    con=sqlite3.connect(":memory:")
    ensure_metadata_schema(con);ensure_flow_schema(con)
    con.execute("CREATE TABLE dns_resolution_events (client_ip TEXT,resolved_ip TEXT,domain TEXT,ts TEXT,expires_at TEXT)")
    return con


def flow(identity="one",sport=12345,dest="8.8.8.8",source="192.168.1.5"):
    return dict(measurement_id=identity,src_ip=source,dst_ip=dest,src_port=sport,dst_port=443,protocol=6,bytes=1000,packets=10,first_ms=NOW-1000,last_ms=NOW,exported_ms=NOW+1000)


def metadata(con,domain="youtube.com",sport=12345,started=NOW-1000,ech=False):
    value=dict(schema_version=1,event_type="tls_client_hello",observed_at_unix_ms=started+100,connection_started_at_unix_ms=started,
        connection=dict(source="192.168.1.5",destination="8.8.8.8",source_port=sport,destination_port=443),hostname=domain,ech_present=ech)
    store_metadata(con,[validate_metadata(json.dumps(value).encode(),now_ms=NOW)])


def classify(domain):
    return {"youtube.com":("YouTube","Streaming"),"netflix.com":("Netflix","Streaming"),"googlevideo.com":("YouTube","Streaming")}.get(domain,(None,"Unknown"))


def test_same_cdn_connections_keep_separate_applications_and_bytes():
    con=database();metadata(con);metadata(con,"netflix.com",sport=12346)
    assert persist_measurements(con,[flow(),flow("two",sport=12346)],CONFIG,classify)==2
    assert con.execute("SELECT application,bytes FROM measured_internet_flows ORDER BY application").fetchall()==[("Netflix",1000),("YouTube",1000)]
    assert persist_measurements(con,[flow()],CONFIG,classify)==0
    assert con.execute("SELECT sum(bytes) FROM measured_internet_flows").fetchone()[0]==2000


def test_reverse_direction_matches_tuple_and_preserves_download_bytes():
    con=database();metadata(con)
    row=flow();row.update(src_ip="8.8.8.8",dst_ip="192.168.1.5",src_port=443,dst_port=12345)
    persist_measurements(con,[row],CONFIG,classify)
    assert con.execute("SELECT local_ip,direction,application,bytes FROM measured_internet_flows").fetchone()==("192.168.1.5","download","YouTube",1000)


@pytest.mark.parametrize("source,destination",[("192.168.1.5","192.168.1.10"),("10.20.30.9","192.168.1.10"),("192.168.1.10","10.20.30.9"),("192.168.1.5","10.99.0.1"),("192.168.1.5","224.0.0.1")])
def test_internal_and_non_global_transfers_add_no_internet_bytes(source,destination):
    con=database();assert persist_measurements(con,[flow(source=source,dest=destination)],CONFIG,classify)==0


def test_vpn_internet_and_server_internet_still_count():
    con=database()
    assert persist_measurements(con,[flow("vpn",source="10.20.30.9"),flow("server",source="192.168.1.10")],CONFIG,classify)==2


def test_stale_tuple_metadata_cannot_name_a_new_connection():
    con=database();metadata(con,started=NOW-60_000)
    result=Attributor(con,classify).classify(flow(),"192.168.1.5","8.8.8.8")
    assert result.application is None


def dns(con,domain,client="192.168.1.5"):
    con.execute("INSERT INTO dns_resolution_events VALUES (?,?,?,?,?)",(client,"8.8.8.8",domain,"2027-01-01 00:00:00","2030-01-01 00:00:00"))


def test_conflicting_dns_is_unknown_but_same_application_domains_can_agree():
    con=database();dns(con,"youtube.com");dns(con,"netflix.com")
    result=Attributor(con,classify).classify(flow(),"192.168.1.5","8.8.8.8")
    assert result.reason=="ambiguous_dns" and result.application is None
    con.execute("DELETE FROM dns_resolution_events WHERE domain='netflix.com'");dns(con,"googlevideo.com")
    result=Attributor(con,classify).classify(flow(),"192.168.1.5","8.8.8.8")
    assert result.application=="YouTube" and result.hostname is None and result.confidence=="medium"


def test_dns_does_not_leak_between_clients_or_after_expiry():
    con=database();dns(con,"youtube.com",client="192.168.1.6")
    assert Attributor(con,classify).classify(flow(),"192.168.1.5","8.8.8.8").application is None
    dns(con,"youtube.com");con.execute("UPDATE dns_resolution_events SET expires_at='2000-01-01 00:00:00'")
    assert Attributor(con,classify).classify(flow(),"192.168.1.5","8.8.8.8").application is None


def test_exact_unknown_hostname_does_not_inherit_different_dns_application():
    con=database();metadata(con,"unrecognized.example.com");dns(con,"youtube.com")
    result=Attributor(con,classify).classify(flow(),"192.168.1.5","8.8.8.8")
    assert result.application is None and result.hostname=="unrecognized.example.com"


def test_ech_outer_name_never_becomes_application():
    con=database();metadata(con,None,ech=True)
    assert Attributor(con,classify).classify(flow(),"192.168.1.5","8.8.8.8").reason=="ech_or_no_dns"


def test_late_metadata_updates_evidence_without_adding_bytes():
    from services.flow_attribution_service import reconcile_metadata
    con=database();persist_measurements(con,[flow()],CONFIG,classify)
    metadata(con)
    from services.tls_metadata_service import TlsMetadata
    row=con.execute("SELECT * FROM tls_connection_metadata").fetchone()
    observation=TlsMetadata(*row)
    assert reconcile_metadata(con,[observation],CONFIG,classify)==1
    assert con.execute("SELECT application,bytes FROM measured_internet_flows").fetchone()==("YouTube",1000)


def test_reused_nearby_tuple_is_ambiguous_instead_of_choosing_latest_name():
    con=database();metadata(con);metadata(con,"netflix.com",started=NOW-500)
    result=Attributor(con,classify).classify(flow(),"192.168.1.5","8.8.8.8")
    assert result.application is None and result.reason=="ambiguous_connection"


def test_explicit_operator_destination_mapping_takes_precedence():
    con=database();metadata(con)
    config={**CONFIG,"site_application_mappings":[{"ip":"8.8.8.8","application":"Operator Service","category":"Business"}]}
    persist_measurements(con,[flow()],config,classify)
    assert con.execute("SELECT application,evidence FROM measured_internet_flows").fetchone()==("Operator Service","operator_rule")


def test_late_client_dns_is_reconciled_once_without_changing_measured_bytes():
    from services.flow_attribution_service import reconcile_pending
    con=database();persist_measurements(con,[flow()],CONFIG,classify)
    con.execute("UPDATE measured_internet_flows SET checked_ms=0")
    dns(con,"youtube.com")
    assert reconcile_pending(con,CONFIG,now_ms=NOW+1000,domain_classifier=classify)==1
    assert con.execute("SELECT application,bytes FROM measured_internet_flows").fetchone()==("YouTube",1000)
    assert reconcile_pending(con,CONFIG,now_ms=NOW+1001,domain_classifier=classify)==0


def test_default_domain_classifier_recognizes_specific_application_without_port_guesses():
    from services.flow_attribution_service import classify_domain
    app,category=classify_domain("www.youtube.com")
    assert app=="YouTube" and category!="Unknown"
    assert classify_domain("unknown-service.example.invalid")[0] is None


def test_appliance_speedtests_and_ignored_devices_are_not_forwarded_usage():
    con=database()
    assert persist_measurements(con,[flow(source='192.168.1.5')],{**CONFIG,'_appliance_addresses':['192.168.1.5']},classify)==0
    assert persist_measurements(con,[flow(source='192.168.1.5')],{**CONFIG,'ignore_ips':['192.168.1.5']},classify)==0


def test_time_scoped_identity_does_not_assign_old_flow_to_reassigned_ip():
    from services.flow_attribution_service import identity_at_time
    con=database()
    con.executescript('''CREATE TABLE device_identities(device_id TEXT,identity_key TEXT,current_ip TEXT,first_seen TEXT,last_seen TEXT);
        CREATE TABLE device_ip_history(identity_key TEXT,ip TEXT,first_seen TEXT,last_seen TEXT);
        INSERT INTO device_identities VALUES ('old','old-key','192.168.1.9','2020-01-01','2030-01-01');
        INSERT INTO device_identities VALUES ('new','new-key','192.168.1.5','2027-01-20','2030-01-01');
        INSERT INTO device_ip_history VALUES ('old-key','192.168.1.5','2020-01-01','2027-01-19');''')
    assert identity_at_time(con,'192.168.1.5',NOW-1000,NOW)['device_id']=='old'


def test_passive_mode_keeps_old_ip_guesses_out_and_includes_configured_vpn_clients(monkeypatch):
    import live_packet_collector as collector
    from services.traffic_scope_service import accounting_clients
    config={**CONFIG,'passive_attribution_enabled':True,'ids_banned_ips':['8.8.8.8']}
    def unexpected(*_):raise AssertionError('Legacy per-destination estimate requested')
    for name in ['active_estimated_app_targets','active_classification_targets','active_visibility_targets']:
        monkeypatch.setattr(collector,name,unexpected)
    signature=collector.nft_signature(config)
    assert signature[3]==() and signature[5:]==((),(),())
    assert '10.20.30.9' in accounting_clients(config)


def test_measured_report_source_never_sums_legacy_estimates(monkeypatch):
    from services import reporting_service as reporting
    monkeypatch.setattr(reporting,'cfg',lambda:{'passive_attribution_enabled':True})
    source=reporting.estimated_app_source_sql()
    assert 'measured_internet_flows' in source and 'estimated_app_traffic' not in source
