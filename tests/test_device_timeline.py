import sqlite3
import pytest
from services.device_timeline_service import device_timeline,coverage_summary,MIB
from services.flow_attribution_service import ensure_flow_schema,persist_measurements
from services.tls_metadata_service import ensure_metadata_schema

NOW=int(__import__("time").time()*1000)
CONFIG={"lan_prefix":"192.168.1."}


def database():
    con=sqlite3.connect(":memory:");ensure_flow_schema(con);ensure_metadata_schema(con)
    con.executescript("""CREATE TABLE device_identities(device_id TEXT,identity_key TEXT,display_name TEXT,current_ip TEXT,last_seen TEXT);
        CREATE TABLE device_overrides(ip TEXT,name TEXT);
        CREATE TABLE traffic_intervals(ip TEXT,ts TEXT,total_mb REAL);""")
    con.execute("INSERT INTO device_identities VALUES ('stable','mac:1','Learned name','192.168.1.5','2027-01-15')")
    con.execute("INSERT INTO device_overrides VALUES ('192.168.1.5','Edited workstation')")
    return con


def add(con,id="one",ip="192.168.1.5",device_id="stable",last=NOW-200_000):
    row=dict(measurement_id=id,src_ip=ip,dst_ip="8.8.8.8",src_port=12345,dst_port=443,protocol=6,bytes=1000,packets=10,first_ms=last-1000,last_ms=last,exported_ms=last+1000)
    persist_measurements(con,[row],CONFIG,lambda _: (None,"Unknown"),identity_lookup=lambda *_:{"device_id":device_id})


def test_timeline_preserves_edited_name_and_tracks_stable_identity_across_ip_change():
    con=database();add(con,ip="192.168.1.6")
    result=device_timeline(con,"192.168.1.5",NOW-86400_000,NOW,config=CONFIG)
    assert result["name"]=="Edited workstation" and result["rows"][0]["local_ip"]=="192.168.1.6"
    assert result["rows"][0]["uploaded_bytes"]==1000 and result["rows"][0]["downloaded_bytes"]==0


def test_reassigned_ip_does_not_show_another_stable_device_history():
    con=database();add(con,device_id="old-device")
    assert not device_timeline(con,"192.168.1.5",NOW-86400_000,NOW)["rows"]


def test_pagination_is_bounded_and_empty_state_is_valid():
    con=database();assert not device_timeline(con,"192.168.1.5",NOW-10000,NOW)["rows"]
    for i in range(3):add(con,str(i))
    result=device_timeline(con,"192.168.1.5",NOW-86400_000,NOW,limit=2)
    assert len(result["rows"])==2 and result["has_more"]
    assert len(device_timeline(con,"192.168.1.5",NOW-86400_000,NOW,limit=2,page=1)["rows"])==1


def test_bridge_and_flow_denominators_stay_separate_and_mismatch_is_explicit():
    from datetime import datetime
    con=database();add(con)
    con.execute("UPDATE measured_internet_flows SET application='YouTube'")
    ts=datetime.fromtimestamp((NOW-200_000)/1000).strftime("%Y-%m-%d %H:%M:%S")
    con.execute("INSERT INTO traffic_intervals VALUES (?,?,?)",("192.168.1.5",ts,2000/MIB))
    result=coverage_summary(con,NOW-86400_000,NOW,now_ms=NOW)
    assert result["bridge_bytes"]==2000 and result["measured_bytes"]==1000 and result["coverage_pct"]==50
    con.execute("UPDATE traffic_intervals SET total_mb=?",(500/MIB,))
    result=coverage_summary(con,NOW-86400_000,NOW,now_ms=NOW)
    assert result["counter_mismatch"] and result["coverage_pct"] is None


def test_unsettled_flows_do_not_inflate_coverage():
    con=database();add(con,last=NOW-1000)
    result=coverage_summary(con,NOW-86400_000,NOW,now_ms=NOW)
    assert result["measured_bytes"]==0 and result["coverage_pct"] is None



def test_timeline_route_escapes_names_domains_and_application_values(monkeypatch):
    import app as web
    from services import device_timeline_service as timeline_service
    con=database();add(con)
    con.execute("UPDATE device_overrides SET name='<script>bad-name</script>'")
    con.execute("UPDATE measured_internet_flows SET application='<img src=x onerror=alert(1)>',hostname='<script>bad-domain</script>'")
    configuration={**web.cfg(),**CONFIG,"passive_attribution_enabled":True}
    monkeypatch.setattr(web,"cfg",lambda:configuration)
    monkeypatch.setattr(web,"connect_db",lambda:con)
    original=timeline_service.coverage_summary
    monkeypatch.setattr(timeline_service,"coverage_summary",lambda connection,start,end,**kwargs: original(connection,start,end,ips=kwargs.get("ips")))
    with web.app.test_request_context("/device/192.168.1.5/timeline?_partial=1"):
        response=web.device_application_timeline("192.168.1.5")
        html=response.get_data(as_text=True)
    assert "&lt;script&gt;bad-name&lt;/script&gt;" in html
    assert "&lt;script&gt;bad-domain&lt;/script&gt;" in html
    assert "<img src=x onerror" not in html and "<script>bad" not in html
    assert "<html" not in html


def test_timeline_route_is_not_public():
    import app as web
    response=web.app.test_client().get("/device/192.168.1.5/timeline")
    assert response.status_code in {302,303,401,403}


def test_primary_report_uses_measured_bytes_and_keeps_unobserved_bridge_traffic_unknown():
    from datetime import datetime
    from services.device_timeline_service import measured_category_report
    con=database();add(con)
    con.execute("UPDATE measured_internet_flows SET application='YouTube',category='Streaming'")
    ts=datetime.fromtimestamp((NOW-200_000)/1000).strftime("%Y-%m-%d %H:%M:%S")
    con.execute("INSERT INTO traffic_intervals VALUES (?,?,?)",("192.168.1.5",ts,4000/MIB))
    start=datetime.fromtimestamp((NOW-86400_000)/1000).strftime("%Y-%m-%d %H:%M:%S")
    end=datetime.fromtimestamp(NOW/1000).strftime("%Y-%m-%d %H:%M:%S")
    result=measured_category_report(con,start,end)
    assert result["classification_coverage_pct"]==25
    assert result["classified_application_mb"]==1000/MIB
    assert result["unclassified_application_mb"]==3000/MIB
    assert result["rows"][0]["application_names"]==["YouTube"]
    assert result["rows"][-1]["category"]=="Traffic Without Application Attribution"


def test_mismatched_report_does_not_claim_100_percent_coverage():
    from datetime import datetime
    from services.device_timeline_service import measured_category_report
    con=database();add(con)
    con.execute("UPDATE measured_internet_flows SET application='YouTube',category='Streaming'")
    start=datetime.fromtimestamp((NOW-86400_000)/1000).strftime("%Y-%m-%d %H:%M:%S")
    end=datetime.fromtimestamp(NOW/1000).strftime("%Y-%m-%d %H:%M:%S")
    report=measured_category_report(con,start,end)
    assert report["coverage_unavailable"] and report["classification_coverage_pct"] is None
