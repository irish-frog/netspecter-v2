from datetime import datetime
import sqlite3,time
from services import reporting_service as reporting
from services.flow_attribution_service import ensure_flow_schema


def test_passive_top_apps_keep_real_category_and_exclude_unsettled_bytes(monkeypatch):
    con=sqlite3.connect(':memory:');ensure_flow_schema(con)
    now=int(time.time()*1000)
    for name,ip,offset in [('old','192.168.1.5',300000),('fresh','192.168.1.5',1000),('other','192.168.1.6',300000)]:
        con.execute('''INSERT INTO measured_internet_flows
          (measurement_id,source_ip,destination_ip,source_port,destination_port,protocol,local_ip,remote_ip,direction,first_ms,last_ms,exported_ms,bytes,packets,application,category)
          VALUES (?,?,?,12345,443,6,?,?,'download',?,?,?,1048576,1,'TikTok','Social Media')''',
          (name,'8.8.8.8',ip,ip,'8.8.8.8',now-offset-1000,now-offset,now-offset+1000))
    monkeypatch.setattr(reporting,'cfg',lambda:{'passive_attribution_enabled':True})
    def query(sql,params,*_):
        cur=con.execute(sql,params);columns=[x[0] for x in cur.description]
        return [dict(zip(columns,row)) for row in cur]
    monkeypatch.setattr(reporting,'_timed_query',query)
    start=datetime.fromtimestamp((now-86400000)/1000).isoformat();end=datetime.fromtimestamp(now/1000).isoformat()
    rows=reporting.get_application_summary({'device_ids':['192.168.1.5'],'application':'Social Media'},start,end)
    assert len(rows)==1 and rows[0]['application']=='TikTok'
    assert rows[0]['primary_category']=='Social Media' and rows[0]['total_mb']==1 and rows[0]['devices']==1


def test_passive_unattributed_device_totals_do_not_guess_from_name_or_ip(monkeypatch):
    from services import application_classification_service as service
    monkeypatch.setattr(service,'cfg',lambda:{'passive_attribution_enabled':True})
    monkeypatch.setattr(service,'query',lambda *args:[dict(name='YouTube TV',device_type='TV',ip='192.168.1.5',mac='',total_mb=100,classified_mb=10,last_seen='2026-11-19')])
    monkeypatch.setattr(service,'site_application_mappings',lambda:[{'ip':'192.168.1.5','application':'TV'}])
    monkeypatch.setattr(service,'device_identity_hint',lambda *args:True)
    result=service.unclassified_device_summary('2026-11-18','2026-11-19')
    assert result[0]['unclassified_mb']==90 and result[0]['unclassified_pct']==90


def test_retired_security_option_is_absent_and_excel_keeps_real_category(monkeypatch):
    import app as web
    monkeypatch.setattr(web,'cfg',lambda:{'security_features_enabled':False,'passive_attribution_enabled':True})
    assert web.report_security_checkbox(checked=True)==''
    monkeypatch.setattr(web,'build_xlsx',lambda sheets:sheets)
    context={'overview':{'total_mb':1},'start_time':'2026-11-18','end_time':'2026-11-19','category_report':{},'category_rows':[],
      'app_rows':[{'application':'TikTok','category':'TikTok','primary_category':'Social Media','total_mb':1,'devices':1}]}
    sheets=dict(web.reporting_xlsx_response(context,{'applications','security'}))
    assert sheets['Top Apps'][1][:2]==['TikTok','Social Media']
    assert 'Security Events' not in sheets
