"""Bounded device activity and coverage from exact measured flow evidence."""
from datetime import datetime
import ipaddress
import time
from services.flow_attribution_service import flow_table, internet_endpoints
from services.tls_metadata_service import metadata_table

MIB = 1024 * 1024


def bounded_window(start_ms, end_ms, *, settle=False, now_ms=None):
    now=int(time.time()*1000) if now_ms is None else now_ms
    end=min(int(end_ms),now-(120_000 if settle else 0))
    start=max(int(start_ms),end-31*86400_000)
    if end<start:
        end=start
    return start,end


def _dicts(cursor):
    columns=[item[0] for item in cursor.description]
    return [dict(zip(columns,row)) for row in cursor]


def device_reference(con,ip):
    address=str(ipaddress.ip_address(ip))
    identity=con.execute("SELECT device_id,identity_key,display_name FROM device_identities WHERE current_ip=? ORDER BY last_seen DESC LIMIT 1",(address,)).fetchone()
    override=con.execute("SELECT name FROM device_overrides WHERE ip=?",(address,)).fetchone()
    display=(override[0] if override and override[0] else identity[2] if identity and identity[2] else address)
    return {"ip":address,"device_id":identity[0] if identity else None,"name":display}


def device_timeline(con,ip,start_ms,end_ms,*,limit=50,page=0,config=None):
    reference=device_reference(con,ip)
    start,end=bounded_window(start_ms,end_ms)
    limit=max(1,min(100,int(limit)));page=max(0,min(1000,int(page)))
    key,value=("device_id",reference["device_id"]) if reference["device_id"] else ("local_ip",reference["ip"])
    rows=_dicts(con.execute(f"""SELECT measurement_id,local_ip,remote_ip,first_ms,last_ms,application,category,hostname,evidence,confidence,reason,
        CASE WHEN direction='download' THEN bytes ELSE 0 END AS downloaded_bytes,
        CASE WHEN direction='upload' THEN bytes ELSE 0 END AS uploaded_bytes
        FROM {flow_table(con)} WHERE {key}=? AND last_ms>=? AND last_ms<?
        ORDER BY last_ms DESC,measurement_id DESC LIMIT ? OFFSET ?""",(value,start,end,limit+1,page*limit)))
    has_more=len(rows)>limit
    observations=[]
    # Observations never add bytes. They are useful while waiting for a flow export.
    candidates=_dicts(con.execute(f"""SELECT source_ip,destination_ip,source_port,destination_port,started_ms,observed_ms,hostname,ech_present
        FROM {metadata_table(con)} WHERE source_ip=? AND observed_ms>=? AND observed_ms<?
        ORDER BY observed_ms DESC LIMIT 100""",(reference["ip"],start,end)))
    for observation in candidates:
        candidate={"src_ip":observation["source_ip"],"dst_ip":observation["destination_ip"]}
        if config is not None and not internet_endpoints(candidate,config):continue
        exists=con.execute(f"""SELECT 1 FROM {flow_table(con)} WHERE protocol=6 AND first_ms BETWEEN ? AND ? AND
            ((source_ip=? AND destination_ip=? AND source_port=? AND destination_port=?) OR
             (source_ip=? AND destination_ip=? AND source_port=? AND destination_port=?)) LIMIT 1""",
            (observation["started_ms"]-2000,observation["started_ms"]+2000,observation["source_ip"],observation["destination_ip"],observation["source_port"],observation["destination_port"],observation["destination_ip"],observation["source_ip"],observation["destination_port"],observation["source_port"])).fetchone()
        if not exists:observations.append(observation)
        if len(observations)>=20:break
    return {**reference,"rows":rows[:limit],"observations":observations,"has_more":has_more,"page":page,"start_ms":start,"end_ms":end}


def coverage_summary(con,start_ms,end_ms,*,ips=None,now_ms=None,bridge_source_sql=None):
    start,end=bounded_window(start_ms,end_ms,settle=True,now_ms=now_ms)
    selected=tuple(dict.fromkeys(str(ipaddress.ip_address(ip)) for ip in (ips or [])))[:256]
    where="first_ms>=? AND last_ms<?";params=[start,end]
    bridge_where="ts>=? AND ts<?";bridge_params=[datetime.fromtimestamp(start/1000).strftime("%Y-%m-%d %H:%M:%S"),datetime.fromtimestamp(end/1000).strftime("%Y-%m-%d %H:%M:%S")]
    if selected:
        placeholders=",".join("?" for _ in selected)
        where+=f" AND local_ip IN ({placeholders})";params.extend(selected)
        bridge_where+=f" AND ip IN ({placeholders})";bridge_params.extend(selected)
    total,known=con.execute(f"SELECT COALESCE(SUM(bytes),0),COALESCE(SUM(CASE WHEN application IS NOT NULL THEN bytes ELSE 0 END),0) FROM {flow_table(con)} WHERE {where}",params).fetchone()
    bridge_source=bridge_source_sql or "SELECT ip,ts,total_mb FROM traffic_intervals"
    bridge=float(con.execute(f"SELECT COALESCE(SUM(total_mb),0) FROM ({bridge_source}) WHERE {bridge_where}",bridge_params).fetchone()[0])*MIB
    bridge=int(round(bridge))
    mismatch=bool(total>bridge)
    available=bool(bridge>0 and not mismatch)
    return {"start_ms":start,"end_ms":end,"bridge_bytes":int(bridge),"measured_bytes":int(total),"attributed_bytes":int(known),
            "unattributed_bridge_bytes":max(0,int(bridge-known)),"unclassified_flow_bytes":int(total-known),
            "coverage_pct":round(known/bridge*100,1) if available else None,
            "flow_classification_pct":round(known/total*100,1) if total else None,
            "flow_visibility_pct":round(total/bridge*100,1) if available else None,
            "counter_mismatch":mismatch,"settling_seconds":120}



def measured_category_report(con,start_time,end_time,filters=None,limit=8,bridge_source_sql=None):
    """Primary report adapter: never combine legacy destination guesses with measured flows."""
    from services.application_classification_service import color_for_category
    filters=filters or {}
    start=int(datetime.fromisoformat(str(start_time)).timestamp()*1000)
    end=int(datetime.fromisoformat(str(end_time)).timestamp()*1000)
    coverage=coverage_summary(con,start,end,ips=filters.get("device_ids"),bridge_source_sql=bridge_source_sql)
    where="first_ms>=? AND last_ms<? AND application IS NOT NULL";params=[coverage["start_ms"],coverage["end_ms"]]
    ips=tuple(dict.fromkeys(filters.get("device_ids") or []))[:256]
    if ips:
        where+=" AND local_ip IN ("+",".join("?" for _ in ips)+")";params.extend(ips)
    requested=str(filters.get("application") or "").strip()
    if requested:
        where+=" AND (category=? OR application=?)";params.extend([requested,requested])
    cursor=con.execute(f"""SELECT category,SUM(CASE WHEN direction='download' THEN bytes ELSE 0 END) AS downloaded_bytes,
        SUM(CASE WHEN direction='upload' THEN bytes ELSE 0 END) AS uploaded_bytes,SUM(bytes) AS total_bytes,
        COUNT(DISTINCT local_ip) AS devices,COUNT(DISTINCT application) AS applications
        FROM {flow_table(con)} WHERE {where} GROUP BY category ORDER BY total_bytes DESC LIMIT 100""",params)
    categories=_dicts(cursor)
    apps=_dicts(con.execute(f"SELECT category,application,SUM(bytes) AS bytes FROM {flow_table(con)} WHERE {where} GROUP BY category,application ORDER BY bytes DESC LIMIT 1000",params))
    bridge=coverage["bridge_bytes"];known=coverage["attributed_bytes"]
    rows=[]
    for category in categories:
        names=[item["application"] for item in apps if item["category"]==category["category"]]
        rows.append({"category":category["category"],"usage_group":"Measured applications","classification_source":"Connection / client DNS evidence",
            "color":color_for_category(category["category"]),"downloaded_mb":category["downloaded_bytes"]/MIB,"uploaded_mb":category["uploaded_bytes"]/MIB,
            "total_mb":category["total_bytes"]/MIB,"devices":category["devices"],"applications":category["applications"],"application_names":names,
            "share_classified_pct":round(category["total_bytes"]/known*100,1) if known else 0,
            "share_total_pct":round(category["total_bytes"]/bridge*100,1) if bridge and not coverage["counter_mismatch"] else 0,
            "share_pct":round(category["total_bytes"]/bridge*100,1) if bridge and not coverage["counter_mismatch"] else 0})
    count=max(1,min(50,int(limit)))
    if len(rows)>count:
        rest=rows[count-1:];rows=rows[:count-1]
        rows.append({"category":"Other","usage_group":"Measured applications","classification_source":"Grouped measured flows","color":"#94a3b8",
            "downloaded_mb":sum(x["downloaded_mb"] for x in rest),"uploaded_mb":sum(x["uploaded_mb"] for x in rest),"total_mb":sum(x["total_mb"] for x in rest),
            "devices":0,"applications":sum(x["applications"] for x in rest),"application_names":sorted({name for x in rest for name in x["application_names"]}),
            "share_classified_pct":sum(x["share_classified_pct"] for x in rest),"share_total_pct":sum(x["share_total_pct"] for x in rest),"share_pct":sum(x["share_pct"] for x in rest)})
    unknown=coverage["unattributed_bridge_bytes"]
    if unknown:
        rows.append({"category":"Traffic Without Application Attribution","usage_group":"Unattributed","classification_source":"No primary application evidence","color":"#64748b",
            "downloaded_mb":0,"uploaded_mb":0,"total_mb":unknown/MIB,"devices":0,"applications":0,"application_names":[],"share_classified_pct":0,
            "share_total_pct":round(unknown/bridge*100,1) if bridge else 0,"share_pct":round(unknown/bridge*100,1) if bridge else 0})
    note="Flow and bridge counters disagree; application coverage is unavailable." if coverage["counter_mismatch"] else "Application bytes use measured connections. Coverage excludes the latest two minutes while flow exports settle; unobserved traffic remains unattributed."
    if coverage['counter_mismatch']:
        note+=f" Settled bridge traffic: {bridge/MIB:.2f} MiB; measured connections: {coverage['measured_bytes']/MIB:.2f} MiB."
        if coverage['flow_classification_pct'] is not None:
            note+=f" {coverage['flow_classification_pct']:.1f}% of measured connection bytes have an application label (a separate denominator)."
    if not bridge and not coverage["counter_mismatch"]:note="No settled bridge traffic is available for calculating application coverage."
    return {"rows":rows,"total_network_mb":bridge/MIB,"classified_application_mb":known/MIB,"matched_application_mb":known/MIB,
        "unclassified_application_mb":unknown/MIB,"classification_coverage_pct":coverage["coverage_pct"],"classification_match_rate_pct":coverage["coverage_pct"],
        "classification_is_overlapping":False,"coverage_unavailable":coverage["coverage_pct"] is None,"coverage_note":note,
        "measured_flow_mb":coverage["measured_bytes"]/MIB,"flow_visibility_pct":coverage["flow_visibility_pct"],"measurement_scope":"settled_internet_flows",**{"coverage":coverage}}
