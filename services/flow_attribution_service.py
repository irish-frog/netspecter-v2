"""Connection-scoped attribution of deduplicated measured internet flows."""
from dataclasses import dataclass
from datetime import datetime
import fnmatch
import ipaddress
import json
import sqlite3
import time
from services.traffic_scope_service import internal_ipv4_networks
from services.tls_metadata_service import metadata_table


@dataclass(frozen=True)
class Attribution:
    application: str | None = None
    category: str = "Unknown"
    hostname: str | None = None
    evidence: str = "none"
    confidence: str = "none"
    reason: str = "no_evidence"


def flow_table(con):
    attached={row[1] for row in con.execute("PRAGMA database_list")}
    return "trafficdb.measured_internet_flows" if "trafficdb" in attached else "measured_internet_flows"


def ensure_flow_schema(con):
    con.execute("""CREATE TABLE IF NOT EXISTS measured_internet_flows (
        measurement_id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL,
        source_port INTEGER NOT NULL, destination_port INTEGER NOT NULL, protocol INTEGER NOT NULL,
        local_ip TEXT NOT NULL, remote_ip TEXT NOT NULL, direction TEXT NOT NULL,
        first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL, exported_ms INTEGER NOT NULL,
        bytes INTEGER NOT NULL, packets INTEGER NOT NULL, device_id TEXT, identity_key TEXT,
        application TEXT, category TEXT NOT NULL DEFAULT 'Unknown', hostname TEXT,
        evidence TEXT NOT NULL DEFAULT 'none', confidence TEXT NOT NULL DEFAULT 'none',
        reason TEXT NOT NULL DEFAULT 'no_evidence', checked_ms INTEGER NOT NULL DEFAULT 0
    )""")
    columns={row[1] for row in con.execute("PRAGMA table_info(measured_internet_flows)")}
    if "checked_ms" not in columns:
        con.execute("ALTER TABLE measured_internet_flows ADD COLUMN checked_ms INTEGER NOT NULL DEFAULT 0")
    con.execute("CREATE INDEX IF NOT EXISTS idx_measured_recheck ON measured_internet_flows(checked_ms,last_ms)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_measured_device_time ON measured_internet_flows(local_ip,last_ms)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_measured_identity_time ON measured_internet_flows(device_id,last_ms)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_measured_time ON measured_internet_flows(last_ms)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_measured_tuple_time ON measured_internet_flows(source_ip,destination_ip,source_port,destination_port,first_ms,last_ms)")


def internet_endpoints(row, config):
    source=ipaddress.ip_address(row["src_ip"]); destination=ipaddress.ip_address(row["dst_ip"])
    excluded=set(config.get("_appliance_addresses",[])) | set(config.get("ignore_ips",[]) if isinstance(config.get("ignore_ips",[]),list) else [])
    gateway=str(config.get("gateway_ip") or "")
    if source.version != destination.version or str(source) in excluded or str(destination) in excluded or str(source)==gateway or str(destination)==gateway:
        return None
    networks=list(internal_ipv4_networks(config))
    for text in config.get("internal_ipv6_networks",[]) or []:
        network=ipaddress.ip_network(text,strict=False)
        if network.version!=6 or network.prefixlen==0:
            raise ValueError("invalid internal IPv6 network")
        networks.append(network)
    def local(address):
        return any(address.version==network.version and address in network for network in networks)
    if local(source) and destination.is_global and not destination.is_multicast and not local(destination):
        return str(source),str(destination),"upload"
    if local(destination) and source.is_global and not source.is_multicast and not local(source):
        return str(destination),str(source),"download"
    return None


def classify_domain(domain):
    from services.application_classification_service import classify_application
    result=classify_application(domain=domain,persistent_cache=False)
    app=result.get("primary_app")
    category=result.get("primary_category") or result.get("category") or "Unknown"
    # A broad category alone, shared provider, or protocol is not a primary application.
    if not app or str(app).casefold() in {"unknown","https","http","tls","google","microsoft","amazon","cloudflare","akamai","fastly","cloudfront","azure","aws",category.casefold()}:
        return None,category
    return str(app),category


class Attributor:
    def __init__(self,con,domain_classifier=None,config=None):
        self.con=con
        self.config=config or {}
        self.domain_classifier=domain_classifier or classify_domain
        self.domain_cache={}
        self.rules=[]
        prefix="trafficdb." if flow_table(con).startswith("trafficdb.") else ""
        try:
            cursor=con.execute(f"SELECT * FROM application_signatures WHERE enabled=1 AND source IN ('operator','local','manual') ORDER BY priority DESC,confidence DESC,id LIMIT 4096")
            columns=[item[0] for item in cursor.description]
            self.rules=[dict(zip(columns,row)) for row in cursor]
        except sqlite3.OperationalError as error:
            if "no such table" not in str(error): raise
        self.dns_prefix="dnsdb." if "dnsdb" in {row[1] for row in con.execute("PRAGMA database_list")} else ""

    def _domain(self,name):
        if name not in self.domain_cache:
            if len(self.domain_cache)>=2048: self.domain_cache.clear()
            self.domain_cache[name]=self.domain_classifier(name)
        return self.domain_cache[name]

    def _operator(self,row,remote,domain=""):
        for mapping in self.config.get("site_application_mappings",[]) or []:
            if isinstance(mapping,dict) and mapping.get("ip")==remote and mapping.get("application"):
                return Attribution(str(mapping["application"]),str(mapping.get("category") or "Custom"),domain or None,"operator_rule","operator","")
        protocol={6:"tcp",17:"udp"}.get(row["protocol"],str(row["protocol"]))
        remote_port=row["dst_port"] if row["dst_ip"]==remote else row["src_port"]
        for rule in self.rules:
            try:
                domains=json.loads(rule.get("domains_json") or "[]")
                ips=json.loads(rule.get("destination_ips_json") or "[]")
                ports=json.loads(rule.get("ports_json") or "[]")
                protocols=json.loads(rule.get("protocols_json") or "[]")
                if any(not isinstance(items,list) for items in (domains,ips,ports,protocols)): continue
                if ports and str(remote_port) not in {str(x) for x in ports}: continue
                if protocols and protocol not in {str(x).lower() for x in protocols}: continue
                domain_match=bool(domain) and any(isinstance(p,str) and (fnmatch.fnmatchcase(domain,p.lower()) or (p.startswith("*.") and domain==p[2:].lower())) for p in domains)
                ip_match=any(ipaddress.ip_address(remote) in ipaddress.ip_network(p,strict=False) for p in ips)
                if not (domain_match or ip_match or (not domains and not ips and (ports or protocols))): continue
                return Attribution(str(rule["app"]),str(rule["category"]),domain or None,"operator_rule","operator","")
            except (ValueError,TypeError,KeyError): continue
        return None

    def classify(self,row,local,remote):
        operator=self._operator(row,remote)
        if operator: return operator
        first,last=row["first_ms"],row["last_ms"]
        candidates=[]
        if row["protocol"]==6:
            # Either direction must match the exact sensor tuple. A tuple's later reuse cannot inherit an old name.
            candidates=self.con.execute(f"""SELECT source_ip,destination_ip,source_port,destination_port,started_ms,observed_ms,hostname,ech_present
                FROM {metadata_table(self.con)} WHERE
                ((source_ip=? AND destination_ip=? AND source_port=? AND destination_port=?)
                OR (source_ip=? AND destination_ip=? AND source_port=? AND destination_port=?))
                AND started_ms BETWEEN ? AND ? AND observed_ms<=? ORDER BY started_ms DESC LIMIT 33""",
                (row["src_ip"],row["dst_ip"],row["src_port"],row["dst_port"],row["dst_ip"],row["src_ip"],row["dst_port"],row["src_port"],max(0,first-2000),last+2000,last+2000)).fetchall()
        if len(candidates)>32: return Attribution(reason="ambiguous_connection")
        if candidates:
            latest=candidates[0]
            # New handshake inside the measured interval or near its start makes ownership uncertain.
            if latest[4]>first+2000 or len(candidates)>1:
                return Attribution(reason="ambiguous_connection")
            if latest[6] and not latest[7]:
                domain=latest[6]
                operator=self._operator(row,remote,domain)
                if operator: return operator
                application,category=self._domain(domain)
                return Attribution(application,category,domain,"tls_sni","high" if application else "none","" if application else "unrecognized_hostname")
        timestamp=datetime.fromtimestamp(first/1000).strftime("%Y-%m-%d %H:%M:%S")
        try:
            dns=self.con.execute(f"""SELECT DISTINCT domain FROM {self.dns_prefix}dns_resolution_events
                WHERE client_ip=? AND resolved_ip=? AND ts<=? AND expires_at>=? LIMIT 33""",(local,remote,timestamp,timestamp)).fetchall()
        except sqlite3.OperationalError as error:
            if "no such table" not in str(error): raise
            dns=[]
        if len(dns)>32: return Attribution(reason="ambiguous_dns")
        if dns:
            domains=[str(item[0]).strip(".").lower() for item in dns]
            resolved=[]
            for domain in domains:
                operator=self._operator(row,remote,domain)
                app,category=(operator.application,operator.category) if operator else self._domain(domain)
                resolved.append((app,category))
            if len(set(resolved))==1 and resolved[0][0]:
                app,category=resolved[0]
                return Attribution(app,category,domains[0] if len(domains)==1 else None,"client_dns","medium","")
            if len(domains)==1:
                return Attribution(hostname=domains[0],evidence="client_dns",reason="unrecognized_hostname")
            return Attribution(reason="ambiguous_dns")
        reason="ech_or_no_dns" if candidates and candidates[0][7] else "unsupported_quic_or_no_dns" if row["protocol"]==17 and 443 in (row["src_port"],row["dst_port"]) else "no_connection_evidence"
        return Attribution(reason=reason)


def persist_measurements(con,rows,config,domain_classifier=None,identity_lookup=None):
    if len(rows)>200: raise ValueError("flow batch exceeds limit")
    table=flow_table(con); resolver=Attributor(con,domain_classifier,config); inserted=0
    for row in rows:
        endpoints=internet_endpoints(row,config)
        if not endpoints: continue
        local,remote,direction=endpoints
        if con.execute(f"SELECT 1 FROM {table} WHERE measurement_id=?",(row["measurement_id"],)).fetchone(): continue
        result=resolver.classify(row,local,remote)
        identity=identity_lookup(con,local) if identity_lookup else identity_at_time(con,local,row["first_ms"],row["last_ms"])
        identity=identity or {}
        con.execute(f"""INSERT OR IGNORE INTO {table}
                    (measurement_id,source_ip,destination_ip,source_port,destination_port,protocol,local_ip,remote_ip,direction,
                     first_ms,last_ms,exported_ms,bytes,packets,device_id,identity_key,application,category,hostname,evidence,confidence,reason,checked_ms)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (row["measurement_id"],row["src_ip"],row["dst_ip"],row["src_port"],row["dst_port"],row["protocol"],local,remote,direction,
                     row["first_ms"],row["last_ms"],row["exported_ms"],row["bytes"],row["packets"],identity.get("device_id"),identity.get("identity_key"),
                     result.application,result.category,result.hostname,result.evidence,result.confidence,result.reason,int(time.time()*1000)))
        inserted+=1
    return inserted


def reconcile_metadata(con, observations, config, domain_classifier=None):
    """Revisit a bounded set of exact flows when metadata arrives after their export."""
    if len(observations)>200: raise ValueError("metadata reconciliation batch exceeds limit")
    resolver=Attributor(con,domain_classifier,config);table=flow_table(con);updated=0
    for observation in observations:
        remaining=500-updated
        if remaining<=0: break
        cursor=con.execute(f"""SELECT measurement_id,source_ip AS src_ip,destination_ip AS dst_ip,
            source_port AS src_port,destination_port AS dst_port,protocol,first_ms,last_ms,local_ip,remote_ip
            FROM {table} WHERE protocol=6 AND first_ms BETWEEN ? AND ? AND
            ((source_ip=? AND destination_ip=? AND source_port=? AND destination_port=?) OR
             (source_ip=? AND destination_ip=? AND source_port=? AND destination_port=?)) LIMIT ?""",
            (observation.started_ms-2000,observation.started_ms+2000,
             observation.source_ip,observation.destination_ip,observation.source_port,observation.destination_port,
             observation.destination_ip,observation.source_ip,observation.destination_port,observation.source_port,remaining))
        columns=[item[0] for item in cursor.description]
        rows=[dict(zip(columns,row)) for row in cursor]
        for row in rows:
            result=resolver.classify(row,row["local_ip"],row["remote_ip"])
            con.execute(f"UPDATE {table} SET application=?,category=?,hostname=?,evidence=?,confidence=?,reason=?,checked_ms=? WHERE measurement_id=?",
                (result.application,result.category,result.hostname,result.evidence,result.confidence,result.reason,int(time.time()*1000),row["measurement_id"]))
            updated+=1
    return updated


def reconcile_pending(con,config,*,now_ms=None,domain_classifier=None):
    """Round-robin recent unresolved/DNS flows after delayed DNS import; bytes remain immutable."""
    current=int(time.time()*1000) if now_ms is None else now_ms
    table=flow_table(con);resolver=Attributor(con,domain_classifier,config)
    cursor=con.execute(f"""SELECT measurement_id,source_ip AS src_ip,destination_ip AS dst_ip,
        source_port AS src_port,destination_port AS dst_port,protocol,first_ms,last_ms,local_ip,remote_ip
        FROM {table} WHERE last_ms>=? AND checked_ms<? AND (application IS NULL OR evidence='client_dns')
        ORDER BY checked_ms,last_ms LIMIT 200""",(current-300_000,current-10_000))
    columns=[item[0] for item in cursor.description];rows=[dict(zip(columns,row)) for row in cursor]
    for row in rows:
        result=resolver.classify(row,row["local_ip"],row["remote_ip"])
        con.execute(f"UPDATE {table} SET application=?,category=?,hostname=?,evidence=?,confidence=?,reason=?,checked_ms=? WHERE measurement_id=?",
            (result.application,result.category,result.hostname,result.evidence,result.confidence,result.reason,current,row["measurement_id"]))
    return len(rows)


def measured_usage_source_sql(destination=False):
    remote=",remote_ip" if destination else ""
    category="COALESCE(application,'Unknown')" if destination else "application"
    condition="1=1" if destination else "application IS NOT NULL"
    return f"""SELECT local_ip AS ip{remote},device_id,identity_key,{category} AS category,
        CASE WHEN direction='download' THEN bytes/1048576.0 ELSE 0 END AS downloaded_mb,
        CASE WHEN direction='upload' THEN bytes/1048576.0 ELSE 0 END AS uploaded_mb,
        bytes/1048576.0 AS total_mb, date(last_ms/1000,'unixepoch','localtime') AS day,
        datetime(last_ms/1000,'unixepoch','localtime') AS ts,
        strftime('%Y-%m-%d %H:00',last_ms/1000,'unixepoch','localtime') AS hour
        FROM measured_internet_flows WHERE {condition}"""


def identity_at_time(con,local,first_ms,last_ms):
    first=datetime.fromtimestamp(first_ms/1000).strftime("%Y-%m-%d %H:%M:%S")
    last=datetime.fromtimestamp(last_ms/1000).strftime("%Y-%m-%d %H:%M:%S")
    try:
        rows=con.execute("""SELECT DISTINCT i.device_id,i.identity_key FROM device_ip_history h
            JOIN device_identities i ON i.identity_key=h.identity_key
            WHERE h.ip=? AND h.first_seen<=? AND h.last_seen>=? LIMIT 2""",(local,first,last)).fetchall()
        if len(rows)==1:return {"device_id":rows[0][0],"identity_key":rows[0][1]}
        if len(rows)>1:return {}
        rows=con.execute("""SELECT device_id,identity_key FROM device_identities
            WHERE current_ip=? AND first_seen<=? AND last_seen>=? LIMIT 2""",(local,first,last)).fetchall()
        if len(rows)==1:return {"device_id":rows[0][0],"identity_key":rows[0][1]}
    except sqlite3.OperationalError as error:
        if "no such table" not in str(error):raise
    return {}
