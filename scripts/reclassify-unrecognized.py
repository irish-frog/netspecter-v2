#!/usr/bin/env python3
"""Preview/apply catalogue labels using stored SNI or revalidated client DNS; never reset history."""
import argparse,json,os,pwd,socket,sqlite3,sys,time
from functools import lru_cache
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.flow_attribution_service import classify_domain,reclassify_unrecognized_batch


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--expected-hostname',required=True);p.add_argument('--apply',action='store_true')
    p.add_argument('--tls-only',action='store_true',help='Skip historical client-DNS revalidation')
    p.add_argument('--after-id',default='',help='Resume a bounded preview/apply after its reported measurement ID')
    p.add_argument('--max-flows',type=int,default=20000);args=p.parse_args()
    if socket.gethostname()!=args.expected_hostname:raise SystemExit('Wrong appliance hostname; no labels changed')
    if not 1<=args.max_flows<=100000:p.error('max-flows must be 1..100000')
    if Path('/var/lib/netspecter/history-reset.in-progress').exists():raise SystemExit('Recover the pending history reset first')
    account=pwd.getpwnam('netspecter')
    if os.geteuid()==0:
        # Create any SQLite companions as the normal writer, never as root.
        os.initgroups(account.pw_name,account.pw_gid);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
    elif os.geteuid()!=account.pw_uid:raise SystemExit('Run as root or the existing netspecter service user')
    config=json.loads(Path('/etc/netspecter/config.json').read_text())
    if not config.get('passive_attribution_enabled'):raise SystemExit('Passive attribution must be active first')
    path=Path('/var/lib/netspecter/netspecter_traffic.db')
    con=sqlite3.connect(path.as_uri()+('?mode=rw' if args.apply else '?mode=ro'),uri=True,timeout=5)
    dns_path=path.with_name('netspecter_dns.db')
    include_dns=not args.tls_only and dns_path.is_file()
    if include_dns:con.execute('ATTACH DATABASE ? AS dnsdb',(dns_path.as_uri()+'?mode=ro',))
    if not args.apply:con.execute('PRAGMA query_only=ON')
    result={'mode':'apply' if args.apply else 'preview','scanned':0,'candidates':0,'updated':0,'bytes':0,'applications':{},'by_evidence':{},'dns_revalidation_available':include_dns,'measurements_deleted':0,'settings_changed':False}
    cursor=args.after_id
    # One bounded cache per invocation: repeated hostnames need one classification,
    # while subsequent runs still pick up edited operator rules and catalogue changes.
    classify_once=lru_cache(maxsize=2048)(classify_domain)
    try:
        while result['scanned']<args.max_flows:
            with con:
                batch=reclassify_unrecognized_batch(con,config,after_id=cursor,limit=min(200,args.max_flows-result['scanned']),apply=args.apply,domain_classifier=classify_once,include_client_dns=include_dns)
            for key in ('scanned','candidates','updated','bytes'):result[key]+=batch[key]
            for app,size in batch['applications'].items():result['applications'][app]=result['applications'].get(app,0)+size
            for evidence,counts in batch['by_evidence'].items():
                totals=result['by_evidence'].setdefault(evidence,{'flows':0,'bytes':0})
                for key in ('flows','bytes'):totals[key]+=counts[key]
            cursor=batch['next_id']
            if not batch['scanned']:break
            if args.apply:time.sleep(0.05)
    finally:con.close()
    result['limit_reached']=result['scanned']>=args.max_flows
    result['next_id']=cursor
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
