#!/usr/bin/env python3
"""Disposable hosted-CI test of actual systemd services on an isolated Linux bridge."""
from contextlib import closing
from datetime import datetime,timedelta
import json,os
from pathlib import Path
import selectors,shutil,socket,sqlite3,struct,subprocess,sys,threading,time

SOURCE=Path(__file__).resolve().parents[2]
DEST=Path('/opt/netspecter')
CONFIG=Path('/etc/netspecter')
DATA=Path('/var/lib/netspecter')
MAINTENANCE=Path('/var/lib/netspecter-maintenance')
BRIDGE='nsbrtest'
CLIENT='netspecter-ci-client'
SERVER='netspecter-ci-server'
UNITS=['netspecter-maintenance.path','netspecter-maintenance.service','netspecter-tls-inspector','netspecter-softflowd','netspecter-collector','netspecter-tls-metadata.socket']


def run(*args,**kwargs):return subprocess.run(args,check=True,text=True,**kwargs)


def query(sql):
    with closing(sqlite3.connect((DATA/'netspecter_traffic.db').as_uri()+'?mode=ro',uri=True,timeout=2)) as con:return con.execute(sql).fetchall()


def counters():
    data=json.loads(subprocess.check_output(['nft','-j','list','table','bridge','netspecter']))
    return sum(int(expr['counter'].get('bytes',0)) for item in data['nftables'] if 'rule' in item and item['rule'].get('comment','').startswith(('netspecter:tx:192.168.77.5','netspecter:rx:192.168.77.5')) for expr in item['rule']['expr'] if 'counter' in expr)


def wait_for(predicate,seconds=60):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            result=predicate()
            if result:return result
        except (sqlite3.Error,subprocess.CalledProcessError):pass
        time.sleep(1)
    raise AssertionError('Timed out waiting for pipeline condition')


def main():
    if sys.platform!='linux' or os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':
        raise SystemExit('Only run as root inside a disposable GitHub-hosted CI runner.')
    for path in [DEST,CONFIG,DATA,MAINTENANCE]:
        if path.exists() or path.is_symlink():raise SystemExit(f'Refusing preexisting fixture target: {path}')
    created=[];server=None;trace=None;exports=[]
    def trace_exports():
        while trace is not None:
            try:packet=trace.recv(65535)
            except socket.timeout:continue
            except OSError:return
            if len(packet)<42 or packet[12:14]!=b'\x08\x00' or packet[23]!=17:continue
            udp=14+(packet[14]&15)*4
            if len(packet)<udp+8 or struct.unpack_from('!H',packet,udp+2)[0]!=2055:continue
            if len(exports)<32:exports.append(packet[udp+8:])
    try:
        for path in [DEST,CONFIG,DATA,MAINTENANCE]:path.mkdir(mode=0o755,parents=True);created.append(path)
        for path in SOURCE.glob('*.py'):shutil.copyfile(path,DEST/path.name)
        for name in ['services','config','scripts','systemd','inspector']:
            shutil.copytree(SOURCE/name,DEST/name,ignore=shutil.ignore_patterns('target','prebuilt','__pycache__'))
        shutil.copytree(SOURCE/'.ci-venv',DEST/'venv',symlinks=False)
        bundle=DEST/'inspector/prebuilt/linux-x86_64'
        shipped=SOURCE/'inspector/prebuilt/linux-x86_64'
        shutil.copytree(shipped if (shipped/'build.json').is_file() else SOURCE/'inspector/target/bundle',bundle)
        for user in ['netspecter']:
            if subprocess.run(['id',user],capture_output=True).returncode:
                run('useradd','--system','--user-group','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',user)
        run('chown','netspecter:netspecter',str(DATA))
        run('ip','link','add',BRIDGE,'type','bridge');run('ip','link','set',BRIDGE,'up')
        run('ip','addr','add','192.168.77.1/24','dev',BRIDGE)
        for namespace,host,peer,address in [(CLIENT,'nsvethc','ethc','192.168.77.5/24'),(SERVER,'nsveths','eths','8.8.8.8/24')]:
            run('ip','netns','add',namespace);run('ip','link','add',host,'type','veth','peer','name',peer)
            run('ip','link','set',peer,'netns',namespace);run('ip','link','set',host,'master',BRIDGE);run('ip','link','set',host,'up')
            run('ip','-n',namespace,'link','set','lo','up');run('ip','-n',namespace,'addr','add',address,'dev',peer);run('ip','-n',namespace,'link','set',peer,'up')
        run('ip','-n',CLIENT,'route','add','8.8.8.8/32','dev','ethc')
        run('ip','-n',SERVER,'route','add','192.168.77.5/32','dev','eths')
        run('ip','-n',SERVER,'addr','add','192.168.77.10/24','dev','eths')
        config=dict(packet_iface=BRIDGE,lan_prefix='192.168.77.',gateway_ip='192.168.77.1',adguard_url='',unifi_url='',adguard_client_import_enabled=False,
                    netbios_discovery_enabled=False,internet_quality_targets=['127.0.0.1'],internet_quality_dns_server='127.0.0.1',internet_quality_external_dns_enabled=False,
                    internet_quality_interval_seconds=3600,config_change_monitor_interval_seconds=3600,flow_visibility_enabled=True)
        (CONFIG/'config.json').write_text(json.dumps(config))
        # Match production installer permissions before exercising the web normalizer.
        run('chown','root:netspecter',str(CONFIG),str(CONFIG/'config.json'))
        run('chmod','750',str(CONFIG));run('chmod','660',str(CONFIG/'config.json'))
        run('install','-m','644',str(DEST/'systemd/netspecter-collector.service'),'/etc/systemd/system/netspecter-collector.service')
        run('bash',str(DEST/'scripts/install-tls-inspector.sh'))
        # Exercise the actual web loader before collection; it must retain activation.
        run(str(DEST/'venv/bin/python'),'-c',"import netspecter_config; assert netspecter_config.cfg()['passive_attribution_enabled']",cwd=DEST)
        run('systemctl','start','netspecter-tls-metadata.socket','netspecter-collector')
        run('systemctl','start','netspecter-tls-inspector','netspecter-softflowd')
        wait_for(lambda: query('SELECT count(*) FROM collector_heartbeat WHERE id=1')[0][0],30)
        time.sleep(3)
        run(sys.executable,str(DEST/'scripts/verify-passive-attribution.py'))
        run(str(DEST/'venv/bin/python'),str(DEST/'scripts/reclassify-unrecognized.py'),'--expected-hostname',socket.gethostname())
        server_code='''import socket
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',443));s.listen();s.settimeout(180)
print('ready',flush=True)
for _ in range(4):
 c,_=s.accept();c.settimeout(10)
 with c:
  data=bytearray()
  while True:
   block=c.recv(65536)
   if not block:break
   data.extend(block)
  assert len(data)>1000
  c.sendall(b'Z'*65536)
s.close()
'''
        server=subprocess.Popen(['ip','netns','exec',SERVER,sys.executable,'-c',server_code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        select=selectors.DefaultSelector();select.register(server.stdout,selectors.EVENT_READ)
        assert select.select(10) and server.stdout.readline().strip()=='ready';select.close()
        client_code='''import socket,sys
name=sys.argv[2].encode();names=b'\\0'+len(name).to_bytes(2,'big')+name;sni=len(names).to_bytes(2,'big')+names
ext=b'\\0\\0'+len(sni).to_bytes(2,'big')+sni
body=b'\\3\\3'+bytes(32)+b'\\0\\0\\2\\x13\\1\\1\\0'+len(ext).to_bytes(2,'big')+ext
hs=b'\\1'+len(body).to_bytes(3,'big')+body;hello=b'\\x16\\3\\3'+len(hs).to_bytes(2,'big')+hs
with socket.create_connection((sys.argv[1],443),timeout=10) as s:
 print(s.getsockname()[1],flush=True);s.sendall(hello+b'X'*8192);s.shutdown(socket.SHUT_WR);response=bytearray()
 while True:
  block=s.recv(65536)
  if not block:break
  response.extend(block)
 assert response==b'Z'*65536
'''
        trace=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));trace.bind(('lo',0));trace.settimeout(1)
        threading.Thread(target=trace_exports,daemon=True).start()
        ports=[]
        for name in ['www.youtube.com','www.netflix.com']:
            result=run('ip','netns','exec',CLIENT,sys.executable,'-c',client_code,'8.8.8.8',name,capture_output=True)
            ports.append(int(result.stdout.strip()))
        wait_for(lambda: query("SELECT count(*) FROM measured_internet_flows WHERE application IS NOT NULL")[0][0]>=2)
        rows=query("SELECT source_port,destination_port,application,bytes FROM measured_internet_flows WHERE remote_ip='8.8.8.8'")
        for port,name in zip(ports,['YouTube','Netflix']):
            matching=[row for row in rows if port in row[:2]]
            assert matching and all(row[2]==name and row[3]>0 for row in matching),(port,name,rows)
        # Exercise root CLI privilege drop and an actual stored-SNI relabel, not only empty preview.
        target=query("SELECT measurement_id,bytes,hostname,evidence FROM measured_internet_flows WHERE application='YouTube' LIMIT 1")[0]
        with closing(sqlite3.connect(DATA/'netspecter_traffic.db')) as con,con:
            con.execute("UPDATE measured_internet_flows SET application=NULL,reason='unrecognized_hostname' WHERE measurement_id=?",(target[0],))
        preview=run(str(DEST/'venv/bin/python'),str(DEST/'scripts/reclassify-unrecognized.py'),'--expected-hostname',socket.gethostname(),capture_output=True)
        assert json.loads(preview.stdout)['candidates']>=1
        assert query("SELECT application FROM measured_internet_flows WHERE measurement_id='"+target[0]+"'")[0][0] is None
        applied=run(str(DEST/'venv/bin/python'),str(DEST/'scripts/reclassify-unrecognized.py'),'--apply','--expected-hostname',socket.gethostname(),capture_output=True)
        assert json.loads(applied.stdout)['updated']>=1
        restored=query("SELECT application,bytes,hostname,evidence FROM measured_internet_flows WHERE measurement_id='"+target[0]+"'")[0]
        assert restored==('YouTube',target[1],target[2],target[3]),restored
        print('PASS: root catalogue CLI preview/apply under the service identity, with immutable measured bytes and SNI evidence.')
        # Exercise the actual root CLI against client/time/TTL-scoped DNS in its
        # read-only attached database, including medium confidence preservation.
        stamp=datetime.now()-timedelta(seconds=60)
        with closing(sqlite3.connect(DATA/'netspecter_dns.db')) as con,con:
            con.execute("INSERT INTO dns_resolution_events (ts,client_ip,domain,resolved_ip,ttl,expires_at,source) VALUES (?,?,?,?,?,?,?)",
                (stamp.strftime('%Y-%m-%d %H:%M:%S'),'192.168.77.5','www.youtube.com','8.8.4.4',600,(stamp+timedelta(seconds=600)).strftime('%Y-%m-%d %H:%M:%S'),'adguard'))
        with closing(sqlite3.connect(DATA/'netspecter_traffic.db')) as con,con:
            cursor=con.execute('SELECT * FROM measured_internet_flows WHERE measurement_id=?',(target[0],))
            sample=dict(zip([col[0] for col in cursor.description],cursor.fetchone()))
            sample.update(measurement_id='ci-dns-catalogue',source_ip='192.168.77.5',destination_ip='8.8.4.4',source_port=50001,destination_port=443,
                protocol=17,local_ip='192.168.77.5',remote_ip='8.8.4.4',direction='upload',first_ms=int(stamp.timestamp()*1000)+1000,
                last_ms=int(stamp.timestamp()*1000)+2000,bytes=1234567,application=None,hostname='www.youtube.com',evidence='client_dns',confidence='none',reason='unrecognized_hostname')
            con.execute('INSERT INTO measured_internet_flows ('+','.join(sample)+') VALUES ('+','.join('?' for _ in sample)+')',tuple(sample.values()))
        preview=run(str(DEST/'venv/bin/python'),str(DEST/'scripts/reclassify-unrecognized.py'),'--expected-hostname',socket.gethostname(),capture_output=True)
        assert json.loads(preview.stdout)['by_evidence']['client_dns']['flows']>=1
        assert query("SELECT application FROM measured_internet_flows WHERE measurement_id='ci-dns-catalogue'")[0][0] is None
        run(str(DEST/'venv/bin/python'),str(DEST/'scripts/reclassify-unrecognized.py'),'--apply','--expected-hostname',socket.gethostname(),capture_output=True)
        assert query("SELECT application,bytes,hostname,evidence,confidence FROM measured_internet_flows WHERE measurement_id='ci-dns-catalogue'")[0]==('YouTube',1234567,'www.youtube.com','client_dns','medium')
        print('PASS: root DNS catalogue preview/apply with read-only DNS attachment, exact client/time matching and immutable bytes.')
        measured_before=query('SELECT sum(bytes) FROM measured_internet_flows')[0][0]
        bridge_before=counters()
        run('ip','netns','exec',CLIENT,sys.executable,'-c',client_code,'192.168.77.10','www.youtube.com',capture_output=True)
        time.sleep(15)
        assert counters()==bridge_before,'Internal transfers changed internet bridge counters'
        assert query("SELECT count(*) FROM measured_internet_flows WHERE remote_ip='192.168.77.10'")[0][0]==0
        assert query("SELECT count(*) FROM tls_connection_metadata WHERE destination_ip='192.168.77.10'")[0][0]==0
        assert query('SELECT sum(bytes) FROM measured_internet_flows')[0][0]>=measured_before
        assert query('SELECT count(*) FROM classified_flow_facts')[0][0]==0,'Legacy IP guesses must not contribute facts'
        assert query('SELECT count(*) FROM estimated_app_traffic')[0][0]==0,'Legacy estimates must stay disabled'
        # Exercise actual root orchestration, not just mocked reset state transitions.
        configuration_before=(CONFIG/'config.json').read_bytes()
        with closing(sqlite3.connect(DATA/'netspecter.db')) as con,con:
            con.execute("INSERT OR REPLACE INTO device_overrides (ip,name) VALUES ('192.168.77.5','CI Edited Workstation')")
        run(sys.executable,str(DEST/'scripts/reset-collected-history.py'),'--apply','--expected-hostname',__import__('socket').gethostname())
        assert (CONFIG/'config.json').read_bytes()==configuration_before,'Reset changed saved settings'
        with closing(sqlite3.connect(DATA/'netspecter.db')) as con:
            assert con.execute("SELECT name FROM device_overrides WHERE ip='192.168.77.5'").fetchone()[0]=='CI Edited Workstation'
        assert not (DATA/'history-reset.in-progress').exists()
        assert not list(Path('/var/backups/netspecter/history-reset').glob('reset-*')),'Temporary old history copy was retained'
        assert query('SELECT count(*) FROM measured_internet_flows')[0][0]==0
        run('ip','netns','exec',CLIENT,sys.executable,'-c',client_code,'8.8.8.8','www.youtube.com',capture_output=True)
        wait_for(lambda:query("SELECT count(*) FROM measured_internet_flows WHERE application='YouTube'")[0][0]>0)
        # Exercise the actual root worker/path, including inherited operation locks.
        run('chown','root:netspecter',str(MAINTENANCE));run('chmod','750',str(MAINTENANCE))
        for name in ('netspecter-maintenance.service','netspecter-maintenance.path'):
            run('install','-m','644',str(DEST/'systemd'/name),'/etc/systemd/system/'+name)
        run('systemctl','daemon-reload');run('systemctl','start','netspecter-maintenance.path')
        def request_maintenance(kind,**options):
            import uuid
            payload={'id':uuid.uuid4().hex,'kind':kind,'hostname':socket.gethostname(),**options}
            code="import sys,json;sys.path.insert(0,'/opt/netspecter');from services.appliance_maintenance_service import queue_request;queue_request(json.loads(sys.argv[1]))"
            run('runuser','-u','netspecter','--',str(DEST/'venv/bin/python'),'-c',code,json.dumps(payload))
            def finished():
                try:state=json.loads((MAINTENANCE/'state.json').read_text())
                except (FileNotFoundError,ValueError):return None
                return state if state.get('id')==payload['id'] and state.get('status')!='running' else None
            return wait_for(finished,seconds=120)
        plan=request_maintenance('preview',scope='traffic',purge_ids=False)
        assert plan['status']=='ready'
        sys.path.insert(0,str(DEST))
        from services.appliance_operation_service import operation_lock
        with operation_lock():
            blocked=request_maintenance('apply',preview_id=plan['id'])
        assert blocked['status']=='failed' and 'running' in blocked['error']
        assert query('SELECT COUNT(*) FROM measured_internet_flows')[0][0]>0,'Contended maintenance cleared traffic'
        plan=request_maintenance('preview',scope='traffic',purge_ids=False)
        assert plan['status']=='ready'
        completed=request_maintenance('apply',preview_id=plan['id'])
        assert completed['status']=='complete',completed
        assert completed['result']['reset_scope']=='traffic' and completed['result']['dns_verified']
        assert (CONFIG/'config.json').read_bytes()==configuration_before
        with closing(sqlite3.connect(DATA/'netspecter.db')) as con:
            assert con.execute("SELECT name FROM device_overrides WHERE ip='192.168.77.5'").fetchone()[0]=='CI Edited Workstation'
        assert not (DATA/'history-reset.in-progress').exists()
        assert run('systemctl','is-active','netspecter-maintenance.path',capture_output=True).stdout.strip()=='active'
        run('ip','netns','exec',CLIENT,sys.executable,'-c',client_code,'8.8.8.8','www.youtube.com',capture_output=True)
        wait_for(lambda:query("SELECT count(*) FROM measured_internet_flows WHERE application='YouTube'")[0][0]>0)
        print('PASS: actual systemd maintenance preview/confirmation worker, contended-lock refusal, inherited-lock traffic reset, path restart and fresh collection.')
        print('PASS: real writer-stop, database rebuild, preserved edited name/settings, discarded rollback copy, and fresh collection after restart.')
        print('PASS: dedicated systemd identities, root-owned socket activation, bridge SNI capture, real softflowd exports, exact separate apps on one IP, unchanged TCP payload, and zero internal internet attribution.')
    except BaseException:
        for table in ['tls_connection_metadata','measured_internet_flows']:
            try:print('DIAGNOSTIC '+table,query('SELECT * FROM '+table+' LIMIT 8'),flush=True)
            except sqlite3.Error as error:print(str(error),flush=True)
        for packet in exports[:4]:print('DIAGNOSTIC NetFlow UDP',len(packet),packet.hex(),flush=True)
        subprocess.run(['softflowctl','-c','/run/netspecter-flow/softflowd.ctl','statistics'],check=False)
        subprocess.run(['journalctl','--no-pager','-n','120',*[item for unit in UNITS for item in ['-u',unit]]],check=False)
        raise
    finally:
        if trace is not None:trace.close();trace=None
        if server and server.poll() is None:server.terminate();server.communicate(timeout=5)
        subprocess.run(['systemctl','stop',*UNITS],check=False)
        for namespace in [CLIENT,SERVER]:subprocess.run(['ip','netns','delete',namespace],check=False)
        subprocess.run(['ip','link','delete',BRIDGE],check=False)
        # Only fixture directories which were absent before this disposable CI test.
        for path in reversed(created):
            if path in [DEST,CONFIG,DATA,MAINTENANCE] and not path.is_symlink():shutil.rmtree(path)


if __name__=='__main__':main()
