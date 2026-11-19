"""Fixed maintenance requests; no caller-selected commands, paths or package names."""
import json,os,re,socket,stat,subprocess,time,uuid
from pathlib import Path

STATE_ROOT=Path('/var/lib/netspecter-maintenance')
REQUEST_PATH=Path('/var/lib/netspecter/maintenance.request')
INSTALL_ROOT=Path('/opt/netspecter')
PACKAGES=('suricata','suricata-update')
SCOPES={'none','traffic','all'}
PREVIEW_SECONDS=900


def validate_request(value,hostname):
    if not isinstance(value,dict) or value.get('hostname')!=hostname:raise ValueError('Wrong appliance hostname')
    if not re.fullmatch('[0-9a-f]{32}',str(value.get('id',''))):raise ValueError('Invalid maintenance request')
    if value.get('kind')=='preview':
        if set(value)!={'id','kind','hostname','scope','purge_ids'}:raise ValueError('Unexpected maintenance options')
        if not isinstance(value['scope'],str) or value['scope'] not in SCOPES or type(value['purge_ids']) is not bool:raise ValueError('Invalid maintenance selection')
        if value['scope']=='none' and not value['purge_ids']:raise ValueError('Choose a reset or retired IDS purge')
    elif value.get('kind')=='apply':
        if set(value)!={'id','kind','hostname','preview_id'} or not re.fullmatch('[0-9a-f]{32}',str(value['preview_id'])):raise ValueError('Invalid preview reference')
    else:raise ValueError('Unsupported maintenance operation')
    return value


def queue_request(value,path=REQUEST_PATH):
    # A fully-written inode is linked atomically; path activation never sees a partial JSON file.
    validate_request(value,socket.gethostname())
    temporary=path.parent/('.maintenance-'+uuid.uuid4().hex)
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(descriptor,'w',encoding='utf-8') as stream:
            json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
        os.link(temporary,path,follow_symlinks=False)
    finally:temporary.unlink(missing_ok=True)


def read_state(root=STATE_ROOT,job_id=None):
    try:
        if job_id is not None and not re.fullmatch('[0-9a-f]{32}',str(job_id)):return {}
        path=root/((job_id+'.json') if job_id is not None else 'state.json')
        with path.open(encoding='utf-8') as stream:return json.load(stream)
    except (FileNotFoundError,PermissionError,ValueError):return {}


def write_state(value,root=STATE_ROOT,gid=None):
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022:raise ValueError('Unsafe maintenance state directory')
    if not re.fullmatch('[0-9a-f]{32}',str(value.get('id',''))):raise ValueError('Invalid maintenance status ID')
    for destination in (value['id']+'.json','state.json'):
        temporary=root/('.state-'+uuid.uuid4().hex)
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            if gid is not None:os.fchown(fd,0,gid)
            os.fchmod(fd,0o640)
            with os.fdopen(fd,'w',encoding='utf-8') as stream:
                json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,root/destination)
        finally:temporary.unlink(missing_ok=True)
    # Retain a bounded set of job summaries so another queued job cannot hide
    # completion from an already-open browser. Private failure logs stay root-only.
    for suffix in ('json','log'):
        entries=[p for p in root.iterdir() if re.fullmatch(r'[0-9a-f]{32}\.'+suffix,p.name) and stat.S_ISREG(p.lstat().st_mode)]
        for old in sorted(entries,key=lambda p:p.stat().st_mtime,reverse=True)[32:]:old.unlink()



def consume_request(path,uid):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_size>4096 or stat.S_IMODE(info.st_mode)&0o077:raise ValueError('Unsafe maintenance request file')
        data=os.read(fd,4097)
        current=path.lstat()
        if (current.st_dev,current.st_ino)!=(info.st_dev,info.st_ino):raise ValueError('Maintenance request changed')
        path.unlink()
        return validate_request(json.loads(data),socket.gethostname())
    finally:os.close(fd)


def command(args,timeout=30,pass_fds=()):
    return subprocess.run(args,check=True,text=True,capture_output=True,timeout=timeout,pass_fds=pass_fds,env={**os.environ,'LC_ALL':'C'})


def ensure_updater_idle(run=command):
    # Also covers the first rollout while an older updater lacks the shared lock.
    try:result=run(['/usr/bin/systemctl','show','netspecter-update.service','--property=LoadState,ActiveState'])
    except subprocess.CalledProcessError:raise RuntimeError('Cannot verify updater state; maintenance refused') from None
    values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    if values.get('LoadState')=='not-found':return
    if values.get('LoadState')!='loaded' or values.get('ActiveState') not in {'inactive','failed'}:
        raise RuntimeError('An update is running or changing state; try maintenance after it finishes')


def package_plan(run=command):
    installed=[]
    for name in PACKAGES:
        try:status=run(['/usr/bin/dpkg-query','-W','-f=${db:Status-Status}',name]).stdout.strip()
        except subprocess.CalledProcessError as error:
            if error.returncode==1:continue
            raise RuntimeError('Cannot inspect the package database') from None
        if status in {'installed','config-files'}:installed.append(name)
        elif status!='not-installed':raise ValueError('Repair incomplete IDS package state in a root shell before maintenance')
    if installed:
        result=run(['/usr/bin/apt-get','-s','purge','--no-auto-remove',*installed])
        removed=[]
        for line in result.stdout.splitlines():
            if line.startswith(('Remv ','Purg ')):
                name=line.split()[1]
                if name not in PACKAGES:raise ValueError('Package plan would remove an unrelated package; purge refused')
                removed.append(name)
        if not set(installed).issubset(removed):raise ValueError('Package simulation did not confirm the expected removals')
    return installed


def build_preview(scope,purge_ids,*,data_root,config_path,run=command):
    from services.history_reset_service import preview_reset
    if scope not in SCOPES or type(purge_ids) is not bool or (scope=='none' and not purge_ids):raise ValueError('Invalid maintenance selection')
    config=json.loads(config_path.read_text())
    if not config.get('passive_attribution_enabled') or config.get('security_features_enabled') or config.get('suricata_enabled'):
        raise ValueError('Activate the passive attribution update before maintenance')
    if (data_root/'history-reset.in-progress').exists():raise ValueError('An interrupted reset needs root-shell recovery first')
    history=preview_reset(data_root,scope=scope) if scope!='none' else None
    return {'scope':scope,'purge_ids':purge_ids,'history':history,'packages':package_plan(run) if purge_ids else []}


def checked_preview(state,request,now=None):
    now=time.time() if now is None else now
    if state.get('status')!='ready' or state.get('id')!=request['preview_id'] or state.get('hostname')!=request['hostname']:
        raise ValueError('Preview is missing or was already used; preview again')
    if not 0<=now-float(state.get('created_at',0))<=PREVIEW_SECONDS:raise ValueError('Preview expired; preview again')
    plan=state.get('plan',{})
    if plan.get('scope') not in SCOPES or type(plan.get('purge_ids')) is not bool:raise ValueError('Invalid maintenance preview')
    return plan


def execute_plan(plan,*,data_root,config_path,install_root=INSTALL_ROOT,run=command,lock_factory=None,dns_snapshot=None,dns_verify=None):
    from services.appliance_operation_service import operation_lock
    from services.dns_continuity_service import snapshot,verify
    lock_factory=lock_factory or operation_lock
    dns_snapshot=dns_snapshot or snapshot;dns_verify=dns_verify or verify
    with lock_factory() as lock_fd:
        # Hold the complete operation lock, including preflight and final DNS/service checks.
        ensure_updater_idle(run)
        fresh=build_preview(plan['scope'],plan['purge_ids'],data_root=data_root,config_path=config_path,run=run)
        dns_state=dns_snapshot()
        run(['/usr/bin/python3',str(install_root/'scripts/verify-passive-attribution.py')],timeout=60)
        if plan['purge_ids']:
            installed=package_plan(run)
            if set(installed)!=set(plan['packages']):raise ValueError('Installed IDS packages changed; preview again')
            # dpkg processes only these explicit package names. It does not resolve
            # additional removals and retains normal dependency/database-lock checks.
            if installed:run(['/usr/bin/dpkg','--purge',*reversed(installed)],timeout=600)
            dns_verify(dns_state)
        if plan['scope']!='none':
            args=['/usr/bin/python3',str(install_root/'scripts/reset-collected-history.py'),'--apply','--expected-hostname',socket.gethostname()]
            if plan['scope']=='traffic':args.append('--traffic-only')
            inherited=()
            if lock_fd is not None:
                args.extend(['--operation-lock-fd',str(lock_fd)]);inherited=(lock_fd,)
            run(args,timeout=1200,pass_fds=inherited)
        dns_verify(dns_state)
        run(['/usr/bin/python3',str(install_root/'scripts/verify-passive-attribution.py')],timeout=60)
        return {'reset_scope':fresh['scope'],'purged_packages':fresh['packages'],'dns_verified':True}



def process_request(*,uid,gid,root=STATE_ROOT,request_path=REQUEST_PATH,data_root=Path('/var/lib/netspecter'),config_path=Path('/etc/netspecter/config.json'),run=command):
    request=consume_request(request_path,uid)
    previous=read_state(root)
    state={'id':request['id'],'hostname':socket.gethostname(),'created_at':time.time(),'status':'running','kind':request['kind']}
    try:
        plan=checked_preview(previous,request) if request['kind']=='apply' else None
        write_state(state,root,gid)
        if request['kind']=='preview':
            from services.appliance_operation_service import operation_lock
            with operation_lock():
                ensure_updater_idle(run)
                state['plan']=build_preview(request['scope'],request['purge_ids'],data_root=data_root,config_path=config_path,run=run)
            state['status']='ready'
        else:
            state['plan']=plan
            state['result']=execute_plan(plan,data_root=data_root,config_path=config_path,run=run)
            state['status']='complete'
    except Exception as error:
        state['status']='failed'
        if isinstance(error,(subprocess.CalledProcessError,subprocess.TimeoutExpired)):
            output=(str(error.stdout or '')+'\n'+str(error.stderr or ''))[-65536:]
            log=root/(state['id']+'.log')
            descriptor=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(descriptor,'w',encoding='utf-8') as stream:stream.write(output)
        # Subprocess output may include sensitive config. Keep it out of web status/journal.
        state['error']=str(error) if isinstance(error,(ValueError,RuntimeError)) else 'Maintenance failed; inspect /var/lib/netspecter-maintenance/'+state['id']+'.log and any reset recovery journal before retrying'
    state['finished_at']=time.time();write_state(state,root,gid)
    return state
