from contextlib import nullcontext
import json,os,socket,subprocess,time
from pathlib import Path
import pytest
from services import appliance_maintenance_service as service


def request(kind='preview',**values):
    return dict(id='a'*32,kind=kind,hostname=socket.gethostname(),**values)


@pytest.mark.skipif(os.name!='posix',reason='Linux atomic request activation')
@pytest.mark.parametrize('scope,purge',[('none',True),('traffic',False),('all',True)])
def test_fixed_request_choices_and_atomic_complete_queue(tmp_path,scope,purge):
    value=request(scope=scope,purge_ids=purge);path=tmp_path/'request'
    service.queue_request(value,path)
    assert json.loads(path.read_text())==value
    with pytest.raises(FileExistsError):service.queue_request(value,path)
    assert json.loads(path.read_text())==value
    assert sorted(x.name for x in tmp_path.iterdir())==['request']


@pytest.mark.parametrize('change',[
 {'scope':'/etc'}, {'scope':[]}, {'purge_ids':'true'}, {'kind':'shell'},
 {'hostname':'another-unit'}, {'command':'rm'}, {'id':'../evil'},
 {'scope':'none','purge_ids':False},
])
def test_requests_fail_closed(change):
    value=request(scope='traffic',purge_ids=False);value.update(change)
    with pytest.raises(ValueError):service.validate_request(value,socket.gethostname())


def test_apply_requires_recent_unconsumed_matching_root_preview():
    now=time.time();value=request('apply',preview_id='b'*32)
    state={'id':'b'*32,'hostname':socket.gethostname(),'created_at':now,'status':'ready','plan':{'scope':'all','purge_ids':True}}
    assert service.checked_preview(state,value,now)['scope']=='all'
    for update in ({'status':'complete'},{'id':'c'*32},{'hostname':'other'},{'created_at':now-901},{'created_at':now+1}):
        with pytest.raises(ValueError):service.checked_preview({**state,**update},value,now)


def test_package_simulation_is_limited_and_never_autoremoves():
    calls=[]
    def run(args,**kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args,0,stdout='installed' if 'dpkg-query' in args[0] else 'Purg suricata [1]\nPurg suricata-update [1]')
    assert service.package_plan(run)==['suricata','suricata-update']
    assert calls[-1]==['/usr/bin/apt-get','-s','purge','--no-auto-remove','suricata','suricata-update']
    def unsafe(args,**kwargs):
        result=run(args,**kwargs)
        if 'apt-get' in args[0]:result.stdout+='\nRemv AdGuardHome [1]'
        return result
    with pytest.raises(ValueError,match='unrelated'):service.package_plan(unsafe)
    def unconfirmed(args,**kwargs):
        return subprocess.CompletedProcess(args,0,stdout='installed' if 'dpkg-query' in args[0] else '')
    with pytest.raises(ValueError,match='simulation'):service.package_plan(unconfirmed)


def test_missing_ids_packages_are_idempotent():
    def run(args,**kwargs):raise subprocess.CalledProcessError(1,args)
    assert service.package_plan(run)==[]


def test_execute_only_passes_fixed_reset_flags_and_preserves_dns(monkeypatch,tmp_path):
    monkeypatch.setattr(service,'ensure_updater_idle',lambda run:None)
    calls=[];checks=[]
    plan={'scope':'traffic','purge_ids':True,'packages':['suricata']}
    monkeypatch.setattr(service,'build_preview',lambda *a,**k:plan)
    monkeypatch.setattr(service,'package_plan',lambda run:['suricata'])
    def run(args,**kwargs):calls.append(args);return subprocess.CompletedProcess(args,0,stdout='')
    result=service.execute_plan(plan,data_root=tmp_path,config_path=tmp_path/'config',run=run,lock_factory=nullcontext,
      dns_snapshot=lambda:{'dns':'unchanged'},dns_verify=lambda state:checks.append(state))
    assert 'verify-passive-attribution.py' in calls[0][1]
    assert calls[1]==['/usr/bin/dpkg','--purge','suricata']
    assert calls[2]==['/usr/bin/python3',str(Path('/opt/netspecter')/'scripts/reset-collected-history.py'),'--apply','--expected-hostname',socket.gethostname(),'--traffic-only']
    assert 'verify-passive-attribution.py' in calls[-1][1]
    assert checks==[{'dns':'unchanged'},{'dns':'unchanged'}] and result['dns_verified']


def test_purge_plan_change_or_lock_conflict_prevents_modifications(monkeypatch,tmp_path):
    monkeypatch.setattr(service,'ensure_updater_idle',lambda run:None)
    plan={'scope':'all','purge_ids':True,'packages':['suricata']};calls=[]
    monkeypatch.setattr(service,'build_preview',lambda *a,**k:plan)
    monkeypatch.setattr(service,'package_plan',lambda run:['suricata','suricata-update'])
    with pytest.raises(ValueError,match='changed'):
        service.execute_plan(plan,data_root=tmp_path,config_path=tmp_path/'c',run=lambda args,**k:calls.append(args),lock_factory=nullcontext,dns_snapshot=lambda:{},dns_verify=lambda _:None)
    assert len(calls)==1 and 'verify-passive-attribution.py' in calls[0][1]


def test_dns_failure_stops_before_history_deletion(monkeypatch,tmp_path):
    monkeypatch.setattr(service,'ensure_updater_idle',lambda run:None)
    plan={'scope':'all','purge_ids':True,'packages':[]};calls=[]
    monkeypatch.setattr(service,'build_preview',lambda *a,**k:plan)
    monkeypatch.setattr(service,'package_plan',lambda run:[])
    def fail(_):raise RuntimeError('DNS continuity failed')
    with pytest.raises(RuntimeError,match='DNS'):
        service.execute_plan(plan,data_root=tmp_path,config_path=tmp_path/'c',run=lambda args,**k:calls.append(args),lock_factory=nullcontext,dns_snapshot=lambda:{},dns_verify=fail)
    assert len(calls)==1 and 'verify-passive-attribution.py' in calls[0][1]


@pytest.mark.skipif(os.name!='posix',reason='Linux file permission boundary')
def test_request_reader_refuses_symlinks_other_owners_and_oversized_input(tmp_path):
    path=tmp_path/'request';value=request(scope='traffic',purge_ids=False)
    service.queue_request(value,path)
    with pytest.raises(ValueError,match='Unsafe'):service.consume_request(path,os.getuid()+1)
    assert path.exists()
    assert service.consume_request(path,os.getuid())==value and not path.exists()
    target=tmp_path/'target';target.write_text(json.dumps(value));path.symlink_to(target)
    with pytest.raises(OSError):service.consume_request(path,os.getuid())
    assert target.exists()
    path.unlink();path.write_text('x'*4097);path.chmod(0o600)
    with pytest.raises(ValueError,match='Unsafe'):service.consume_request(path,os.getuid())


@pytest.fixture
def web_client(monkeypatch):
    import app as web
    from werkzeug.security import generate_password_hash
    config={'auth_enabled':True,'admin_password_hash':generate_password_hash('test-admin-password')}
    state={'id':'b'*32,'hostname':socket.gethostname(),'created_at':time.time(),'status':'ready','plan':{'scope':'traffic','purge_ids':False,'packages':[],'history':{'databases':{}}}}
    queued=[]
    monkeypatch.setattr(web,'cfg',lambda:config)
    monkeypatch.setattr(web,'auth_required',lambda:False)
    monkeypatch.setattr(web,'maybe_start_netlic_checkin',lambda:None)
    monkeypatch.setattr(web,'shell',lambda title,body,active:body)
    monkeypatch.setattr(web,'topbar',lambda title:'<h1>'+title+'</h1>')
    monkeypatch.setattr(web,'settings_menu',lambda active:'')
    monkeypatch.setattr(web,'maintenance_worker_available',lambda:True)
    monkeypatch.setattr(web.maintenance_service,'read_state',lambda **kwargs:state)
    monkeypatch.setattr(web.maintenance_service,'queue_request',lambda value:queued.append(value))
    monkeypatch.setattr(web,'login_lockout_seconds',lambda key:0)
    monkeypatch.setattr(web,'clear_login_failures',lambda key:None)
    monkeypatch.setattr(web,'record_login_failure',lambda key:None)
    client=web.app.test_client()
    with client.session_transaction() as session:session.update(authenticated=True,_csrf_token='token')
    return client,config,state,queued


def test_ui_get_is_read_only_and_shows_preview_password_and_preservation(web_client):
    client,config,state,queued=web_client
    response=client.get('/settings?section=maintenance')
    assert response.status_code==200
    text=response.get_data(as_text=True)
    for label in ['Preview selected maintenance','Administrator password','Type this appliance hostname','licence','Suricata']:assert label in text
    assert not queued and response.headers['Cache-Control']=='no-store'


def test_apply_needs_csrf_password_ack_hostname_and_recent_preview(web_client):
    client,config,state,queued=web_client
    fields={'_csrf_token':'token','action':'apply','preview_id':'b'*32,'confirm_hostname':socket.gethostname(),'confirm_loss':'yes','admin_password':'test-admin-password'}
    for changed,code in [({'_csrf_token':'bad'},400),({'confirm_hostname':'other'},409),({'confirm_loss':''},409),({'admin_password':'wrong'},403),({'preview_id':'c'*32},409)]:
        assert client.post('/settings/maintenance',data={**fields,**changed}).status_code==code
        assert not queued
    assert client.post('/settings/maintenance',data=fields).status_code==302
    assert len(queued)==1 and set(queued[0])=={'id','kind','hostname','preview_id'}
    assert 'password' not in json.dumps(queued[0])


def test_preview_cannot_queue_when_unauthenticated_even_if_normal_auth_disabled(web_client):
    client,config,state,queued=web_client
    for auth in [False,True]:
        config['auth_enabled']=auth
        with client.session_transaction() as session:session['authenticated']=False
        assert client.get('/api/maintenance/status').status_code==403
        assert client.post('/settings/maintenance',data={'_csrf_token':'token','action':'preview','scope':'all'}).status_code==403
    assert not queued


def test_apply_cannot_reuse_running_completed_or_expired_preview(web_client):
    client,config,state,queued=web_client
    data={'_csrf_token':'token','action':'apply','preview_id':'b'*32,'confirm_hostname':socket.gethostname(),'confirm_loss':'yes','admin_password':'test-admin-password'}
    for status in ['running','complete','failed']:
        state['status']=status
        assert client.post('/settings/maintenance',data=data).status_code==409
    state.update(status='ready',created_at=time.time()-901)
    assert client.post('/settings/maintenance',data=data).status_code==409
    assert not queued



def test_root_state_machine_consumes_preview_then_apply_and_rejects_replay(monkeypatch,tmp_path):
    monkeypatch.setattr(service,'ensure_updater_idle',lambda run:None)
    states=[];requests=[request(scope='traffic',purge_ids=False)]
    plan={'scope':'traffic','purge_ids':False,'packages':[]}
    monkeypatch.setattr(service,'consume_request',lambda *a:requests.pop(0))
    from services import appliance_operation_service
    monkeypatch.setattr(appliance_operation_service,'operation_lock',nullcontext)
    monkeypatch.setattr(service,'read_state',lambda root:states[-1] if states else {})
    monkeypatch.setattr(service,'write_state',lambda value,*a:states.append(dict(value)))
    monkeypatch.setattr(service,'build_preview',lambda *a,**k:plan)
    executed=[]
    monkeypatch.setattr(service,'execute_plan',lambda selected,**kwargs:executed.append(selected) or {'dns_verified':True})
    result=service.process_request(uid=123,gid=123,root=tmp_path)
    assert result['status']=='ready' and not executed
    requests.append(request('apply',preview_id='a'*32))
    result=service.process_request(uid=123,gid=123,root=tmp_path)
    assert result['status']=='complete' and executed==[plan]
    requests.append(request('apply',preview_id='a'*32))
    result=service.process_request(uid=123,gid=123,root=tmp_path)
    assert result['status']=='failed' and executed==[plan]


def test_root_preview_preserves_real_tables_and_rejects_active_ids_config(tmp_path):
    from test_collected_history_reset import fixture
    data,recovery,config=fixture(tmp_path)
    path=config/'config.json';path.write_text(json.dumps({'passive_attribution_enabled':True}))
    original=(data/'netspecter.db').read_bytes()
    plan=service.build_preview('traffic',False,data_root=data,config_path=path)
    assert plan['history']['databases']['netspecter_dns.db']['dns_querylog']['action']=='preserve unchanged'
    assert (data/'netspecter.db').read_bytes()==original and not list(recovery.iterdir())
    path.write_text(json.dumps({'passive_attribution_enabled':True,'suricata_enabled':True}))
    with pytest.raises(ValueError,match='passive'):service.build_preview('all',False,data_root=data,config_path=path)



def test_removed_but_not_purged_ids_configuration_is_included():
    def run(args,**kwargs):
        return subprocess.CompletedProcess(args,0,stdout='config-files' if 'dpkg-query' in args[0] else 'Purg suricata [1]\nPurg suricata-update [1]')
    assert service.package_plan(run)==['suricata','suricata-update']


def test_complete_operation_inherits_lock_and_never_runs_outside_it(monkeypatch,tmp_path):
    monkeypatch.setattr(service,'ensure_updater_idle',lambda run:None)
    from contextlib import contextmanager
    plan={'scope':'all','purge_ids':True,'packages':['suricata','suricata-update']};active=[];calls=[]
    @contextmanager
    def lock():
        active.append(True)
        try:yield 17
        finally:active.clear()
    def preview(*a,**k):assert active;return plan
    def run(args,**kwargs):assert active;calls.append((args,kwargs));return subprocess.CompletedProcess(args,0,stdout='')
    monkeypatch.setattr(service,'build_preview',preview)
    monkeypatch.setattr(service,'package_plan',lambda run:['suricata','suricata-update'])
    service.execute_plan(plan,data_root=tmp_path,config_path=tmp_path/'c',run=run,lock_factory=lock,dns_snapshot=lambda:{},dns_verify=lambda _:None)
    assert not active
    assert calls[1][0]==['/usr/bin/dpkg','--purge','suricata-update','suricata']
    reset=next((args,options) for args,options in calls if 'reset-collected-history.py' in args[1])
    assert reset[0][-2:]==['--operation-lock-fd','17'] and reset[1]['pass_fds']==(17,)



def test_job_status_lookup_cannot_read_arbitrary_paths(tmp_path):
    (tmp_path/('a'*32+'.json')).write_text('{"status":"complete"}')
    assert service.read_state(tmp_path,job_id='a'*32)['status']=='complete'
    for bad in ['../config','state.json','a'*32+'.log','/etc/passwd']:
        assert service.read_state(tmp_path,job_id=bad)=={}


@pytest.mark.parametrize('status',['active','activating','deactivating','reloading','unknown'])
def test_older_active_updater_blocks_maintenance_even_before_shared_lock_rollout(status):
    def run(args,**kwargs):return subprocess.CompletedProcess(args,0,stdout='LoadState=loaded\nActiveState='+status)
    with pytest.raises(RuntimeError,match='update'):service.ensure_updater_idle(run)


def test_absent_or_idle_update_unit_allows_maintenance():
    for output in ['LoadState=not-found\nActiveState=inactive','LoadState=loaded\nActiveState=inactive','LoadState=loaded\nActiveState=failed']:
        service.ensure_updater_idle(lambda args:subprocess.CompletedProcess(args,0,stdout=output))



def test_settings_progress_remains_available_when_setup_fields_are_incomplete(web_client,monkeypatch):
    import app as web
    client,config,state,queued=web_client
    monkeypatch.setattr(web,'auth_required',lambda:True)
    monkeypatch.setattr(web,'admin_password_set',lambda:True)
    monkeypatch.setattr(web,'setup_missing_items',lambda:['Confirm AdGuard URL'])
    assert client.get('/settings?section=maintenance').status_code==200
    assert client.get('/settings/maintenance').status_code==200
    assert client.get('/api/maintenance/status?id='+'b'*32).status_code==200


def test_ready_preview_puts_explicit_confirmation_before_selection_and_keeps_scope(web_client):
    client,config,state,queued=web_client
    state['plan'].update(scope='all',purge_ids=True)
    text=client.get('/settings?section=maintenance').get_data(as_text=True)
    assert text.index('2. Confirm and run cleanup')<text.index('1. Select maintenance')
    assert 'Nothing has been cleared yet' in text
    assert '<option value="all" selected>' in text
    assert 'Clear all collected history and purge retired IDS' in text


def test_queued_page_has_manual_and_non_javascript_progress_fallback(web_client,monkeypatch):
    import app as web
    client,config,state,queued=web_client
    monkeypatch.setattr(web.maintenance_service,'read_state',lambda **kwargs:{})
    response=client.get('/settings?section=maintenance&pending='+'c'*32)
    assert response.status_code==200
    assert 'Refresh' in response.headers
    assert 'Check preview or result' in response.get_data(as_text=True)
    assert 'c'*32 in response.headers['Refresh']



def test_missing_job_stops_refresh_after_bounded_wait(web_client,monkeypatch):
    import app as web
    client,config,state,queued=web_client
    monkeypatch.setattr(web.maintenance_service,'read_state',lambda **kwargs:{})
    response=client.get('/settings?section=maintenance&result='+'c'*32+'&wait_started='+str(int(time.time())-31))
    assert 'Refresh' not in response.headers
    assert 'Automatic checking stopped' in response.get_data(as_text=True)
    assert 'Back to maintenance' in response.get_data(as_text=True)
    assert not queued
