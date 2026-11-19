import threading
import app as web


def test_update_check_reads_remote_without_fetch_or_git_writes(monkeypatch,tmp_path):
    calls=[]
    monkeypatch.setattr(web,'source_checkout_root',lambda:tmp_path)
    monkeypatch.setattr(web,'git_upstream_ref',lambda source:'origin/main')
    def git(source,*args,**kwargs):
        calls.append(args)
        if args==('rev-parse','HEAD'):return 0,'a'*40,''
        if args[0]=='ls-remote':return 0,'b'*40+'\trefs/heads/main',''
        if args[0]=='cat-file':return 1,'','missing object'
        raise AssertionError(args)
    monkeypatch.setattr(web,'git_command',git)
    monkeypatch.setattr(web,'UPDATE_STATUS_CACHE',{})
    result=web.update_status(force=True)
    assert result['ok'] and result['available'] and result['behind'] is None
    assert all(args[0] in ('rev-parse','ls-remote','cat-file') for args in calls)


def test_public_ip_returns_stale_while_lookup_is_blocked(monkeypatch):
    entered=threading.Event();release=threading.Event();writes=[]
    monkeypatch.setattr(web,'cfg',lambda:{})
    monkeypatch.setattr(web,'cache_get',lambda *args:None)
    monkeypatch.setattr(web,'cache_value',lambda key:'198.51.100.1')
    monkeypatch.setattr(web,'cache_set',lambda *args:writes.append(args))
    monkeypatch.setattr(web,'_PUBLIC_IP_NEXT_ATTEMPT',0)
    monkeypatch.setattr(web,'_PUBLIC_IP_REFRESH_LOCK',threading.Lock())
    def lookup(**kwargs):
        entered.set();release.wait(5)
        return {'public_ip':'198.51.100.2'}
    monkeypatch.setattr(web,'lookup_public_ip_info',lookup)
    try:
        assert web.public_ip()=='198.51.100.1'
        assert entered.wait(2)
        assert web.public_ip()=='198.51.100.1'
        assert not writes
    finally:
        release.set()
        for thread in threading.enumerate():
            if thread.name=='public-ip-refresh':thread.join(2)
    assert ('public_ip','198.51.100.2') in writes
