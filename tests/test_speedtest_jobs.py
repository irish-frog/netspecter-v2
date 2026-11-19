import os
import threading
from services import speedtest_job_service as jobs


def test_background_job_excludes_duplicates_and_releases_lock(tmp_path):
    started=threading.Event();release=threading.Event();finished=threading.Event()
    state=tmp_path/'job.json';lock=tmp_path/'run.lock'
    def run():
        started.set();release.wait(5);finished.set()
        return {'success':True}
    assert jobs.start(run,state,lock)
    assert started.wait(2)
    try:
        assert jobs.status(state,lock)['status']=='running'
        assert not jobs.start(lambda:None,state,lock)
    finally:release.set()
    assert finished.wait(2)
    # Joining the worker observes both final state persistence and lock release.
    for thread in threading.enumerate():
        if thread.name=='manual-speedtest':thread.join(2)
    assert jobs.status(state,lock)['status']=='finished'


def test_failed_job_releases_lock(tmp_path):
    state=tmp_path/'job.json';lock=tmp_path/'run.lock'
    def fail():raise RuntimeError('private detail')
    assert jobs.start(fail,state,lock)
    for thread in threading.enumerate():
        if thread.name=='manual-speedtest':thread.join(2)
    assert jobs.status(state,lock)['status']=='failed'
    assert 'private detail' not in state.read_text()
    fd=jobs.acquire_lock(lock);assert fd is not None;os.close(fd)


def test_dead_worker_is_reported_interrupted(tmp_path):
    state=tmp_path/'job.json';lock=tmp_path/'run.lock'
    jobs._write(state,{'status':'running','id':'old'})
    assert jobs.status(state,lock)['status']=='interrupted'


def test_scheduled_lock_blocks_manual_job(tmp_path):
    lock=tmp_path/'run.lock';fd=jobs.acquire_lock(lock)
    try:assert not jobs.start(lambda:None,tmp_path/'job.json',lock)
    finally:os.close(fd)
