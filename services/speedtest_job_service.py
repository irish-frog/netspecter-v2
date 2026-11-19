"""Cross-worker speed-test exclusion and nonblocking manual job state."""
import json,os,stat,tempfile,threading,time,uuid
from pathlib import Path


def acquire_lock(path):
    path=Path(path);path.parent.mkdir(mode=0o750,parents=True,exist_ok=True)
    fd=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('Unsafe speed-test lock')
        if os.name=='nt':
            import msvcrt
            if not info.st_size:os.write(fd,b'0')
            os.lseek(fd,0,os.SEEK_SET);msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return fd
    except (BlockingIOError,PermissionError):os.close(fd);return None
    except OSError as error:
        os.close(fd)
        if error.errno in (11,13):return None
        raise
    except BaseException:os.close(fd);raise


def _write(path,data):
    path=Path(path);path.parent.mkdir(mode=0o750,parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.speedtest-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as output:json.dump(data,output)
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)


def status(state_path,lock_path):
    path=Path(state_path);data={}
    try:
        descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
        try:
            info=os.fstat(descriptor)
            if stat.S_ISREG(info.st_mode) and info.st_size<=4096:
                saved=json.loads(os.read(descriptor,4097))
                if isinstance(saved,dict):
                    data={key:saved[key] for key in ('id','status','started_at','finished_at') if key in saved}
        finally:os.close(descriptor)
    except (OSError,ValueError,TypeError):pass
    fd=acquire_lock(lock_path)
    if fd is None:return {**data,'status':'running'}
    os.close(fd)
    if data.get('status')=='running':data['status']='interrupted'
    return data or {'status':'idle'}


def start(run,state_path,lock_path):
    fd=acquire_lock(lock_path)
    if fd is None:return False
    data={'id':uuid.uuid4().hex,'status':'running','started_at':time.time()}
    try:_write(state_path,data)
    except BaseException:os.close(fd);raise
    def worker():
        try:
            result=run()
            data['status']='finished' if not isinstance(result,dict) or result.get('success') else 'failed'
        except Exception:data['status']='failed'
        finally:
            try:data['finished_at']=time.time();_write(state_path,data)
            finally:os.close(fd)
    try:threading.Thread(target=worker,daemon=True,name='manual-speedtest').start()
    except BaseException:
        try:data['status']='failed';_write(state_path,data)
        finally:os.close(fd)
        raise
    return True
