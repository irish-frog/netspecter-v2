"""Root-only lock shared by updates, resets and retired-package removal."""
from contextlib import contextmanager
import os,stat
from pathlib import Path


@contextmanager
def operation_lock(path=Path('/run/netspecter-operation.lock'),*,inherited_fd=None):
    import fcntl
    if inherited_fd is not None and (type(inherited_fd) is not int or not 3<=inherited_fd<=1024):raise ValueError('Invalid inherited operation lock')
    fd=os.dup(inherited_fd) if inherited_fd is not None else os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)&0o022:
            raise ValueError('Unsafe appliance operation lock')
        actual=path.lstat()
        if (actual.st_dev,actual.st_ino)!=(info.st_dev,info.st_ino) or not stat.S_ISREG(actual.st_mode):raise ValueError('Operation lock descriptor does not match the fixed lock file')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('Another update or maintenance operation is running') from None
        yield fd
    finally:os.close(fd)
