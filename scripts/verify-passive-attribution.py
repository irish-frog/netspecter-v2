#!/usr/bin/env python3
"""Read-only deployment verification, without sending traffic or exposing credentials."""
import hashlib,json,os
from pathlib import Path
import socket,stat,subprocess,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.passive_deployment_service import validate
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'inspector'))
from build_manifest import verify


def check():
    config=json.loads(Path('/etc/netspecter/config.json').read_text())
    if not config.get('passive_attribution_enabled') or config.get('security_features_enabled') or config.get('suricata_enabled'):raise ValueError('Passive attribution/retired IDS configuration is not active')
    interface,port=validate(config)
    build=verify(root/'inspector/prebuilt/linux-x86_64')
    if hashlib.sha256((root/'bin/netspecter-tls-inspector').read_bytes()).hexdigest()!=build['sha256']:raise ValueError('Installed sensor checksum differs from tested bundle')
    units=['netspecter-collector','netspecter-tls-inspector','netspecter-softflowd','netspecter-tls-metadata.socket']
    subprocess.run(['systemctl','is-active','--quiet',*units],check=True)
    for unit in units:
        subprocess.run(['systemctl','is-active','--quiet',unit],check=True)
    metadata=Path('/run/netspecter-metadata/tls.sock').lstat();directory=Path('/run/netspecter-metadata').lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid!=0 or stat.S_IMODE(metadata.st_mode)!=0o660 or directory.st_uid!=0 or stat.S_IMODE(directory.st_mode)!=0o750:raise ValueError('Unsafe metadata socket/directory')
    sockets=subprocess.check_output(['ss','-H','-lun'],text=True)
    matches=[line for line in sockets.splitlines() if f'127.0.0.1:{port} ' in line]
    if not matches:raise ValueError('Loopback flow receiver is not listening')
    if any(f'0.0.0.0:{port} ' in line or f'*:{port} ' in line for line in sockets.splitlines()):raise ValueError('Flow receiver must not listen publicly')
    for unit in ['netspecter-tls-inspector','netspecter-softflowd']:
        user=subprocess.check_output(['systemctl','show',unit,'-p','User','--value'],text=True).strip()
        if user in {'','root'}:raise ValueError('Capture services must use dedicated unprivileged accounts')
    return {'status':'ready','capture_interface':interface,'flow_receiver':f'127.0.0.1:{port}','sensor_version':build['version'],'sensor_build_commit':build['source_commit'],'history_reset_performed':False}


if __name__=='__main__':print(json.dumps(check(),indent=2))
