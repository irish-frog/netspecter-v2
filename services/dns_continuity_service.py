"""Read-only DNS continuity checks for explicit appliance deployments."""
import hashlib
from pathlib import Path
import subprocess

CONFIG_PATHS=(Path('/opt/AdGuardHome/AdGuardHome.yaml'),Path('/etc/AdGuardHome.yaml'),Path('/etc/adguardhome.yaml'))


def config_hashes(paths=CONFIG_PATHS):
    return {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths if path.is_file()}


def probe_dns(server='127.0.0.1'):
    for transport in ([],['+tcp']):
        result=subprocess.run(['dig','@'+server,'example.com','A','+time=3','+tries=1','+noall','+comments',*transport],capture_output=True,text=True,timeout=5,check=True)
        if not any('status: '+status+',' in result.stdout for status in ('NOERROR','NXDOMAIN')):
            raise RuntimeError('AdGuard DNS probe failed; deployment/cleanup must stop')


def snapshot():
    active=subprocess.run(['systemctl','is-active','--quiet','AdGuardHome'],check=False).returncode==0
    state={'adguard_was_active':active,'configuration_hashes':config_hashes()}
    if active:probe_dns()
    return state


def verify(state):
    if config_hashes()!=state['configuration_hashes']:
        raise RuntimeError('AdGuard configuration changed during deployment; history cleanup refused')
    if state['adguard_was_active']:
        subprocess.run(['systemctl','is-active','--quiet','AdGuardHome'],check=True)
        probe_dns()
