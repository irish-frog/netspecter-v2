"""Read-only DNS continuity checks using the native AdGuard listener, not assumed loopback."""
import hashlib,ipaddress,re
from pathlib import Path
import subprocess

CONFIG_PATHS=(Path('/opt/AdGuardHome/AdGuardHome.yaml'),Path('/etc/AdGuardHome.yaml'),Path('/etc/adguardhome.yaml'))


def config_hashes(paths=CONFIG_PATHS):
    return {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths if path.is_file()}


def adguard_dns_servers():
    result=subprocess.run(['systemctl','show','AdGuardHome','--property=MainPID','--value'],capture_output=True,text=True,timeout=5,check=True)
    pid=result.stdout.strip()
    if not pid.isdigit() or int(pid)<=0:raise RuntimeError('Cannot identify the active AdGuard process')
    listeners={'udp':set(),'tcp':set()};wildcards={'udp':set(),'tcp':set()}
    for version in (4,6):
        result=subprocess.run(['ss','-H','-'+str(version),'-lntup','( sport = :53 )'],capture_output=True,text=True,timeout=5,check=True)
        for line in result.stdout.splitlines():
            fields=line.split()
            if len(fields)<6 or fields[0] not in listeners or not re.search(r'pid='+pid+r'(?:,|\))',line):continue
            host,separator,port=fields[4].rpartition(':');host=host.strip('[]')
            if not separator or port!='53':continue
            if host in {'*','0.0.0.0','::'}:
                wildcards[fields[0]].add(version);continue
            try:address=ipaddress.ip_address(host)
            except ValueError:continue
            if address.version==version:listeners[fields[0]].add(str(address))
    candidates=listeners['udp']|listeners['tcp']
    for version,loopback in ((4,'127.0.0.1'),(6,'::1')):
        if version in wildcards['udp'] or version in wildcards['tcp']:candidates.add(loopback)
    shared=[host for host in candidates if all(host in listeners[protocol] or ipaddress.ip_address(host).version in wildcards[protocol] for protocol in ('udp','tcp'))]
    if not shared:raise RuntimeError('No common UDP/TCP port-53 listener owned by AdGuard was found; cleanup refused')
    return sorted(shared,key=lambda host:(not ipaddress.ip_address(host).is_loopback,ipaddress.ip_address(host).version,host))


def probe_dns(server='127.0.0.1'):
    for transport in (['+ignore'],['+tcp']):
        try:result=subprocess.run(['dig','@'+server,'example.com','A','+time=3','+tries=1','+noall','+comments',*transport],capture_output=True,text=True,timeout=5,check=True)
        except (OSError,subprocess.SubprocessError) as error:
            raise RuntimeError('AdGuard DNS probe failed at '+server+' over '+('TCP' if '+tcp' in transport else 'UDP')+'; cleanup refused') from error
        if not any('status: '+status+',' in result.stdout for status in ('NOERROR','NXDOMAIN')):
            raise RuntimeError('AdGuard DNS probe failed at '+server+'; deployment/cleanup must stop')


def snapshot():
    active=subprocess.run(['systemctl','is-active','--quiet','AdGuardHome'],check=False).returncode==0
    state={'adguard_was_active':active,'configuration_hashes':config_hashes(),'dns_server':None}
    if active:
        state['dns_server']=adguard_dns_servers()[0]
        probe_dns(state['dns_server'])
    return state


def verify(state):
    if config_hashes()!=state['configuration_hashes']:
        raise RuntimeError('AdGuard configuration changed during deployment; history cleanup refused')
    if state['adguard_was_active']:
        subprocess.run(['systemctl','is-active','--quiet','AdGuardHome'],check=True)
        server=state.get('dns_server') or '127.0.0.1'
        if server not in adguard_dns_servers():raise RuntimeError('The original AdGuard DNS listener disappeared; cleanup refused')
        probe_dns(server)
