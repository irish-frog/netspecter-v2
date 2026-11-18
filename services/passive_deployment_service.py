"""Validate and atomically activate passive attribution without exposing stored secrets."""
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from services.traffic_scope_service import accounting_clients,internal_ipv4_networks


def validate(config):
    interface=str(config.get('packet_iface') or 'br0')
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',interface):raise ValueError('Invalid capture interface')
    port=config.get('netflow_receiver_port',2055)
    if type(port) is not int or not 1024<=port<=65535:raise ValueError('NetFlow port must be 1024..65535')
    internal_ipv4_networks(config);accounting_clients(config)
    return interface,port


def activate(path,additional_networks=()):
    path=Path(path)
    if path.is_symlink():raise ValueError('Refusing linked configuration')
    attributes=path.stat();config=json.loads(path.read_text())
    if additional_networks:
        current=config.get('internal_networks',[])
        if not isinstance(current,list):
            import re
            current=re.split(r'[,\s]+',str(current).strip())
        config['internal_networks']=list(dict.fromkeys([*current,*additional_networks]))
    validate(config)
    config.update(passive_attribution_enabled=True,flow_visibility_enabled=True,netflow_receiver_host='127.0.0.1',
        security_features_enabled=False,suricata_enabled=False,ids_auto_ban_enabled=False,ids_email_enabled=False,
        ids_telegram_enabled=False,threat_intel_enabled=False,anomaly_enabled=False)
    descriptor,temporary=tempfile.mkstemp(prefix='.passive-config-',dir=path.parent)
    try:
        with os.fdopen(descriptor,'w',encoding='utf-8') as handle:
            json.dump(config,handle,indent=2);handle.write('\n');handle.flush();os.fsync(handle.fileno())
        if hasattr(os,'chown'):os.chown(temporary,attributes.st_uid,attributes.st_gid)
        os.chmod(temporary,stat.S_IMODE(attributes.st_mode));os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    return config
