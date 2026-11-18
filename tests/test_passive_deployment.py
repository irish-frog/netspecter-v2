import hashlib,json,struct,sys
from pathlib import Path
import pytest
from services.passive_deployment_service import activate,validate


def test_activation_preserves_settings_credentials_and_licence(tmp_path):
    path=tmp_path/'config.json'
    saved={'packet_iface':'br0','lan_prefix':'192.168.1.','internal_networks':['10.20.30.0/24'],
        'admin_password':'stored-hash','adguard_pass':'enc:opaque','netlic_licence_key':'enc:licence',
        'site_domain_mappings':[{'domain':'work.example.com','application':'Work'}]}
    path.write_text(json.dumps(saved))
    updated=activate(path)
    assert all(updated[key]==value for key,value in saved.items())
    assert updated['passive_attribution_enabled'] and not updated['suricata_enabled']
    assert updated['netflow_receiver_host']=='127.0.0.1'


@pytest.mark.parametrize('config',[{'packet_iface':'br0;evil'}, {'netflow_receiver_port':'2055'}, {'netflow_receiver_port':True}, {'netflow_receiver_port':53}])
def test_hostile_configuration_rejected_before_write(config):
    with pytest.raises(ValueError):validate(config)


def test_bundle_source_and_binary_integrity(tmp_path):
    import importlib.util
    source=Path(__file__).resolve().parents[1]/'inspector/build_manifest.py'
    spec=importlib.util.spec_from_file_location('sensor_build_manifest',source);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    binary=bytearray(128);binary[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',binary,18,62)
    (tmp_path/'netspecter-tls-inspector').write_bytes(binary)
    manifest={'schema_version':1,'target':'x86_64-unknown-linux-gnu','source_commit':'a'*40,'source_sha256':module.fingerprint(),'sha256':hashlib.sha256(binary).hexdigest()}
    (tmp_path/'build.json').write_text(json.dumps(manifest))
    assert module.verify(tmp_path)['sha256']==manifest['sha256']
    (tmp_path/'netspecter-tls-inspector').write_bytes(b'tampered')
    with pytest.raises(ValueError,match='checksum'):module.verify(tmp_path)
