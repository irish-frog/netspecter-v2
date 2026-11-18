import ipaddress
import struct
from services.netflow_measurement_service import NetflowDecoder

NOW=1_800_000_000_000


def v5(*,uptime=100000,first=99000,last=99900,sequence=1,sampling=0):
    header=struct.pack("!HHIIIIBBH",5,1,uptime,NOW//1000,0,sequence,0,0,sampling)
    record=struct.pack("!IIIHHIIIIHHBBBBHHBBH",int(ipaddress.IPv4Address("192.168.1.5")),int(ipaddress.IPv4Address("8.8.8.8")),0,0,0,10,1000,first,last,12345,443,0,0,6,0,0,0,0,0,0)
    return header+record


def test_v5_preserves_connection_times_and_stable_export_identity():
    decoder=NetflowDecoder();row=decoder.decode(v5(),now_ms=NOW)[0]
    assert row["first_ms"]==NOW-1000 and row["last_ms"]==NOW-100
    assert row["src_port"]==12345 and row["bytes"]==1000
    assert decoder.decode(v5(),now_ms=NOW)[0]["measurement_id"]==row["measurement_id"]
    assert decoder.decode(v5(sequence=2),now_ms=NOW)[0]["measurement_id"]==row["measurement_id"]
    assert decoder.decode(v5(sequence=3,first=99901,last=99950),now_ms=NOW)[0]["measurement_id"]!=row["measurement_id"]


def test_uptime_wrap_is_decoded_without_future_timestamps():
    row=NetflowDecoder().decode(v5(uptime=100,first=2**32-900,last=0),now_ms=NOW)[0]
    assert row["first_ms"]==NOW-1000 and row["last_ms"]==NOW-100


def test_sampled_remote_truncated_stale_and_impossible_measurements_rejected():
    decoder=NetflowDecoder()
    assert not decoder.decode(v5(sampling=100),now_ms=NOW)
    assert not decoder.decode(v5(),exporter="192.168.1.4",now_ms=NOW)
    assert not decoder.decode(v5()[:-1],now_ms=NOW)
    assert not decoder.decode(v5(),now_ms=NOW+600000)
    assert not decoder.decode(v5(first=99999,last=99000),now_ms=NOW)


def v9(fields,values,*,sequence=1,uptime=100000,include_template=True):
    header=struct.pack("!HHIIII",9,2,uptime,NOW//1000,sequence,7)
    template=struct.pack("!HH",256,len(fields))+b"".join(struct.pack("!HH",field,width) for field,width in fields)
    sets=(struct.pack("!HH",0,len(template)+4)+template) if include_template else b""
    payload=b"".join(value.to_bytes(width,"big") if isinstance(value,int) else value for value,(_,width) in zip(values,fields))
    padding=(-len(payload))%4;payload+=bytes(padding)
    return header+sets+struct.pack("!HH",256,len(payload)+4)+payload


FIELDS=[(8,4),(12,4),(7,2),(11,2),(4,1),(1,4),(2,4),(22,4),(21,4)]
VALUES=[bytes([192,168,1,5]),bytes([8,8,8,8]),12345,443,6,1000,10,99000,99900]


def test_v9_templates_expire_and_restart_invalidates_old_schema():
    decoder=NetflowDecoder();packet=v9(FIELDS,VALUES)
    assert decoder.decode(packet,now_ms=NOW)[0]["bytes"]==1000
    assert decoder.decode(v9(FIELDS,VALUES,sequence=2,include_template=False),now_ms=NOW)
    assert not decoder.decode(v9(FIELDS,VALUES,uptime=100,include_template=False),now_ms=NOW)


def test_v9_ipv6_and_absolute_millisecond_timestamps():
    fields=[(27,16),(28,16),*FIELDS[2:-2],(152,8),(153,8)]
    values=[ipaddress.IPv6Address("fd00::1").packed,ipaddress.IPv6Address("2001:4860:4860::8888").packed,*VALUES[2:-2],NOW-1000,NOW-100]
    row=NetflowDecoder().decode(v9(fields,values),now_ms=NOW)[0]
    assert row["src_ip"]=="fd00::1" and row["last_ms"]==NOW-100


def test_malformed_packets_are_bounded_and_do_not_raise():
    decoder=NetflowDecoder()
    for length in range(512): assert decoder.decode(bytes([9])*length,now_ms=NOW)==[]
    assert not decoder.decode(v9([(8,65535)],[b"a"]),now_ms=NOW)
