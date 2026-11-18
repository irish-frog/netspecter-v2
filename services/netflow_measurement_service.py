"""Bounded NetFlow measurements; no application guesses or byte estimates."""
from collections import OrderedDict
from datetime import datetime
import hashlib
import ipaddress
import struct
import time

MAX_AGE_MS = 86_400_000


class NetflowDecoder:
    def __init__(self):
        self.templates = OrderedDict()
        self.exporters = OrderedDict()

    def decode(self, packet, exporter="127.0.0.1", now_ms=None):
        try:
            if not ipaddress.ip_address(exporter).is_loopback or not 2 <= len(packet) <= 65535:
                return []
            version = struct.unpack_from("!H", packet)[0]
            current = int(time.time() * 1000) if now_ms is None else now_ms
            digest = exporter
            if version == 5:
                return self._v5(packet, digest, current)
            if version == 9:
                return self._v9(packet, exporter, digest, current)
        except (ValueError, TypeError, struct.error, OverflowError):
            return []
        return []

    @staticmethod
    def _times(uptime, exported_ms, first, last, current):
        if abs(exported_ms - current) > 300_000:
            return None
        first_age = (uptime - first) & 0xffffffff
        last_age = (uptime - last) & 0xffffffff
        if first_age > MAX_AGE_MS or last_age > first_age:
            return None
        return exported_ms - first_age, exported_ms - last_age

    @staticmethod
    def _row(digest, index, source, destination, source_port, destination_port, protocol, octets, packets, times, exported):
        if not times or not 0 < octets <= 2**63-1 or not 0 <= packets <= 2**63-1 or not 0 <= protocol <= 255:
            return None
        if source.version != destination.version:
            return None
        first, last = times
        if first < 0 or last < first:
            return None
        identity = f"{digest}|{source}|{destination}|{source_port}|{destination_port}|{protocol}|{first}|{last}|{octets}|{packets}"
        return {"measurement_id": hashlib.sha256(identity.encode()).hexdigest(),
                "src_ip": str(source), "dst_ip": str(destination), "src_port": source_port, "dst_port": destination_port,
                "protocol": protocol, "bytes": octets, "packets": packets,
                "first_ms": first, "last_ms": last, "exported_ms": exported,
                "ts": datetime.fromtimestamp(last / 1000).strftime("%Y-%m-%d %H:%M:%S")}

    def _v5(self, packet, digest, current):
        if len(packet) < 24:
            return []
        _version, count, uptime, seconds, nanos, _sequence, _engine_type, _engine_id, sampling = struct.unpack_from("!HHIIIIBBH", packet)
        if not 1 <= count <= 30 or len(packet) != 24 + 48 * count or nanos >= 1_000_000_000 or sampling:
            return []  # sampled measurements cannot claim complete bytes
        digest = f"v5:{digest}:{_engine_type}:{_engine_id}"
        exported = seconds * 1000 + nanos // 1_000_000
        rows = []
        for index in range(count):
            record = packet[24 + 48 * index:24 + 48 * (index + 1)]
            src, dst, _next, _in, _out, packets, octets, first, last, sport, dport, _pad, _flags, protocol, *_tail = struct.unpack("!IIIHHIIIIHHBBBBHHBBH", record)
            row = self._row(digest,index,ipaddress.IPv4Address(src),ipaddress.IPv4Address(dst),sport,dport,protocol,octets,packets,
                            self._times(uptime,exported,first,last,current),exported)
            if row:
                rows.append(row)
        return rows

    def _v9(self, packet, exporter, digest, current):
        if len(packet) < 20:
            return []
        _version, count, uptime, seconds, sequence, source_id = struct.unpack_from("!HHIIII",packet)
        if count > 2048:
            return []
        exported = seconds * 1000
        if abs(exported-current) > 300_000:
            return []
        digest = f"v9:{exporter}:{source_id}"
        source = (exporter,source_id)
        previous = self.exporters.get(source)
        if previous and (uptime < previous[0] and previous[0]-uptime < 2**31):
            for key in list(self.templates):
                if key[:2] == source:
                    self.templates.pop(key)
        self.exporters[source] = (uptime,sequence)
        self.exporters.move_to_end(source)
        while len(self.exporters)>32:
            self.exporters.popitem(last=False)
        offset, rows = 20, []
        while offset + 4 <= len(packet):
            kind, length = struct.unpack_from("!HH",packet,offset)
            if length<4 or offset+length>len(packet):
                return []
            payload=packet[offset+4:offset+length]
            if kind == 0:
                self._templates(source,payload,current)
            elif kind >= 256:
                key=(*source,kind)
                entry=self.templates.get(key)
                if entry and current-entry[1]<=1_800_000:
                    fields=entry[0]
                    size=sum(n for _,n in fields)
                    position=0
                    while position+size<=len(payload) and len(rows)<1024:
                        values={}; at=position
                        for field, width in fields:
                            values[field]=payload[at:at+width];at+=width
                        row=self._values(values,digest,f"{offset}:{position}",uptime,exported,current)
                        if row: rows.append(row)
                        position+=size
                    if len(payload)-position>3 or any(payload[position:]):
                        return []
            offset+=length
        if offset!=len(packet):
            return []
        return rows

    def _templates(self, source, payload, current):
        offset=0
        while offset+4<=len(payload):
            kind,count=struct.unpack_from("!HH",payload,offset);offset+=4
            if kind>=256:
                self.templates.pop((*source,kind),None)
            if kind<256 or not 1<=count<=64 or offset+4*count>len(payload):
                return
            fields=[]
            for _ in range(count):
                field,width=struct.unpack_from("!HH",payload,offset);offset+=4
                if not 1<=width<=256 or field & 0x8000:
                    return
                fields.append((field,width))
            if len({field for field,_ in fields})!=len(fields) or sum(n for _,n in fields)>2048:
                return
            key=(*source,kind);self.templates[key]=(fields,current);self.templates.move_to_end(key)
            while len(self.templates)>256:
                self.templates.popitem(last=False)

    def _values(self, values, digest, index, uptime, exported, current):
        def integer(field, widths):
            raw=values.get(field,b"")
            if len(raw) not in widths:
                raise ValueError("invalid NetFlow field width")
            return int.from_bytes(raw,"big")
        try:
            ipv6=27 in values or 28 in values
            source=ipaddress.ip_address(values[27 if ipv6 else 8])
            destination=ipaddress.ip_address(values[28 if ipv6 else 12])
            protocol=integer(4,{1})
            if 34 in values and integer(34,{1,2,4}) != 1:
                return None
            if 48 in values or 49 in values or 50 in values:
                return None  # sampling selector present: semantics not supported
            if 152 in values and 153 in values:
                first,last=integer(152,{8}),integer(153,{8})
                times=(first,last) if -999<=exported-last<=MAX_AGE_MS and 0<=last-first<=MAX_AGE_MS else None
            else:
                times=self._times(uptime,exported,integer(22,{4}),integer(21,{4}),current)
            sport=integer(7,{2}) if protocol in {6,17} else 0
            dport=integer(11,{2}) if protocol in {6,17} else 0
            return self._row(digest,index,source,destination,sport,dport,protocol,integer(1,{4,8}),integer(2,{4,8}),times,exported)
        except (KeyError,ValueError,TypeError):
            return None
