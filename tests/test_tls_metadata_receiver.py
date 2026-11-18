import json
import sqlite3
import pytest
from services.tls_metadata_service import ensure_metadata_schema, store_metadata, validate_metadata, inherited_listener


def wire(**changes):
    item = dict(schema_version=1, event_type="tls_client_hello", observed_at_unix_ms=100_000,
                connection_started_at_unix_ms=99_000, connection={"source":"192.168.1.5","destination":"8.8.8.8","source_port":12345,"destination_port":443}, hostname="example.com",ech_present=False)
    item.update(changes)
    return json.dumps(item).encode()


def test_validated_metadata_is_deduplicated_without_measured_byte_claims():
    con=sqlite3.connect(":memory:")
    ensure_metadata_schema(con)
    item=validate_metadata(wire(),now_ms=100_000)
    store_metadata(con,[item,item])
    assert con.execute("SELECT count(*) FROM tls_connection_metadata").fetchone()[0]==1
    assert con.execute("SELECT hostname FROM tls_connection_metadata").fetchone()[0]=="example.com"


@pytest.mark.parametrize("changes", [
    {"schema_version":True},{"schema_version":2},{"hostname":"<script>.com"},
    {"hostname":"127.0.0.1"},{"hostname":"a\nb.com"},{"hostname":"EXAMPLE.com"},
    {"hostname":"example.com","ech_present":True},{"ech_present":1},
    {"observed_at_unix_ms":99999999},{"connection_started_at_unix_ms":1},
    {"connection":{"source":"192.168.1.5","destination":"8.8.8.8","source_port":True,"destination_port":443}},
    {"connection":{"source":"192.168.1.5","destination":"::1","source_port":12345,"destination_port":443}},
])
def test_invalid_metadata_is_rejected(changes):
    with pytest.raises((ValueError,TypeError)): validate_metadata(wire(**changes),now_ms=100_000)


def test_oversized_duplicate_and_nonstandard_json_are_rejected():
    for value in [b" "*4097,b'{"x":1,"x":2}',b'{"x":NaN}',b"[]"]:
        with pytest.raises(ValueError): validate_metadata(value,now_ms=100_000)


def test_ech_without_outer_name_is_retained_as_limitation():
    assert validate_metadata(wire(hostname=None,ech_present=True),now_ms=100_000).ech_present


def test_unrelated_process_cannot_supply_listener_environment():
    assert inherited_listener({"LISTEN_PID":"-1","LISTEN_FDS":"1"}) is None


def test_metadata_addresses_must_be_strings_without_scope_suffixes():
    for source in [123,True,"fe80::1%lo"]:
        with pytest.raises(ValueError):
            validate_metadata(wire(connection={"source":source,"destination":"8.8.8.8","source_port":12345,"destination_port":443}),now_ms=100_000)


@pytest.mark.skipif(__import__("sys").platform!="linux",reason="Linux peer credentials")
def test_unix_receiver_authenticates_peer_and_reconnects_after_oversized_input(tmp_path):
    import os,socket,threading,time
    from services.tls_metadata_service import serve_metadata,peer_is_allowed
    path=str(tmp_path/"tls.sock")
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(path);listener.listen(2)
    stop=threading.Event();stored=[];errors=[]
    def worker():
        try: serve_metadata(listener,os.getuid(),lambda rows:stored.extend(rows),stop)
        except Exception as exc:errors.append(exc)
    thread=threading.Thread(target=worker,daemon=True);thread.start()
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.connect(path)
            assert peer_is_allowed(client,os.getuid())
            assert not peer_is_allowed(client,os.getuid()+1)
            client.sendall(b"x"*5000)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.connect(path)
            now=int(time.time()*1000)
            message=wire(observed_at_unix_ms=now,connection_started_at_unix_ms=now-1000)+b"\n"
            client.sendall(message[:20]);client.sendall(message[20:])
        stop.wait(0.1)
    finally:
        stop.set();thread.join(3);listener.close()
    assert not errors and not thread.is_alive()
    assert len(stored)==1 and stored[0].hostname=="example.com"


@pytest.mark.skipif(__import__("sys").platform!="linux",reason="Linux socket activation")
def test_inherited_descriptor_requires_listening_unix_socket_and_expected_path(tmp_path,monkeypatch):
    import os,socket
    path=str(tmp_path/"listen.sock")
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(path);listener.listen(1)
    duplicate=os.dup
    monkeypatch.setattr(os,"dup",lambda fd:duplicate(listener.fileno()))
    environment={"LISTEN_PID":str(os.getpid()),"LISTEN_FDS":"1"}
    try:
        accepted=inherited_listener(environment,expected_path=path)
        assert accepted.family==socket.AF_UNIX and not accepted.get_inheritable()
        accepted.close()
        with pytest.raises(ValueError):inherited_listener(environment,expected_path=path+"wrong")
    finally:listener.close()
