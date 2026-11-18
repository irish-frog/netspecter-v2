#!/usr/bin/env python3
"""Isolated Linux capture/IPC test. Run as root in disposable CI, never as part of an appliance update."""
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import threading


def client_hello():
    name = b"inspector-test.example.com"
    names = b"\0" + len(name).to_bytes(2, "big") + name
    sni = len(names).to_bytes(2, "big") + names
    extensions = b"\0\0" + len(sni).to_bytes(2, "big") + sni
    body = b"\3\3" + bytes(32) + b"\0\0\2\x13\1\1\0" + len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\1" + len(body).to_bytes(3, "big") + body
    return b"\x16\3\3" + len(handshake).to_bytes(2, "big") + handshake


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("This isolated capture test requires Linux and root/CAP_NET_RAW in disposable CI.")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    invalid = subprocess.run([binary, "missing-ns-test", "/run/missing.sock"], capture_output=True, timeout=5)
    assert invalid.returncode != 0, "missing interface must fail cleanly"
    with tempfile.TemporaryDirectory(prefix="netspecter-capture-test-") as directory:
        ipc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        address = str(Path(directory) / "metadata.sock")
        ipc.bind(address)
        os.chmod(address, 0o660)
        ipc.listen(1)
        ipc.settimeout(10)
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(10)
        process = subprocess.Popen([binary, "lo", address], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            selector = selectors.DefaultSelector()
            selector.register(process.stderr, selectors.EVENT_READ)
            assert selector.select(10), "capture readiness timed out"
            assert process.stderr.readline().strip() == b"capture_ready"
            selector.close()
            payload = client_hello()
            errors = []
            def receive():
                try:
                    connection, _ = server.accept()
                    with connection:
                        received = bytearray()
                        while len(received) < len(payload):
                            block = connection.recv(4096)
                            assert block, 'TCP stream closed early'
                            received.extend(block)
                        assert bytes(received) == payload, "sensor must not alter forwarding"
                except Exception as exc:
                    errors.append(exc)
            worker = threading.Thread(target=receive, daemon=True)
            worker.start()
            with socket.create_connection(server.getsockname(), timeout=5) as client:
                local_port = client.getsockname()[1]
                # Exercise real TCP delivery; portable tests cover deterministic segment reordering.
                client.sendall(payload)
                connection, _ = ipc.accept()
                with connection:
                    connection.settimeout(5)
                    line = bytearray()
                    while not line.endswith(b"\n") and len(line) < 4096:
                        block = connection.recv(4096)
                        assert block, "metadata connection closed prematurely"
                        line.extend(block)
                    observation = json.loads(line)
                assert observation["hostname"] == "inspector-test.example.com", observation
                assert observation["schema_version"] == 1
                assert observation["connection"]["source_port"] == local_port
                assert observation["connection"]["destination_port"] == server.getsockname()[1]
                assert observation["connection_started_at_unix_ms"] <= observation["observed_at_unix_ms"]
                assert "payload" not in observation and "bytes" not in observation
            worker.join(5)
            assert not worker.is_alive() and not errors, errors
            assert process.poll() is None, "sensor died after capture"
            print("Linux loopback capture, exact tuple, metadata IPC and unchanged TCP delivery passed.")
        finally:
            process.terminate()
            process.communicate(timeout=5)
            ipc.close()
            server.close()


if __name__ == "__main__":
    main()
