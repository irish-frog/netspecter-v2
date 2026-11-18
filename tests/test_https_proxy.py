import http.client
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netspecter_https_proxy import NetSpecterHttpsProxy


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class DownloadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_HEAD(self):
        self.respond()

    def respond(self):
        body = b"device,bytes\nworkstation,123\n"
        status = 304 if self.path == "/unchanged" else 200
        self.send_response(status)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="traffic.csv"')
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("ETag", '"report-v1"')
        self.send_header("Connection", "close, X-Internal")
        self.send_header("X-Internal", "must not escape")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and status != 304:
            self.wfile.write(body)

    def log_message(self, *args):
        pass


def fetch(method="GET", path="/report.csv"):
    with running(ThreadingHTTPServer(("127.0.0.1", 0), DownloadHandler)) as upstream:
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), NetSpecterHttpsProxy)
        proxy.target_host = "127.0.0.1"
        proxy.target_port = upstream.server_port
        proxy.target_timeout = 3
        with running(proxy):
            connection = http.client.HTTPConnection("127.0.0.1", proxy.server_port, timeout=3)
            try:
                connection.request(method, path)
                response = connection.getresponse()
                return response.status, dict(response.getheaders()), response.read()
            finally:
                connection.close()


def test_download_preserves_metadata_and_application_security_headers():
    status, headers, body = fetch()
    assert status == 200
    assert headers["Content-Type"] == "text/csv; charset=utf-8"
    assert headers["Content-Disposition"] == 'attachment; filename="traffic.csv"'
    assert headers["Content-Security-Policy"] == "default-src 'self'"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store"
    assert headers["ETag"] == '"report-v1"'
    assert "Connection" not in headers
    assert "X-Internal" not in headers
    assert int(headers["Content-Length"]) == len(body)
    assert body == b"device,bytes\nworkstation,123\n"


def test_head_keeps_get_representation_length_without_a_body():
    status, headers, body = fetch("HEAD")
    assert status == 200
    assert int(headers["Content-Length"]) == len(b"device,bytes\nworkstation,123\n")
    assert body == b""


def test_not_modified_has_no_synthetic_content_length_or_body():
    status, headers, body = fetch(path="/unchanged")
    assert status == 304
    assert "Content-Length" not in headers
    assert "Location" not in headers
    assert headers["ETag"] == '"report-v1"'
    assert body == b""
