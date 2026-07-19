#!/usr/bin/env python3
import argparse
import html
import http.client
import re
import socket
import ssl
import sys
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from netspecter_config import DEFAULT_CONFIG, cfg


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
HTTP_METHOD_PREFIXES = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"PATCH ", b"DELETE ", b"OPTIONS ")
COOKIE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,80}$")
COOKIE_VALUE_PATTERN = re.compile(r'^[A-Za-z0-9!#$%&\'()*+\-./:<=>?@\[\]^_`{|}~%]*$')
SAFE_COOKIE_FLAGS = {"httponly", "secure"}
SAFE_COOKIE_ATTRS = {"path", "samesite", "max-age", "expires"}


def safe_header_value(value):
    text = str(value or "")
    if "\r" in text or "\n" in text:
        return ""
    return text


def safe_redirect_path(path):
    text = str(path or "/")
    if "\r" in text or "\n" in text:
        return "/"
    text = text.replace("\\", "/").strip()
    parsed = urlsplit(text)
    if parsed.scheme or parsed.netloc or not text.startswith("/") or text.startswith("//"):
        return "/"
    return safe_header_value(text) or "/"


def safe_set_cookie_headers(upstream_headers):
    safe_headers = []
    for name, raw_value in upstream_headers:
        if name.lower() != "set-cookie":
            continue
        if not safe_header_value(raw_value):
            continue
        parsed = SimpleCookie()
        try:
            parsed.load(raw_value)
        except Exception:
            continue
        for morsel in parsed.values():
            cookie_name = str(morsel.key or "")
            cookie_value = str(morsel.coded_value or "")
            if not COOKIE_NAME_PATTERN.fullmatch(cookie_name) or not COOKIE_VALUE_PATTERN.fullmatch(cookie_value):
                continue
            parts = [f"{cookie_name}={cookie_value}"]
            for attr in SAFE_COOKIE_ATTRS:
                attr_value = str(morsel[attr] or "")
                if attr_value and safe_header_value(attr_value):
                    parts.append(f"{attr}={attr_value}")
            for flag in SAFE_COOKIE_FLAGS:
                if morsel[flag]:
                    parts.append(flag)
            safe_headers.append("; ".join(parts))
    return safe_headers


def proxy_content_type(path, upstream_content_type):
    content_type = str(upstream_content_type or "").split(";", 1)[0].strip().lower()
    if content_type == "text/html":
        return "text/html; charset=utf-8"
    if content_type == "text/css" or str(path).endswith(".css"):
        return "text/css; charset=utf-8"
    if content_type in {"application/javascript", "text/javascript"} or str(path).endswith(".js"):
        return "application/javascript; charset=utf-8"
    if content_type == "application/json":
        return "application/json; charset=utf-8"
    if content_type == "image/png" or str(path).endswith(".png"):
        return "image/png"
    if content_type == "image/jpeg" or str(path).endswith((".jpg", ".jpeg")):
        return "image/jpeg"
    if content_type == "image/svg+xml" or str(path).endswith(".svg"):
        return "image/svg+xml"
    if content_type == "image/x-icon" or str(path).endswith(".ico"):
        return "image/x-icon"
    return "application/octet-stream"


class RedirectingHttpsServer(ThreadingHTTPServer):
    def get_request(self):
        while True:
            request_socket, client_address = self.socket.accept()
            try:
                first_bytes = request_socket.recv(16, socket.MSG_PEEK)
                if first_bytes.startswith(HTTP_METHOD_PREFIXES):
                    self._send_plain_http_redirect(request_socket)
                    continue
                tls_socket = self.ssl_context.wrap_socket(request_socket, server_side=True)
                return tls_socket, client_address
            except ssl.SSLError as error:
                sys.stderr.write(f"TLS handshake failed from {client_address[0]}: {error}\n")
                request_socket.close()

    def _send_plain_http_redirect(self, request_socket):
        request_socket.settimeout(1.0)
        try:
            data = request_socket.recv(8192).decode("iso-8859-1", errors="replace")
            location = self._redirect_location(data)
            payload = (
                "HTTP/1.1 308 Permanent Redirect\r\n"
                f"Location: {location}\r\n"
                "Connection: close\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            request_socket.sendall(payload.encode("ascii", errors="ignore"))
        except Exception as error:
            sys.stderr.write(f"Plain HTTP redirect failed: {error}\n")
        finally:
            request_socket.close()

    def _redirect_location(self, request_text):
        lines = request_text.splitlines()
        path = "/"
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2 and parts[1].startswith("/"):
                path = safe_redirect_path(parts[1])
        host = ""
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = safe_header_value(line.split(":", 1)[1].strip())
                break
        if not host:
            host = f"{self.server_name}:{self.server_port}"
        return f"https://{host}{path}"


class NetSpecterHttpsProxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NetSpecterHttpsProxy/1.0"

    def do_GET(self):
        self._proxy()

    def do_POST(self):
        self._proxy()

    def do_PUT(self):
        self._proxy()

    def do_PATCH(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def do_OPTIONS(self):
        self._proxy()

    def do_HEAD(self):
        self._proxy()

    def _proxy(self):
        content_length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(content_length) if content_length else None
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS
        }
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Forwarded-Host"] = self.headers.get("Host", "")
        forwarded_for = self.client_address[0]
        if self.headers.get("X-Forwarded-For"):
            forwarded_for = f"{self.headers.get('X-Forwarded-For')}, {forwarded_for}"
        headers["X-Forwarded-For"] = forwarded_for

        connection = http.client.HTTPConnection(
            self.server.target_host,
            self.server.target_port,
            timeout=self.server.target_timeout,
        )
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read()
            self.send_response(response.status, response.reason)
            self.send_header("Content-Type", proxy_content_type(self.path, response.getheader("Content-Type")))
            if 300 <= response.status < 400:
                redirect_location = safe_redirect_path(response.getheader("Location") or "/")
                self.send_header("Location", safe_header_value(redirect_location) or "/")
            for cookie_header in safe_set_cookie_headers(response.getheaders()):
                self.send_header("Set-Cookie", cookie_header)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response_body)
        except Exception as exc:
            if self._wants_html_failover():
                payload = self._failover_page(exc)
                content_type = "text/html; charset=utf-8"
            else:
                message = f"NetSpecter HTTPS proxy could not reach local web service: {exc}"
                payload = message.encode("utf-8", errors="replace")
                content_type = "text/plain; charset=utf-8"
            self.send_response(503, "Service Unavailable")
            self.send_header("Content-Type", content_type)
            self.send_header("Retry-After", "5")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        finally:
            connection.close()

    def _wants_html_failover(self):
        if self.command not in {"GET", "HEAD"}:
            return False
        accept = self.headers.get("Accept", "")
        return "text/html" in accept or "*/*" in accept or not accept

    def _failover_page(self, error):
        detail = html.escape(str(error), quote=True)
        host = html.escape(self.headers.get("Host", "NetSpecter"), quote=True)
        body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="5">
  <title>NetSpecter is restarting</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg:#061322;
      --panel:#0b2035;
      --line:#1c4869;
      --text:#e8f3ff;
      --muted:#95a9c2;
      --cyan:#00d6ff;
      --green:#20df9f;
    }}
    * {{ box-sizing:border-box; }}
    body {{
      margin:0;
      min-height:100vh;
      display:grid;
      place-items:center;
      padding:24px;
      background:
        radial-gradient(circle at 20% 0%, rgba(0,214,255,.14), transparent 28%),
        linear-gradient(180deg, #071827, #040b13);
      color:var(--text);
      font:15px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      width:min(620px, 100%);
      padding:28px;
      border:1px solid rgba(0,214,255,.28);
      border-radius:12px;
      background:linear-gradient(180deg, rgba(11,32,53,.96), rgba(7,20,35,.96));
      box-shadow:0 22px 60px rgba(0,0,0,.35);
    }}
    .brand {{ display:flex; align-items:center; gap:12px; margin-bottom:18px; }}
    .mark {{
      width:42px;
      height:42px;
      display:grid;
      place-items:center;
      border:1px solid rgba(0,214,255,.42);
      border-radius:10px;
      color:var(--cyan);
      font-weight:900;
      box-shadow:0 0 18px rgba(0,214,255,.18);
    }}
    h1 {{ margin:0; font-size:25px; line-height:1.15; }}
    p {{ margin:10px 0 0; color:var(--muted); }}
    .status {{
      margin-top:18px;
      padding:13px 14px;
      border:1px solid rgba(32,223,159,.28);
      border-radius:8px;
      background:rgba(32,223,159,.08);
      color:#c7ffdf;
      font-weight:700;
    }}
    .actions {{ display:flex; flex-wrap:wrap; gap:10px; margin-top:22px; }}
    a, button {{
      min-height:40px;
      padding:9px 14px;
      border:1px solid rgba(0,214,255,.35);
      border-radius:8px;
      background:rgba(0,214,255,.12);
      color:var(--text);
      font:inherit;
      font-weight:800;
      text-decoration:none;
      cursor:pointer;
    }}
    details {{ margin-top:18px; color:var(--muted); }}
    code {{ word-break:break-word; color:#bad7f4; }}
  </style>
</head>
<body>
  <main>
    <div class="brand"><div class="mark">N</div><div><h1>NetSpecter is restarting</h1><p>{host}</p></div></div>
    <p>The HTTPS proxy is online, but the local web service is still starting. This normally happens during updates or service restarts.</p>
    <div class="status">Retrying automatically every 5 seconds...</div>
    <div class="actions">
      <a href="/">Try now</a>
      <button onclick="location.reload()">Refresh</button>
    </div>
    <details>
      <summary>Technical detail</summary>
      <p><code>{detail}</code></p>
    </details>
  </main>
</body>
</html>"""
        return body.encode("utf-8", errors="replace")

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))


def build_arg_parser():
    config = cfg()
    parser = argparse.ArgumentParser(description="NetSpecter HTTPS reverse proxy")
    parser.add_argument("--listen-host", default=config.get("https_proxy_host", DEFAULT_CONFIG["https_proxy_host"]))
    parser.add_argument("--listen-port", type=int, default=int(config.get("https_proxy_port", DEFAULT_CONFIG["https_proxy_port"])))
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=int(config.get("web_port", DEFAULT_CONFIG["web_port"])))
    parser.add_argument("--cert", default=config.get("https_proxy_cert_path", DEFAULT_CONFIG["https_proxy_cert_path"]))
    parser.add_argument("--key", default=config.get("https_proxy_key_path", DEFAULT_CONFIG["https_proxy_key_path"]))
    parser.add_argument("--timeout", type=int, default=60)
    return parser


def main():
    args = build_arg_parser().parse_args()
    httpd = RedirectingHttpsServer((args.listen_host, args.listen_port), NetSpecterHttpsProxy)
    httpd.target_host = args.target_host
    httpd.target_port = args.target_port
    httpd.target_timeout = args.timeout

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    httpd.ssl_context = context

    print(
        f"NetSpecter HTTPS proxy listening on {args.listen_host}:{args.listen_port}, "
        f"forwarding to {args.target_host}:{args.target_port}",
        flush=True,
    )
    httpd.serve_forever()


if __name__ == "__main__":
    main()
