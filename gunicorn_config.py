import json
import os
import multiprocessing
from pathlib import Path


CONFIG_PATH = Path(os.environ.get("NETSPECTER_CONFIG_ROOT", "/etc/netspecter")) / "config.json"

host = "127.0.0.1"
port = 5050
request_timeout = int(os.environ.get("NETSPECTER_WEB_TIMEOUT") or 300)
try:
    app_settings = json.loads(CONFIG_PATH.read_text())
    host = str(app_settings.get("web_host", host) or host)
    port = int(app_settings.get("web_port", port) or port)
    request_timeout = int(app_settings.get("web_request_timeout_seconds", request_timeout) or request_timeout)
    if host in {"0.0.0.0", "::"} and not app_settings.get("allow_lan_http_5050", False):
        host = "127.0.0.1"
except Exception:
    pass

bind = f"{host}:{port}"
workers = int(os.environ.get("NETSPECTER_WEB_WORKERS") or (multiprocessing.cpu_count() or 1))
preload_app = True
accesslog = "-"
errorlog = "-"
capture_output = True
timeout = max(30, min(900, request_timeout))
graceful_timeout = max(30, min(900, request_timeout))
