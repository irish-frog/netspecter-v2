import json
import os
from pathlib import Path


CONFIG_PATH = Path(os.environ.get("NETSPECTER_CONFIG_ROOT", "/etc/netspecter")) / "config.json"

host = "127.0.0.1"
port = 5050
try:
    app_settings = json.loads(CONFIG_PATH.read_text())
    host = str(app_settings.get("web_host", host) or host)
    port = int(app_settings.get("web_port", port) or port)
    if host in {"0.0.0.0", "::"} and not app_settings.get("allow_lan_http_5050", False):
        host = "127.0.0.1"
except Exception:
    pass

bind = f"{host}:{port}"
workers = 2
preload_app = True
accesslog = "-"
errorlog = "-"
capture_output = True
timeout = 30
graceful_timeout = 30
