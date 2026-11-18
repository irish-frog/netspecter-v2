"""Keep test imports and application caches away from appliance/local data."""

import os
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / ".test-runtime"
BASE.mkdir(exist_ok=True)
RUNTIME = tempfile.TemporaryDirectory(prefix="session-", dir=BASE, ignore_cleanup_errors=True)
ORIGINAL = {}
for name, value in {
    "NETSPECTER_INSTALL_ROOT": str(Path(RUNTIME.name) / "install"),
    "NETSPECTER_CONFIG_ROOT": str(Path(RUNTIME.name) / "config"),
    "NETSPECTER_DATA_ROOT": str(Path(RUNTIME.name) / "data"),
    "NETSPECTER_APP_ROOT": str(ROOT),
    "TEMP": RUNTIME.name,
    "TMP": RUNTIME.name,
}.items():
    ORIGINAL[name] = os.environ.get(name)
    os.environ[name] = value
tempfile.tempdir = RUNTIME.name


def pytest_unconfigure(config):
    for name, value in ORIGINAL.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    tempfile.tempdir = None
    RUNTIME.cleanup()
