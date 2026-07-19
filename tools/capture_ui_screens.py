#!/usr/bin/env python3
"""
Capture NetSpecter UI screenshots from a running appliance.

Usage:
    python tools/capture_ui_screens.py --base-url http://192.168.99.6:5050

The script opens a visible Chromium window so you can log in manually once.
After you press Enter in the terminal, it captures the configured pages.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except ImportError:
    print("Playwright is not installed. Run: python -m pip install playwright")
    print("Then run: python -m playwright install chromium")
    sys.exit(2)


DEFAULT_ROUTES = [
    ("/", "dashboard"),
    ("/devices", "devices"),
    ("/traffic", "traffic"),
    ("/history", "history"),
    ("/applications", "applications"),
    ("/blocked", "blocked"),
    ("/blocked-services", "blocked-services"),
    ("/ids-alerts", "ids-alerts"),
    ("/incidents", "incidents"),
    ("/anomalies", "anomalies"),
    ("/health", "health"),
    ("/telemetry", "telemetry"),
    ("/adguard", "adguard"),
    ("/unifi", "unifi"),
    ("/gatus", "gatus"),
    ("/monitor", "monitor"),
    ("/beszel", "beszel"),
    ("/telegram", "telegram"),
    ("/integrations", "integrations"),
    ("/settings", "settings"),
    ("/speed-tests", "speed-tests"),
    ("/system", "system"),
    ("/vault", "vault"),
    ("/exports", "exports"),
]

VIEWPORTS = {
    "desktop": {"width": 1440, "height": 1100},
    "mobile": {"width": 390, "height": 844, "is_mobile": True},
}


def safe_name(value: str) -> str:
    value = value.strip("/").replace("/", "-") or "dashboard"
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-").lower()


def parse_routes(raw_routes: list[str]) -> list[tuple[str, str]]:
    routes = []
    for route in raw_routes:
        if not route:
            continue
        if "=" in route:
            name, path = route.split("=", 1)
            routes.append((path.strip(), safe_name(name)))
        else:
            routes.append((route.strip(), safe_name(route)))
    return routes


def capture_page(page, base_url: str, path: str, label: str, output_dir: Path) -> tuple[bool, str]:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    target = output_dir / f"{label}.png"
    try:
        response = page.goto(url, wait_until="networkidle", timeout=30000)
        status = response.status if response else "no-response"
        page.screenshot(path=str(target), full_page=True)
        return True, f"{label}: {status} -> {target}"
    except PlaywrightTimeoutError:
        try:
            page.screenshot(path=str(target), full_page=True)
            return False, f"{label}: timeout, partial screenshot -> {target}"
        except PlaywrightError as error:
            return False, f"{label}: timeout and screenshot failed: {error}"
    except PlaywrightError as error:
        return False, f"{label}: failed: {error}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture NetSpecter UI screenshots.")
    parser.add_argument("--base-url", default="http://192.168.99.6:5050", help="NetSpecter base URL")
    parser.add_argument("--output", default="ui-screenshots", help="Output directory")
    parser.add_argument("--route", action="append", default=[], help="Extra route or name=/route. Can be repeated.")
    parser.add_argument("--only", action="append", default=[], help="Only capture these routes or labels. Can be repeated.")
    parser.add_argument("--mobile", action="store_true", help="Also capture mobile viewport screenshots")
    parser.add_argument("--headless", action="store_true", help="Run headless. Use only when already authenticated.")
    parser.add_argument("--no-login-wait", action="store_true", help="Do not pause for manual login")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    root = Path(args.output) / stamp
    root.mkdir(parents=True, exist_ok=True)

    routes = list(DEFAULT_ROUTES)
    routes.extend(parse_routes(args.route))
    if args.only:
        wanted = {safe_name(item) for item in args.only} | {item for item in args.only}
        routes = [(path, label) for path, label in routes if label in wanted or path in wanted]

    viewport_names = ["desktop", "mobile"] if args.mobile else ["desktop"]

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=args.headless)
        context = browser.new_context(viewport=VIEWPORTS["desktop"], ignore_https_errors=True)
        page = context.new_page()

        print(f"Opening {base_url}")
        page.goto(base_url, wait_until="domcontentloaded", timeout=30000)
        if not args.no_login_wait and not args.headless:
            print("Log in in the Chromium window if needed.")
            input("Press Enter here when the app is logged in and ready to capture...")

        results = []
        for viewport_name in viewport_names:
            context.set_default_timeout(30000)
            page.set_viewport_size(
                {
                    "width": VIEWPORTS[viewport_name]["width"],
                    "height": VIEWPORTS[viewport_name]["height"],
                }
            )
            output_dir = root / viewport_name
            output_dir.mkdir(parents=True, exist_ok=True)
            for path, label in routes:
                ok, message = capture_page(page, base_url, path, label, output_dir)
                results.append((ok, message))
                print(("OK  " if ok else "WARN") + message)

        browser.close()

    index = root / "index.txt"
    index.write_text("\n".join(message for _ok, message in results) + "\n", encoding="utf-8")
    failures = sum(1 for ok, _message in results if not ok)
    print(f"\nScreenshots saved under: {root}")
    if failures:
        print(f"Completed with {failures} warning(s). Check index.txt for details.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
