import importlib.util
import json
import os
import re
import tempfile
import unittest
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]


class WebSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.original_env = {
            key: os.environ.get(key)
            for key in (
                "NETSPECTER_INSTALL_ROOT",
                "NETSPECTER_CONFIG_ROOT",
                "NETSPECTER_DATA_ROOT",
                "NETSPECTER_APP_ROOT",
            )
        }
        root = Path(cls.tempdir.name)
        os.environ["NETSPECTER_INSTALL_ROOT"] = str(root / "install")
        os.environ["NETSPECTER_CONFIG_ROOT"] = str(root / "config")
        os.environ["NETSPECTER_DATA_ROOT"] = str(root / "data")
        os.environ["NETSPECTER_APP_ROOT"] = str(SOURCE_DIR)

        spec = importlib.util.spec_from_file_location("netspecter_test_app", SOURCE_DIR / "app.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        cls.module.app.config.update(TESTING=True)

    @classmethod
    def tearDownClass(cls):
        for key, value in cls.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        cls.tempdir.cleanup()

    def setUp(self):
        self.client = self.module.app.test_client()

    def csrf_from(self, path="/setup-admin"):
        page = self.client.get(path)
        match = re.search(r'name="_csrf_token" value="([^"]+)"', page.get_data(as_text=True))
        self.assertIsNotNone(match)
        return match.group(1)

    def test_post_without_csrf_token_is_rejected(self):
        response = self.client.post("/setup-admin", data={"password": "not-important"})
        self.assertEqual(400, response.status_code)

    def test_post_with_issued_csrf_token_reaches_handler(self):
        token = self.csrf_from()
        response = self.client.post(
            "/setup-admin",
            data={"_csrf_token": token, "password": "short", "confirm": "short"},
        )
        self.assertEqual(200, response.status_code)

    def test_mutating_action_routes_do_not_accept_get(self):
        source = (SOURCE_DIR / "app.py").read_text()
        rules = {rule.rule: rule.methods for rule in self.module.app.url_map.iter_rules()}
        for path in ("/device/pause/<ip>", "/device/resume/<ip>", "/adguard/action"):
            self.assertNotIn("GET", rules[path])
            self.assertIn("POST", rules[path])
        self.assertNotIn("GET", rules["/collector/restart"])
        self.assertIn("POST", rules["/collector/restart"])
        self.assertIn("Block DNS", source)
        self.assertIn("Allow DNS", source)
        self.assertNotIn("Pause Internet", source)

    def test_range_picker_escapes_request_path(self):
        with self.module.app.test_request_context('/applications/" onmouseover="x'):
            html = self.module.time_picker()
        self.assertIn("/applications/&quot; onmouseover=&quot;x?range=1d", html)
        self.assertNotIn('href="/applications/" onmouseover="x', html)

    def test_browser_security_headers_are_set(self):
        response = self.client.get("/setup-admin")
        self.assertEqual("nosniff", response.headers["X-Content-Type-Options"])
        self.assertEqual("DENY", response.headers["X-Frame-Options"])
        self.assertEqual("strict-origin-when-cross-origin", response.headers["Referrer-Policy"])
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_fresh_install_interval_matches_live_collection_intent(self):
        example = json.loads((SOURCE_DIR / "config.example.json").read_text())
        self.assertEqual(2, self.module.DEFAULT_CONFIG["collect_interval_seconds"])
        self.assertEqual(2, example["collect_interval_seconds"])
        self.assertEqual(90, self.module.DEFAULT_CONFIG["traffic_retention_days"])
        self.assertEqual(90, example["traffic_retention_days"])
        self.assertEqual(90, self.module.DEFAULT_CONFIG["dns_retention_days"])
        self.assertEqual(90, example["dns_retention_days"])
        self.assertTrue(self.module.DEFAULT_CONFIG["fast_page_mode"])
        self.assertTrue(example["fast_page_mode"])
        self.assertFalse(self.module.DEFAULT_CONFIG["snmp_enabled"])
        self.assertFalse(example["snmp_enabled"])
        self.assertFalse(self.module.DEFAULT_CONFIG["mqtt_enabled"])
        self.assertFalse(example["mqtt_enabled"])

    def test_web_service_uses_gunicorn_wsgi_entrypoint(self):
        requirements = (SOURCE_DIR / "requirements.txt").read_text().splitlines()
        service = (SOURCE_DIR / "systemd" / "netspecter-web.service").read_text()
        installer = (SOURCE_DIR / "install.sh").read_text()
        source = (SOURCE_DIR / "app.py").read_text()
        gunicorn_config = (SOURCE_DIR / "gunicorn_config.py").read_text()
        self.assertIn("gunicorn", requirements)
        self.assertIn("paho-mqtt", requirements)
        self.assertIn(" snmp ", installer)
        self.assertIn("detect_os", installer)
        self.assertIn("NetSpecter v2 targets Debian 13 Trixie", installer)
        self.assertIn("Detected Debian 13 Trixie.", installer)
        self.assertIn("without cross-release repositories", installer)
        self.assertNotIn("bookworm-backports", installer)
        self.assertNotIn("-t bookworm-backports", installer)
        self.assertNotIn("BACKPORTS_LIST", installer)
        self.assertIn("apt install -y suricata suricata-update", installer)
        self.assertIn("suricata -T -c /etc/suricata/suricata.yaml", installer)
        self.assertIn("install_suricata_safety_override", installer)
        self.assertIn("guard_suricata_restart_loop", installer)
        self.assertIn("configure_suricata_interface", installer)
        self.assertIn("NETSPECTER_SURICATA_IFACE", installer)
        self.assertIn("Suricata interface '$iface' does not exist", installer)
        self.assertIn("StartLimitBurst=3", installer)
        self.assertIn("CPUQuota=50%", installer)
        self.assertIn("Suricata restart loop detected", installer)
        self.assertIn("gunicorn_config.py wsgi:application", service)
        self.assertIn('cp gunicorn_config.py "$INSTALL_DIR/gunicorn_config.py"', installer)
        self.assertIn('cp wsgi.py "$INSTALL_DIR/wsgi.py"', installer)
        self.assertIn('cp THIRD_PARTY_NOTICES.md "$INSTALL_DIR/THIRD_PARTY_NOTICES.md"', installer)
        self.assertIn('cp -r licenses "$INSTALL_DIR/licenses"', installer)
        self.assertIn('cp LICENSE "$INSTALL_DIR/LICENSE"', installer)
        self.assertIn('cp EULA.md "$INSTALL_DIR/EULA.md"', installer)
        self.assertIn('User=netspecter', service)
        self.assertIn('Group=netspecter', service)
        self.assertIn('ensure_runtime_user', installer)
        self.assertIn('validate_anomaly_permissions "netspecter-collector.service"', installer)
        self.assertIn('chmod 750 "$CONFIG_DIR" "$CONFIG_DIR/adguard" "$DATA_DIR" "$LOG_DIR"', installer)
        self.assertIn('chmod 640 "$CONFIG_DIR/config.json"', installer)
        self.assertIn('chmod 660 "$DATA_DIR/netspecter.db"', installer)
        self.assertIn('find "$INSTALL_DIR/venv/bin" -maxdepth 1 -type f -exec chmod 755 {} \\;', installer)
        self.assertIn("installer_anomaly_permission_test", installer)
        self.assertIn("Anomaly permissions:   VALID", installer)
        self.assertIn('"$DATA_DIR/netspecter_security.db"', installer)
        self.assertNotIn("config = json.loads", gunicorn_config)
        self.assertIn("ROOT,", source)
        self.assertNotIn('"/root/netspecter"', source)

    def test_adguard_third_party_notices_are_shipped_and_visible(self):
        notice = SOURCE_DIR / "THIRD_PARTY_NOTICES.md"
        gpl = SOURCE_DIR / "licenses" / "AdGuardHome-GPL-3.0.txt"
        source = (SOURCE_DIR / "app.py").read_text()
        readme = (SOURCE_DIR / "README.md").read_text()

        self.assertTrue(notice.exists())
        self.assertTrue(gpl.exists())
        notice_text = notice.read_text()
        gpl_text = gpl.read_text()
        self.assertIn("| Project | AdGuard Home |", notice_text)
        self.assertIn("GNU General Public License v3.0", notice_text)
        self.assertIn("Separate local DNS service", notice_text)
        self.assertIn("does not own AdGuard Home", notice_text)
        self.assertIn("What GPL-3.0 means for AdGuard Home", notice_text)
        self.assertIn("does not currently bundle an AdGuard", notice_text)
        self.assertIn("Home binary in this GitHub repository", notice_text)
        self.assertIn("GPL-3.0 does not automatically make NetSpecter GPL", notice_text)
        self.assertIn("Included version: [ADGUARD_HOME_VERSION]", notice_text)
        self.assertIn("Do not copy AdGuard Home source into the NetSpecter repository", notice_text)
        self.assertIn("THIRD_PARTY_NOTICES.md", readme)
        self.assertIn("licenses/AdGuardHome-GPL-3.0.txt", readme)
        self.assertIn("docs/images/netspecter-rack-appliance.jpg", readme)
        self.assertTrue((SOURCE_DIR / "docs" / "images" / "netspecter-rack-appliance.jpg").exists())
        self.assertIn("GNU GENERAL PUBLIC LICENSE", gpl_text)
        self.assertIn("Version 3, 29 June 2007", gpl_text)
        self.assertIn("/third-party-licences", source)
        self.assertIn("Legal &amp; Licences", source)

    def test_netspecter_proprietary_license_is_shipped_and_visible(self):
        license_path = SOURCE_DIR / "LICENSE"
        source = (SOURCE_DIR / "app.py").read_text()
        readme = (SOURCE_DIR / "README.md").read_text()
        notice = (SOURCE_DIR / "THIRD_PARTY_NOTICES.md").read_text()
        eula = (SOURCE_DIR / "EULA.md").read_text()

        self.assertTrue(license_path.exists())
        license_text = license_path.read_text()
        self.assertIn("NetSpecter is proprietary software", license_text)
        self.assertIn("may copy,", license_text)
        self.assertIn("resell, host, bundle", license_text)
        self.assertIn("This licence does not apply to separately identified third-party software.", license_text)
        self.assertIn("See [LICENSE](LICENSE)", readme)
        self.assertIn("[EULA](EULA.md)", readme)
        self.assertIn("Third-party components remain governed by their own licence terms.", readme)
        self.assertIn("NetSpecter is proprietary software; see `LICENSE`.", notice)
        self.assertIn("may not:", eula)
        self.assertIn("host NetSpecter commercially", eula)
        self.assertIn("This agreement applies only to NetSpecter.", eula)
        self.assertIn("AdGuard Home is separate third-party software", eula)
        self.assertIn("license_path = ROOT / \"LICENSE\"", source)
        self.assertIn("eula_path = ROOT / \"EULA.md\"", source)
        self.assertIn("NetSpecter licence", source)
        self.assertIn("NetSpecter EULA", source)

    def test_adguard_install_notice_is_shown_before_upstream_install(self):
        installer = (SOURCE_DIR / "install.sh").read_text()
        docs = (SOURCE_DIR / "docs" / "ADGUARD.md").read_text()

        self.assertIn("## Third-Party Licence Notice", docs)
        self.assertIn("AdGuard Home is separate third-party software licensed under the GNU General", docs)
        self.assertIn("Project and source: https://github.com/AdguardTeam/AdGuardHome", docs)
        self.assertIn("NetSpecter notices: [Third-Party Notices](../THIRD_PARTY_NOTICES.md)", docs)

        notice_index = installer.index("AdGuard Home is separate third-party software licensed under GPL-3.0.")
        install_index = installer.index("wget -O - https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh")
        self.assertLess(notice_index, install_index)
        self.assertIn("Project and source: https://github.com/AdguardTeam/AdGuardHome", installer)
        self.assertIn("Licence: https://github.com/AdguardTeam/AdGuardHome/blob/master/LICENSE.txt", installer)
        self.assertIn("NetSpecter third-party notices: $SOURCE_DIR/THIRD_PARTY_NOTICES.md", installer)

    def test_dashboard_summary_refreshes_fast_and_heavy_chart_refreshes_slower(self):
        source = (SOURCE_DIR / "app.py").read_text()
        self.assertIn("setInterval(loadDashboardSummary, 10000);", source)
        self.assertIn("setInterval(loadDashboardTraffic, 30000);", source)
        self.assertIn("const dashboardFastMode =", source)
        self.assertIn("const netSpecterFastMode =", source)
        self.assertIn("const netSpecterLiveIntervalSeconds = 5;", source)
        self.assertIn("function hasLiveSpeedWidgets()", source)
        self.assertNotIn("data-live-countdown", source)
        self.assertNotIn("next live update in", source)
        self.assertNotIn("Live collector:", source)
        self.assertIn('DL <span data-live-network="1" data-live-field="down"', source)
        self.assertIn('/collector/restart', source)
        self.assertIn('Click to restart', source)
        self.assertIn("loadDashboardTraffic();", source)
        self.assertNotIn("Fast mode is on. Graph loads once and only refreshes when requested.", source)
        self.assertNotIn('id="dashboardGraphRefresh"', source)
        self.assertNotIn("setDashboardGraphStatus", source)
        self.assertIn("def cached_query(key, max_age, sql, params=()):", source)
        self.assertIn("cached_query(", source)
        self.assertIn("live_speeds = live_all_host_speeds()", source)
        self.assertIn('data-app-shell="1"', source)
        self.assertIn('id="appContent"', source)
        self.assertIn('request.args.get("_partial") == "1"', source)
        self.assertIn("loadAppShellPage", source)
        self.assertIn("/api/dashboard-apps", source)
        self.assertIn("/api/dashboard-health", source)
        self.assertIn("/api/traffic-rows", source)
        self.assertIn('id="trafficRows"', source)
        self.assertIn('id="dashboardSummaryLoading"', source)
        self.assertIn("Last 60 Days", source)
        self.assertIn("Last 90 Days", source)
        self.assertNotIn("setInterval(loadDashboardSummary, 30000);", source)
        self.assertNotIn("setInterval(loadDashboardSummary, 5000);", source)
        self.assertNotIn("setInterval(refreshLiveSpeeds, 2000);", source)
        self.assertNotIn("setInterval(loadDashboardTraffic, 5000);", source)
        self.assertIn('class="dash-app-row" href="/applications/{quote(category, safe=\'\')}?range={range_key()}"', source)
        self.assertIn("if (hasLiveSpeedWidgets())", source)
        self.assertIn("font-size:24px", source)
        self.assertIn("font-size:12px", source)
        self.assertIn('if title == "Dashboard" else \'<a href="/system#performance"><span>Logs</span></a>\'', source)
        self.assertIn('id="dashboardUpdateButton"', source)
        self.assertIn('action="/system"', source)
        self.assertIn('Update Available</button>', source)
        self.assertIn('if (dashboardButton) dashboardButton.style.display = "inline-flex";', source)

    def test_range_picker_includes_longer_ranges(self):
        with self.module.app.test_request_context("/traffic?range=90d"):
            html = self.module.time_picker()
            self.assertIn('href="/traffic?range=60d"', html)
            self.assertIn('href="/traffic?range=90d"', html)
            self.assertIn('class="active" href="/traffic?range=90d"', html)
            self.assertEqual(90, self.module.range_days())
            self.assertEqual("90d", self.module.range_key())

    def test_settings_exposes_snmp_and_mqtt_setup(self):
        with self.module.app.test_request_context("/settings"):
            html = self.module.settings()
        self.assertIn("SNMP Enabled", html)
        self.assertIn("SNMP Targets", html)
        self.assertIn("MQTT Enabled", html)
        self.assertIn("MQTT Broker Host", html)
        self.assertIn("MQTT Subscribe Topics", html)
        self.assertIn("type='checkbox' name='snmp_enabled'", html)
        self.assertIn("type='checkbox' name='mqtt_tls'", html)

    def test_app_shell_partial_returns_body_only(self):
        with self.module.app.test_request_context("/traffic?_partial=1"):
            response = self.module.shell("Total Traffic", "<table></table>", "Traffic")
            response = self.module.set_security_headers(response)
        html = response.get_data(as_text=True)
        self.assertEqual(200, response.status_code)
        self.assertEqual("Total Traffic", response.headers["X-NetSpecter-Title"])
        self.assertEqual("Traffic", response.headers["X-NetSpecter-Active"])
        self.assertIn("<table>", html)
        self.assertNotIn("<!DOCTYPE html>", html)
        self.assertNotIn('<div class="sidebar">', html)

    def test_estimated_app_traffic_has_storage_and_app_detail_output(self):
        source = (SOURCE_DIR / "app.py").read_text()
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        self.module.init_db()
        con = self.module.connect_db()
        tables = {
            row[0]
            for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        con.close()
        self.assertIn("estimated_app_traffic", tables)
        self.assertIn("remote_traffic_intervals", tables)
        self.assertIn("remote_ip_locations", tables)
        self.assertNotIn("<h2>Estimated App Traffic", source)
        self.assertIn("remember_estimated_app_targets", collector)
        self.assertIn("MONITORED_APP_DOMAIN_KEYS", collector)
        self.assertIn("MONITORED_APP_CATEGORIES", source)
        self.assertIn("Est. Download / Total", source)
        self.assertIn("Estimated data is measured from DNS-attributed delivery traffic for this monitored app.", source)

    def test_data_tables_offer_stable_sorting_without_live_rate_sorting(self):
        self.module.init_db()
        config = self.module.cfg()
        config["auth_enabled"] = False
        self.module.save_cfg(config)

        pages = {
            "/devices?sort=vendor&dir=asc": [
                '/devices?sort=name&dir=desc',
                '/devices?sort=last&dir=desc',
            ],
            "/traffic?sort=download&dir=asc": [
                "sort=download&dir=desc",
                "sort=total&dir=desc",
            ],
            "/applications?sort=app&dir=asc": [
                "sort=app&dir=desc",
                "sort=share&dir=desc",
            ],
            "/applications/YouTube?sort=estimated&dir=asc": [
                "sort=estimated&dir=desc",
                "sort=last&dir=desc",
            ],
        }
        for path, expected_links in pages.items():
            response = self.client.get(path)
            self.assertEqual(200, response.status_code, path)
            html = response.get_data(as_text=True)
            for link in expected_links:
                self.assertIn(link, html, path)

        blocked_services = self.client.get("/blocked-services?sort=service&dir=asc")
        self.assertEqual(302, blocked_services.status_code)
        self.assertIn("/blocked?range=", blocked_services.headers.get("Location", ""))

        devices_html = self.client.get("/devices").get_data(as_text=True)
        traffic_html = self.client.get("/traffic").get_data(as_text=True)
        self.assertNotIn("sort=live", devices_html)
        self.assertNotIn("sort=throughput", traffic_html)

    def test_sidebar_branding_and_third_party_licence_link_are_present(self):
        source = (SOURCE_DIR / "app.py").read_text()
        css = (SOURCE_DIR / "static" / "theme.css").read_text()
        self.assertIn("/static/theme.css?v=20260718a", source)
        self.assertIn('<img src="/static/brand/logo-sidebar.png?v=20260711-ui5" class="brand-logo" alt="NetSpecter">', source)
        self.assertIn('href="/third-party-licences"', source)
        self.assertIn(".legal-notice", css)
        self.assertIn("word-break: break-word;", css)

    def test_speed_test_is_manual_post_action_and_installed(self):
        source = (SOURCE_DIR / "app.py").read_text()
        installer = (SOURCE_DIR / "install.sh").read_text()
        rules = {rule.rule: rule.methods for rule in self.module.app.url_map.iter_rules()}
        self.assertIn("/speed-test", rules)
        self.assertIn("POST", rules["/speed-test"])
        self.assertNotIn("GET", rules["/speed-test"])
        self.assertIn('("/usr/bin/speedtest", ["--accept-license", "--accept-gdpr"])', source)
        self.assertIn('("/usr/bin/speedtest-cli", [])', source)
        self.assertIn("def speedtest_command():", source)
        self.assertIn('speedtest_env.setdefault("HOME", "/root")', source)
        self.assertIn('speedtest_env.setdefault("LC_ALL", "C.UTF-8")', source)
        self.assertIn("install_speedtest_optional", installer)
        self.assertIn("ookla/speedtest-cli/script.deb.sh", installer)
        self.assertIn("dpkg-query -W -f='${Status}' speedtest", installer)
        self.assertIn("dpkg-query -W -f='${Status}' speedtest-cli", installer)
        self.assertIn("apt install -y speedtest-cli", installer)
        self.assertIn("No supported speed test client is installed", source)
        self.assertNotIn("apt install -y python3 python3-pip python3-venv sqlite3 bridge-utils nftables tcpdump curl nano git bmon vnstat ieee-data snmp speedtest", installer)

    def test_optional_unifi_discovery_and_scheduled_speed_history_ship_disabled(self):
        source = (SOURCE_DIR / "app.py").read_text()
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        installer = (SOURCE_DIR / "install.sh").read_text()
        schedule = (SOURCE_DIR / "scheduled_speedtest.py").read_text()
        example = json.loads((SOURCE_DIR / "config.example.json").read_text())
        rules = {rule.rule: rule.methods for rule in self.module.app.url_map.iter_rules()}
        self.assertFalse(example["unifi_enabled"])
        self.assertFalse(example["unifi_skip_tls_verify"])
        self.assertFalse(example["ids_email_enabled"])
        self.assertFalse(example["ids_auto_ban_enabled"])
        self.assertEqual([], example["ids_banned_ips"])
        self.assertEqual(0, example["scheduled_speedtests_per_day"])
        self.assertIn("unifi_password", self.module.SENSITIVE_CONFIG_KEYS)
        self.assertIn("smtp_password", self.module.SENSITIVE_CONFIG_KEYS)
        self.assertIn("snmp_community", self.module.SENSITIVE_CONFIG_KEYS)
        self.assertIn("mqtt_password", self.module.SENSITIVE_CONFIG_KEYS)
        self.assertIn("/integrations", rules)
        self.assertIn("/unifi", rules)
        self.assertIn("/gatus", rules)
        self.assertIn("/telegram", rules)
        self.assertIn("/beszel", rules)
        self.assertIn("/speed-tests", rules)
        self.assertIn("POST", rules["/speed-tests"])
        self.assertIn("Enable automatic speed tests", source)
        self.assertIn("Once per day", source)
        self.assertIn("/api/update-status", rules)
        self.assertIn("/system", rules)
        self.assertIn("POST", rules["/system"])
        self.assertIn("def start_background_update():", source)
        self.assertIn("Update Available", source)
        self.assertIn("git pull --ff-only", source)
        self.assertIn("def record_request_timing(response):", source)
        self.assertIn("X-NetSpecter-Render-Ms", source)
        self.assertIn("Slow Request Timing", source)
        self.assertIn("fetch_remote=force_update_check", source)
        self.assertIn("def find_unifi_site(config):", source)
        self.assertIn("def unifi_verify_tls(config):", source)
        self.assertIn("def unifi_connector_bases(config):", source)
        self.assertIn("def unifi_json_response(result):", source)
        self.assertIn("UniFi OS firmware 5.0.3 or newer", source)
        self.assertIn("Connector URL corrected automatically.", source)
        self.assertIn("local UniFi gateway URL", source)
        self.assertIn("Find Site Automatically", source)
        self.assertIn("Allow self-signed certificate for local UniFi gateway", source)
        self.assertIn("refresh_unifi_clients", collector)
        self.assertIn("def unifi_verify_tls(config):", collector)
        self.assertIn("def unifi_connector_bases(config):", collector)
        self.assertIn("UniFi connected clients imported: {imported} ({named_imported} named)", collector)
        self.assertIn("WHERE ip=? AND (name IS NULL OR TRIM(name)='' OR name=ip)", collector)
        self.assertIn('"X-API-Key": api_key', collector)
        self.assertIn("UNIFI_CLIENT_REFRESH_SECONDS = 300", collector)
        self.assertIn("process_ids_email_alerts(c)", collector)
        self.assertIn("def send_ids_email(config, alert):", collector)
        self.assertIn("IDS_EMAIL_STATE_PATH", collector)
        self.assertIn("smtp_password", collector)
        self.assertIn("CREATE TABLE IF NOT EXISTS speed_tests", source)
        self.assertIn("CREATE TABLE IF NOT EXISTS telemetry_readings", source)
        self.assertIn("/telemetry", source)
        self.assertIn("SNMP and MQTT Pulled Data", source)
        self.assertIn("CREATE TABLE IF NOT EXISTS telemetry_readings", collector)
        self.assertIn("def poll_snmp_targets(config):", collector)
        self.assertIn("def mqtt_subscription_loop():", collector)
        self.assertIn("mqtt_subscribe_topics", collector)
        self.assertIn("store_telemetry(\"mqtt\"", collector)
        self.assertIn("scheduled_speedtest.py", installer)
        self.assertIn("netspecter-speedtest.timer", installer)
        self.assertIn("/usr/bin/speedtest-cli", schedule)
        self.assertIn('if runs == 0:', schedule)

    def test_common_pages_do_not_block_on_public_ip_and_devices_batch_live_speeds(self):
        source = (SOURCE_DIR / "app.py").read_text()
        self.assertIn("def public_ip(refresh=True):", source)
        self.assertIn("Public IP: {h(public_ip_text)}", source)
        self.assertIn("def live_all_host_speeds():", source)
        self.assertIn("live_speeds = live_all_host_speeds()", source)

    def test_traffic_and_speed_history_graphs_use_bar_charts(self):
        source = (SOURCE_DIR / "app.py").read_text()
        self.assertGreaterEqual(source.count('type: "bar"'), 2)
        self.assertIn("type: 'bar'", source)

    def test_suricata_ids_alerts_page_has_filtered_notification_actions(self):
        source = (SOURCE_DIR / "app.py").read_text()
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        rules = {rule.rule: rule.methods for rule in self.module.app.url_map.iter_rules()}
        self.assertIn("/ids-alerts", rules)
        self.assertIn("GET", rules["/ids-alerts"])
        self.assertIn("POST", rules["/ids-alerts"])
        self.assertIn('("IDS Alerts", "/ids-alerts", "ids")', source)
        self.assertIn('("Incidents", "/incidents", "ids")', source)
        self.assertIn("def recent_suricata_alerts(limit=300, filters=None):", source)
        self.assertIn("Only show alerts from source IPs not already known in Devices", source)
        self.assertIn("Excluded Source IPs", source)
        self.assertIn("hidden alerts remain in Suricata logs", source)
        self.assertIn("Enable IDS email alerts", source)
        self.assertIn("Save Notification Settings", source)
        self.assertIn("def send_smtp_message(config, subject, body):", source)
        self.assertIn('value="ignore_source"', source)
        self.assertIn('value="add_source_exception"', source)
        self.assertIn('value="add_signature_exception"', source)
        self.assertIn('value="bulk_ignore_alerts"', source)
        self.assertIn('value="bulk_source_exceptions"', source)
        self.assertIn('value="bulk_rule_exceptions"', source)
        self.assertIn("Select visible", source)
        self.assertIn("IDS Exceptions", source)
        self.assertIn("Highest severity first", source)
        self.assertIn('value="ban_source"', source)
        self.assertIn('value="ban_destination"', source)
        self.assertIn("Firewall Ban List", source)
        self.assertNotIn('/device/block/', source)
        self.assertIn('"ids_banned_ips": [],', collector)
        self.assertIn('"ids_auto_ban_enabled": False', collector)
        self.assertIn('"ids_exceptions": []', collector)
        self.assertIn("def ids_alert_is_excepted(config, alert):", collector)
        self.assertIn('if ids_alert_is_excepted(config, alert):', collector)
        self.assertIn('if not config.get("ids_auto_ban_enabled", False):', collector)
        self.assertIn("netspecter:ids-ban:forward-source", collector)
        self.assertIn("netspecter:ids-ban:forward-destination", collector)

    def test_vendor_lookup_and_private_mac_guidance(self):
        source = (SOURCE_DIR / "app.py").read_text()
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        installer = (SOURCE_DIR / "install.sh").read_text()
        self.assertIn("private_mac_address", source)
        self.assertIn("Private Wi-Fi Address / Randomized MAC", source)
        self.assertIn('"private / random mac"', source)
        self.assertIn('SYSTEM_OUI_PATH = Path("/usr/share/ieee-data/oui.txt")', collector)
        self.assertIn('return "Private / Random MAC"', collector)
        self.assertIn("ieee-data", installer)

    def test_adguard_client_names_fill_device_labels_without_overwriting_custom_names(self):
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        self.assertIn('f"{base}/control/clients"', collector)
        self.assertIn("ADGUARD_CLIENT_REFRESH_SECONDS = 300", collector)
        self.assertIn("def parse_adguard_client_names(payload):", collector)
        self.assertIn("remember_adguard_client_activity(client, ts)", collector)
        self.assertIn("CREATE TABLE IF NOT EXISTS device_overrides", collector)
        self.assertIn("WHERE ip=? AND (name IS NULL OR TRIM(name)='' OR name=ip)", collector)

    def test_removed_legacy_live_probe_is_not_shipped(self):
        source = (SOURCE_DIR / "app.py").read_text()
        installer = (SOURCE_DIR / "install.sh").read_text()
        self.assertNotIn("iftop_live_hosts", source)
        self.assertNotIn("iftop_iface", source)
        self.assertNotRegex(installer, r"\biftop\b")
        self.assertFalse((SOURCE_DIR / "static" / "netspecter-logo-wide.png").exists())

    def test_unsupported_legacy_config_keys_are_removed_on_load(self):
        legacy = self.module.DEFAULT_CONFIG.copy()
        legacy["old_unused_password"] = "not-needed"
        self.module.CONFIG_PATH.write_text(json.dumps(legacy))
        loaded = self.module.cfg()
        persisted = json.loads(self.module.CONFIG_PATH.read_text())
        self.assertNotIn("old_unused_password", loaded)
        self.assertNotIn("old_unused_password", persisted)

    def test_network_map_uses_cached_traffic_and_dns_destination_locations(self):
        source = (SOURCE_DIR / "app.py").read_text()
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        css = (SOURCE_DIR / "static" / "theme.css").read_text()
        self.assertIn("Internet Destinations", source)
        self.assertIn("Top Mapped DNS Destinations", source)
        self.assertIn("dns_destination_map_rows", source)
        self.assertIn('id="destinationMap"', source)
        self.assertIn("https://unpkg.com/leaflet@1.9.4", source)
        self.assertIn("https://tile.openstreetmap.org", source)
        self.assertNotIn("<h2>Active Devices</h2>", source)
        self.assertNotIn("<h2>Recently Seen / Stale</h2>", source)
        map_source = source[source.index("def network_map():"):source.index("def csv_response", source.index("def network_map():"))]
        self.assertNotIn("{time_picker()}", map_source)
        self.assertIn("compact-topology", map_source)
        self.assertIn("update_one_remote_location", collector)
        self.assertIn("GEOLOCATION_REFRESH_SECONDS = 3600", collector)
        self.assertIn("remote_traffic_intervals", collector)
        self.assertIn("#destinationMap", css)
        self.assertIn(".compact-topology", css)


if __name__ == "__main__":
    unittest.main()
