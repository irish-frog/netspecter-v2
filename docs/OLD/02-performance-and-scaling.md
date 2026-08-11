Handoff Summary
Repo: C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2
Main branch is updated and pushed to GitHub at commit:
bb91fca Keep internet quality in traffic database
Feature branch used:
codex/live-memory-snapshot
Merged into:
main
Main Work Completed
Implemented live in-memory snapshot/cache path so UI/LCD live values do not wait on SQLite.
Live values now come from memory/file snapshot:
Current Mbps
Device count
Service health
Ping/internet quality
LCD summary
Dashboard live values
Added:
netspecter_live_snapshot.py
/var/lib/netspecter/live_snapshot.json
Collector writes live snapshot; web reads it first.
Database Split
Split high-write/history data away from main DB.
Fresh/current layout:
/var/lib/netspecter/netspecter.db
Core DB: devices, labels, app state, security/incidents/anomaly/threat tables.

/var/lib/netspecter/netspecter_dns.db
dns_import_state
dns_querylog
dns_resolved_ips

/var/lib/netspecter/netspecter_traffic.db
collector_heartbeat
live_device_speed
speed_tests
estimated_app_traffic
remote_ip_locations
traffic_intervals
internet_quality
remote_traffic_intervals
traffic_samples

/var/lib/netspecter/netspecter_security.db
Created by installer as future split target, not actively routed yet.
Old SQL names still work because netspecter_db.connect_db() and collector DB connections attach split DBs automatically.
Reset Workflow
Added:
scripts/reset-history.sh
It:
Stops NetSpecter services
Moves old DB/cache/live snapshot files into timestamped backup folder
Keeps /etc/netspecter/config.json
Creates fresh split DB files
Clears history/runtime data
Fresh install readiness:
install.sh creates all split DB files
Applies permissions
Installs reset-history.sh
Existing config is preserved
Important Appliance Commands
Normal update:
cd /opt/netspecter
git pull --ff-only
bash ./install.sh
systemctl restart netspecter-web netspecter-https netspecter-collector
Fresh history reset while keeping settings:
cd /opt/netspecter
bash scripts/reset-history.sh
bash ./install.sh
systemctl restart netspecter-web netspecter-https netspecter-collector
Verify DB split:
sqlite3 /var/lib/netspecter/netspecter.db ".tables" | grep -E "dns|traffic|speed_tests|internet_quality|live_device_speed|collector_heartbeat" || echo "main DB has no DNS/traffic history tables"

sqlite3 /var/lib/netspecter/netspecter_dns.db ".tables"
sqlite3 /var/lib/netspecter/netspecter_traffic.db ".tables"
Expected:
main DB has no DNS/traffic history tables
Tests
Added/updated:
tests/test_live_snapshot.py
tests/test_lcd_api.py
tests/test_split_databases.py
Run on appliance:
cd /opt/netspecter
./venv/bin/python -m unittest tests.test_split_databases tests.test_live_snapshot tests.test_lcd_api
./venv/bin/python -m py_compile app.py live_packet_collector.py netspecter_db.py netspecter_paths.py netspecter_internet_quality.py netspecter_live_snapshot.py scheduled_speedtest.py
Latest appliance tests passed:
Ran 13 tests
OK
Local checks before pushing main passed:
python -m unittest tests.test_split_databases tests.test_live_snapshot
python -m py_compile app.py live_packet_collector.py netspecter_db.py netspecter_paths.py netspecter_internet_quality.py netspecter_live_snapshot.py scheduled_speedtest.py tests/test_split_databases.py tests/test_live_snapshot.py
Appliance Verification Already Done
After reset, verified:
main DB has no DNS/traffic history tables
dns_import_state  dns_querylog  dns_resolved_ips
collector_heartbeat live_device_speed speed_tests estimated_app_traffic remote_ip_locations traffic_intervals internet_quality remote_traffic_intervals traffic_samples
Recent lock checks were clean:
journalctl -u netspecter-collector --since "10 minutes ago" --no-pager | grep -Ei "database is locked|Packet collector loop took|AdGuard/import loop took|Exception"

journalctl -u netspecter-web --since "10 minutes ago" --no-pager | grep -Ei "database is locked| 500 |Exception|Traceback"
Both returned no output.
Performance Result
Before split:
AdGuard/import loops around 90s earlier
Later around 46-53s before reset/split
After DNS split:
AdGuard/import loop took 7.15s
After traffic split:
No recent slow loop or DB lock logs in 10-minute check
LCD
LCD API fixed:
active_alerts missing now defaults to 0
IDS shows healthy instead of unknown when no alert count in snapshot
LCD does not require physical LCD for tests
Dashboard/UI
Responsive layout updates:
Main dashboard adapts better between ultrawide and square screens
IDS page responsive layout improved
Monitor page still needs possible card layout polish; user screenshot showed cramped monitor cards on ultrawide, but work paused when user clarified services/devices status
Monitoring Notes
User thought devices were offline, but they were on /monitor, not /devices.
Verified:
devices table: 24
Active: 24
live snapshot: 19 known, 10 online
Monitor red cards were Gatus/service checks, not LAN devices.
Nextcloud stable monitor endpoint suggested:
https://192.168.99.4/status.php
It returned:
installed true
maintenance false
needsDbUpgrade false
version 33.0.0.16
Known Local Dirty Files
These were intentionally not touched/committed:
M adguard/AdGuardHome.yaml.example
?? nul
Potential Next Work
Monitor card responsive polish in static/theme.css and static/ui-polish.css.
Optional future security DB split for IDS/security tables if they become large.
Fix appliance local mode-change annoyance where live_packet_collector.py sometimes becomes executable and blocks git pull.
Consider making Gatus monitor checks accept redirects or use stable health endpoints.


6:29 PM


















Approve for me







5.6 TerraExtra High5.6 TerraExtra High5.5Light