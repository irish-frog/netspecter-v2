Handoff Summary
We are working on NetSpecter v2 in:
C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2
Remote deploy path:
/opt/netspecter
GitHub remote:
https://github.com/irish-frog/netspecter-v2.git
Current pushed branch:
main
Latest pushed commit:
fab80ca Classify reverse DNS as infrastructure
Main Goal
Improve NetSpecter traffic classification and scalability so unknown traffic decreases over time without expensive UI/API/report lookups, and so the appliance can support roughly:
50 users + 50 mobiles + 50 desk phones + 150-250 active endpoints
without CPU/HDD degradation over 30-90 days.
Major Decisions
No expensive reverse DNS during UI/API/report rendering.
Correlation/classification happens during ingestion or scheduled background processing.
Keep RAM usage acceptable, but prioritize low CPU and HDD churn.
Suricata should help classify unknown traffic.
UniFi import is useful but not critical; import every ~10 minutes is fine.
Do not rely on AdGuard client import; UniFi is primary for device identity.
Remove GeoIP/map path because map was removed.
Reverse DNS PTR domains are infrastructure housekeeping, not user browsing.
Important User-Specific Classifications
e7a37f2d.hvcdn.to is the user’s Plex service / HVCDN and should classify as video/streaming.
BitTorrent DHT on “moms” device is expected.
AnyDesk use is expected.
Reverse lookup domains:*.in-addr.arpa
*.ip6.arpa
classify as DNS reverse lookup / infrastructure and are excluded from user/application/report views.

Pushed Work
Recent pushed commits include:
7abe315 Make incident building incremental
Incident builder uses checkpoints.
Adds incident indexes and timing logs.
Avoids walking old IDS history.

e5c2f55 Instrument final collector bottlenecks
Adds detailed traffic counter batch timing:
prepare, live_speed_write, device_write, traffic_fact_write, estimated_write, destination_write.
Incident builder logs:
rows_selected, incidents_created, incidents_updated, incidents_closed, checkpoint_start, checkpoint_end, sql_time, txn_time, commit_time.

f3156ec Throttle traffic device inventory writes
Keeps live speed and traffic facts continuous.
Throttles devices table writes to once per IP per 60s unless metadata changes.
Adds traffic_device_update_interval_seconds.

fab80ca Classify reverse DNS as infrastructure
Adds central PTR detection.
Labels reverse DNS as DNS Reverse Lookup.
Rich classification returns Network Infrastructure, usage group Infrastructure, tag System Services.
Excludes PTR domains from top apps, device domain lists, application detail, blocked-domain views, reporting domain summaries.
Skips estimated app target attribution for PTR domains.

Performance Findings
Before fixes:
Threat intel: ~115s+
Anomaly: ~152s+
Destination classification: ~122s
Suricata metadata classification: 8-9s
Incident builder: 17-18s
Traffic batch: 12-15s
After fixes observed:
Threat correlation: ~2.7s
Anomaly batch: ~2.1s
Destination classification: ~0.015-0.032s
Suricata metadata classification with cache: ~0.5-1.2s
Traffic batch instrumentation showed device_write was the culprit:Example: device_write=2.135s, total=2.170s
Fixed by throttling device inventory writes.

Need verify after latest deploy:
device_writes should often be 0.
device_write should drop near 0.000s.
traffic_counter_batch should usually be under 1s.
Incident builder should use new log format and not scan history.
Deployment Commands
Use on appliance:
cd /opt/netspecter
git pull origin main
/opt/netspecter/venv/bin/python -m py_compile app.py live_packet_collector.py netspecter_db.py netspecter_config.py netspecter_incidents.py services/application_classification_service.py services/classification_resolver_service.py services/suricata_classification_service.py services/reporting_service.py
systemctl restart netspecter-collector
systemctl restart netspecter-web
systemctl status netspecter-collector --no-pager
systemctl status netspecter-web --no-pager
Useful log check:
journalctl -u netspecter-collector -n 220 -l --no-pager | grep -E "Incident build detail|Incident correlation detail|Traffic counter batch detail|traffic_counter_batch|Suricata metadata classification|database is locked"
Fresh Install / Update Readiness
User asked if this is ready for new deployments and updates.
Answer given:
Yes, code side is ready for fresh installs and updates.
Defaults are in netspecter_config.py and config.example.json.
Schema/index/checkpoint creation uses CREATE IF NOT EXISTS style.
Existing DB should migrate forward on app init/restart.
Fresh install still needs system requirements:
Python venv and requirements installed.
systemd services installed.
/etc/netspecter/config.json created.
/var/lib/netspecter exists and is writable by service user.
Suricata installed/configured if IDS is used.
nftables available.
AdGuard URL/user/pass configured if DNS import is used.
UniFi configured only if wanted.
Permissions
Desired permissions:
/etc/netspecter                 root:netspecter 750
/etc/netspecter/config.json     root:netspecter 640
/var/lib/netspecter             netspecter:netspecter 750
/var/lib/netspecter/*.db        netspecter:netspecter 660
Validation commands:
systemctl show netspecter-collector -p User -p Group
namei -l /etc/netspecter/config.json
ls -ld /etc/netspecter /var/lib/netspecter
ls -l /var/lib/netspecter/*.db
Appliance Paths
Important actual DB paths are under:
/var/lib/netspecter/netspecter.db
/var/lib/netspecter/netspecter_dns.db
/var/lib/netspecter/netspecter_traffic.db
Earlier checks against /opt/netspecter/*.db failed because those are not the active DB paths.
Known Dirty Local Files
Before latest commits, there were unrelated local dirty files not staged:
docs/ADGUARD.md
docs/FIRST-SETUP.md
docs/INSTALL.md
docs/TROUBLESHOOTING.md
netspecter_ids.py
Do not stage/revert them unless explicitly asked.
Things To Watch Next
Deploy latest main.
Confirm git log -1 --oneline shows fab80ca.
Watch collector logs.
If incident builder still slow, investigate the candidate query with EXPLAIN QUERY PLAN.
If traffic batch still slow, use the new sub-timers to target the exact SQL step.
Once stable, reduce noisy performance instrumentation if desired.


6:07 PM


















Approve for me







5.6 TerraExtra High5.6 TerraExtra High5.5Light