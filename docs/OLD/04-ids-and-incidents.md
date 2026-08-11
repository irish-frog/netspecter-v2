Handoff Summary
Repo:
C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2
Branch:
main
Remote:
https://github.com/irish-frog/netspecter-v2.git
Latest pushed commits:
f929887 Fix Suricata informational alert severity mapping
30bddbb Classify Steam IDS user-agent as informational
Current state:
GitHub is updated.
Working tree was clean after push, except Git warning that .pytest_cache/ cannot be opened due permissions.
Key IDS severity changes:
ET INFO external-IP lookup alerts are Informational.
External-IP lookup alerts are labeled External IP discovery.
.biz and .management DNS observations are Low, not High/Critical.
Truncated packet decoder alerts are Diagnostic/hidden by default.
ET USER_AGENTS Steam HTTP Client User-Agent is Informational.
Steam override stores application=Steam, category=Gaming.
ET USER_AGENTS* defaults to Informational unless a future explicit malicious override exists.
Informational/default-suppressed alerts stay searchable in expanded/raw IDS history but do not show in High/Critical totals and do not notify by default.
Suricata policy/privacy categories no longer drive Critical classification on their own.
Data/schema changes:
ids_events now has:first_seen
last_seen
alert_count
application

Duplicate alert aggregation uses signature/signature ID, source, destination/domain, protocol, and configurable time bucket.
Existing alerts are reclassified by collector import/retention and by scripts/post-update-maintenance.sh.
Files changed in the latest Steam commit:
netspecter_ids.py
netspecter_db.py
tests/test_ids_eve.py
Validation run:
python -m pytest tests/test_ids_eve.py tests/test_ids_notifications.py -q
Result:
22 passed
Compile check passed:
python -m py_compile netspecter_ids.py netspecter_db.py live_packet_collector.py app.py tests/test_ids_eve.py tests/test_ids_notifications.py
Box update command given to user:
cd /opt/netspecter
git pull
./scripts/post-update-maintenance.sh
systemctl restart netspecter-web netspecter-collector
Important note:
The changes apply to new installs because the defaults are in netspecter_ids.py and the schema is in netspecter_db.py. Existing installs get migrated/reclassified by post-update maintenance.


6:29 PM


















Approve for me







5.6 TerraExtra High5.6 TerraExtra High5.5Light