Handoff Summary
Repo: irish-frog/netspecter-v2
Local Windows path: C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2
Appliance live path: /opt/netspecter
Branch: main
Current issue: user still sees high Unclassified traffic in reports. Important discovery: report GB attribution comes mostly from estimated_app_traffic, which is produced by the collector’s monitored DNS answer counters, not just by config/application_categories.json.
Recent pushed commits:
78ae65c classification report coverage fix
fec954a cached classification + unknown review
df47319, f6afb2e traffic rollup fixes
15c5e8b export filename fix
71f8a98, a748989 common signatures
06178f6 device identity hints
ea6bdfb, e5d38c7 unclassified device table fixes
0f1fed4 more mobile/CDN JSON signatures
54bc711 fix built-in signatures being disabled by DB signatures
72964c3 collector now monitors common CDN/mobile domains for byte attribution
Key files changed:
config/application_categories.json
services/application_signature_service.py
services/application_classification_service.py
live_packet_collector.py
services/reporting_service.py
services/report_context_service.py
app.py
tests/test_application_classification.py
Important finding:
Changing JSON signatures improves classification lookup, but old unknown GB will not magically change unless matching bytes were already in estimated_app_traffic. Commit 72964c3 makes new traffic for domains like hvcdn.to, icloud.com, whatsapp.net, facebook.net, googleusercontent.com, gvt1.com, Akamai/Cloudflare, etc. become monitored byte-attribution targets.
Correct appliance update command:
cd /opt/netspecter
git fetch origin
git reset --hard origin/main
sqlite3 /var/lib/netspecter/netspecter_traffic.db "delete from classification_cache;"
systemctl restart netspecter-web
systemctl restart netspecter-collector
After update, wait for new DNS answers and traffic. Then verify new attribution:
sqlite3 /var/lib/netspecter/netspecter_traffic.db "
select category, round(sum(total_mb),2)
from estimated_app_traffic
where day >= date('now','localtime')
group by category
order by sum(total_mb) desc
limit 30;
"
If still unchanged, check collector logs and whether new monitored targets are being created:
journalctl -u netspecter-collector -n 100 --no-pager
Known local repo state:
User has unrelated unstaged doc edits:
docs/ADGUARD.md
docs/FIRST-SETUP.md
docs/INSTALL.md
docs/TROUBLESHOOTING.md
Do not stage/revert those unless explicitly asked.


6:29 PM


















Approve for me







5.6 TerraExtra High5.6 TerraExtra High5.5Light