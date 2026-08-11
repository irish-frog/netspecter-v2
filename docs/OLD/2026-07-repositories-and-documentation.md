Handoff Summary
We have been working on two GitHub repos under:
C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website
Main repos:
netspecter-v2
netspecter
NetSpecter v2
Repo:
https://github.com/irish-frog/netspecter-v2
Branch:
main
Current pushed state includes:
Security hardening
App helper split
IDS alert/incident status work
MaxMind GeoLite2 local database support
Online GeoIP fallback removed
README/docs restructure
Updated logo assets
Main branch combined from earlier working branch
Important pushed commits:
0dfb64b - logo assets update
1ac89bf - README/docs restructure
f5becb8 - README tagline tightened
4b2b1c2 - removed small-network positioning
ea77984 - added original NetSpecter guidance
README/docs:
README.md is now short and landing-page style.
Detailed docs moved/created under docs/.
Includes Telegram and MaxMind setup guides.
v2 README points users with older/simpler hardware to original NetSpecter:
https://github.com/irish-frog/netspecter
Known local issue:
Untracked weird Windows file nul exists in netspecter-v2.
It was not committed and is not on GitHub.
Test note:
Full test suite failed before/after docs work due to existing/stale tests, not README changes.
Failures included:ids_events missing in temp test DB for test_ids_notifications
Windows temp SQLite cleanup lock
stale test_security assertions looking for old code strings after refactor
system Python missing Flask unless using venv

Original NetSpecter
Repo:
https://github.com/irish-frog/netspecter
Branch:
main
This repo was freshly cloned locally into:
C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter
Git identity had to be set locally:
git config user.name "irish-frog"
git config user.email "bbm@it-inyanga.co.za"
README was rewritten in the same clean style as v2, keeping the old logo:
static/netspecter-logo-sidebar.png
Pushed commits:
d7e8dbf - Rewrite README for original NetSpecter
6b32a4d - Clarify original NetSpecter hardware guidance
d564cdf - Trim original README integration claims
Current README intent:
Original NetSpecter is positioned for:home networks
very small networks
older hardware
simpler deployments

It points to v2 for:better hardware
expanded monitoring
IDS incident workflows
MaxMind GeoLite2
backup/restore tooling
telemetry
broader health views

Important correction:
User clarified v1 does not really include Gatus, Telegram, or Beszel as features.
I checked the code:There are some config/routes/pages and opt-in Gatus installer bits in code.
But README claims were trimmed to avoid overselling.

Current README feature claims were reduced to:UniFi
SNMP
MQTT
Suricata

Removed Gatus, Beszel, Telegram from v1 README feature/integration claims.
v1 does not claim backup.
v2 still mentions backup/restore as a v2 feature.
Potential next cleanup:
If continuing in original netspecter, re-open README.md and verify every claimed feature against code once more.
User’s last concern was: “check what the code says and make sure you not adding in whats not there”.
I did scan code with rg, found v1 actually has some old Gatus/Beszel/Telegram code paths, but because user says they aren’t part of v1, README now omits them.
Current pushed original repo head:
d564cdf Trim original README integration claims
Useful Commands
For v2:
cd "C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2"
git status --short --branch
git log --oneline -n 5
For original:
cd "C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter"
git status --short --branch
git log --oneline -n 5
On appliance update for v2:
cd /opt/netspecter
git checkout main
git pull
python3 -m py_compile app.py live_packet_collector.py monitor_sweeper.py netspecter_config.py netspecter_ids.py netspecter_ui_helpers.py
systemctl restart netspecter-web
systemctl restart netspecter-collector
systemctl restart netspecter-monitor
User Preferences/Context
User runs appliance commands as root; no sudo.
User wants docs honest, not overselling.
User prefers GitHub pushed changes.
User is actively comparing v1 vs v2:v1: older hardware / very small networks / simpler.
v2: newer feature-rich appliance for better hardware.

Avoid claiming features unless code confirms or user confirms.