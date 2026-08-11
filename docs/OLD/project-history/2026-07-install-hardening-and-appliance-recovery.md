Handoff Summary
We’ve been hardening irish-frog/netspecter-v2 for clean Debian 13 appliance installs, especially so a non-expert can install and recover it.
Repo State
Local repo: C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2
Main branch has been pushed repeatedly.
Latest pushed commit mentioned: 17937e3 Harden installed checkout update detection
There are unrelated local unstaged doc edits that were intentionally not committed:docs/ADGUARD.md
docs/FIRST-SETUP.md
docs/INSTALL.md
docs/TROUBLESHOOTING.md

Major Changes Already Pushed
Removed experimental AI/API layer from v2.
README clarified for NetSpecter v2 only:Debian 13
run as root, no sudo
install path /opt/netspecter
no experimental third-party AI API shipped

Installer now:creates HTTPS cert automatically with SANs
creates session.key and secret.key
sets /etc/netspecter/config.json to root:netspecter 660
fixes Suricata missing rules placeholder
removes collector 2-core cap

Runtime:Gunicorn workers now use all detected CPU cores
collector has no CPU cap unless old systemd override exists
config normalization no longer crashes services if config is not writable
recoverable error handler now logs full tracebacks

Update checker:prefers installed checkout
checks /opt/netspecter
falls back to origin/<current-branch> and origin/main

Fresh Box
New Debian 13 test box:
Host: Wslunifi
IP: 192.168.1.4
LAN bridge: br0
NICs:enp11s0f0 LAN
enp11s0f1 WAN/no carrier at one point

CPU: Intel Atom C3558, 4 cores
Confirmed:Gunicorn: 1 master + 4 workers
collector: no CPU cap
web, HTTPS, collector were active

AdGuard had install/reinstall issues due leftover /etc/systemd/system/AdGuardHome.service; manual cleanup was advised.
Old Box
Old box:
Host: Netspecter
IP: 192.168.99.6
CPU: Intel Atom C3508, 4 cores
It still had old systemd CPUQuota override:/etc/systemd/system.control/netspecter-collector.service.d/50-CPUQuota.conf
CPUQuota=200.00%

Suggested fix:
systemctl revert netspecter-collector
systemctl daemon-reload
systemctl restart netspecter-collector
Current User Issue Before Handoff
User saw in UI:
Update Progress
Version: Check Failed
Git upstream not configured.
But on old box:
cd /opt/netspecter
git remote -v
git branch --show-current
git status
showed:
origin https://github.com/irish-frog/netspecter-v2.git
main
Your branch is up to date with 'origin/main'.
working tree clean
A code fix was pushed to update checker. User was told to run:
cd /opt/netspecter
git pull origin main
bash ./install.sh
systemctl restart netspecter-web netspecter-https
curl -k "https://127.0.0.1:9443/api/update-status?force=1&fetch=1"
Then refresh:
https://192.168.99.6:9443/health?check=1#updateProgress
Useful Verification Commands
systemctl status netspecter-web netspecter-https netspecter-collector --no-pager -l
curl -I http://127.0.0.1:5050/
curl -k -I https://127.0.0.1:9443/
journalctl -u netspecter-web -n 160 --no-pager -l
CPU/core check:
lscpu | egrep 'Model name|CPU\(s\)|Thread|Core|Socket'
nproc
systemctl cat netspecter-collector | grep CPUQuota || echo "Collector: no CPU cap"
pgrep -af gunicorn
Expected Gunicorn on 4-core:
1 master
4 workers
Important Installer/Noob-Install Concerns Still Worth Reviewing
AdGuard reinstall should probably automatically remove stale /etc/systemd/system/AdGuardHome.service when /opt/AdGuardHome is missing.
A proper install-check.sh would be useful:DNS
bridge
web
HTTPS
collector
Suricata
AdGuard
disk/log retention
update checker

Some docs are dirty locally and may need review before commit.
Tone/Constraints From User
User runs as root; no sudo.
User wants “noob can install with no issue.”
User prefers step-by-step commands.
API/AI integration should remain off/removed from v2 for now.