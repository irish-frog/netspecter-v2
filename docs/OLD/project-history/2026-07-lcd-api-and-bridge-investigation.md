Hand-Off Summary
NetSpecter v2 repo is at:
C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2
Latest pushed LCD-related commit seen locally:
3baeabc Harden LCD summary backend
Local uncommitted items not related to LCD:
M adguard/AdGuardHome.yaml.example
?? nul
Do not blindly remove/revert those unless confirmed.
LCD Work Done
Backend foundation is implemented and pushed.
Added:
GET /api/lcd/summary
Served through existing HTTPS proxy:
https://<netspecter-host>:9443/api/lcd/summary
Auth:
Authorization: Bearer <lcd_token>
Important: the header must include Bearer.
LCD tokens:
Created from Settings → LCD Displays
One token per named display
Token hash stored only
Full token shown only once
Token suffix shown after creation
Can regenerate, revoke, remove
Does not grant admin/session/control access
Endpoint returns compact JSON including:
generated_at
status
internet_status
devices_online
active_alerts
live download_mbps / upload_mbps
traffic_history
total_traffic_today_gb
ping/jitter/loss/DNS
service states: DNS, IDS, collector, database, bridge
system CPU/RAM/disk/uptime
top talker
top application
devices known/online/new
latest completed speed test
Verified working command on appliance:
curl -sk -H "Authorization: Bearer ns_lcd_vYDYahUI2SLEBvI9k0-20WkPXgUNx38ldFCiqifeuIs" https://192.168.99.6:9443/api/lcd/summary
Example result showed valid JSON with internet_status: online, live Mbps, system stats, services healthy.
LCD Outstanding
Firmware/ESP32/KNOMI side is not built yet.
Backend is ready, but the screen still needs to:
Poll /api/lcd/summary
Use Bearer auth
Apply fixed status/colour rules
Display service states independently
Badge priority rules agreed:
Grey CONNECTING if no successful response yet
Amber STALE if cached/old data because NetSpecter cannot be reached
Red INTERNET OFFLINE if internet_status = offline
Red SERVICE DOWN if DNS/IDS/collector/database/bridge down
Amber WATCH if degraded/warning/watch
Red ALERT if status alert or active critical IDS incident
Green ONLINE only when internet online, services healthy, no active alerts
Service colours:
healthy = green
warning = amber
down = red
unknown = grey
LCD Load Assessment
LCD polling was seen roughly every 6–7 seconds from:
192.168.99.157
Conclusion: LCD endpoint is too light to explain the outage/crash. It uses cached/collector data and no speed tests/reports.
Speed Test Note
User saw Internal Server Error at:
/speed-test
But the manual speed test completed and appeared on the page. Likely stale login/session/CSRF after restart. If it recurs, check:
journalctl -u netspecter-web --since "10 minutes ago" --no-pager -l | grep -E 'POST /speed-test|500|Traceback|Exception|Invalid CSRF|login|speed-test'
DNS Notes
DNS latency history mostly averaged 40–60 ms with spikes. Not catastrophic, but could be better.
AdGuard cache discussion:
User has 16 GB RAM
256 MB cache is safe for this appliance
Value:
268435456
This is RAM, not disk. It should not cause crashes. It may smooth DNS latency but will not fix bridge/network topology problems.
Recommended not to enable optimistic caching immediately; first increase cache and observe.
Crash / Network Outage Finding
The box stopped responding and later rebooted.
Evidence:
system boot 2026-07-16 20:49
previous boot ended 2026-07-16 20:34
Root disk is internal SSD:
/ on /dev/sda1 ext4
sda TS64GMTS400SD
Not USB boot.
Previous boot kernel logs had serious bridge warnings:
br0: received packet on enp11s0f0 with own address as source address
br0: received packet on enp11s0f1 with own address as source address
net_ratelimit: 35918 callbacks suppressed
ixgbe ... enp11s0f1: NIC Link is Down
That strongly suggests a Layer 2 loop/bridge topology issue.
Current bridge state:
enp11s0f0 master br0 state forwarding
enp11s0f1 master br0 state forwarding
br0 IP: 192.168.99.6/24
VLAN: both ports untagged VLAN 1
STP: 0
So both physical ports are bridged and forwarding with STP off.
This is safe only if NetSpecter is truly inline:
router/firewall -> NetSpecter port A -> NetSpecter port B -> switch/LAN
It is dangerous if both ports connect back into the same switch/LAN fabric.
Recommended Bridge Follow-Up
Immediate live protective test:
ip link set br0 type bridge stp_state 1
cat /sys/class/net/br0/bridge/stp_state
bridge link
May cause brief reconvergence pause.
To make STP persistent, first identify network config source:
grep -R "br0\|enp11s0f0\|enp11s0f1\|stp" /etc/network /etc/systemd/network /etc/netplan 2>/dev/null
Need inspect result before editing. Do not blindly patch networking.
Other Performance Context
Collector CPU had been high during previous work. Several commits were pushed to reduce DB locks and CPU:
0b0ffee Cap collector CPU usage
4b57261 Refresh dashboard quality metrics safely
88b3f44 Set default history retention windows
Earlier performance commits included batching and reduced DB lock pressure.
User cares strongly that traffic/reporting accuracy is preserved. Avoid changing collection semantics without explaining accuracy impact.
Preferred Appliance Commands
User runs as root and said do not use sudo.
Restart command they prefer:
systemctl restart netspecter-web netspecter-collector netspecter-https
Pull/update:
cd /opt/netspecter
git pull origin main
systemctl restart netspecter-web netspecter-collector netspecter-https
Tone/User Preferences
User wants direct practical guidance, commands to paste, and clear risk calls. They are worried about downtime. Be concise but firm when topology is dangerous.


6:29 PM


















Approve for me







5.6 TerraExtra High5.6 TerraExtra High5.5Light