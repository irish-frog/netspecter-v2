We worked mainly in C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2, repo https://github.com/irish-frog/netspecter-v2.git, branch main.
Current repo/GitHub state:
Latest pushed commit: 100459d docs: add printable Sophos bracket STL files
main has been pushed to GitHub successfully.
Local untracked files still exist and were intentionally not committed:examples/
nul

Recent important commits:
303d3ad docs: clarify AdGuard GPL terms and add appliance image
8a7b95f docs: update appliance image and bracket fitment note
9e980ad docs: remove NetLic example and refresh appliance image path
100459d docs: add printable Sophos bracket STL files
Legal/GPL/proprietary work done:
Added/updated LICENSE and EULA.md earlier so NetSpecter is proprietary/free-to-use-for-now.
Added/updated THIRD_PARTY_NOTICES.md.
Added full GPL text at licenses/AdGuardHome-GPL-3.0.txt.
Clarified AdGuard Home is separate GPL-3.0 third-party software.
Clarified NetSpecter does not own, modify, relicense, endorse, or partner with AdGuard Home.
Clarified NetSpecter currently downloads/runs the official AdGuard Home upstream installer and does not bundle AdGuard binaries in GitHub.
Added admin-visible legal page/link /third-party-licences, sidebar/footer says Legal & Licences.
install.sh prints AdGuard GPL/project/licence notice before upstream install command.
README/image/hardware work:
README now uses new rack image:docs/images/netspecter-rack-appliance.jpg

Old image path was renamed from docs/images/netspecter-appliance.jpg to force GitHub/browser cache refresh.
README appliance section says brackets are intended for Sophos SX/SG 125 Rev.3 and may fit SX/SG 135 Rev.3 but unconfirmed.
Added printable STL files:hardware/sophos-sx-sg-125-rev3/left-hand-side.stl
hardware/sophos-sx-sg-125-rev3/right-hand-side.stl
hardware/sophos-sx-sg-125-rev3/lcd-back-cover.stl
hardware/sophos-sx-sg-125-rev3/README.md

Hardware README says:intended for Sophos SX/SG 125 Rev.3
SX/SG 135 Rev.3 may fit but unconfirmed
check screw length/clearance/airflow

The 3D STL files were added intentionally after user first said not to, then changed mind.
Example folder:
examples/netlic_client.py originally had live NetLic URL.
It was sanitized, then user asked to remove example folder from Git only.
Commit 9e980ad removed examples/netlic_client.py from Git.
Local examples/ remains untracked.
Tests run:
Focused legal/static test passed after image path changes:.\venv\Scripts\python.exe -m unittest tests.test_security.WebSecurityTests.test_adguard_third_party_notices_are_shipped_and_visible

Earlier focused legal tests passed:test_adguard_third_party_notices_are_shipped_and_visible
test_netspecter_proprietary_license_is_shipped_and_visible
test_adguard_install_notice_is_shown_before_upstream_install
test_sidebar_branding_and_third_party_licence_link_are_present
test_web_service_uses_gunicorn_wsgi_entrypoint

Full suite was not run after the last STL addition.
Appliance/box state from earlier:
Box path: /opt/netspecter
Box was switched from old codex/live-memory-snapshot branch to main.
Latest confirmed box pull before later docs/STL updates was up to 711de27, then later GitHub moved ahead with docs/image/STL commits.
Box settings were almost lost/reset but restored from vault backup:/var/lib/netspecter/vault/backups/NetSpecter-Vault-2026-07-17-182252.nsbackup

Current box config recovered:admin password hash SET
NetLic licence key SET
LCD displays 2
Telegram enabled/token SET
UniFi enabled/password SET
AdGuard URL http://192.168.99.6

AdGuard auth was re-entered and collector became healthy.
Good collector log lines:AdGuard querylog imported rows: ...
UniFi connected clients imported: 25 (24 named)
Internet quality summary: ok - WAN healthy.
nftables traffic counters installed for 192.168.99.0/24 on bridge traffic (br0)

Box had only mode changes:100644 => 100755 on service scripts/python files
advised to leave or use git config core.filemode false.

Thingiverse/Creality:
User published Thingiverse:https://www.thingiverse.com/thing:7384791

Draft text supplied for Thingiverse/Creality:NetSpecter Sophos SX/SG 125 Rev.3 rack brackets and LCD back cover
LCD is BigTreeTech KNOMI V2 or similar 1.28 inch 240x240 GC9A01 round TFT
M3 screws approx 25 mm
PETG recommended, PLA only for test fitting
print settings: 0.20 mm layer, 0.4 nozzle, 4 walls, 5 top/bottom, 40% infill, gyroid/grid/cubic, brim recommended
disclaimer: not affiliated with Sophos or BigTreeTech

Important caution:
User does not want NetLic PHP service repo pushed to GitHub.
Avoid committing nul or local examples/.
If updating box, latest GitHub main is now 100459d; box may need pull if user wants README/STL/legal docs locally, but runtime does not urgently need this docs/hardware-only update.