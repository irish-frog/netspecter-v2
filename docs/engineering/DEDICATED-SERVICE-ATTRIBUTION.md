# Dedicated service endpoint attribution

Owner-only rollout; client Wslunifi and inaccessible third unit remain untouched. Shared rules reach other units only when they later update.

## Scope and evidence

Add narrow catalogue rules for AnyDesk transport relays, Google Safe Browsing, Apple WeatherKit, Home Assistant connectivity checks, Firebase Remote Config, N-able software-distribution service and N-able Take Control. These identify the destination service, including background API traffic. WeatherKit does not identify the Apple Weather app, Firebase does not identify the app using its SDK, and a Take Control endpoint does not prove an interactive remote-control session.

Rules use exact endpoint names or documented product-specific hostname families. No IP/ASN/provider/port-only inference, client identity, newest-DNS shortcut, weakened ambiguity guard or extended TTL. Generic Google APIs, Android/Assistant endpoints without a specific documented role, shared Cloudflare challenges/CDNs, generic storage and opaque hostnames remain unknown. No QUIC inspection or DNS/filtering/firewall changes. Existing exact connection TLS and client/destination/time-valid unanimous DNS matching remain unchanged. Historical relabeling requires stored SNI or revalidated DNS, keeps evidence/confidence and never rewrites byte counts or times.

Vendor references:

- AnyDesk transport family `*.net.anydesk.com`: https://support.anydesk.com/firewall
- Safe Browsing endpoint: https://developers.google.com/safe-browsing/reference/rest
- WeatherKit API endpoint: https://developer.apple.com/documentation/weatherkitrestapi/request-authentication-for-weatherkit-rest-api
- Home Assistant connectivity hostname: https://contributors.home-assistant.io/os/operating-system/networking/
- Firebase Remote Config endpoint: https://firebase.google.com/docs/reference/remote-config/rest/v1/projects.namespaces/getRemoteConfig
- N-able software distribution, modern/remote endpoint roles: https://documentation.n-able.com/N-central/userguide/Content/ReleaseDocs/Install_Config/FirewallRequirements.htm

Tests exercise the real catalogue with dedicated endpoints, spoofed suffixes, unrelated vendor hosts and shared Google/Cloudflare exclusions. Existing flow tests cover exact tuples, DNS conflicts, other clients, expiry, internal traffic, read-only DNS attachment, immutable measurement bytes and repeat-safe historical relabeling. No production reset is part of deployment. Validate live results with bounded preview/apply and record counts/bytes; do not infer a coverage gain from changing traffic windows.

Adversarial review found the proposed ncoddigit wildcard accepted arbitrary characters/extra labels after its first digit. That rule was removed entirely, rather than inferring a numeric hostname grammar from one observed name. Tests retain ncoddigit and malformed/extra-label examples as unknowns. The N-central hosted prefix alone is not used as primary application evidence.


## Verified rollout — 19 November 2026, 15:18 SAST

Owner runtime92accaa5 installed via normal updater; no reset. Local full suite436passed/5Linux-onlyskipped; final focused82passed after removing the overbroad N-central pattern. Linux feature44531138857 passed441Python/23Rust tests and real bridge/systemd/TLS/measured-flow integration, binary provenance and offline bootstrap. Main history-reset safety44531804891 passed. Duplicate main Linux44531804922 was still running at this observation.

Live bounded preview scanned1464unknown-hostname rows, found81eligible labels/221,690bytes; apply scanned1474and updated exactly81/221,690bytes. Breakdown:24TLS-SNI flows/136,733bytes;57client-DNS flows/84,957bytes. Service labels cover Firebase Remote Config, WeatherKit, Home Assistant Connectivity, N-able software distribution/Take Control, Safe Browsing and AnyDesk. Repeat full bounded preview scanned1410rows with0candidates and no cap hit. No measurements deleted or settings changed; byte/time preservation is covered by actual SQL regressions. Do not claim a before/after coverage percentage from moving windows.

All six services active, passive verifierready, fresh collector heartbeatOK, measured flows6297and TLS/flow collection continuing. Live generated reportHTTP200in0.384s with76.2%primary coverage at that instant. Updater check under actual service usercurrent=latest=92accaa, available=false before final docs-only recording. AdGuardPID830/NRestarts0unchanged; loopbackUDP/LANTCP DNS succeeded. Client and third unit untouched. Temporary fixed-action owner maintenance access retains its existing18:23SASTexpiry. Generic/shared hosts, missing evidence, encrypted/QUIC unknowns and ambiguous DNS remain unknown rather than guessed.


## Package and download endpoints — 19 November 2026 evening

New exact rules identify GitHub Packages (`ghcr.io`, `pkg-containers.githubusercontent.com`), GitHub Releases (`release-assets.githubusercontent.com`) and Adobe Acrobat Downloads (`ardownload.adobe.com`, `ardownload2.adobe.com`, `ardownload3.adobe.com`, `armdl.adobe.com`) under Downloads. These describe the serving service, not the package publisher, container contents, executing application or proof that an update installed. No wildcard GitHub/Adobe rule or generic CDN attribution is added.

Vendor endpoint references:

- https://docs.github.com/en/actions/reference/runners/self-hosted-runners documents package/container and release-asset endpoints separately.
- https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/endpoints.html documents these Acrobat updater endpoints.

Tests use real catalogue classification and flow persistence: agreeing package DNS names can label a measured connection; an additional unrecognized shared address candidate still makes it ambiguous; exact Adobe SNI labels only the matching tuple. Byte totals stay unchanged. Exact rules reject nested names, suffix spoofing, unrelated GitHub/Adobe hosts and shared CDN names. DNS settings, matching windows, TTL handling and ambiguity rules are unchanged. No collected history is reset. Deployment and live relabel results must be recorded separately; catalogue potential is not an observed coverage gain.

Review removed `armmf.adobe.com`: Adobe also uses that hostname for onboarding/SMS configuration, so its hostname alone does not establish download activity. It remains unknown rather than receiving the download label.
