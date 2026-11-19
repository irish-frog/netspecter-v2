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
