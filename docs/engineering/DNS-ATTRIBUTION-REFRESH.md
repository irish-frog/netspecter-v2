# Hostname and DNS attribution refresh — 19 November 2026

## Problem and decision

The first historical refresh handled only exact TLS SNI. Existing DNS-backed unknowns therefore retained old labels even when their hostname now matches the catalogue. The refresh now reads the split DNS database in read-only mode and revalidates client IP, destination IP, connection-start time and expiry. Every active DNS candidate must identify the same application; selecting the latest shared-IP name, ignoring an unknown candidate, or widening the time window is not allowed. An existing exact SNI result takes precedence. DNS-backed refreshes retain their hostname/evidence and medium confidence. Measurements and identities are immutable.

The parser previously replaced TTL=0 with the 900-second default, and ignored CNAME lifetimes. Both can retain stale candidates and create false ambiguity. Zero/malformed TTLs now provide no reusable evidence; CNAME chains and duplicate addresses use their shortest lifetime. Invalid timestamp/client/address records and IP-type mismatches are rejected. Blocked DNS responses are not used as resolution evidence. Expiry is exclusive, and case/trailing-dot duplicates normalize to one name. No AdGuard settings, resolver behavior, filtering or firewall rules are changed.

An old malformed lifetime already stored by an earlier parser cannot be reconstructed from the resolution table. The refresh does not extend, rewrite or manufacture historical DNS answers; revalidation uses stored validity. Fresh imports use corrected lifetime semantics. Retention and the primary-coverage denominator are unchanged.

## Catalogue scope

Add dedicated Teams static-content domains, X/Twitter media, Pinterest, Roblox, selected Apple software-update endpoints, Microsoft 365 Copilot and OpenAI uploaded-content hosts. Existing TikTok, Windows Update, Instagram and other rules also become available to revalidated historical DNS records. Shared Cloudflare challenges, generic Google/AWS/Fastly hosts, Meta shared CDN, ByteDance shared images, broad Apple/iCloud services and opaque site names remain unknown. Product endpoints identify service use, including embedded assets, not proof of a foreground app.

Supporting vendor references: Microsoft 365 endpoint/unified-domain documentation (https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges), X API media data dictionary (https://docs.x.com/x-api/fundamentals/data-dictionary), Pinterest API (https://developers.pinterest.com/docs/api/v5/pins-get/), Roblox developer-domain examples (https://devforum.roblox.com/t/ssl-configuration-error-setuprobloxcom/4509644), Apple enterprise network guidance (https://support.apple.com/en-us/101555), OpenAI network guidance (https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps). Use narrow dedicated domains; these references do not justify treating every provider endpoint as an application.

## Bounds, rollout and checks

The CLI previews by default, drops root to the existing service user, attaches DNS mode=ro and updates at most 200 flow labels per transaction. A per-invocation 2,048-host cache avoids repeated catalogue lookups. Each invocation scans 20,000 rows by default, supports an explicit maximum of 100,000, and exposes a resume cursor. A partial scan must be reported as partial. --tls-only disables DNS refresh. No database reset or DNS restart is part of this change.

Rules and matching code are shared through main and become available on each appliance when it updates. The owner alone is authorized for this rollout. Do not contact/update/restart/reset the held client; the third unit remains untouched. Private hostname exports stay outside Git. Temporary owner privilege was previously revoked; live installation requires the reviewed owner-only helper to be re-enabled by the operator after tests pass.

Validation: TTL-zero/malformed/expiry boundaries, shortest CNAME/duplicate lifetimes, IPv6 canonicalization, invalid observations, strict DNS client/time/conflict checks, medium-confidence history relabeling, immutable bytes/evidence and read-only DNS attachment. Linux bridge integration exercises the actual root CLI with a DNS-backed stored measurement, as well as SNI, internal-traffic exclusion, fresh services and reset safety.
