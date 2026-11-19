# Domain catalogue update: November 2026

The measured-flow classifier now has product-specific domain signatures for Instagram, Facebook, TikTok, OneDrive/SharePoint, Teams, Outlook, Microsoft 365, Microsoft authentication, OpenAI static assets, Autodesk Fusion and Life360. Category-wide domain lists are not copied to every application. `*-my.sharepoint.com` is more specific than the SharePoint domain, so personal OneDrive sites are kept distinct.

A Microsoft network endpoint allowlist is supporting category evidence, not proof of a particular app. Imported endpoint categories no longer short-circuit a stronger product signature. Explicit operator domain mappings keep their named application and take precedence.

Shared Meta `fbcdn.net`, generic Google APIs/content, opaque AWS/CDN tenant names, general iCloud gateways, shared Autodesk APIs and broad vendor names remain unknown without stronger evidence. A product domain can show use of that service or embedded assets; it does not prove a user opened its foreground app or reveal page contents.

Primary supporting sources reviewed:

- Microsoft 365 service endpoint documentation: https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges
- Autodesk Fusion domain requirements: https://www.autodesk.com/support/technical/article/caas/sfdcarticles/sfdcarticles/Fusion-360-cannot-access-the-services-through-proxy.html
- OpenAI network requirements and static-asset domain: https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps
- Meta Instagram media documentation: https://developers.facebook.com/docs/instagram-platform/reference/instagram-media/

## Existing unknown measurements

`scripts/reclassify-unrecognized.py --expected-hostname HOSTNAME` previews bounded relabeling. Add `--apply` only to update labels. Run with the installed venv Python as root; the command drops to the existing netspecter service identity before opening SQLite, avoiding root-owned database companions.

Records carrying `unrecognized_hostname` and stored TLS SNI can be refreshed directly. DNS-backed records additionally require revalidation against the read-only attached DNS database: same client IP, destination, connection-start time, valid TTL and agreement of every candidate application. DNS stays medium confidence; contradictory SNI/DNS, missing or expired evidence, already attributed records and shared/unknown hostnames are left alone. Current internet/internal scope is checked again. Byte counts, flow timestamps, identities, hostnames and measured evidence are preserved. Each transaction covers at most 200 candidate rows, with a short pause between write batches. There is no history reset or DNS change. `--tls-only` retains the previous narrow mode. If `limit_reached` is true, resume with `--after-id` using the reported `next_id`; a bounded scan is not proof that the entire history was checked.

## CI fixture correction

The shared web-config regression test exposed incorrect fixture permissions: root-created config ownership did not match the installer. The fixture now uses root:netspecter ownership, directory 0750 and config 0660 before web normalization. Runtime code is not weakened to accommodate the test. This addresses the failed bridge run 44452978588; the earlier installed owner appliance was independently confirmed collecting and attributing.

The full installer also stops old web/proxy workers before activating new configuration keys. Older workers keep their old supported-key list in memory and could otherwise remove newly introduced flags before their restart. The failure trap resumes whichever core services were previously active. AdGuard is not stopped.


See DNS-ATTRIBUTION-REFRESH.md for TTL fixes, new product domains, validation and remaining limits.
