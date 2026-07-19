# Third-Party Notices

This document lists third-party software that NetSpecter can install, run, or
integrate with. NetSpecter is proprietary software; see `LICENSE`. NetSpecter's
proprietary restrictions do not apply to separately identified third-party
software, and this notice does not state or imply that NetSpecter itself is
licensed under the GPL.

## AdGuard Home

| Field | Details |
|---|---|
| Project | AdGuard Home |
| Upstream source | https://github.com/AdguardTeam/AdGuardHome |
| Licence | GNU General Public License v3.0 |
| Licence text | https://github.com/AdguardTeam/AdGuardHome/blob/master/LICENSE.txt |
| Relationship | Separate local DNS service used by NetSpecter for DNS filtering and DNS analytics. |

NetSpecter does not own AdGuard Home, does not modify AdGuard Home, does not
relicense AdGuard Home, does not endorse AdGuard Home, and does not have a
partnership with AdGuard. AdGuard Home remains a separate, independent
third-party component.

NetSpecter currently downloads and runs the official AdGuard Home upstream
installer during local setup. NetSpecter does not currently bundle an AdGuard
Home binary in this GitHub repository.

## What GPL-3.0 means for AdGuard Home

AdGuard Home may be used free of charge, including as part of a NetSpecter
appliance. It may be modified for private use and distributed, including in a
paid product.

If NetSpecter distributes a copy of AdGuard Home, whether modified or
unmodified, NetSpecter must:

- retain AdGuard Home copyright notices and the GPL-3.0 licence;
- clearly identify AdGuard Home as separate third-party software;
- provide the corresponding source code for the exact AdGuard Home version
  distributed, including any changes made to AdGuard Home itself;
- licence modifications to AdGuard Home under GPL-3.0;
- not add restrictions that take away GPL rights for the AdGuard Home component.

GPL-3.0 does not automatically make NetSpecter GPL merely because NetSpecter
communicates with AdGuard Home through its local API, DNS logs, or a separate
local service. NetSpecter must keep the components separate and must not copy
AdGuard Home code into NetSpecter.

## Distribution Scenarios

### Bundled AdGuard Home Binary

If a NetSpecter appliance image, installer, archive, ISO, USB image, VM image,
or release includes an AdGuard Home binary, that distribution must include:

- `THIRD_PARTY_NOTICES.md`;
- `licenses/AdGuardHome-GPL-3.0.txt`;
- the exact AdGuard Home version/build;
- a working URL to source for that exact version;
- any NetSpecter-specific AdGuard patches;
- any scripts needed to build/install the included AdGuard component.

Use this format for each bundled AdGuard Home build:

```text
Included version: [ADGUARD_HOME_VERSION]
Upstream release/source: [ADGUARD_HOME_SOURCE_URL]
NetSpecter patches: None / [PATCH_URL]
Build or installation scripts: [SCRIPT_URL]
```

Do not copy AdGuard Home source into the NetSpecter repository unless it is
genuinely necessary. Use a version-pinned upstream release/source URL instead.

### Upstream Download During Setup

If NetSpecter downloads AdGuard Home from the official upstream project during
setup and does not bundle the AdGuard Home binary, the setup UI/docs must show
the official project and licence links:

```text
Project and source: https://github.com/AdguardTeam/AdGuardHome
Licence: https://github.com/AdguardTeam/AdGuardHome/blob/master/LICENSE.txt
```

## Release Packaging Checklist

Before publishing a NetSpecter release that bundles AdGuard Home:

- update the AdGuard Home version;
- verify the exact upstream source URL for that version/build;
- include `THIRD_PARTY_NOTICES.md`;
- include `licenses/AdGuardHome-GPL-3.0.txt`;
- include or publish the matching source, patches, and build/install scripts
  whenever the AdGuard Home binary is bundled.

Do not copy AdGuard Home source into the NetSpecter repository unless it is
genuinely needed. Prefer a version-pinned upstream source/release link and
publish only any NetSpecter-specific patch or installation scripts.
