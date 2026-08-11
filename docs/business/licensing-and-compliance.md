# Licensing and Compliance

## NetSpecter Licence Position

NetSpecter v2 is proprietary/free-to-use-for-now as documented through project licence/EULA work.

## AdGuard Home

AdGuard Home is separate third-party GPL-3.0 software.

NetSpecter should clearly state:

- NetSpecter does not own AdGuard Home.
- NetSpecter does not modify or relicense AdGuard Home.
- NetSpecter does not claim endorsement or partnership with AdGuard Home.
- NetSpecter currently downloads/runs the official AdGuard Home upstream installer.
- NetSpecter does not bundle AdGuard binaries in GitHub.

## Files / Notices

Relevant files:

- `LICENSE`
- `EULA.md`
- `THIRD_PARTY_NOTICES.md`
- `licenses/AdGuardHome-GPL-3.0.txt`

The UI should expose legal/licence notes through a Legal & Licences link such as `/third-party-licences`.

## Installer Notice

`install.sh` should print the AdGuard GPL/project/licence notice before running the upstream install command.
