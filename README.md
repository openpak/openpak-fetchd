# Switch Boot Updater

OpenPak's Switch Boot Updater.

| | |
| --- | --- |
| Console | Nintendo Switch |
| Kind | Switch boot2 sysmodule (title `01FE000000000F00`, Atmosphere) |
| Licence | AGPL-3.0-only, see [LICENSE](LICENSE) |

## What it does

- Keeps the OpenPak block of the Atmosphere hosts files (`hosts/default.txt`, `hosts/emummc.txt`) in step with openpak.org.
- Runs one cycle after the network comes up, then every 6 hours of uptime.
- Verifies the signed ceiling and switch profile against a pinned Ed25519 key before it writes anything.
- Refuses a ceiling older than the last accepted one.
- Writes only the marked OpenPak block, never creates the hosts block, and asks dns_mitm to reload.

## Build

Needs devkitPro with devkitA64 and libnx:

    export DEVKITPRO=/opt/devkitpro
    make            # produces openpak-fetchd.nsp (ExeFS)
    make test       # host side, no devkitPro

## Docs

- [Protocol](docs/protocol.md)
- [Evidence](docs/evidence.md)
- [Deploy](docs/deploy.md)
- [Notes](docs/notes.md)

## Licence

See [LICENSE](LICENSE).
