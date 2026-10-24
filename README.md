# openpak-fetchd

A Nintendo Switch boot2 sysmodule (title `01FE000000000F00`, Atmosphere) that keeps the OpenPak
block of the Atmosphere hosts files in step with openpak.org, with no homebrew launch needed.

Each cycle (one after the network comes up, then every 6 hours of uptime) it resolves openpak.org,
fetches the signed ceiling and the switch profile over HTTPS, verifies them, builds the hosts block
exactly as `console/openpak-nro` would, rewrites the block, and tells dns_mitm to reload.

## Files

Under `/atmosphere`:

- `hosts/default.txt` and `hosts/emummc.txt`: read and written; only the marked OpenPak block changes.
- `openpak-fetchd.log`: log, one line opened, written and closed at a time.
- `openpak-fetchd/ceiling.version`: last accepted ceiling version (the one-way rule).
- `openpak-fetchd/dry-block.txt`: the would-be block, written in dry mode.
- `config/openpak/ip_redirects.txt`: the signed ceiling's switch `ip_redirects` that name a title,
  one `<tcp|udp> <title> <from> <to>` line each, for the `bsd:u` MITM in OpenPak's boot package
  (a title that dials a hard-coded address, never a name). It is written only when its text
  changes and removed when the ceiling lists none. A game reads it when it opens its sockets, so a
  change applies from the game's next start.

Read only, under `/switch/openpak`: `ceiling.version` (the NRO's own floor) and `server.txt` (the
user's server address override).

Gate files (`/atmosphere/openpak-fetchd.<name>`):

| file | effect |
| --- | --- |
| `.enable` | one-shot: run on this boot only (consumed at once). Without it and `.auto` the process exits silently and writes nothing |
| `.auto` | run on every boot; also allows writes |
| `.write` | real hosts writes are allowed |
| `.dry` | force dry mode even if `.auto` or `.write` exist |
| `.stop` | checked between cycles; the process exits |
| `.stage` | decimal N: single cycle, stop before step N (1 dns, 2 bsd init, 3 fetch, 4 verify+build, 5 write, 6 reload) |
| `.reloadtest` | call the dns_mitm reload even when nothing was written |
| `.running` | crash marker, written before bsdInitialize and removed when the cycle ends; if present at start the process exits untouched |

Writes happen only if (`.auto` or `.write`) exists and `.dry` does not; otherwise the cycle is dry.
Also read: `.delay` (seconds to wait after the first "connected", default 20) and `.nifmreq`.

## Build

Needs devkitPro with devkitA64 and libnx:

    export DEVKITPRO=/opt/devkitpro
    make            # produces openpak-fetchd.nsp (ExeFS)

## Test

    make test       # host side, no devkitPro: core_test (ASan/UBSan) and nro_compare

`nro_compare` checks the block byte for byte against `console/openpak-nro` (needs its sources and
json-c). `FETCHD_LIVE=1 make test` also fetches the live envelope and profile (read-only GET).
Test binaries go to `$TMPDIR/fetchd-test` or `test/out/fetchd-test`.

## Trust model

- The ceiling and profile are verified against a pinned Ed25519 key compiled in.
- One-way version rule: a version older than the last accepted one is refused.
- It never creates the hosts block: a hosts file without the OpenPak begin marker is left alone
  (that console never chose OpenPak).
- It writes only the marked OpenPak block; damaged markers or an oversize result leave all files alone.

Hardware-proven on a console 2026-10-15.
