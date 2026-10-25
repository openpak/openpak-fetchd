# Deploy: openpak-fetchd

## Files

Under `/atmosphere`:

- `hosts/default.txt` and `hosts/emummc.txt`: read and written; only the marked OpenPak block changes.
- `openpak-fetchd.log`: log, one line opened, written and closed at a time.
- `openpak-fetchd/ceiling.version`: last accepted ceiling version (the one-way rule).
- `openpak-fetchd/dry-block.txt`: the would-be block, written in dry mode.

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

