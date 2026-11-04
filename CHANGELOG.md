# Changelog

## v0.1.1 — 2026-11-04

- maintenance

## 0.1.0 - 2026-11-04

- First tagged release: boot2 updater keeping the OpenPak hosts block in step with openpak.org.
- Writes the signed ceiling's switch `ip_redirects` that name a title to `/atmosphere/config/openpak/ip_redirects.txt` (read by the `bsd:u` MITM in the boot package, switch-patcher), only when the text changes, removed when the ceiling lists none.
