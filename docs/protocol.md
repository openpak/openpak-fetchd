# Protocol: openpak-fetchd

Each cycle (one after the network comes up, then every 6 hours of uptime) it resolves openpak.org,
fetches the signed ceiling and the switch profile over HTTPS, verifies them, builds the hosts block
exactly as `console/openpak-nro` would, rewrites the block, and tells dns_mitm to reload.

## Trust model

- The ceiling and profile are verified against a pinned Ed25519 key compiled in.
- One-way version rule: a version older than the last accepted one is refused.
- It never creates the hosts block: a hosts file without the OpenPak begin marker is left alone
  (that console never chose OpenPak).
- It writes only the marked OpenPak block; damaged markers or an oversize result leave all files alone.
