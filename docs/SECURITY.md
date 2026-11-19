# Security model

## Trust anchor

In the common configuration all nodes share one password or keypair. That means
**every authenticated peer is equally trusted**: a peer that holds the shared
secret can join the mesh, announce routes, and relay traffic.

Opt-in per-node identity binding is available: set `node-key` (base62 Ed25519
private key) on each node to sign its NodeInfo announcements, and configure
`trusted-node-key` entries (`node-id-hex=base62-public-key`) on peers that must
verify them. An announcement for a configured node id without a valid signature
is rejected — its e2e key and claims are not installed. Nodes without configured
keys keep the shared-key model, so this is backward compatible. A full per-node
handshake (replacing the shared secret entirely) would be a protocol v3 change;
the signed-announcement layer covers identity binding for keys, routes, and
claims today.

## Encryption

- DATA frames use AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305 with per-key
  random nonces and a replay window. The Noise option uses X25519 with the
  vetted `snow` implementation.
- `plain` is available but opt-in and always warned about. It sends traffic in
  the clear.
- Handshake messages are Ed25519-signed. A present config signature is verified
  opportunistically; `--require-signed-config` enforces it.

## Signed configs

`--require-signed-config` is only meaningful with a trust anchor the config
cannot influence. Supply verification keys via `--verify-key`,
`--verify-key-file`, or `VPNCLOUD_VERIFY_KEY`; keys in the file itself
(`trusted-keys`, `public-key`) are peer keys and are **not** accepted for this.
Startup fails closed if no out-of-band key is given. The signature covers the
file body with exactly one trailing column-zero signature line.

Config write access is equivalent to code execution: `ifup`/`ifdown`, event
hooks, and `|`-prefixed beacons run as `sh -c` (as root before privilege drop).
Config and key files are created `0600` with `O_NOFOLLOW` where supported, but
the directory containing them must also be trusted.

## Compression

Compression is **off by default**. It runs LZ4 on DATA payloads before AEAD
encryption and only when the result shrinks. Compressing attacker-chosen
plaintext before encryption can leak information via ciphertext lengths
(CRIME/BREACH-style oracles). Enable it only on meshes where no adversary can
choose tunnel plaintext while observing packet sizes.

## Websocket endpoints

The websocket proxy and native `ws-listen://` server accept unauthenticated
clients and have no Origin check. Traffic is end-to-end encrypted at the
VpnCloud layer, but the endpoints are usable as an open UDP relay by anyone who
can reach the port. Bind to loopback, firewall the port, or terminate TLS and
authenticate at a reverse proxy. Frame size is capped at 65 KiB and the inbound
queue is bounded.

## Compression / relay / loop defenses

- Relay frames may carry only DATA message types; CLOSE and NODE_INFO from a
  relay are rejected.
- Relay frames are loop-checked with a bounded seen-set (they have no TTL).
- E2e-sealed bodies have a per-sealer replay window.
- NodeInfo peer/claim/transit lists are capped to prevent connection floods.
- ACL allow-only lists default-deny; deny-only lists keep allow-by-default.
- Linux seccomp installs `no_new_privs` and a syscall blacklist after bind/TUN
  and privilege drop, including x32 syscall handling on x86_64.

## Reporting a vulnerability

Please report privately to the maintainers rather than opening a public issue.
Include the version, platform, and a minimal reproduction.
