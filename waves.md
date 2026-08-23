# Feature-matrix waves

Gaps vs [vpnbench.clan.lol/feature-matrix](https://vpnbench.clan.lol/feature-matrix).
That matrix scores **upstream** VpnCloud (Linux 2.2/2.3) at 47/108. This fork already
closed Noise, macOS, Windows, FreeBSD, Android TUN, and iOS TUN — those cells are
stale, not code work.

Skip (out of product shape): userspace TCP/gVisor, kernel datapath, OAuth/OIDC
control plane, skip-crypto-on-LAN, per-app split tunnel.

---

## Wave A — cheap correctness

| Item | Plan |
|------|------|
| STUN + reflexive addrs | STUN Binding to a short server list; publish XOR-MAPPED-ADDRESS in `NODE_INFO` alongside local/UPnP addrs. |
| LAN endpoint preference | Sort peer underlay addrs so same-subnet / RFC1918-on-same-prefix come first (uses `getifaddrs`). |
| Handshake rate-limit | Token bucket per source IP on crypto-init (PING). |
| Stronger password KDF | Keep PBKDF2-4096+static salt as **legacy** (existing password nets). If `crypto.salt` is set, use PBKDF2-HMAC-SHA256 **100000** iterations with that salt. |
| `--lan-only` | Reject underlay peers that are not on a local interface prefix. |
| Matrix correction | Document Noise + platforms; optional PR to vpn-bench (not in this tree). |

## Wave B — connectivity

| Item | Plan |
|------|------|
| NAT-PMP | UDP 5351 next to UPnP in `PortForwarding`. |
| Relay-via-peer | `MESSAGE_TYPE_RELAY`: ciphertext forward to a destination node id via a connected peer; pick lowest recent RTT. Direct path retried in housekeep. |
| TCP fallback | Optional TCP listen/connect with length-prefixed datagrams; same crypto. Used when UDP handshake does not complete. |
| Claim metrics | `10.0.0.0/8@50` (lower metric wins). Optional NODE_INFO part; old nodes ignore it. Lookup: longest prefix, then lowest metric. |

## Wave C — speed

| Item | Plan |
|------|------|
| Batch UDP | Linux `recvmmsg`/`sendmmsg` (batch 64); other OS keep one-packet. Drain a batch per socket event. |
| Socket buffers | Configurable `SO_RCVBUF`/`SO_SNDBUF` (default 2 MiB). |
| UDP GSO | Linux `UDP_SEGMENT` on send after batching. |
| Crypto off wait thread | Encrypt/decrypt DATA on a small worker pool; control messages stay on the wait thread. |

## Wave D — policy

| Item | Plan |
|------|------|
| Overlay ACLs | After decrypt, before TUN write: allow/deny by overlay CIDR, optional proto/port. |
| Signed configs | Ed25519 signature over the config blob; `--require-signed-config` refuses unsigned files. |
| Seccomp | Linux: after bind/TUN, drop to a small syscall set. |
| Node expiry | `trusted-key` may be `key` or `key:YYYY-MM-DD`; expired keys are not trusted. |

## Order of work in this tree

A → B → C → D. Each wave should compile and `cargo test` on its own.

## Status

| Wave | Done | Not in this pass |
|------|------|------------------|
| A | STUN on the mesh socket, LAN sort, `--lan-only`, init rate-limit, `crypto.salt` → PBKDF2-100000; [vpn-bench PR #2](https://github.com/Qubasa/vpn-bench/pull/2) | skips listed above |
| B | NAT-PMP probes, `claim/prefix@metric`, `MESSAGE_TYPE_RELAY` via freshest peer, native TCP fallback (`--tcp-fallback`, length-prefixed datagrams) | |
| C | Configurable `SO_RCVBUF`/`SO_SNDBUF` (`--socket-buffer`, default 2 MiB), drain socket until `WouldBlock`, Linux `recvmmsg`/`sendmmsg`, UDP GSO (`UDP_SEGMENT`), UDP GRO receive split, `--crypto-threads` DATA worker pool | |
| D | Overlay `--acl` (CIDR + optional proto/port), `trusted-key:YYYY-MM-DD` expiry, Ed25519 signed configs (`sign-config`, `--require-signed-config`), Linux seccomp blacklist after bind/TUN | |
