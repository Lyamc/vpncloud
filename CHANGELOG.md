# Changelog

This project follows [semantic versioning](http://semver.org).

### v2.7.0-alpha.1 (2026-11-19)

- [changed] Cleanup: zero clippy warnings on every target (host, Linux, Windows, macOS, iOS, Android). Replaced `Result<_, ()>` with a named `NoDetail` error, used c-string literals, removed needless returns, added type aliases for complex signatures, and boxed the oversized AEAD/crypto enums (shrinking `CryptoCore` from ~4.2 KiB to ~3.2 KiB). Justified lint allowances remain only for flat wire-header constructors and parallel-array hot loops.
- [changed] Cleanup/QoL: zero warnings on all targets including Android (removed stale imports, allowed intentionally test-only device-name helpers), removed unused test helpers, exposed `--install-routes` and `--per-peer-rate-limit` in the settings GUI, added a `mask check` recipe for the full local quality gate, and expanded troubleshooting docs for noisy peers and broadcast loops.
- [added] Loop defense and route hygiene: relay and flood frames now carry a capability-gated hop count (`MESSAGE_TYPE_RELAY_TTL`/`MESSAGE_TYPE_FLOOD_TTL`, self-describing so old peers keep the legacy format), decremented per hop and dropped at zero; dedup remains as a second line of defence. Gossiped peer RTTs are bounded and aggregated by median, and relay choice is sticky under small RTT changes to avoid flapping. `--install-routes` optionally installs kernel routes for announced claims (never a default route). `claims`/`auto-claim` are now SIGHUP-reloadable and re-announced immediately.
- [added] Peer-quality gossip and relay suggestions: `NodeInfo` carries first-hand RTTs to direct peers (`PART_PEER_QUALITY`, ignored by old peers). The aggregate quality table and best relayed path are exposed in `status --json`, `vpncloud status` (estimated quality + suggested relay) and Prometheus (`vpncloud_estimated_rtt_ms`, `vpncloud_suggested_relay_rtt_ms`).
- [added] Multiple overlay addresses: `--local-address <ip>` / `local-addresses:` assigns extra IPs (best-effort on Linux/Android, `ifup` elsewhere) and announces each as a /32 host claim. On TAP bridge nodes each address gets a distinct synthetic MAC and matching local ARP reply, so one node can serve several IPs over Ethernet. Added `wire.rs` per-IP MAC helper and tests.
- [added] Per-peer abuse throttling: `--per-peer-rate-limit <bytes/sec>` (default 20 MB/s, `--no-per-peer-rate-limit` to disable) adds a per-peer token bucket on DATA/GSO ingress with escalating penalties for noisy peers and gradual recovery. Throttle counts and penalty are exposed in `status --json`, `vpncloud status` and Prometheus (`vpncloud_peer_throttled_total`, `vpncloud_peer_penalty`). Added `-vv`/`--log-level <level>`/`--wire-log` (bounded hex dump of decrypted wire messages) and documented `RUST_LOG` and underlay tcpdump usage.
- [added] Mixed TAP/TUN meshes: `NodeInfo` now advertises supported wire formats (`PART_WIRE_FORMAT`), with a legacy fallback that infers the format from announced claims. Ethernet frames are validated against known EtherTypes and IP headers are length-checked, so a device-type mismatch is rejected instead of silently learning garbage addresses. `--l2-l3-bridge` on a TAP node accepts IP-only (TUN) clients: DATA payloads are translated per peer (Ethernet header stripped/added), ARP is answered locally from the route table, and IP-only payloads are dropped on TUN links. `flood-relay` falls back to per-peer delivery in mixed meshes. Added `wire.rs` with the capability/shim helpers and tests, including an end-to-end TAP-bridge/TUN exchange.
- [changed] Desktop GUI is now a full settings manager: added sections for per-node keys/trust bindings, device name/path, routing mode/claims/grants/split/exit node, discovery/STUN, network profile (including the previously missing Balanced option), advanced knobs (status/metrics, seccomp, crypto threads) and validation feedback. Saving now preserves config fields the GUI does not expose. SIGHUP reload is wired up for nodes started from the GUI. Uses the existing lightweight Iced software renderer (no wgpu); no second GUI toolkit added.
- [fixed] Live reconfiguration: SIGHUP reload now enforces the same config-signature policy as startup (previously a signed config could be swapped for an unsigned one and accepted). Reloading `exit-node`/`exit-allow` now re-parses the node IDs the datapath routes on — the old code only changed the unused string fields, making exit-node changes a no-op. Added `vpncloud service reload` on Windows (uses the standard `SERVICE_CONTROL_PARAMCHANGE` control code, which maps to the same reload flag as SIGHUP) and fixed the macOS tray "Reload config" item to kickstart the LaunchDaemon when controlling the service instead of setting a flag in the tray process.
- [fixed] Config/signature parsing: `to_base62` omits leading zero bytes, so ~1 in 256 generated 32-byte keys and 64-byte signatures round-tripped to the wrong length and were rejected (a rare intermittent failure in key generation, `genkey --out`, and config-signature checks). Added `from_base62_fixed` for all fixed-size key/signature decoding and a regression test.
- [added] Split platform device internals out of `device.rs`: Linux TUN send batching/GSO/pacing helpers (`tun_linux.rs`), rooted-Android TUN helpers (`android_tun.rs`), and pure unit tests (`cloud_tests.rs`), following the earlier `peers.rs`/`identity.rs` extraction. CPU topology detection / datapath thread pinning was extracted to `affinity.rs`. `device.rs` shrank from 2,654 to 2,255 lines and `cloud.rs` from 3,407 to 2,978, with re-exports preserving the public API.
- [added] Full per-node-key mode (`--per-node-keys`): each node uses a unique private-key and explicit `trusted-node-key` (node-id=public-key) bindings. The handshake binds the authenticated signing key to a node id, rejects keys bound to a different node, and derives the session key from a transcript of both identities and both ephemeral keys. Replaces shared-password trust when enabled; config validation refuses password-only setups in this mode.
- [added] macOS `.dmg` target alongside the universal `.pkg` in `contrib/macos/package.sh`.
- [added] Extracted peer address management (`peers.rs`) and identity/relay helpers (`identity.rs`) from `cloud.rs`.
- [added] Mobility and network profiles: peers with a stable node id (config `node-id`, or derived from `node-key`) migrate immediately when they reconnect from a new IP/port instead of lingering at the stale address; MTU is tracked per peer so the tunnel recovers when a low-MTU peer leaves, and can be capped with `max-underlay-mtu`. New `--profile latency|consistency|throughput` sets MTU/jitter defaults: consistency adds a configurable receive jitter buffer (`jitter-ms`) for predictable spacing. Mobility is on by default (`--no-mobility` disables it).
- [added] Opt-in `flood-relay`: in L2 broadcast modes the sender emits one copy to the lowest-RTT peer, which redistributes to the rest. A node with poor upload no longer sends a separate copy to every peer. Flood frames carry (origin, sequence) for loop/drop-duplicate prevention. `flood-relay-via` pins the redistribution peer. Default off.
- [added] Quality of life (complete list): `check-config`, `doctor`, `status --json`, `config --print`, and `network list/start/stop/status`; `genkey --out`; actionable TUN/driver error hints; startup config warnings; SIGHUP policy reload; richer GUI (more fields + peer list) and tray menus (reload, view log, settings fallback); `--log-json` structured logs; `--metrics-addr` Prometheus endpoint; `status-file` JSON snapshot; macOS `.pkg` builder and unattended install flags; reproducible benchmark script; generated CLI reference; troubleshooting and security-model docs; fuzz targets, migration fixture, nextest CI, and message-type collision test.
- [added] Per-node identity (opt-in): `node-key` signs NodeInfo announcements and `trusted-node-key` mappings let a peer reject unsigned or tampered identity/e2e-key announcements. Backward compatible — nodes without configured keys keep the shared-key trust model.
- [added] Quality of life: `check-config` validates configs without root/TUN; `status` (with `--json`) reads a JSON status file refreshed every second; logs append across restarts with 10 MiB rotation; the desktop GUI now edits MTU, peer timeout, ACL, port forwarding, compression and stateful filtering. CI now checks rustfmt and builds/tests on Windows as well as Linux and macOS.
- [fixed] Security (audit follow-up): e2e-sealed relay bodies now have a per-sealer replay window; ephemeral X25519 scalars and shared secrets are zeroized; enrollment checks the JWT alg exactly and uses 600k PBKDF2 iterations; salted node-id self-detection compared 20 vs 32 bytes and never worked; the logger no longer panics on write failure or dumps secrets; flow table is bounded; the Linux TUN helper uses a private random socket directory; Android TUN access is granted to the app uid only instead of world-writable; the iOS `vpncloud_last_error` returns a stable heap copy with a free function; macOS installer validates SUDO_USER.
- [fixed] Security (audit follow-up): relay frames may only carry data message types and are loop-checked; NodeInfo peer/claim/transit lists are capped; e2e keys can only be rotated by the peer that introduced them; ACL allow-only lists now default-deny; seccomp kills x32 syscalls on x86_64 and blocks more privilege syscalls; Android `su -c` arguments are shell-quoted; websocket inbound queue is bounded; config/key/log files are created 0600 without symlink races and secrets are no longer logged. Also fixed the Wintun archive layout in the Windows driver download and pinned the extracted DLL hash.
- [fixed] Security: config signatures now require an out-of-band trust anchor (`--verify-key` / `--verify-key-file` / `VPNCLOUD_VERIFY_KEY`); keys inside the verified config are no longer accepted. Signature canonicalization is strict (one column-zero signature line, last in the file) and config bytes are parsed and verified from a single read. Signed-config enforcement now also applies to the GUI. **Migration:** `--require-signed-config` now fails closed unless a verification key is supplied out-of-band.
- [fixed] Security: reject short encrypted messages and malformed ECDH keys instead of panicking (the release profile aborts on panic), bound WebSocket frame sizes, and validate SCM_RIGHTS ancillary-data lengths. Found in a security audit.
- [added] Opt-in LZ4 tunnel compression for direct DATA / DATA_GSO frames. Compressed before encryption, only when it shrinks the frame, gated on peer capability advertised in NodeInfo; off by default because of the compression-oracle caveat.
- [added] Windows driver setup: when the selected device type's driver is missing (Wintun for TUN, tap-windows6 for TAP), an interactive CLI, `vpncloud config`, or the GUI asks whether to download and install it. Downloads are pinned to a SHA-256 checksum. Non-interactive runs are never prompted.
- [added] macOS menu bar tray with a configuration context menu, installed as a user LaunchAgent alongside the LaunchDaemon; macOS builds work from a clean checkout.

### v2.6.0 (2026-11-06)

- [added] Opt-in library paths for a QUIC link, multipath failover, multi-queue TUN steering, and an in-process TCP handshake. Default UDP peers keep the existing frames.
- [added] Tunnel compression is off unless switched on. The same payload is smaller on the wire when on, and unchanged when off.
- [added] Opt-in ML-KEM-768 hybrid handshake. With it off, the default algorithms stay AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
- [added] NAT classification from one internal endpoint, a PCP MAP client distinct from NAT-PMP, and symmetric-NAT exchange on a predicted port without the relay.
- [added] LAN broadcast or multicast discovery, and peer endpoints reloaded from disk before any socket is opened.
- [added] In-tree kernel forward, and forwarding from an already-open TUN fd.
- [added] Certificate enrollment, locally checked OAuth/OIDC tokens, scripted login, opt-in admin approval, exact-match enrollment rules, and ephemeral nodes that are not reloaded as stable members.
- Default UDP encryption, the replay window, and sealed relay are unchanged. `--algorithm plain` stays opt-in. UDP GRO stays off on listen.

### v2.5.0 (2026-11-04)

- [added] Windows NSIS installer and portable zip (CLI + GUI + official Wintun 0.14.1). Optional TAP component downloads OpenVPN's tap-windows6 installer at install time (not shipped).
- [changed] Crypto is pure Rust (`aes-gcm`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`, `sha2`, `pbkdf2`). `ring`, AWS-LC, and the `aws-lc` feature are gone, so a default build does not compile C.
- [added] A Linux TUN GSO frame, and a run of same-flow UDP datagrams, cross the mesh as one AEAD message. The peer writes that aggregate back with its virtio header.
- [added] Multi-hop relay seals the inner payload to the destination and sends it through the lowest-RTT live hop. A missing end-to-end key or a failed seal drops the packet.
- [added] Transit records carry the claim metric and the announced group. Relay delivery checks the sealer's own claims. A group that is not granted installs nothing.
- [changed] Direct UDP to a connected peer is still one datagram. The relay header is not on that wire.
- Direct AEAD with a 2.4.x peer uses the same algorithms. A 2.4.x peer does not parse the new transit tail or the sealed relay body.

### v2.4.3 (2026-08-23)

- [added] GUI shows Sent / Received mesh bytes and last handshake time
- Mesh protocol remains compatible with 2.4.0 / 2.4.1 / 2.4.2 peers

### v2.4.2 (2026-08-23)

- [fixed] Linux seccomp arch check was inverted (SIGSYS on `write()`); 2.4.1 Linux binaries needed `--no-seccomp`
- [fixed] Linux `sendmmsg` compiles on stable rustc (index-assign mmsghdr slots)
- [fixed] Linux musl `msghdr` construction (private padding fields)
- Mesh protocol remains compatible with 2.4.0 / 2.4.1 peers

### v2.4.1 (2026-08-23)

- [changed] Datapath: reuse packet buffers (no 64 KiB zero / `to_vec` per packet); skip crypto mutex when `--crypto-threads` is 0; Linux TUN GSO/GRO offload; queue TUN writes and `send_multiple` after a UDP/TUN batch
- [changed] Datapath: move packets into TUN/UDP queues without an extra payload copy; reuse recvmmsg/sendmmsg/GSO scratch; Linux TUN `send_multiple` writes from `MsgBuffer` (virtio header prepend)
- [fixed] Crypto worker threads are recreated after `--daemon` (fork)
- [changed] Per-flow overlay stats HashMap is off unless `stats-file` / statsd is set
- [changed] `--crypto-threads` defaults to extra cores minus one (capped at 4) outside tests; tests stay at 0
- [added] Optional AES-GCM backend `aws-lc-rs` (`--features aws-lc`; `ring` remains default, Noise still uses `ring`)
- [changed] Release builds use thin LTO, abort-on-panic, and symbol stripping; packaged binaries can use `--profile dist` (fat LTO)
- [changed] Optional crates are feature-gated (`noise`, `installer`/`service-manager`, GUI Iced). Host lib crate-type is `rlib` only
- [changed] Service install uses the `service-manager` crate (systemd, launchd, Windows `sc.exe`); the Windows service *process* is unchanged
- [added] macOS `vpncloud install` registers LaunchDaemon `ca.witherow.vpncloud`
- [added] FreeBSD TUN/TAP (`tun`/`tap`) and rc.d install (`/usr/local/etc/rc.d/vpncloud`)
- [added] STUN mapped-address publish, LAN peer preference, `--lan-only`, handshake rate-limit
- [added] Optional password KDF PBKDF2-100000 when `crypto.salt` is set (legacy 4096 remains default)
- [added] NAT-PMP mapping, claim metrics (`10.0.0.0/8@50`), ciphertext peer-relay
- [added] Configurable UDP socket buffers (`--socket-buffer`, default 2 MiB) and multi-packet socket drain
- [added] Overlay ACLs (`--acl allow:10.0.0.0/8`, optional `:tcp:22` / port ranges) and `trusted-key` expiry (`key:YYYY-MM-DD`)
- [added] Optional TCP fallback (`--tcp-fallback`) with length-prefixed datagrams on the mesh port
- [added] Linux `recvmmsg`/`sendmmsg` batch I/O, UDP GSO (`UDP_SEGMENT`), and UDP GRO receive split
- [added] Optional DATA crypto worker pool (`--crypto-threads N`)
- [added] Ed25519 config signatures (`vpncloud sign-config`, `--require-signed-config`)
- [added] Linux seccomp blacklist after bind/TUN/privdrop (`--seccomp` / `--no-seccomp`)
- Mesh protocol remains compatible with 2.4.0 peers

### v2.4.0 (2026-08-22)

- [added] macOS TUN (`utun`) and TAP (`feth` + BPF) via tun-rs
- [added] Windows TUN (Wintun) and TAP (tap-windows6)
- [added] Optional Windows system tray (Enable / Disable / Exit), chosen at install
- [added] Windows system service (`vpncloud service install`, LocalSystem auto-start)
- [added] Android TUN via VpnService; TAP/L2 on rooted devices with /dev/net/tun
- [added] iOS TUN via Packet Tunnel Provider; TAP is not available
- [added] Optional Iced desktop GUI (`vpncloud-gui`, `--features gui`)
- [added] Noise protocol handshake (`--algorithm noise`: Noise_XX_25519_ChaChaPoly_SHA256)
- [added] Native websocket listen (`ws-listen://` / `ws://0.0.0.0:port`)
- [added] Configurable device MTU (`--mtu`)
- [added] Multiple addresses per peer with priority order
- [added] IPv6 overlay addresses on `--ip` (e.g. `fd00:1::1/64`)
- [added] Firewall, LXC/Proxmox, and IPv6 documentation
- [added] TOML config files (`.toml`); YAML still wins if both exist for the same name
- [changed] Updated dependencies (clap 4, serde_norway, igd-next, libc::daemon)
- [changed] Unique TAP MAC on every node
- [fixed] Dual-stack UDP listen on macOS (IPV6_V6ONLY)
- [fixed] IPv6-only hosts no longer panic in `get_ip`
- [fixed] Peer-list interval overflow, loopback crypto-init flood
- [fixed] TUN vs TAP mismatch error message
- [fixed] Republish addresses when the public IP changes
- [fixed] Parse interface IPs without host-endian ioctl packing
- [fixed] Windows build against windows-sys 0.61 (HANDLE as pointer: tray, service, poll)
- [fixed] Windows `vpncloud install` copies `wintun.dll` when it sits next to the exe

### v2.3.0 (2021-12-23)

- [added] Added build for armv5te (thanks to xek)
- [added] Option to specify advertised addresses
- [added] Peers now learn their own address from peers
- [changed] Changed Rust version to 1.57.0
- [changed] Updated dependencies
- [fixed] Fixed problem with IPv4 addresses in listen option
- [fixed] Fixed periodic broadcast messages in switch mode

### v2.2.0 (2021-04-06)

- [added] Service target file (thanks to mnhauke)
- [added] Added interactive configuration wizard
- [added] Support for (un-)installation
- [added] Building static binaries
- [added] Building i686 rpm
- [changed] Restructured example config
- [changed] Changed Rust version to 1.51.0
- [changed] Updated dependencies
- [changed] Change permissions of /etc/vpncloud

### v2.1.0 (2021-02-06)

- [added] Support for websocket proxy mode
- [added] Support for hook scripts to handle certain situations
- [added] Support for creating shell completions
- [removed] Removed dummy device type
- [changed] Updated dependencies
- [changed] Changed Rust version to 1.49.0
- [fixed] Added missing peer address propagation
- [fixed] Fixed problem with peer addresses without port

### v2.0.1 (2020-11-07)

- [changed] Changed documentation
- [changed] Updated dependencies
- [changed] Retrying connections for 120 secs
- [changed] Resetting own addresses periodically
- [changed] Using smallvec everywhere
- [changed] Assume default port for peers without port
- [fixed] Fixed corner case with lost init message
- [fixed] Do not reconnect to timed out pending connections
- [fixed] Most specific claims beat less specific claims
- [fixed] Count all invalid protocol traffic
- [fixed] Fixed compile with musl
- [fixed] Fixed time format in logs

### v2.0.0 (2020-10-30)

- [added] **Add strong crypto, complete rewrite of crypto system**
- [added] Automatically claim addresses based on interface addresses (disable with --no-auto-claim)
- [added] Allow to give --ip instead of ifup cmd
- [added] Automatically set optimal MTU on interface
- [added] Warning for disabled or loose rp_filter setting
- [added] Add --fix-rp-filter to fix rp filter settings
- [added] Offer to migrate old configs
- [changed] **Complete change of network protocol**
- [changed] Negotiate crypto method per peer, select best method
- [changed] Make encryption the default, no encryption must be stated explicitly
- [changed] Changed default device type to TUN
- [changed] Rename subnet to claim
- [changed] Set peer exchange interval to 5 minutes
- [changed] Periodically send claims with peer list
- [changed] Changed Rust version to 1.47.0
- [removed] Remove network-id parameter
- [removed] Remove port config option in favor of --listen

### UNRELEASED v1.x.y

- [added] Added crypto option AES128
- [added] Default port for peers
- [changed] Updated dependencies
- [changed] Removed C code, now 100% Rust
- [fixed] Fixed keepalive for small timeouts
- [fixed] Fixed problem with port forwarding
- [fixed] Fixed problem with TUN on dynamic host addresses

### v1.4.0 (2020-06-03)

- [added] Added option to listen on specified IP
- [added] Added support for statsd monitoring
- [changed] No longer using two sockets for ipv4 and ipv6
- [changed] Warning for missing router is now info
- [changed] New warning on claimed addresses in learning mode
- [changed] Rewrote argument parsing
- [changed] Changed stats file format to YAML
- [changed] Using asciidoc for manpage
- [changed] Updated dependencies
- [fixed] Fixed problem that could lead to 100% cpu consumption
- [fixed] Fixed startup race condition

### v1.3.0 (2020-01-25)

- [added] Building for aarch64 aka arm64 (thanks to Ivan)
- [added] Added feature to disable special NAT support
- [changed] Improved port forwarding on quirky routers
- [changed] Reduced peer timeout to 5min to work better with NAT
- [changed] Improved builder scripts
- [changed] Updated dependencies
- [fixed] Fixed problem with growing stats file

### v1.2.1 (2019-12-22)

- [fixed] Fixed a problem with service restrictions

### v1.2.0 (2019-12-20)

- [added] Added service restrictions to systemd
- [changed] Rust version 1.40.0
- [changed] Also drop privileges in foreground mode
- [changed] Set builders to Ubuntu 16.04 and CentOS 7
- [changed] Set keepalive to 120 secs when NAT is detected
- [changed] Deleting beacon file at shutdown
- [changed] Updated dependencies
- [fixed] Added parameter keepalive to manpage
- [fixed] Fixed problems on stats file when dropping permissions
- [fixed] Deleting files before overwriting them
- [fixed] Fixed duplicate port bindings

### v1.1.0 (2019-12-04)

- [added] Exchange peer timeout and adapt keepalive accordingly
- [added] Reducing published peer timeout to 5 min when NAT is detected
- [added] Added more tests
- [changed] Rust version 1.39.0
- [changed] Updated dependencies
- [fixed] Fixed potential startup dependency issue
- [fixed] Fixed wrong base62 encoding

### v1.0.0 (2019-03-21)

- [added] Added ability to publish small beacons for rendezvous
- [added] Added build chain for packages
- [added] Added more tests
- [changed] Allow to build binary without manpage
- [changed] Rust edition 2018
- [changed] Rust version 1.33.0
- [changed] Updated dependencies
- [fixed] Fixed bug that could cause repeated initialization messages

### v0.9.1 (2019-02-16)

- [fixed] Fixed bug in new hex secret key functionality

### v0.9.0 (2019-02-15)

- [added] Added support for cross-compilation
- [added] Added keepalive option for nodes behind NAT
- [added] Added ability to write out statistics file with peers and traffic info
- [added] Added dummy device type that does not allocate an interface
- [added] Added ability to change /dev/tun path
- [changed] Using ring instead of libsodium
- [changed] Using PBKDF2 for shared keys (**incompatible**)
- [changed] Updated dependencies
- [fixed] Hashed magics now also consider first character (**incompatible**)

### v0.8.2 (2019-01-02)

- [changed] Using serde instead of rustc_serialize
- [changed] Updated libsodium to 1.0.16
- [changed] Updated dependencies
- [changed] Making clippy happy
- [fixed] Fixed wrong address

### v0.8.1 (2017-05-09)

- [added] Added more tests
- [changed] Updated dependencies
- [changed] Updated libsodium to 1.0.12
- [changed] Small fixes to make clippy happy
- [changed] Removed a layer of indirection from inner loop
- [fixed] Fixed two problems with routing table

### v0.8.0 (2016-11-25)

- [added] Support for automatic port forwarding via UPnP
- [added] Added `-s` shorthand for `--subnet`
- [added] Support for YAML config file via `--config`
- [added] Support for running in the background
- [added] Support for dropping permissions
- [added] Support for writing a pid file
- [added] Support for writing logs to logfile
- [changed] Not overriding recently learnt addresses in switch mode
- [changed] Caching resolved addresses to increase performance
- [changed] Configurable magic header is now used instead of Network-ID (**incompatible**)
- [changed] Clarified documentation on TUN netmasks
- [changed] Added timestamps to output
- [changed] Using new YAML config instead of old config files (**incompatible**)
- [changed] Prefer IPv4 over IPv6 when possible
- [changed] Updated dependencies
- [fixed] Fixed documentation of listen parameter
- [fixed] Fixed problem with multiple subnets
- [fixed] Fixed problem with interrupted poll after suspend to ram
- [fixed] Forgot to extend peer timeout on peer exchange
- [fixed] No longer broadcasting to additional addresses

### v0.7.0 (2016-08-05)

- [added] Added more tests
- [added] Added pluggable polling system
- [added] Added documentation
- [changed] Code cleanup
- [changed] Updated dependencies
- [changed] Turned some clippy warnings off
- [changed] Cross-compiling for ARM
- [changed] Updated libsodium to 1.0.11
- [removed] Removed Address remove code for prefix table
- [fixed] Reconnecting to lost peers when receiving from them or sending to them
- [fixed] Sending peer list more often to prevent timeouts
- [fixed] Removing learnt addresses of lost peers
- [fixed] Fixed possible crash in message decoding

### v0.6.0 (2016-06-02)

- [added] Exponential backoff for reconnect timeouts
- [added] Systemd compatible startup scripts
- [changed] Repeatedly resolving connect addresses to allow DynDNS
- [changed] Listening on IPv4 and IPv6
- [changed] Using SO_REUSEADDR to allow frequent rebinding
- [changed] Building and using local libsodium library automatically
- [changed] Updated dependencies

### v0.5.0 (2016-04-05)

- [added] Added license and copyright information
- [added] Added documentation for daemon config files
- [added] Script for performance measurements
- [added] Added more tests and benchmarks
- [changed] Daemon now detects network config files on its own
- [changed] Using display format for addresses
- [changed] Updated dependencies
- [changed] New measurements
- [changed] Only calling crypto_init once
- [changed] Passing listen address as &str
- [changed] Using FNV hash for better performance
- [changed] Using slice operations instead of loops
- [changed] Updated libsodium to 1.0.10
- [changed] Renamed default.net to example.net
- [fixed] Fixed wrong hex address formatting
- [fixed] Fixed peer exchange for more than 65000 peers
- [fixed] Initializing crypto for benchmarks
- [fixed] Removing learned addresses of lost peers

### v0.4.3 (2016-02-02)

- [changed] Updated libsodium to 1.0.8
- [fixed] Fixed problem with nodes broadcasting to themselves

### v0.4.2 (2016-01-19)

- [changed] Updated dependencies
- [changed] New measurements
- [changed] Using copy trait more often
- [fixed] Fixed deb changelog

### v0.4.1 (2015-12-22)

- [changed] Logging more verbosely
- [fixed] Removing NULL-bytes from interface name
- [fixed] Supporting hostnames as peers
- [fixed] No longer encrypting multiple times
- [fixed] Properly decoding protocol header when sending
- [fixed] Corrected size of read data

### v0.4.0 (2015-12-22)

- [added] Init script
- [changed] Removed last payload memcopy
- [changed] Using RNG to select peers for peers list exchange
- [changed] Updated dependency versions
- [changed] Updated documentation
- [fixed] Printing errors instead of panics in some cases
- [fixed] Build script for Debian packages

### v0.3.1 (2015-12-03)

- [added] Unique node ids to avoid connecting to self (**incompatible**)
- [fixed] Calling sync when writing to TUN/TAP device

### v0.3.0 (2015-12-02)

- [added] Support for AES256GCM encryption
- [added] Including current libsodium in builds
- [added] --crypto parameter to select encryption method
- [changed] Increased ChaCha20Poly1305 nonce from 8 to 12 bytes (**incompatible**)
- [changed] Updated dependency versions
- [changed] More tests
- [changed] Removed more "unsafe" blocks
- [fixed] Forgot to call `sodium_init`, huge performance increase

### v0.2.0 (2015-11-26)

- [added] Sending close message at the end
- [added] Support for IPv6 addresses
- [added] Support for ChaCha20Poly1305 encryption
- [removed] Support for ChaCha20HmacSha512256 encryption
- [changed] Complete rewrite of encryption code (**incompatible**)
- [changed] Removed unused code
- [changed] Some speed improvements
- [changed] Removed lots of "unsafe" blocks (**fixes security issue**)
- [changed] Added benchmarks
- [changed] Two step handshake in order to fix problems with inconsistent state
- [fixed] Pretty error messages instead of panics with traces
- [fixed] Pretty addresses instead of debug representation

### v0.1.0 (2015-11-25)

- First release
