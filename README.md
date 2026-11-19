VpnCloud - Peer-to-Peer VPN
---------------------------
![Checks](https://github.com/Lyamc/vpncloud/workflows/Checks/badge.svg?branch=master)
![Security audit](https://github.com/Lyamc/vpncloud/workflows/Security%20audit/badge.svg?branch=master)

**VpnCloud** is a high performance peer-to-peer mesh VPN over UDP with strong
encryption, NAT traversal, and a simple config file. Nodes form a fully meshed,
self-healing network. Traffic is encrypted end-to-end (Curve25519, AES-256 /
ChaCha20) and forwarded over a virtual TUN (IP) or TAP (Ethernet) interface.

**Documentation:** [Troubleshooting](docs/TROUBLESHOOTING.md) ·
[Security model](docs/SECURITY.md)

This repository is [Lyamc/vpncloud](https://github.com/Lyamc/vpncloud), a fork
of [dswd/vpncloud](https://github.com/dswd/vpncloud). The fork adds **macOS**,
**Windows**, **FreeBSD**, **Android**, and **iOS (TUN only)** support plus
protocol, config, and dependency fixes. Upstream documentation lives at
[vpncloud.ddswd.de](https://vpncloud.ddswd.de).

Prebuilt **2.6.0** binaries are on
[GitHub Releases](https://github.com/Lyamc/vpncloud/releases/tag/v2.6.0)
(`SHA256SUMS` in the same release). Direct AEAD with a 2.4.x peer uses the
same algorithms. A 2.4.x peer does not parse the 2.5.0 transit tail or the
sealed relay body.

```sh
vpncloud -c REMOTE_HOST:PORT -p 'mypassword' --ip 10.0.0.1/24
```

Or as a config file (`/etc/vpncloud/mynet.net` on Linux). YAML
(`.yaml` / `.yml` / `.net`) and TOML (`.toml`) are both accepted. If both
exist for the same name, **YAML is used**.

```yaml
crypto:
  password: mysecret
ip: 10.0.0.1/24
peers:
  - REMOTE_HOST:PORT
```

```toml
ip = "10.0.0.1/24"
peers = ["REMOTE_HOST:PORT"]

[crypto]
password = "mysecret"
```

See `vpncloud.adoc` (the man page) for every option, `assets/example.net.disabled`
for a commented YAML template, and `assets/example.toml.disabled` for TOML.

**Two-node TUN** (default `--type tun`; both ends must match — TAP will not
mesh with TUN). Unique overlay IPs, same password. Needs root to create the
device (`sudo` in a terminal; no extra start script):

```sh
# node A
sudo vpncloud --type tun --ip 10.0.0.1/24 -p 'mypassword' --listen 3210

# node B
sudo vpncloud --type tun --ip 10.0.0.2/24 -c HOST_A:3210 -p 'mypassword'
ping 10.0.0.1
```

`--ip` auto-claims only that host (`10.0.0.1/32`). To route extra subnets
(WireGuard `AllowedIPs`-style), advertise them with `--claim 10.8.0.0/24`
on the node that owns them. `--mode normal` is router on TUN and switch on
TAP. For a process that outlives the terminal, use `vpncloud install`
(systemd / LaunchDaemon / rc.d / Windows service), not a custom wrapper.


### Project status

VpnCloud 2.6.0 on this fork is usable on Linux, macOS, FreeBSD, Windows,
Android, and iOS (TUN). It includes:

* Automatic peer-to-peer meshing, no central servers
* Automatic reconnect, including several addresses per peer (priority order)
* TUN (IP) and TAP (Ethernet) virtual interfaces
* Linux, macOS (`utun` / `feth`), FreeBSD (`tun` / `tap`), Windows (Wintun /
  tap-windows6), Android TUN, iOS TUN (Packet Tunnel Provider)
* Strong end-to-end encryption (Curve25519, AES-128/256, ChaCha20, optional Noise_XX)
* Hub / switch / router forwarding modes
* NAT hole punching and UPnP port forwarding
* IPv6 transport (`[2001:db8::1]:3210`) and IPv6 overlay (`--ip fd00:1::1/64`)
* Websocket proxy **and** native websocket listen (for nginx / cloudflared)
* Beacons, statsd, hook scripts, configurable MTU
* Single binary, no kernel module

Known limits: on macOS, TAP L2/ARP works but ICMP through `feth` is often
lossy — prefer TUN there. Windows TUN needs `wintun.dll` (bundled in the
setup.exe / portable zip). TAP can be downloaded by the NSIS setup from
OpenVPN (not shipped).


### Performance

Rates below are iperf3 at the receiver. TCP is bidirectional for 30 seconds.
UDP is one direction with an unlimited offer (`-b 0`). Ping loss was 0% in
every row. These are one-path iperf3 numbers on this host, not the Hetzner
vpn-bench run, and not a promise for another machine.

**Gigabit switch, this host, 2026-11-04.** One pass. `enp4s0` at
`192.168.88.1` talked to `enp0s20f0u5` in a network namespace at
`192.168.88.2`. Neighbor MACs showed the frames crossed the L2 switch.
VpnCloud's TUN MTU was 1430, with GSO capped at 1420. WireGuard's MTU was
1420. Default encryption stayed on. Numbers are Mbps.

| Path | TCP each way | UDP received | Average ping |
|---|---:|---:|---:|
| No VPN | 936 / 932 | 956 | 0.38 ms |
| VpnCloud (this fork) | 877 / 877 | 911 | 0.50 ms |
| WireGuard | 856 / 879 | 888 | 0.59 ms |

VpnCloud's unlimited UDP offer (`-b 0`) was received at 911 Mbps, and none
of those datagrams were lost. WireGuard on that same path received 888 Mbps.
A second 30 second UDP pass on the same NICs received 915 Mbps for VpnCloud
and 808 Mbps for WireGuard. TCP each way was 877 Mbps. The no-VPN TCP rates
in this session were 936 and 932 Mbps.

**Same host, veth.** This is not a NIC test and it is not comparable to the
switch row or to vpn-bench. Two 30 second runs, encryption on, inner MTU
1400: VpnCloud TCP was about 6.7–7.2 and 5.9–6.9 Gbit/s, kernel WireGuard
about 3.7 and 3.8–4.3 Gbit/s. UDP received was about 8.3 Gbit/s versus
5.9–6.0 Gbit/s. An earlier 10 second pass had WireGuard ahead on TCP (about
5.4 Gbit/s versus 2.6–2.9 Gbit/s).

**Published vpn-bench, 18 Dec 2025, Hetzner host lom.** That column is
upstream VpnCloud, not this fork. Dedicated machines, separate NICs.
TCP each way and UDP received, in Mbps: no VPN about 939 / 931 and 956;
upstream VpnCloud about 525 / 355 and 726 (about 85% of the UDP offer lost);
WireGuard about 823 / 882 and 898.


### Platforms

**Linux.** Default target. Needs `/dev/net/tun` and usually root. For
unprivileged LXC/Proxmox, bind-mount `/dev/net` and allow cgroup device
`10:200` (see *CONTAINERS* in `vpncloud.adoc`).

**macOS.** TUN uses `utun`. TAP uses `feth` plus BPF. Create the interface
with `sudo` from a terminal (`sudo vpncloud --type tun --ip 10.0.0.2/24
-c HOST:3210 -p PASS`). Dual-stack UDP listen works (`--listen 3210` binds
IPv4 and IPv6). `--daemon` from a one-shot GUI/osascript helper can die when
that helper exits; persist with `vpncloud install` (LaunchDaemon
`ca.witherow.vpncloud` plus a menu bar tray application), then
`sudo launchctl start system/ca.witherow.vpncloud` or use the tray's
**Enable / Disable VPN** menu item.

**FreeBSD.** TUN uses `tun(4)`, TAP uses `tap(4)` (both via tun-rs). Default
`vpncloud%d` names are ignored; the kernel assigns `tunN` / `tapN`. Dual-stack
UDP listen works (`IPV6_V6ONLY` is cleared). `vpncloud install` writes
`/usr/local/bin/vpncloud`, `/usr/local/etc/vpncloud/`, and an rc.d script.

**Windows.** Prefer the NSIS setup (`vpncloud-*-windows-*-setup.exe`) or the
portable zip: both ship `vpncloud.exe`, `vpncloud-gui.exe`, and the official
[Wintun](https://www.wintun.net/) 0.14.1 DLL for TUN. TAP uses
[tap-windows6](https://github.com/OpenVPN/tap-windows6) (NdisWan / `tap0901`)
and is **not** bundled (signed OpenVPN kernel driver). The NSIS setup can
download that installer from OpenVPN at install time (optional checkbox).
Run as Administrator to create the adapter. See *Installing* below. Optional system tray (Enable / Disable /
Exit) is offered at `vpncloud install` (build with `--features installer`) or
`vpncloud.exe --tray`. Unattended: `vpncloud install --tray` / `--no-tray` /
`--autostart`. `vpncloud install` copies `wintun.dll` when it sits next to the
exe.

As a **system service** (Administrator, LocalSystem, auto-start at boot):

```bat
vpncloud service install --config C:\ProgramData\VpnCloud\vpncloud.yaml --start
vpncloud service start
vpncloud service stop
rem reload ACL/grants/split/peers without a restart:
vpncloud service reload
vpncloud service uninstall
```

Or `vpncloud install --service` (installer feature). Put `wintun.dll` next to
the installed `vpncloud.exe`. The service has no tray icon.

**Android.** TUN works on all devices through `VpnService` (`--tun-fd` / JNI,
`protect()` so the UDP mesh does not hairpin). **TAP/L2 is rooted-only:** it
opens `/dev/net/tun` with `IFF_TAP`. On an unrooted phone, `--type tap` errors
and `--help` states that TAP needs root. The app shows the same message if you
select TAP without `/dev/net/tun` access.

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk
./android/build-native.sh   # writes jniLibs/*.so
# then open android/ in Android Studio and run the app
```

**iOS.** TUN only, via a Network Extension **Packet Tunnel Provider**. TAP/L2
is not available (no Ethernet, no `/dev/net/tun`). The extension installs
**overlay routes only** so the UDP mesh does not hairpin through the tunnel
(no Android-style `protect()`). Requires an Apple Developer team with the
Network Extension capability. iOS 16+.

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
./ios/build-native.sh       # writes ios/libvpncloud.xcframework
# then open ios/VpnCloud.xcodeproj, set your team, enable
# Network Extension + App Groups, and run on a device
```


### Installing

Download a 2.6.0 binary from
[GitHub Releases](https://github.com/Lyamc/vpncloud/releases/tag/v2.6.0)
(checksums in `SHA256SUMS`):

| File | Platform |
|---|---|
| `vpncloud-2.6.0-linux-x86_64` | Linux CLI, x86_64, static musl |

This tag attaches that Linux binary. macOS, Windows, FreeBSD, Android, ARM64
Linux, and iOS are built from source with the sections below.

To build from source: Rust/Cargo (edition 2021, toolchain 1.75+). On Linux,
install `asciidoctor` if you want the man page. The `install` subcommand is
compiled only with `--features installer`. Crypto is pure Rust
(AES-GCM, ChaCha20-Poly1305, Ed25519, X25519). The default build also
compiles the vendored ML-KEM sources with clang.

```sh
git clone https://github.com/Lyamc/vpncloud.git
cd vpncloud
cargo test
```

#### Linux

Static musl binaries from the release run on most distributions (no glibc
version pin). Example:

```sh
chmod +x vpncloud-2.6.0-linux-x86_64
sudo ./vpncloud-2.6.0-linux-x86_64 --help
```

Or build from source:

```sh
cargo build --release --features installer
sudo ./target/release/vpncloud --help
sudo ./target/release/vpncloud install
```

That copies the binary, example config, man page, and the systemd units
`vpncloud@.service`, `vpncloud.target`, and `vpncloud-wsproxy.service`
(same templates as `assets/`). Enable a network with
`sudo systemctl enable --now vpncloud@mynet`.

Desktop GUI (Iced, software renderer — not pulled into the CLI, ~5.8 MB):

```sh
cargo build --release --features gui --bin vpncloud-gui
sudo ./target/release/vpncloud-gui                 # optional path: vpncloud-gui ./mynet.yaml
```

The window is a full settings manager: it loads and saves connection basics,
per-node keys and trust bindings, device name/path, routing mode, claims,
grants, split prefixes, exit node, ACL, discovery/transport options, network
profile, jitter/MTU, and advanced knobs (status/metrics files, seccomp, crypto
threads). Settings are grouped into sections in one scrollable view. Saving
preserves config fields the GUI does not expose (hooks, stats file, signature,
etc.). `Connect` runs a node in-process for a quick check and reads live
peer/traffic stats; `Load`/`Save` only touch the config file. If a config is
signed, editing it invalidates the signature — re-sign it with `sign-config`
before connecting.

Debian/RPM packaging helpers live in `maskfile.md` (requires
[mask](https://github.com/jacobdeichert/mask)). Systemd units are in
`assets/`.

#### macOS

Universal CLI/GUI binaries are on the GitHub release (`x86_64` + `arm64`).
Or build from source:

```sh
cargo build --release --features installer
sudo ./target/release/vpncloud install
```

Copies `/usr/local/bin/vpncloud`, writes `/usr/local/etc/vpncloud/` (the
`/usr/bin` and `/etc` trees are sealed by SIP on modern macOS), and registers
the LaunchDaemon `ca.witherow.vpncloud`
(`/usr/local/bin/vpncloud --config /usr/local/etc/vpncloud/vpncloud.yaml`).
It also installs a per-user LaunchAgent `ca.witherow.vpncloud.tray` that shows a
**menu bar icon with a configuration context menu** (Enable / Disable VPN,
Restart VPN, Open config folder, Edit configuration, Quit). The agent starts at
login and controls the privileged daemon, which runs as root because TUN
requires it.

Edit `/usr/local/etc/vpncloud/vpncloud.yaml` (add `password:` or a private key),
then use the menu bar **Enable / Disable VPN** item, or start from the shell:

```sh
sudo launchctl start system/ca.witherow.vpncloud
```

The standalone menu bar app is also available without installing the service:
`./target/release/vpncloud --tray --config vpncloud.yaml` (needs root for TUN).

Uninstall: `sudo ./target/release/vpncloud install --uninstall` (also removes
the menu bar LaunchAgent).

#### FreeBSD

The `if_tuntap` module is in GENERIC on recent releases; otherwise
`kldload if_tuntap`. A prebuilt x86_64 binary is on the GitHub release
(linked against FreeBSD 15 `libc.so.7`). To build on a FreeBSD host:

```sh
pkg install rust
git clone https://github.com/Lyamc/vpncloud.git
cd vpncloud
cargo build --release --features installer
sudo ./target/release/vpncloud install
```

Copies `/usr/local/bin/vpncloud`, writes `/usr/local/etc/vpncloud/`, and
installs `/usr/local/etc/rc.d/vpncloud`. Edit
`/usr/local/etc/vpncloud/vpncloud.yaml`, then:

```sh
sudo sysrc vpncloud_enable=YES
sudo sysrc vpncloud_config=/usr/local/etc/vpncloud/vpncloud.yaml
sudo service vpncloud start
```

Uninstall: `sudo ./target/release/vpncloud install --uninstall`.

#### Windows

Windows has no in-box TUN/TAP. **TUN** needs [Wintun](https://www.wintun.net/)
(`wintun.dll` next to `vpncloud.exe`). **TAP** needs the
[tap-windows6](https://github.com/OpenVPN/tap-windows6) driver. Creating the
virtual interface requires **Administrator**.

`./contrib/windows/package.sh` (needs `makensis`) builds an NSIS installer
and a portable zip. Both include `vpncloud.exe`, `vpncloud-gui.exe`, and the
official Wintun 0.14.1 DLL plus its license. The setup.exe writes
`C:\Program Files\VpnCloud`, Start Menu shortcuts, an uninstaller, and
optionally PATH, a LocalSystem service, and a download of OpenVPN's
tap-windows6 installer (TAP/L2; SHA-256 verified; not shipped in the setup).
Those Windows artifacts are not attached to the 2.6.0 release. Put
`wintun.dll` next to a CLI you build yourself if you are not using the
installer.

To build from source:

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   with the **Desktop development with C++** workload. **MSVC is the path that
   works out of the box.**

2. Build with the MSVC toolchain and the installer feature:

```bat
rustup toolchain install stable-x86_64-pc-windows-msvc
cargo +stable-x86_64-pc-windows-msvc build --release --features installer
```

The binary is `target\release\vpncloud.exe`.

3. Download [Wintun 0.14.1](https://www.wintun.net/builds/wintun-0.14.1.zip)
   (SHA2-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`).
   Copy `bin\amd64\wintun.dll` (or `arm64` on ARM) next to `vpncloud.exe`:

```bat
copy path\to\wintun\bin\amd64\wintun.dll target\release\
```

Without `wintun.dll`, TUN fails at startup with `LoadLibraryExW failed`.
When you start VpnCloud or pick a device type in `vpncloud config` or the GUI,
Windows detects a missing driver and **asks whether to download it for you**.
Answering yes downloads the exact pinned artifact above, verifies its SHA-256,
then installs it: Wintun's DLL is placed beside `vpncloud.exe`, and tap-windows6
runs OpenVPN's signed installer (with a UAC prompt if needed). Declining leaves
the files untouched; non-interactive runs never prompt.

4. Optional TAP: tick **TAP driver** in the NSIS setup (downloads OpenVPN
   `tap-windows-9.24.7-I601-Win10.exe`, verifies SHA-256, runs their wizard)
   or install tap-windows6 from
   [OpenVPN downloads](https://build.openvpn.net/downloads/releases/)
   (hardware id `tap0901` / NdisWan). ARM64 has no standalone TAP `.exe`; the
   setup opens the [9.27.0 GitHub release](https://github.com/OpenVPN/tap-windows6/releases/tag/9.27.0)
   instead. Uninstalling VpnCloud does not remove TAP.

5. Install (copies the exe, `wintun.dll` if present, an example config, and a
   Start Menu shortcut). User-level files go to `%LOCALAPPDATA%\VpnCloud`
   (`C:\Users\<you>\AppData\Local\VpnCloud`):

```bat
.\target\release\vpncloud.exe install --no-service
```

Unattended flags: `--tray` / `--no-tray`, `--autostart`, `--service` /
`--no-service`. `--service` requires Administrator and registers a LocalSystem
auto-start service (`C:\Program Files\VpnCloud` plus
`C:\ProgramData\VpnCloud\vpncloud.yaml`).

```bat
vpncloud.exe install --uninstall
```

6. Edit `%LOCALAPPDATA%\VpnCloud\vpncloud.yaml` (set `crypto.password` or a
   keypair and `--ip`), then run **as Administrator**:

```bat
cd %LOCALAPPDATA%\VpnCloud
vpncloud.exe --config vpncloud.yaml --ip 10.0.0.1/24 -p mysecret
```

Or `vpncloud.exe --tray --config vpncloud.yaml` for the tray icon. Keep
`wintun.dll` in that same folder.


### Websocket

Restrictive networks can use the existing proxy:

```sh
vpncloud ws-proxy --listen 8080
vpncloud --listen ws://proxy.example.com:8080 -c OTHER:3210 -p PASS --ip 10.0.0.1/24
```

Or listen for websocket peers on the node itself (no extra proxy process).
Put TLS on nginx / Caddy / cloudflared in front:

```sh
vpncloud --listen ws-listen://0.0.0.0:8080 --ip 10.0.0.1/24 -p PASS
vpncloud --listen ws-listen://0.0.0.0:8081 -c ws://listener.example.com:8080 --ip 10.0.0.2/24 -p PASS
```

`ws://hostname:port` as `--listen` is still the **proxy client**. Unspecified
hosts (`0.0.0.0`, `[::]`, `*`) and the `ws-listen://` scheme bind a native
server.


### Compression

Tunnel compression is **off by default**. Opt in on trusted meshes with
`--compression` (or `compression: true` in the config). DATA / DATA_GSO frames
are LZ4-compressed *before* encryption and only when the result is smaller, so
already-compressed traffic (PNG, gzip, TLS, etc.) is left alone. Peers advertise
support in NodeInfo; older peers never receive compressed frames.

Only direct traffic is compressed — relayed payloads are end-to-end sealed and
incompressible. **Security caveat:** compressing attacker-chosen plaintext
before encryption can leak information via ciphertext lengths
(CRIME/BREACH-style). Leave it off where an adversary can inject tunnel
payloads and observe packet sizes.


### Operations

Validate a config before starting (no TUN or root needed):

```sh
vpncloud check-config --config net.net
```

It reports parse/semantic errors and warns about risky settings (plain crypto,
compression, no peers). Add `--verify-signature` together with `--verify-key`
to check a signed config.

For a running node, set `status-file: /path/to/status.json` in the config (or
`--status-file`) and read it back:

```sh
vpncloud status --config net.net          # human-readable
vpncloud status --config net.net --json   # raw JSON for monitoring
```

The file is refreshed once per second with device name, uptime, traffic
counters, last handshake, and per-peer RTT. Logs now append across restarts
and rotate once past 10 MiB (`<log-file>.old`).

`vpncloud doctor --config net.net` runs preflight checks (TUN access, config
permissions, listen port, clock, peer DNS) without starting the VPN.
`vpncloud config --print --config net.net` prints the effective config with
secrets redacted. `vpncloud network list|start|stop|status <name>` manages
per-network service instances.

For monitoring, `--metrics-addr 127.0.0.1:9090` serves read-only Prometheus
metrics at `/metrics`, and `--log-json` emits structured JSON log lines.
Send `SIGHUP` to reload ACLs, grants, split prefixes, exit-node, and peers
without restarting the TUN device (`vpncloud service reload` on the Windows
service). A reload is verified against the same out-of-band config-signature
keys as the initial load, so `--require-signed-config` cannot be bypassed by
editing the file and signaling the process. Changes to the device, crypto keys,
listen port, and most other settings still require a full restart.

See [Troubleshooting](docs/TROUBLESHOOTING.md),
[Security model](docs/SECURITY.md), and the generated
[CLI reference](docs/CLI.md).

### Per-node keys (no shared password)

By default a mesh share one password or keypair, so every authenticated peer
is equally trusted. With `--per-node-keys` (or `per-node-keys: true`) you can
drop the shared password entirely:

- each node has its **own** `private-key` (generate one with `vpncloud genkey`);
- each node lists the peers it trusts as `trusted-node-key: <node-id-hex>=<base62-public-key>`;
- `node-id` is derived from the private key unless set explicitly.

The handshake then binds the signing key to a specific node id, rejects a key
claimed by a different node, and derives the session key from a transcript of
both identities and both ephemeral keys (unknown-key-share defence). Config
validation fails if you try to use this mode with only a password.

```sh
vpncloud genkey   # run once per node; put the private key in that node's config
vpncloud --per-node-keys --config mynode.net
```

Both ends must enable the mode. It is backward-compatible with shared-key
peers only in the sense that a per-node-key node will refuse to talk to a
shared-key peer — configure all nodes consistently.

### Multiple overlay addresses and site-to-site subnets

A node can announce and use more than one overlay IP with `--local-address
10.9.0.10 --local-address 10.9.0.11` (or `local-addresses:` in the config).
Each address is announced as a `/32` host claim, so peers route to it through
this node. On TAP bridge nodes each IP gets its own synthetic MAC and a local
ARP reply, so a single node can present several Ethernet identities. Linux and
Android assign the extra addresses to the interface automatically; elsewhere use
`ifup` to add them.

For site-to-site routing (e.g. `192.168.0.0/16` on site A and `172.16.0.0/16`
on site B), announce each subnet with `--claim` and make sure the OS on each
site routes those prefixes into the VpnCloud interface — VpnCloud advertises
routes but does not install kernel routes. If clients on one site must appear
as the peer's overlay IP, use OS-level NAT (nftables/iptables) on that peer;
VpnCloud does not rewrite source addresses.

`vpncloud status` now also prints estimated RTTs to remote nodes and a
**suggested relay** derived from quality gossip between peers (bounded and
median-aggregated so one peer cannot skew it). Relay choice is sticky under
small RTT changes. `--install-routes` installs kernel routes for announced
claims (requires privileges; default routes are never installed automatically).

For loop safety, relay and flood frames carry a hop count that is decremented at
each forwarding node; peers that do not advertise this capability keep the
legacy dedup-only format. External Ethernet bridges still need STP — VpnCloud
does not participate in spanning tree.

### Mixed TAP/TUN networks

Normally all nodes must use the same `--type` (TUN = IP packets, TAP = Ethernet
frames). Nodes now advertise the payload formats they can receive in their
`NodeInfo`; a mismatch is rejected with a clear warning instead of being
misparsed. Legacy peers that omit the capability are inferred from their
announced claims (IP vs MAC address lengths).

A TAP node started with `--l2-l3-bridge` can also serve **TUN-only clients**
(e.g. Android VpnService, iOS Packet Tunnel, Wintun):

- DATA payloads are translated per peer: Ethernet headers are stripped for
  IP-only peers and synthesized for the local TAP interface.
- ARP is answered locally from the route table, so L2 broadcast need not cross
  the mesh. Non-IP Ethernet frames (ARP etc.) are never sent to TUN peers.
- Peers still need a route to each other: configure `claims` (or let TUN nodes
  auto-claim their IP). `flood-relay` falls back to per-peer delivery when the
  mesh has mixed formats.

Use `--type tap --l2-l3-bridge` on one or more nodes; TUN clients need no
special flag. All nodes must still share the same crypto settings.

### Network profiles and mobile peers

Set `--profile latency`, `--profile consistency`, or `--profile throughput`
(or `profile:` in the config) to match what your current network is good at:

| Profile | MTU cap | Jitter buffer | Use when |
|---|---|---|---|
| `latency` | 1500 | none | a clean, low-latency link — minimise delay |
| `consistency` | 1500 | 20 ms (tune with `jitter-ms`) | jittery but otherwise good — predictable spacing |
| `throughput` | 9000 (jumbo) | none | very high latency or poor quality — maximise goodput |

`balanced` (the default) keeps the previous behaviour. Individual `mtu`,
`jitter-ms`, and `max-underlay-mtu` settings override the profile.

For phones and other roaming devices, vpncloud tracks a stable node id (set
`node-id`, or derive one from `node-key`) and **migrates the peer immediately**
when it reconnects from a new IP/port — e.g. switching WiFi to 4G. The stale
address is dropped at once instead of blackholing traffic until the old peer
timeout. MTU is tracked per peer, so when a constrained peer leaves (or moves
to a fatter link) the tunnel MTU recovers automatically. Use `--no-mobility`
to disable this.

### Broadcasts with a slow-upload peer

In TAP/Switch/Hub modes a broadcast is normally sent as a separate copy to
every peer. If one node has poor upload, enable `flood-relay: true` (or
`--flood-relay`): the sender emits **one** copy to its lowest-RTT peer, and that
peer redistributes to the rest. The header carries an origin and sequence so
nodes ignore duplicates. This trades a little latency on the broadcast path
for a large reduction in the weak node's upload; leave it off when every link
is fast. Set `flood-relay-via: <node-id-hex>` to pin the redistribution peer
instead of relying on lowest RTT (a weak-upload peer can still have low latency).

### Signed configs

`vpncloud sign-config --config net.net --private-key KEY` appends an Ed25519
signature line. To *enforce* signed configs, supply the verification key
**out of band** — the keys inside the config are peer-trust keys and are never
used as the verification trust anchor:

```sh
vpncloud --config net.net --require-signed-config \
  --verify-key '<base62-public-key>' -p PASS --ip 10.0.0.1/24
```

`--verify-key` is repeatable; `--verify-key-file PATH` reads one base62 key per
line (a root-owned file is the real trust anchor). The GUI accepts keys via
`VPNCLOUD_VERIFY_KEY` (comma/semicolon separated). With `--require-signed-config`
and no out-of-band key, startup fails closed. The signature must be a single
column-zero line at the end of the file; `sign-config` produces that format.


### Semantic versioning

This project uses [semantic versioning](http://semver.org). See [CHANGELOG.md](CHANGELOG.md).


### License

GPL-3.0. Original work Copyright (C) 2015-2021 Dennis Schwerdel.
See [LICENSE.md](LICENSE.md).
