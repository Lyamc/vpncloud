VpnCloud - Peer-to-Peer VPN
---------------------------
![Checks](https://github.com/Lyamc/vpncloud/workflows/Checks/badge.svg?branch=master)
![Security audit](https://github.com/Lyamc/vpncloud/workflows/Security%20audit/badge.svg?branch=master)

**VpnCloud** is a high performance peer-to-peer mesh VPN over UDP with strong
encryption, NAT traversal, and a simple config file. Nodes form a fully meshed,
self-healing network. Traffic is encrypted end-to-end (Curve25519, AES-256 /
ChaCha20) and forwarded over a virtual TUN (IP) or TAP (Ethernet) interface.

This repository is [Lyamc/vpncloud](https://github.com/Lyamc/vpncloud), a fork
of [dswd/vpncloud](https://github.com/dswd/vpncloud). The fork adds **macOS**,
**Windows**, and **Android (TUN only)** support plus protocol, config, and
dependency fixes. Upstream documentation lives at
[vpncloud.ddswd.de](https://vpncloud.ddswd.de).

```sh
vpncloud -c REMOTE_HOST:PORT -p 'mypassword' --ip 10.0.0.1/24
```

Or as a config file (`/etc/vpncloud/mynet.net` on Linux):

```yaml
crypto:
  password: mysecret
ip: 10.0.0.1/24
peers:
  - REMOTE_HOST:PORT
```

See `vpncloud.adoc` (the man page) for every option, and
`assets/example.net.disabled` for a commented template.


### Project status

VpnCloud 2.4.0 on this fork is usable on Linux, macOS, Windows, and Android
(TUN). It includes:

* Automatic peer-to-peer meshing, no central servers
* Automatic reconnect, including several addresses per peer (priority order)
* TUN (IP) and TAP (Ethernet) virtual interfaces
* Linux, macOS (`utun` / `feth`), Windows (Wintun / tap-windows6), Android TUN
* Strong end-to-end encryption (Curve25519, AES-128/256, ChaCha20)
* Hub / switch / router forwarding modes
* NAT hole punching and UPnP port forwarding
* IPv6 transport (`[2001:db8::1]:3210`) and IPv6 overlay (`--ip fd00:1::1/64`)
* Websocket proxy **and** native websocket listen (for nginx / cloudflared)
* Beacons, statsd, hook scripts, configurable MTU
* Single binary, no kernel module

Known limits: on macOS, TAP L2/ARP works but ICMP through `feth` is often
lossy — prefer TUN there. Windows still needs `wintun.dll` (TUN) or
tap-windows6 (TAP) installed, and a Windows build host or a working MinGW
`cc` for `ring`.


### Platforms

**Linux.** Default target. Needs `/dev/net/tun` and usually root. For
unprivileged LXC/Proxmox, bind-mount `/dev/net` and allow cgroup device
`10:200` (see *CONTAINERS* in `vpncloud.adoc`).

**macOS.** TUN uses `utun`. TAP uses `feth` plus BPF. Create the interface
with sudo; `--ip` configures the address. Dual-stack UDP listen works
(`--listen 3210` binds IPv4 and IPv6).

**Windows.** TUN uses [Wintun](https://www.wintun.net/) (`wintun.dll` next to
`vpncloud.exe`). TAP uses [tap-windows6](https://github.com/OpenVPN/tap-windows6)
(NdisWan / `tap0901`). Run as Administrator. Optional system tray (Enable /
Disable / Exit) is offered at `vpncloud install` (build with `--features installer`)
or `vpncloud.exe --tray`. Install prompts for the tray and optional
Start-with-Windows; unattended: `vpncloud install --tray` / `--no-tray` /
`--autostart`.

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


### Installing

Prerequisites: Rust/Cargo (edition 2021, toolchain 1.75+), and on Linux
`asciidoctor` if you want the man page.

```sh
git clone https://github.com/Lyamc/vpncloud.git
cd vpncloud
cargo build --release
sudo ./target/release/vpncloud --help
```

Tests: `cargo test`.

Debian/RPM packaging helpers live in `maskfile.md` (requires
[mask](https://github.com/jacobdeichert/mask)). Systemd units are in
`assets/`.


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


### Semantic versioning

This project uses [semantic versioning](http://semver.org). See [CHANGELOG.md](CHANGELOG.md).


### License

GPL-3.0. Original work Copyright (C) 2015-2021 Dennis Schwerdel.
See [LICENSE.md](LICENSE.md).
