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
**Windows**, **Android**, and **iOS (TUN only)** support plus protocol, config,
and dependency fixes. Upstream documentation lives at
[vpncloud.ddswd.de](https://vpncloud.ddswd.de).

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


### Project status

VpnCloud 2.4.0 on this fork is usable on Linux, macOS, Windows, Android, and
iOS (TUN). It includes:

* Automatic peer-to-peer meshing, no central servers
* Automatic reconnect, including several addresses per peer (priority order)
* TUN (IP) and TAP (Ethernet) virtual interfaces
* Linux, macOS (`utun` / `feth`), Windows (Wintun / tap-windows6), Android TUN,
  iOS TUN (Packet Tunnel Provider)
* Strong end-to-end encryption (Curve25519, AES-128/256, ChaCha20, optional Noise_XX)
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
(`--listen 3210` binds IPv4 and IPv6). `vpncloud install` (installer feature)
registers a LaunchDaemon (`ca.witherow.vpncloud`).

**Windows.** TUN uses [Wintun](https://www.wintun.net/) (`wintun.dll` next to
`vpncloud.exe`). TAP uses [tap-windows6](https://github.com/OpenVPN/tap-windows6)
(NdisWan / `tap0901`). Run as Administrator. See *Installing* below for MSVC
build steps and where `vpncloud install` puts files. Optional system tray
(Enable / Disable / Exit) is offered at `vpncloud install` (build with
`--features installer`) or `vpncloud.exe --tray`. Install prompts for the tray
and optional Start-with-Windows; unattended: `vpncloud install --tray` /
`--no-tray` / `--autostart`. If `wintun.dll` is next to the built exe, `install`
copies it into the install folder.

As a **system service** (Administrator, LocalSystem, auto-start at boot):

```bat
vpncloud service install --config C:\ProgramData\VpnCloud\vpncloud.yaml --start
vpncloud service start
vpncloud service stop
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

Prerequisites: Rust/Cargo (edition 2021, toolchain 1.75+). On Linux, install
`asciidoctor` if you want the man page. The `install` subcommand is compiled
only with `--features installer`.

```sh
git clone https://github.com/Lyamc/vpncloud.git
cd vpncloud
cargo test
```

#### Linux

```sh
cargo build --release --features installer
sudo ./target/release/vpncloud --help
sudo ./target/release/vpncloud install
```

That copies the binary, example config, man page, and the systemd units
`vpncloud@.service`, `vpncloud.target`, and `vpncloud-wsproxy.service`
(same templates as `assets/`). Enable a network with
`sudo systemctl enable --now vpncloud@mynet`.

Desktop GUI (Iced, software renderer — not pulled into the CLI):

```sh
cargo build --release --features gui --bin vpncloud-gui
sudo ./target/release/vpncloud-gui                 # optional path: vpncloud-gui ./mynet.yaml
```

Debian/RPM packaging helpers live in `maskfile.md` (requires
[mask](https://github.com/jacobdeichert/mask)). Systemd units are in
`assets/`.

#### macOS

```sh
cargo build --release --features installer
sudo ./target/release/vpncloud install
```

Copies `/usr/bin/vpncloud`, writes `/etc/vpncloud/`, and registers LaunchDaemon
`ca.witherow.vpncloud` (`/usr/bin/vpncloud --config /etc/vpncloud/vpncloud.yaml`).
Edit that config, then:

```sh
sudo launchctl start ca.witherow.vpncloud
```

Uninstall: `sudo ./target/release/vpncloud install --uninstall`.

#### Windows

Windows has no in-box TUN/TAP. **TUN** needs [Wintun](https://www.wintun.net/)
(`wintun.dll` next to `vpncloud.exe`). **TAP** needs the
[tap-windows6](https://github.com/OpenVPN/tap-windows6) driver. Creating the
virtual interface requires **Administrator**.

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   with the **Desktop development with C++** workload. The GNU Rust toolchain
   (`x86_64-pc-windows-gnu`) also needs a MinGW `cc` on `PATH` because `ring`
   compiles C; **MSVC is the path that works out of the box**.

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

4. Optional TAP: install a tap-windows6 release from
   [OpenVPN downloads](https://build.openvpn.net/downloads/releases/)
   (hardware id `tap0901` / NdisWan).

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


### Semantic versioning

This project uses [semantic versioning](http://semver.org). See [CHANGELOG.md](CHANGELOG.md).


### License

GPL-3.0. Original work Copyright (C) 2015-2021 Dennis Schwerdel.
See [LICENSE.md](LICENSE.md).
