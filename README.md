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
**Windows**, **FreeBSD**, **Android**, and **iOS (TUN only)** support plus
protocol, config, and dependency fixes. Upstream documentation lives at
[vpncloud.ddswd.de](https://vpncloud.ddswd.de).

Prebuilt **2.4.3** binaries are on
[GitHub Releases](https://github.com/Lyamc/vpncloud/releases/tag/v2.4.3)
(`SHA256SUMS` in the same release). Mesh protocol is compatible with 2.4.0
peers.

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

VpnCloud 2.4.3 on this fork is usable on Linux, macOS, FreeBSD, Windows,
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


### Platforms

**Linux.** Default target. Needs `/dev/net/tun` and usually root. For
unprivileged LXC/Proxmox, bind-mount `/dev/net` and allow cgroup device
`10:200` (see *CONTAINERS* in `vpncloud.adoc`).

**macOS.** TUN uses `utun`. TAP uses `feth` plus BPF. Create the interface
with `sudo` from a terminal (`sudo vpncloud --type tun --ip 10.0.0.2/24
-c HOST:3210 -p PASS`). Dual-stack UDP listen works (`--listen 3210` binds
IPv4 and IPv6). `--daemon` from a one-shot GUI/osascript helper can die when
that helper exits; persist with `vpncloud install` (LaunchDaemon
`ca.witherow.vpncloud`), then `sudo launchctl start ca.witherow.vpncloud`.

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

Download a 2.4.3 binary from
[GitHub Releases](https://github.com/Lyamc/vpncloud/releases/tag/v2.4.3)
(checksums in `SHA256SUMS`):

| File | Platform |
|---|---|
| `vpncloud-2.4.3-linux-x86_64` | Linux CLI, x86_64, static musl |
| `vpncloud-2.4.3-linux-aarch64` | Linux CLI, ARM64, static musl |
| `vpncloud-2.4.3-freebsd-x86_64` | FreeBSD CLI, x86_64 (FreeBSD 15 `libc.so.7`) |
| `vpncloud-2.4.3-macos-universal` | macOS CLI, Intel + Apple silicon |
| `vpncloud-gui-2.4.3-macos-universal` | macOS GUI |
| `vpncloud-2.4.3-windows-x86_64-setup.exe` | Windows installer (x86_64): CLI, GUI, Wintun |
| `vpncloud-2.4.3-windows-aarch64-setup.exe` | Windows installer (ARM64): CLI, GUI, Wintun |
| `vpncloud-2.4.3-windows-x86_64.zip` | Windows portable zip (x86_64) |
| `vpncloud-2.4.3-windows-aarch64.zip` | Windows portable zip (ARM64) |
| `vpncloud-2.4.3-windows-x86_64.exe` | Windows CLI only, x86_64 (needs `wintun.dll` for TUN) |
| `vpncloud-2.4.3-windows-aarch64.exe` | Windows CLI only, ARM64 (needs `wintun.dll` for TUN) |
| `vpncloud-gui-2.4.3-windows-x86_64.exe` | Windows GUI only, x86_64 |
| `vpncloud-gui-2.4.3-windows-aarch64.exe` | Windows GUI only, ARM64 |
| `vpncloud-2.4.3-android-debug.apk` | Android, signed debug, arm64-v8a + armeabi-v7a |
| `vpncloud-2.4.3-android-release-unsigned.apk` | Android, unsigned release |
| `libvpncloud-2.4.3.xcframework.tar.gz` | iOS static lib (device + simulator arm64) |

There is no Windows fat/universal PE and no FreeBSD ARM64 build. The NSIS
setup stub is 32-bit (runs on x64 and ARM64 Windows); the payload matches the
filename architecture. The Android release APK must be signed before
distribution. The iOS artifact is an xcframework for a Packet Tunnel
extension, not a signed IPA.

To build from source: Rust/Cargo (edition 2021, toolchain 1.75+). On Linux,
install `asciidoctor` if you want the man page. The `install` subcommand is
compiled only with `--features installer`. AES-GCM can use AWS-LC instead of
`ring` (`cargo build --release --features aws-lc`; needs cmake). Noise still
uses `ring` via `snow`.

```sh
git clone https://github.com/Lyamc/vpncloud.git
cd vpncloud
cargo test
```

#### Linux

Static musl binaries from the release run on most distributions (no glibc
version pin). Example:

```sh
chmod +x vpncloud-2.4.3-linux-x86_64
sudo ./vpncloud-2.4.3-linux-x86_64 --help
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

Desktop GUI (Iced, software renderer — not pulled into the CLI):

```sh
cargo build --release --features gui --bin vpncloud-gui
sudo ./target/release/vpncloud-gui                 # optional path: vpncloud-gui ./mynet.yaml
```

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

Copies `/usr/bin/vpncloud`, writes `/etc/vpncloud/`, and registers LaunchDaemon
`ca.witherow.vpncloud` (`/usr/bin/vpncloud --config /etc/vpncloud/vpncloud.yaml`).
Edit that config, then:

```sh
sudo launchctl start ca.witherow.vpncloud
```

Uninstall: `sudo ./target/release/vpncloud install --uninstall`.

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

The GitHub release has an NSIS installer and a portable zip per architecture
(`vpncloud-2.4.3-windows-x86_64-setup.exe` / `.zip`, and the ARM64 pair). Both
include `vpncloud.exe`, `vpncloud-gui.exe`, and the official Wintun 0.14.1 DLL
plus its license. The setup.exe writes `C:\Program Files\VpnCloud`, Start Menu
shortcuts, an uninstaller, and optionally PATH, a LocalSystem service, and a
download of OpenVPN's tap-windows6 installer (TAP/L2; SHA-256 verified; not
shipped in the setup). Rebuild with `./contrib/windows/package.sh` (needs
`makensis`).

Standalone `vpncloud-2.4.3-windows-*.exe` CLI/GUI builds are still published;
put `wintun.dll` next to the CLI for TUN if you are not using the installer.

To build from source:

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


### Semantic versioning

This project uses [semantic versioning](http://semver.org). See [CHANGELOG.md](CHANGELOG.md).


### License

GPL-3.0. Original work Copyright (C) 2015-2021 Dennis Schwerdel.
See [LICENSE.md](LICENSE.md).
