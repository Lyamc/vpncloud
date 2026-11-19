# Troubleshooting

Start with `vpncloud doctor --config <file>` — it checks the config, TUN/TAP
access, the listen port, the system clock, and peer DNS without starting the
VPN. `vpncloud check-config --config <file>` gives detailed config errors and
warnings.

## "Permission denied creating tun device"

The virtual network interface needs elevated privileges.

- **Linux / FreeBSD / macOS**: run as root (`sudo vpncloud ...`) or grant the
  binary the appropriate capability (`CAP_NET_ADM`/`CAP_NET_RAW` on Linux).
- **Windows**: run as Administrator. TUN needs `wintun.dll` beside
  `vpncloud.exe`; TAP needs the tap-windows6 driver (`tap0901`). Both are
  installed by `vpncloud install`, which offers to download a missing driver.
- **Android**: TUN requires the `VpnService` fd (`--tun-fd`) or a rooted device.
- **iOS**: only TUN via Packet Tunnel Provider is possible; pass `--tun-fd`.

## "LoadLibraryExW failed" (Windows)

`wintun.dll` is missing. Copy it next to `vpncloud.exe` or run
`vpncloud install` and accept the driver download. Check the architecture:
`amd64` vs `arm64`.

## Peers connect but no traffic flows

1. **Overlay IP**: both peers need addresses in the same prefix
   (`--ip 10.0.0.1/24` / `10.0.0.2/24`). `vpncloud config --print` shows the
   effective config with secrets redacted.
2. **Mode**: `normal` learns peers via handshakes; `router`/`switch` need
   matching `--mode` on all nodes.
3. **ACL**: an allow-only ACL is a whitelist — anything not explicitly allowed
   is denied. Check `--acl` and warnings from `check-config`.
4. **Firewall**: allow UDP on the listen port (default 3210). Relayed traffic
   still travels over UDP between peers.
5. **MTU**: run `vpncloud status` after setting `status-file` and compare the
   reported device with the underlay MTU. Lower `--mtu` if large packets are
   dropped.

## Packet loss / low throughput

- Check `status --json` for per-peer RTT and traffic counters.
- Linux: TUN GSO/GRO and batched UDP are enabled by default; verify with
  `ethtool` on the underlay NIC. Very high loss usually means the underlay
  MTU is wrong.
- `--crypto-threads` offloads AEAD to workers; many peers benefit, one fat
  TCP flow does not.
- Compression (`--compression`) is off by default. Enabling it only helps
  compressible traffic and has a security caveat — see `docs/SECURITY.md`.

## Config signature errors

`--require-signed-config` needs a verification key supplied **out of band**
(`--verify-key`, `--verify-key-file`, or `VPNCLOUD_VERIFY_KEY`). Keys inside the
config file are peer-trust keys and are never used as the trust anchor. The
signature must be the last non-empty line, at column zero. Re-sign with
`vpncloud sign-config --config <file> --private-key <key>` after edits.

## WebSocket connections fail

- `ws://host:port` as `--listen` is a **proxy client**; a native server uses
  `ws-listen://0.0.0.0:port` or an unspecified bind address.
- The websocket proxy is unauthenticated by design — firewall it or put it
  behind TLS in a reverse proxy.
- Frames larger than 65 KiB are rejected because a UDP datagram cannot be
  larger.

## Where to look

- Log file: `--log-file PATH` (appends across restarts, rotates to `.old` at
  10 MiB). `--verbose`/`-v` enables debug logs; `-vv` or `--log-level trace`
  enables trace logs. `RUST_LOG=target=level,...` (e.g. `RUST_LOG=trace` or
  `RUST_LOG=vpncloud::cloud=debug`) overrides the level per module.
- `--wire-log` logs a bounded hex dump (first 64 bytes) of every message after
  decryption and before encryption, with direction, peer, message type and
  length. It implies trace level. **Payloads may contain sensitive data** — the
  dump goes to stdout and the `--log-file`, so use it only for short local
  debugging sessions and protect the log file.
- For underlay packet capture use `tcpdump -ni <iface> udp port 3210 -w cap.pcap`
  (the payload is encrypted); pair it with `--wire-log` to see plaintext.
- Status file: `status-file: /path` then `vpncloud status [--json]`. The status
  also lists estimated RTTs to remote nodes and a **suggested relay** derived
  from quality reports gossiped by peers. Each peer line shows `throttled=`
  (dropped payloads) and `penalty=` (current rate penalty) when the per-peer
  token bucket has engaged.
- `vpncloud check-config`, `vpncloud doctor`, and `vpncloud config --print`
  cover most configuration problems without a restart.

## Diagnosing a noisy or misbehaving peer

If throughput drops or `throttled=` grows for one peer, check that its clock
and crypto settings match, then raise `--per-peer-rate-limit` (or disable it
with `--no-per-peer-rate-limit` on a trusted LAN). The penalty recovers once
the peer stops exceeding its bucket. `vpncloud_peer_throttled_total` and
`vpncloud_peer_penalty` on the `--metrics-addr` endpoint expose the same data
for dashboards.

## Broadcast storms and loops

Relay and flood frames carry a hop count between TTL-capable peers and are
dropped at zero; duplicate suppression (`flood_seen`/`relay_seen`) still applies
to older peers. `--flood-relay` reduces a full-mesh broadcast from O(N²) to O(N)
copies. VpnCloud does **not** run STP — if you bridge the TAP interface with
other network components, configure spanning tree there to prevent L2 loops.

