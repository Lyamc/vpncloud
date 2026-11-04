// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    fs::{self, File},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    process,
    str::FromStr
};

#[cfg(unix)] use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{
    cloud::{ensure_peer_port, GenericCloud},
    config::{Config, DEFAULT_PORT},
    device::{Device, TunTapDevice, Type},
    mesh::MeshSocket,
    mtu::{ipv6_header_budget, shaped_inner_bps, token_bucket},
    net::{parse_listen, path_mtu, set_tx_pace, Socket},
    payload,
    payload::Protocol,
    poll::Pollable,
    util::SystemTimeSource
};

#[cfg(feature = "websocket")]
use crate::wsproxy::{native_ws_bind, ProxyConnection, WsNativeSocket};

pub fn parse_ip_netmask(addr: &str) -> Result<(IpAddr, Option<Ipv4Addr>, Option<u8>), String> {
    let (ip_str, prefix_opt) = match addr.find('/') {
        Some(pos) => (&addr[..pos], Some(&addr[pos + 1..])),
        None => (addr, None)
    };
    if let Ok(ip) = Ipv4Addr::from_str(ip_str) {
        let prefix_len = match prefix_opt {
            Some(s) => u8::from_str(s).map_err(|_| format!("Invalid prefix length: {}", s))?,
            None => 24
        };
        if prefix_len > 32 {
            return Err(format!("Invalid prefix length: {}", prefix_len));
        }
        let netmask =
            if prefix_len == 0 { Ipv4Addr::UNSPECIFIED } else { Ipv4Addr::from(u32::MAX << (32 - prefix_len as u32)) };
        return Ok((IpAddr::V4(ip), Some(netmask), Some(prefix_len)));
    }
    if let Ok(ip) = Ipv6Addr::from_str(ip_str) {
        let prefix_len = match prefix_opt {
            Some(s) => u8::from_str(s).map_err(|_| format!("Invalid prefix length: {}", s))?,
            None => 64
        };
        if prefix_len > 128 {
            return Err(format!("Invalid prefix length: {}", prefix_len));
        }
        return Ok((IpAddr::V6(ip), None, Some(prefix_len)));
    }
    Err(format!("Invalid ip address: {}", ip_str))
}

fn run_script(script: &str, ifname: &str) {
    #[cfg(unix)]
    let (cmd_name, cmd_arg) = ("sh", "-c");
    #[cfg(windows)]
    let (cmd_name, cmd_arg) = ("cmd", "/C");

    let mut cmd = process::Command::new(cmd_name);
    cmd.arg(cmd_arg).arg(script).env("IFNAME", ifname);
    debug!("Running script: {:?}", cmd);
    match cmd.status() {
        Ok(status) => {
            if !status.success() {
                error!("Script returned with error: {:?}", status.code())
            }
        }
        Err(e) => error!("Failed to execute script {:?}: {}", script, e)
    }
}

/// Socket addresses from `--peer`, skipping hostnames. `connect` is not used:
/// a name that does not parse has no route to probe.
fn peer_sockets(peers: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for peer in peers {
        for part in peer.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let part = part.strip_prefix("wss://").or_else(|| part.strip_prefix("ws://")).unwrap_or(part);
            if let Ok(sa) = part.parse::<SocketAddr>() {
                out.push(sa);
                continue;
            }
            if let Ok(ip) = part.parse::<IpAddr>() {
                out.push(SocketAddr::new(ip, DEFAULT_PORT));
            }
        }
    }
    out
}

/// Smallest probed peer path MTU, and whether the outer header is IPv6.
///
/// A dual-stack listen (the default bare port, which binds `[::]`) uses the
/// IPv4 budget when every configured peer is IPv4. Any real IPv6 peer, or
/// no peer at all, keeps the IPv6 budget so one tunnel MTU fits that path.
/// No successful probe means a 1500-byte Ethernet path, never an unbounded one.
fn underlay_limit(config: &Config) -> (usize, bool) {
    let listen = parse_listen(&config.listen, DEFAULT_PORT);
    let listen_v6 = match listen.ip() {
        IpAddr::V4(_) => false,
        IpAddr::V6(ip) => ip.to_ipv4_mapped().is_none()
    };
    let mut best: Option<usize> = None;
    let mut peer_is_ipv6 = Vec::new();
    for mut dst in peer_sockets(&config.peers) {
        let v6 = match dst.ip() {
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(v4) => {
                    dst = SocketAddr::new(IpAddr::V4(v4), dst.port());
                    false
                }
                None => true
            },
            IpAddr::V4(_) => false
        };
        peer_is_ipv6.push(v6);
        match path_mtu(dst) {
            Ok(mtu) if (68..=65535).contains(&mtu) => {
                best = Some(best.map_or(mtu, |cur| cur.min(mtu)));
            }
            Ok(mtu) => debug!("Ignoring path MTU {} for {}", mtu, dst),
            Err(err) => debug!("Path MTU probe {} failed: {}", dst, err)
        }
    }
    let ipv6 = ipv6_header_budget(listen_v6, &peer_is_ipv6);
    let l2 = best.unwrap_or(1500);
    info!("Underlay path MTU {} using {} header budget", l2, if ipv6 { "IPv6" } else { "IPv4" });
    (l2, ipv6)
}

fn route_target(dst: SocketAddr) -> IpAddr {
    match dst.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
        v4 => v4
    }
}

/// Device token from `ip -o route get`. `None` when the line has no `dev`.
fn dev_from_route_get(text: &str) -> Option<&str> {
    let mut parts = text.split_whitespace();
    while let Some(tok) = parts.next() {
        if tok == "dev" {
            return parts.next().filter(|dev| !dev.is_empty() && !dev.contains('/'));
        }
    }
    None
}

/// Sysfs `speed` is megabits per second. `-1` and `0` mean the device has no
/// reported rate (veth, some virtual links) and must not be paced.
fn speed_text_to_bps(text: &str) -> u64 {
    match text.trim().parse::<i64>() {
        Ok(mbps) if mbps > 0 => (mbps as u64).saturating_mul(1_000_000),
        _ => 0
    }
}

/// Slowest positive egress speed toward a configured peer, or 0 if none report one.
fn egress_bitrate(config: &Config) -> u64 {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        return 0;
    }
    #[cfg(target_os = "linux")]
    {
        let mut best: Option<u64> = None;
        for dst in peer_sockets(&config.peers) {
            let bps = link_bitrate(route_target(dst));
            if bps > 0 {
                best = Some(best.map_or(bps, |cur| cur.min(bps)));
            }
        }
        best.unwrap_or(0)
    }
}

#[cfg(target_os = "linux")]
fn link_bitrate(ip: IpAddr) -> u64 {
    let output = match process::Command::new("ip").args(["-o", "route", "get", &ip.to_string()]).output() {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            debug!("ip route get {} failed: {}", ip, String::from_utf8_lossy(&out.stderr).trim());
            return 0;
        }
        Err(err) => {
            debug!("ip route get {} failed: {}", ip, err);
            return 0;
        }
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let Some(dev) = dev_from_route_get(&text) else {
        debug!("ip route get {} has no device: {}", ip, text.trim());
        return 0;
    };
    match fs::read_to_string(format!("/sys/class/net/{}/speed", dev)) {
        Ok(speed) => speed_text_to_bps(&speed),
        Err(err) => {
            debug!("Could not read {} speed: {}", dev, err);
            0
        }
    }
}

fn setup_device(config: &Config) -> (TunTapDevice, usize, bool) {
    let from_fd = config.tun_fd.is_some();
    let mut device = if let Some(fd) = config.tun_fd {
        try_fail!(TunTapDevice::from_tun_fd(fd, config.device_type), "Failed to adopt TUN fd {}: {}", fd)
    } else {
        try_fail!(
            TunTapDevice::new(&config.device_name, config.device_type, config.device_path.as_ref().map(|s| s as &str)),
            "Failed to open virtual {} interface {}: {}",
            config.device_type,
            config.device_name
        )
    };
    info!("Opened device {}", device.ifname());
    config.call_hook("device_setup", vec![("IFNAME", device.ifname())], true);
    // Before seccomp and privilege drop. A link that reports no speed (veth,
    // many virtual devices) stays unpaced so a same-host run is not capped.
    let (l2_mtu, ipv6_underlay) = underlay_limit(config);
    let link_bps = egress_bitrate(config);
    if !from_fd {
        if let Err(err) = device.set_mtu_capped(config.mtu, l2_mtu, ipv6_underlay) {
            error!("Error setting optimal MTU on {}: {}", device.ifname(), err);
        }
        if let Some(ip) = &config.ip {
            let (addr, netmask, prefix) = try_fail!(parse_ip_netmask(ip), "Invalid ip address given: {}");
            info!("Configuring device with ip {}", ip);
            try_fail!(device.configure_ip(addr, netmask, prefix), "Failed to configure device: {}");
        }
        if let Some(script) = &config.ifup {
            run_script(script, device.ifname());
        }
        if config.fix_rp_filter {
            try_fail!(device.fix_rp_filter(), "Failed to change rp_filter settings: {}");
        }
        if let Ok(val) = device.get_rp_filter() {
            if val != 1 {
                warn!("Your networking configuration might be affected by a vulnerability (https://vpncloud.ddswd.de/docs/security/cve-2019-14899/), please change your rp_filter setting to 1 (currently {}).", val);
            }
        }
    }
    // The TUN driver drops when its ring is full and still reports success to
    // the sender, so a userspace sleep never blocks iperf. A fair queue on
    // the tunnel is what keeps one TCP direction's ACKs from waiting behind
    // the other direction's data.
    if !install_tunnel_shaper(device.ifname(), link_bps, ipv6_underlay) {
        set_tx_pace(link_bps);
        if link_bps > 0 {
            info!("Pacing underlay sends at {} Mbit/s", link_bps / 1_000_000);
        }
    } else {
        set_tx_pace(0);
    }
    config.call_hook("device_configured", vec![("IFNAME", device.ifname())], true);
    (device, l2_mtu, ipv6_underlay)
}

/// Replace the tunnel qdisc with a shaper. The rate is on-wire bits and every
/// packet is charged the encapsulation overhead, so a short packet stays under
/// the link and a full-MTU packet still fills it. Returns false when the link
/// speed is unknown or `tc` fails.
fn install_tunnel_shaper(ifname: &str, link_bps: u64, ipv6: bool) -> bool {
    // Re-apply after device setup. A qdisc replace must not leave the ring short.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    crate::device::widen_tx_queue(ifname);
    if link_bps == 0 {
        return false;
    }
    let bucket = token_bucket(link_bps, ipv6);
    if bucket.rate_bps < 1_000_000 {
        return false;
    }
    if install_split_shaper(ifname, link_bps, ipv6, &bucket) {
        log_shaper(ifname, &bucket, link_bps, "split cake");
        return true;
    }
    let rate_arg = format!("{}bit", bucket.rate_bps);
    let overhead_arg = bucket.overhead.to_string();
    // One queue when the split shaper is unavailable. 50ms (2.5ms drop
    // target) lets a full UDP socket block before cobalt discards the flood.
    // `raw` would ignore overhead.
    let cake = [
        "qdisc", "replace", "dev", ifname, "root", "cake", "bandwidth", rate_arg.as_str(), "overhead",
        overhead_arg.as_str(), "rtt", "50ms", "besteffort"
    ];
    if tc_ok(&cake) {
        log_shaper(ifname, &bucket, link_bps, "cake");
        return true;
    }
    let tbf = [
        "qdisc", "replace", "dev", ifname, "root", "tbf", "rate", rate_arg.as_str(), "burst", "64kb", "latency",
        "200ms", "overhead", overhead_arg.as_str()
    ];
    if tc_ok(&tbf) {
        log_shaper(ifname, &bucket, link_bps, "token bucket");
        return true;
    }
    info!("Could not shape {}", ifname);
    false
}

fn device_mtu(ifname: &str) -> Option<u64> {
    let text = fs::read_to_string(format!("/sys/class/net/{}/mtu", ifname)).ok()?;
    let mtu = text.trim().parse().ok()?;
    if mtu >= 576 {
        Some(mtu)
    } else {
        None
    }
}

/// TCP keeps a short cake queue so ACKs are not stuck behind the other
/// direction. UDP is paced by fq under its own class so a flood blocks the
/// sender instead of being discarded by cake's drop target. `raw` is not
/// passed: it would ignore the overhead.
fn install_split_shaper(ifname: &str, link_bps: u64, ipv6: bool, bucket: &crate::mtu::TokenBucket) -> bool {
    let Some(mtu) = device_mtu(ifname) else {
        return false;
    };
    let udp_rate = shaped_inner_bps(link_bps, mtu, ipv6);
    if udp_rate < 1_000_000 {
        return false;
    }
    let rate_arg = format!("{}bit", bucket.rate_bps);
    let overhead_arg = bucket.overhead.to_string();
    let udp_arg = format!("{}bit", udp_rate);
    // quantum = class_rate / r2q. 800000 puts the UDP class under one packet and
    // HTB clamps it. 10000 keeps the 10gbit and the shaped UDP quanta in range.
    let htb = ["qdisc", "replace", "dev", ifname, "root", "handle", "1:", "htb", "default", "10", "r2q", "10000"];
    let parent = ["class", "replace", "dev", ifname, "parent", "1:", "classid", "1:1", "htb", "rate", "10gbit", "ceil", "10gbit"];
    let tcp_class = [
        "class", "replace", "dev", ifname, "parent", "1:1", "classid", "1:10", "htb", "rate", "10gbit", "ceil", "10gbit",
        "burst", "1mb", "prio", "1"
    ];
    let udp_class = [
        "class", "replace", "dev", ifname, "parent", "1:1", "classid", "1:20", "htb", "rate", udp_arg.as_str(), "ceil",
        udp_arg.as_str(), "burst", "64kb", "prio", "1"
    ];
    let cake = [
        "qdisc", "replace", "dev", ifname, "parent", "1:10", "handle", "10:", "cake", "bandwidth", rate_arg.as_str(),
        "overhead", overhead_arg.as_str(), "rtt", "10ms", "besteffort"
    ];
    let fq = [
        "qdisc", "replace", "dev", ifname, "parent", "1:20", "handle", "20:", "fq", "limit", "20000", "flow_limit",
        "20000", "quantum", "1514", "initial_quantum", "15140"
    ];
    let udp4 = [
        "filter", "replace", "dev", ifname, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip",
        "protocol", "17", "0xff", "flowid", "1:20"
    ];
    let udp6 = [
        "filter", "replace", "dev", ifname, "parent", "1:", "protocol", "ipv6", "prio", "2", "u32", "match", "ip6",
        "protocol", "17", "0xff", "flowid", "1:20"
    ];
    tc_ok(&htb)
        && tc_ok(&parent)
        && tc_ok(&tcp_class)
        && tc_ok(&udp_class)
        && tc_ok(&cake)
        && tc_ok(&fq)
        && tc_ok(&udp4)
        && tc_ok(&udp6)
}

fn tc_ok(args: &[&str]) -> bool {
    matches!(process::Command::new("tc").args(args).status(), Ok(status) if status.success())
}

fn log_shaper(ifname: &str, bucket: &crate::mtu::TokenBucket, link_bps: u64, kind: &str) {
    info!(
        "Shaping {} to {} Mbit/s for a {} Mbit/s underlay (overhead {} bytes, {})",
        ifname,
        bucket.rate_bps / 1_000_000,
        link_bps / 1_000_000,
        bucket.overhead,
        kind
    );
}

#[allow(clippy::cognitive_complexity)]
fn run<P: Protocol, S: Socket + Pollable>(config: Config, socket: S) {
    let (device, l2_mtu, ipv6_underlay) = setup_device(&config);
    let port_forwarding = if config.port_forwarding { socket.create_port_forwarding() } else { None };
    let stats_file = match config.stats_file {
        None => None,
        Some(ref name) => {
            let path = Path::new(name);
            if path.exists() {
                try_fail!(fs::remove_file(path), "Failed to remove file {}: {}", name);
            }
            let file = try_fail!(File::create(name), "Failed to create stats file: {}");
            #[cfg(unix)]
            try_fail!(
                fs::set_permissions(name, Permissions::from_mode(0o644)),
                "Failed to set permissions on stats file: {}"
            );
            Some(file)
        }
    };
    let mut cloud =
        GenericCloud::<TunTapDevice, P, S, SystemTimeSource>::new(&config, socket, device, port_forwarding, stats_file);
    // Advertised to peers. A smaller far-side MTU lowers the tunnel again
    // once the handshake carries it; this call only publishes the local NIC.
    cloud.set_local_underlay(l2_mtu, ipv6_underlay);
    for addr in config.peers.clone() {
        let group: Vec<&str> = addr.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        if let Some(first) = group.first() {
            let first = ensure_peer_port(first);
            try_fail!(cloud.connect(&first as &str), "Failed to send message to {}: {}", &first);
        }
        cloud.add_reconnect_peer(addr);
    }
    #[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
    {
        if config.daemonize {
            info!("Running process as daemon");
            try_fail!(crate::util::unix_daemonize(), "Failed to daemonize: {}");
            cloud.restart_crypto_pool();
            if let Some(ref pid_file) = config.pid_file {
                try_fail!(
                    fs::write(pid_file, format!("{}\n", process::id())),
                    "Failed to write pid file {}: {}",
                    pid_file
                );
            }
        }
        if config.user.is_some() || config.group.is_some() {
            info!("Dropping privileges");
            let mut pd = privdrop::PrivDrop::default();
            if let Some(ref user) = config.user {
                pd = pd.user(user);
            }
            if let Some(ref group) = config.group {
                pd = pd.group(group);
            }
            try_fail!(pd.apply(), "Failed to drop privileges: {}");
        }
    }

    #[cfg(any(not(unix), target_os = "android", target_os = "ios"))]
    if config.daemonize || config.user.is_some() || config.group.is_some() {
        warn!("Daemonizing and privilege dropping are not supported on this platform.");
    }
    if config.seccomp {
        crate::seccomp::apply();
    }
    cloud.run();
    if let Some(script) = config.ifdown {
        run_script(&script, cloud.ifname());
    }
}

/// Run a VpnCloud node from a fully merged config. Blocks until shutdown.
pub fn run_vpn(mut config: Config) {
    crate::util::CtrlC::clear_stop();
    if config.tun_fd.is_some() {
        config.port_forwarding = false;
        config.daemonize = false;
    }
    #[cfg(windows)]
    if config.tray {
        if config.daemonize {
            unsafe {
                windows_sys::Win32::System::Console::FreeConsole();
            }
        }
        crate::tray::run(config);
        return;
    }
    #[cfg(target_os = "android")]
    if config.device_type == Type::Tap {
        if config.tun_fd.is_some() {
            fail!(
                "{}",
                "TAP cannot use --tun-fd (VpnService is TUN-only). TAP on Android requires a rooted device. See --help."
            );
        }
        if !crate::device::android_has_tuntap_access() {
            fail!("{}", crate::device::ANDROID_TAP_HELP);
        }
    }
    #[cfg(target_os = "android")]
    if config.listen.starts_with("ws://") || config.listen.starts_with("ws-listen://") {
        fail!("{}", "Websocket listen is not supported on Android; use UDP (--listen PORT).");
    }
    #[cfg(target_os = "ios")]
    if config.device_type == Type::Tap {
        fail!("{}", crate::device::IOS_TAP_HELP);
    }
    #[cfg(target_os = "ios")]
    if config.listen.starts_with("ws://") || config.listen.starts_with("ws-listen://") {
        fail!("{}", "Websocket listen is not supported on iOS; use UDP (--listen PORT).");
    }

    run_vpn_worker(config);
}

/// Socket + device loop. On Windows the tray calls this from a worker thread.
pub(crate) fn run_vpn_worker(config: Config) {
    #[cfg(feature = "websocket")]
    if native_ws_bind(&config.listen).is_some() {
        let socket = try_fail!(
            WsNativeSocket::listen(&config.listen),
            "Failed to open websocket listen socket {}: {}",
            config.listen
        );
        match config.device_type {
            Type::Tap => run::<payload::Frame, _>(config, socket),
            Type::Tun => run::<payload::Packet, _>(config, socket)
        }
        return;
    }
    #[cfg(feature = "websocket")]
    if config.listen.starts_with("ws://") {
        let socket = try_fail!(ProxyConnection::listen(&config.listen), "Failed to open socket {}: {}", config.listen);
        match config.device_type {
            Type::Tap => run::<payload::Frame, _>(config, socket),
            Type::Tun => run::<payload::Packet, _>(config, socket)
        }
        return;
    }
    let socket = try_fail!(
        MeshSocket::open_with_buffers(&config.listen, config.tcp_fallback, config.socket_buffer_bytes),
        "Failed to open socket {}: {}",
        config.listen
    );
    match config.device_type {
        Type::Tap => run::<payload::Frame, _>(config, socket),
        Type::Tun => run::<payload::Packet, _>(config, socket)
    }
}

#[cfg(test)]
mod parse_ip_tests {
    use super::parse_ip_netmask;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn bare_ipv4_defaults_to_slash_24() {
        let (ip, mask, prefix) = parse_ip_netmask("10.67.89.1").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 67, 89, 1)));
        assert_eq!(mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(prefix, Some(24));
    }

    #[test]
    fn explicit_prefix() {
        let (ip, mask, prefix) = parse_ip_netmask("10.67.89.1/16").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 67, 89, 1)));
        assert_eq!(mask, Some(Ipv4Addr::new(255, 255, 0, 0)));
        assert_eq!(prefix, Some(16));
    }

    #[test]
    fn ipv6_unique_local() {
        let (ip, mask, prefix) = parse_ip_netmask("fd00:1::1/64").unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1)));
        assert_eq!(mask, None);
        assert_eq!(prefix, Some(64));
    }
}

#[cfg(test)]
mod egress_pace_tests {
    use super::{dev_from_route_get, route_target, speed_text_to_bps};
    use std::net::SocketAddr;

    #[test]
    fn route_get_device_is_the_dev_token() {
        assert_eq!(dev_from_route_get("192.168.88.2 dev enp4s0 src 192.168.88.1 uid 0 cache"), Some("enp4s0"));
        assert_eq!(
            dev_from_route_get("fd00:88::2 from :: dev enp0s20f0u5 src fd00:88::1 metric 256 pref medium"),
            Some("enp0s20f0u5")
        );
        assert_eq!(dev_from_route_get("local 127.0.0.1 dev lo src 127.0.0.1"), Some("lo"));
        assert_eq!(dev_from_route_get("unreachable"), None);
        assert_eq!(dev_from_route_get("192.168.88.2 dev ../enp4s0"), None);
    }

    #[test]
    fn unknown_link_speed_is_not_paced() {
        assert_eq!(speed_text_to_bps("1000\n"), 1_000_000_000);
        assert_eq!(speed_text_to_bps("-1\n"), 0);
        assert_eq!(speed_text_to_bps("0"), 0);
        assert_eq!(speed_text_to_bps(""), 0);
        assert_eq!(speed_text_to_bps("nope"), 0);
    }

    #[test]
    fn mapped_peer_is_routed_as_ipv4() {
        let mapped: SocketAddr = "[::ffff:192.168.88.2]:3210".parse().unwrap();
        assert_eq!(route_target(mapped).to_string(), "192.168.88.2");
        let v6: SocketAddr = "[fd00:88::2]:3210".parse().unwrap();
        assert_eq!(route_target(v6).to_string(), "fd00:88::2");
    }
}
