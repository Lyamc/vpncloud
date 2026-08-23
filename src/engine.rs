// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    fs::{self, File, Permissions},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    path::Path,
    process,
    str::FromStr
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{
    cloud::GenericCloud,
    config::{Config, DEFAULT_PORT},
    device::{Device, TunTapDevice, Type},
    net::Socket,
    payload,
    payload::Protocol,
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
        let netmask = if prefix_len == 0 {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::from(u32::MAX << (32 - prefix_len as u32))
        };
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

fn setup_device(config: &Config) -> TunTapDevice {
    let from_fd = config.tun_fd.is_some();
    let mut device = if let Some(fd) = config.tun_fd {
        try_fail!(
            TunTapDevice::from_tun_fd(fd, config.device_type),
            "Failed to adopt TUN fd {}: {}",
            fd
        )
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
    if !from_fd {
        if let Err(err) = device.set_mtu(config.mtu) {
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
    config.call_hook("device_configured", vec![("IFNAME", device.ifname())], true);
    device
}

#[allow(clippy::cognitive_complexity)]
fn run<P: Protocol, S: Socket>(config: Config, socket: S) {
    let device = setup_device(&config);
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
    for addr in config.peers.clone() {
        let group: Vec<&str> = addr.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        if let Some(mut first) = group.first().map(|s| (*s).to_string()) {
            if let Some(rest) = first.strip_prefix("ws://").or_else(|| first.strip_prefix("wss://")) {
                first = rest.to_string();
            }
            if first.find(':').unwrap_or(0) <= first.find(']').unwrap_or(0) {
                first = format!("{}:{}", first, DEFAULT_PORT);
            }
            try_fail!(cloud.connect(&first as &str), "Failed to send message to {}: {}", &first);
        }
        cloud.add_reconnect_peer(addr);
    }
    #[cfg(all(unix, not(target_os = "android")))]
    {
        if config.daemonize {
            info!("Running process as daemon");
            try_fail!(crate::util::unix_daemonize(), "Failed to daemonize: {}");
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

    #[cfg(any(not(unix), target_os = "android"))]
    if config.daemonize || config.user.is_some() || config.group.is_some() {
        warn!("Daemonizing and privilege dropping are not supported on this platform.");
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
    let socket = try_fail!(UdpSocket::listen(&config.listen), "Failed to open socket {}: {}", config.listen);
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
