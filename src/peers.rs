// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Peer address parsing, DNS resolution and reconnect scheduling.
//! Extracted from `cloud.rs` so the datapath module stays focused on routing.

use std::net::{IpAddr, Ipv6Addr};

use smallvec::smallvec;

use crate::{
    config::DEFAULT_PORT,
    lan,
    messages::AddrList,
    types::{Address, Range},
    util::{resolve, Time}
};

pub const MAX_RECONNECT_INTERVAL: u16 = 3600;
pub const RESOLVE_INTERVAL: Time = 300;

#[derive(Clone)]
pub struct ReconnectEntry {
    pub address: Option<(Vec<String>, Time)>,
    pub resolved: AddrList,
    pub tries: u16,
    pub timeout: u16,
    pub next: Time,
    pub final_timeout: Option<Time>,
    /// When true, `resolved` is a priority list: try one address per interval, highest first.
    pub prefer_order: bool,
    pub try_index: usize
}

/// Append [`DEFAULT_PORT`] when the peer string has none.
///
/// A colon inside `[ipv6]` is not a port separator. `[fd00::2]:3210` stays as
/// written; `[fd00::2]` and a bare address gain `:3210`.
pub fn ensure_peer_port(addr: &str) -> String {
    let addr = addr.trim();
    let addr = addr.strip_prefix("ws://").or_else(|| addr.strip_prefix("wss://")).unwrap_or(addr);
    if let Some(inner) = addr.strip_prefix('[') {
        if let Some(bracket) = inner.find(']') {
            let after = &inner[bracket + 1..];
            if after.is_empty() {
                return format!("[{}]:{}", &inner[..bracket], DEFAULT_PORT);
            }
            return addr.to_string();
        }
    }
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => format!("{}:{}", v4, DEFAULT_PORT),
            IpAddr::V6(v6) => format!("[{}]:{}", v6, DEFAULT_PORT)
        };
    }
    if let Some((host, port)) = addr.rsplit_once(':') {
        if !host.is_empty() && !port.is_empty() && !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            return addr.to_string();
        }
    }
    format!("{}:{}", addr, DEFAULT_PORT)
}

pub(crate) fn split_peer_group(add: &str) -> Vec<String> {
    add.split(',').map(str::trim).filter(|s| !s.is_empty()).map(ensure_peer_port).collect()
}

/// Host route for a configured IPv6 `--ip`. A /64 would match the peer as well.
/// IPv4 keeps the interface /32 from `Device::address`.
pub(crate) fn configured_ipv6_host_claim(spec: Option<&str>) -> Option<Range> {
    let spec = spec?;
    let ip_str = spec.split('/').next().unwrap_or(spec).trim();
    let v6 = ip_str.parse::<Ipv6Addr>().ok()?;
    Some(Range { base: Address::from(v6), prefix_len: 128, metric: 0 })
}

pub(crate) fn resolve_peer_group(names: &[String]) -> AddrList {
    let mut resolved = smallvec![];
    for name in names {
        match resolve(name as &str) {
            Ok(addrs) => resolved.extend(addrs),
            Err(err) => warn!("Failed to resolve {}: {:?}", name, err)
        }
    }
    let prefixes = lan::interface_prefixes();
    lan::sort_lan_first(&mut resolved, &prefixes);
    resolved
}

pub(crate) fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false)
    }
}

#[cfg(test)]
mod ensure_peer_port_tests {
    use super::ensure_peer_port;

    #[test]
    fn bracketed_ipv6_keeps_an_explicit_port() {
        assert_eq!(ensure_peer_port("[fd00:88::2]:3210"), "[fd00:88::2]:3210");
        assert_eq!(ensure_peer_port("wss://[fd00::2]:3210"), "[fd00::2]:3210");
        assert_eq!(ensure_peer_port("[fd00::2]"), "[fd00::2]:3210");
        assert_eq!(ensure_peer_port("fd00::2"), "[fd00::2]:3210");
    }

    #[test]
    fn ipv4_and_hostnames_gain_a_port_once() {
        assert_eq!(ensure_peer_port("192.168.88.2"), "192.168.88.2:3210");
        assert_eq!(ensure_peer_port("example.com"), "example.com:3210");
        assert_eq!(ensure_peer_port("example.com:3210"), "example.com:3210");
        assert_eq!(ensure_peer_port("ws://example.com"), "example.com:3210");
    }
}
