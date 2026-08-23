// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Local-underlay helpers: interface prefixes, LAN preference, lan-only checks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use getifaddrs::getifaddrs;

use crate::net::mapped_addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8
}

pub fn interface_prefixes() -> Vec<Prefix> {
    let mut out = Vec::new();
    let Ok(iter) = getifaddrs() else {
        return out;
    };
    for iface in iter {
        let Some(ip) = iface.address.ip_addr() else {
            continue;
        };
        if ip.is_loopback() {
            continue;
        }
        let len = match iface.address.netmask() {
            Some(IpAddr::V4(m)) => u32::from(m).count_ones() as u8,
            Some(IpAddr::V6(m)) => u128::from(m).count_ones() as u8,
            None => {
                if ip.is_ipv4() {
                    32
                } else {
                    128
                }
            }
        };
        out.push(Prefix { addr: ip, len });
    }
    out
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4
    }
}

fn prefix_contains(p: Prefix, ip: IpAddr) -> bool {
    let a = unmap(p.addr);
    let b = unmap(ip);
    match (a, b) {
        (IpAddr::V4(pa), IpAddr::V4(pb)) => {
            if p.len >= 32 {
                return pa == pb;
            }
            let mask = if p.len == 0 { 0 } else { u32::MAX << (32 - p.len) };
            (u32::from(pa) & mask) == (u32::from(pb) & mask)
        }
        (IpAddr::V6(pa), IpAddr::V6(pb)) => {
            if p.len >= 128 {
                return pa == pb;
            }
            let mask = if p.len == 0 { 0 } else { u128::MAX << (128 - p.len) };
            (u128::from(pa) & mask) == (u128::from(pb) & mask)
        }
        _ => false
    }
}

pub fn addr_on_local_prefix(addr: SocketAddr, prefixes: &[Prefix]) -> bool {
    let ip = unmap(mapped_addr(addr).ip());
    if let IpAddr::V4(v4) = ip {
        if v4.is_loopback() || v4.is_unspecified() {
            return false;
        }
    }
    prefixes.iter().any(|p| prefix_contains(*p, ip))
}

pub fn sort_lan_first(addrs: &mut [SocketAddr], prefixes: &[Prefix]) {
    addrs.sort_by_key(|a| if addr_on_local_prefix(*a, prefixes) { 0 } else { 1 });
}

pub fn is_private_v4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

pub fn is_ula_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_match_v4() {
        let p = Prefix { addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), len: 24 };
        assert!(prefix_contains(p, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))));
        assert!(!prefix_contains(p, IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
    }

    #[test]
    fn lan_sort() {
        let p = Prefix { addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), len: 8 };
        let mut addrs =
            ["8.8.8.8:3210".parse().unwrap(), "10.1.2.3:3210".parse().unwrap(), "1.2.3.4:3210".parse().unwrap()];
        sort_lan_first(&mut addrs, &[p]);
        assert_eq!(addrs[0], "10.1.2.3:3210".parse().unwrap());
    }
}
