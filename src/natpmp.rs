// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! NAT-PMP (RFC 6886) UDP mapping. Sent from the mesh socket so the mapped port matches.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

pub const NATPMP_PORT: u16 = 5351;

pub fn encode_udp_mapping(internal: u16, suggested_external: u16, lifetime_secs: u32) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0] = 0;
    buf[1] = 1; // UDP map
    buf[4..6].copy_from_slice(&internal.to_be_bytes());
    buf[6..8].copy_from_slice(&suggested_external.to_be_bytes());
    buf[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
    buf
}

pub fn is_natpmp_response(data: &[u8]) -> bool {
    data.len() >= 16 && data[0] == 0 && data[1] == 0x81
}

pub fn parse_udp_mapping(data: &[u8]) -> Option<(u16, u16, u32)> {
    if !is_natpmp_response(data) {
        return None;
    }
    let result = u16::from_be_bytes([data[2], data[3]]);
    if result != 0 {
        return None;
    }
    let internal = u16::from_be_bytes([data[8], data[9]]);
    let external = u16::from_be_bytes([data[10], data[11]]);
    let lifetime = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    Some((internal, external, lifetime))
}

/// Guess the IPv4 gateway as x.x.x.1 on the same /24 as `local`.
pub fn guess_gateway(local: Ipv4Addr) -> SocketAddr {
    let o = local.octets();
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(o[0], o[1], o[2], 1), NATPMP_PORT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_request_shape() {
        let req = encode_udp_mapping(3210, 3210, 1800);
        assert_eq!(req[1], 1);
        assert_eq!(&req[4..6], &3210u16.to_be_bytes());
    }

    #[test]
    fn parse_success() {
        let mut msg = [0u8; 16];
        msg[1] = 0x81;
        msg[8..10].copy_from_slice(&3210u16.to_be_bytes());
        msg[10..12].copy_from_slice(&40000u16.to_be_bytes());
        msg[12..16].copy_from_slice(&1800u32.to_be_bytes());
        let (int, ext, life) = parse_udp_mapping(&msg).unwrap();
        assert_eq!((int, ext, life), (3210, 40000, 1800));
    }
}
