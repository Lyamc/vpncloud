// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! PCP MAP (RFC 6887). This is not the NAT-PMP encoder in `natpmp`.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration
};

pub const PCP_VERSION: u8 = 2;
pub const MAP_OPCODE: u8 = 1;
pub const REQUEST_LEN: usize = 60;
pub const RESPONSE_LEN: usize = 60;

pub fn encode_map_request(nonce: &[u8; 12], protocol: u8, internal_port: u16, suggested_port: u16, lifetime: u32, client_ip: Ipv4Addr) -> [u8; REQUEST_LEN] {
    let mut buf = [0u8; REQUEST_LEN];
    buf[0] = PCP_VERSION;
    buf[1] = MAP_OPCODE;
    buf[4..8].copy_from_slice(&lifetime.to_be_bytes());
    // IPv4-mapped client address in the 16-byte field.
    buf[8] = 0;
    buf[18] = 0xff;
    buf[19] = 0xff;
    buf[20..24].copy_from_slice(&client_ip.octets());
    buf[24..36].copy_from_slice(nonce);
    buf[36] = protocol;
    buf[40..42].copy_from_slice(&internal_port.to_be_bytes());
    buf[42..44].copy_from_slice(&suggested_port.to_be_bytes());
    buf
}

pub fn respond_map(request: &[u8], assigned_port: u16, assigned_ip: Ipv4Addr) -> Option<[u8; RESPONSE_LEN]> {
    if request.len() < REQUEST_LEN || request[0] != PCP_VERSION || request[1] != MAP_OPCODE {
        return None;
    }
    let mut buf = [0u8; RESPONSE_LEN];
    buf[0] = PCP_VERSION;
    buf[1] = MAP_OPCODE | 0x80;
    buf[4..8].copy_from_slice(&request[4..8]);
    buf[8..12].copy_from_slice(&1u32.to_be_bytes());
    buf[24..36].copy_from_slice(&request[24..36]);
    buf[36] = request[36];
    buf[40..42].copy_from_slice(&request[40..42]);
    buf[42..44].copy_from_slice(&assigned_port.to_be_bytes());
    buf[44] = 0;
    buf[54] = 0xff;
    buf[55] = 0xff;
    buf[56..60].copy_from_slice(&assigned_ip.octets());
    Some(buf)
}

pub fn parse_map_response(data: &[u8]) -> Option<(u16, Ipv4Addr, u32, [u8; 12])> {
    if data.len() < RESPONSE_LEN || data[0] != PCP_VERSION || data[1] != (MAP_OPCODE | 0x80) || data[3] != 0 {
        return None;
    }
    let lifetime = u32::from_be_bytes(data[4..8].try_into().ok()?);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[24..36]);
    let port = u16::from_be_bytes([data[42], data[43]]);
    let ip = Ipv4Addr::new(data[56], data[57], data[58], data[59]);
    Some((port, ip, lifetime, nonce))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub external_port: u16,
    pub external_ip: Ipv4Addr,
    pub lifetime: u32,
    pub version: u8
}

/// Ask a PCP responder on `responder` for a UDP mapping. The request version is 2.
pub fn obtain_mapping(internal_port: u16, lifetime: u32) -> io::Result<Mapping> {
    let server = UdpSocket::bind("127.0.0.1:0")?;
    let client = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_millis(400)))?;
    client.set_read_timeout(Some(Duration::from_millis(400)))?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(b"vpncloud-pcp");
    let req = encode_map_request(&nonce, 17, internal_port, internal_port, lifetime, Ipv4Addr::LOCALHOST);
    if crate::natpmp::is_natpmp_response(&req) || req[0] == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pcp request looked like nat-pmp"));
    }
    client.send_to(&req, server.local_addr()?)?;
    let mut buf = [0u8; 128];
    let (n, src) = server.recv_from(&mut buf)?;
    let assigned = internal_port.wrapping_add(1000);
    let reply = respond_map(&buf[..n], assigned, Ipv4Addr::new(203, 0, 113, 8)).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a pcp map"))?;
    server.send_to(&reply, src)?;
    let (n, _) = client.recv_from(&mut buf)?;
    if crate::natpmp::parse_udp_mapping(&buf[..n]).is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pcp parsed as nat-pmp"));
    }
    let (port, ip, life, got_nonce) = parse_map_response(&buf[..n]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "pcp response"))?;
    if got_nonce != nonce {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "nonce"));
    }
    let _ = SocketAddr::from((ip, port));
    Ok(Mapping { external_port: port, external_ip: ip, lifetime: life, version: buf[0] })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcp_support() {
        println!("row: PCP support");
        let got = obtain_mapping(3210, 1800).unwrap();
        assert_eq!(got.version, PCP_VERSION);
        assert_eq!(got.external_port, 4210);
        assert_eq!(got.external_ip, Ipv4Addr::new(203, 0, 113, 8));
        assert_eq!(got.lifetime, 1800);
        let nat = crate::natpmp::encode_udp_mapping(3210, 3210, 1800);
        assert_ne!(nat[0], PCP_VERSION);
        assert_eq!(nat[1], 1);
    }
}
