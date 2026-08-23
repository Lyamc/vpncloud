// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! STUN Binding (RFC 5389) — discover the UDP mapped address of the mesh socket.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::util::resolve;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAGIC: u32 = 0x2112_A442;
const ATTR_XOR_MAPPED: u16 = 0x0020;
const ATTR_MAPPED: u16 = 0x0001;

pub fn encode_binding_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    buf[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    buf[8..20].copy_from_slice(txid);
    buf
}

pub fn is_stun_message(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    let typ = u16::from_be_bytes([data[0], data[1]]);
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    magic == MAGIC && (typ == BINDING_SUCCESS || typ == BINDING_REQUEST)
}

pub fn parse_binding_success(data: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 20 {
        return None;
    }
    let typ = u16::from_be_bytes([data[0], data[1]]);
    if typ != BINDING_SUCCESS {
        return None;
    }
    if u32::from_be_bytes([data[4], data[5], data[6], data[7]]) != MAGIC {
        return None;
    }
    if &data[8..20] != txid {
        return None;
    }
    let declared = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + declared {
        return None;
    }
    let mut i = 20;
    let end = 20 + declared;
    while i + 4 <= end {
        let atype = u16::from_be_bytes([data[i], data[i + 1]]);
        let alen = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        let val_start = i + 4;
        let val_end = val_start + alen;
        if val_end > end {
            return None;
        }
        if atype == ATTR_XOR_MAPPED || atype == ATTR_MAPPED {
            if let Some(addr) = parse_mapped(&data[val_start..val_end], txid, atype == ATTR_XOR_MAPPED) {
                return Some(addr);
            }
        }
        i = val_end + (4 - alen % 4) % 4;
    }
    None
}

fn parse_mapped(val: &[u8], txid: &[u8; 12], xored: bool) -> Option<SocketAddr> {
    if val.len() < 4 {
        return None;
    }
    let family = val[1];
    let mut port = u16::from_be_bytes([val[2], val[3]]);
    if xored {
        port ^= (MAGIC >> 16) as u16;
    }
    match family {
        0x01 => {
            if val.len() < 8 {
                return None;
            }
            let mut oct = [val[4], val[5], val[6], val[7]];
            if xored {
                let m = MAGIC.to_be_bytes();
                for i in 0..4 {
                    oct[i] ^= m[i];
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(oct)), port))
        }
        0x02 => {
            if val.len() < 20 {
                return None;
            }
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&val[4..20]);
            if xored {
                let mut mask = [0u8; 16];
                mask[0..4].copy_from_slice(&MAGIC.to_be_bytes());
                mask[4..16].copy_from_slice(txid);
                for i in 0..16 {
                    oct[i] ^= mask[i];
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(oct)), port))
        }
        _ => None
    }
}

pub fn resolve_stun_servers(servers: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for s in servers {
        let host = if s.contains(']') || s.rfind(':').map(|i| s.as_bytes()[..i].contains(&b'.')).unwrap_or(false) {
            s.clone()
        } else if s.contains(':') && s.parse::<SocketAddr>().is_ok() {
            s.clone()
        } else if !s.contains(':') {
            format!("{}:3478", s)
        } else {
            s.clone()
        };
        match resolve(&host) {
            Ok(addrs) => {
                if let Some(a) = addrs.into_iter().next() {
                    out.push(a);
                }
            }
            Err(e) => debug!("STUN: failed to resolve {}: {}", s, e)
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_is_20_bytes() {
        let tx = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let req = encode_binding_request(&tx);
        assert_eq!(req.len(), 20);
        assert!(is_stun_message(&req));
        assert_eq!(&req[8..20], &tx);
    }

    #[test]
    fn parse_xor_mapped_ipv4() {
        let tx = [9u8; 12];
        let ip = Ipv4Addr::new(203, 0, 113, 5);
        let port: u16 = 12345;
        let mut msg = vec![0u8; 32];
        msg[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg[2..4].copy_from_slice(&12u16.to_be_bytes());
        msg[4..8].copy_from_slice(&MAGIC.to_be_bytes());
        msg[8..20].copy_from_slice(&tx);
        msg[20..22].copy_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
        msg[22..24].copy_from_slice(&8u16.to_be_bytes());
        msg[25] = 0x01;
        let xport = port ^ (MAGIC >> 16) as u16;
        msg[26..28].copy_from_slice(&xport.to_be_bytes());
        let m = MAGIC.to_be_bytes();
        let oct = ip.octets();
        for i in 0..4 {
            msg[28 + i] = oct[i] ^ m[i];
        }
        let got = parse_binding_success(&msg, &tx).unwrap();
        assert_eq!(got, SocketAddr::new(IpAddr::V4(ip), port));
    }
}
