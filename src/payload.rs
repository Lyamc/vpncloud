// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use crate::{error::Error, types::Address};
use std::io::{Cursor, Read};

pub trait Protocol: Sized {
    fn parse(_: &[u8]) -> Result<(Address, Address), Error>;
}

/// An ethernet frame dissector
///
/// This dissector is able to extract the source and destination addresses of ethernet frames.
///
/// If the ethernet frame contains a VLAN tag, both addresses will be prefixed with that tag,
/// resulting in 8-byte addresses. Additional nested tags will be ignored.
pub struct Frame;

impl Protocol for Frame {
    /// Parses an ethernet frame and extracts the source and destination addresses
    ///
    /// # Errors
    /// This method will fail when the given data is not a valid ethernet frame.
    fn parse(data: &[u8]) -> Result<(Address, Address), Error> {
        // HOT PATH
        let mut cursor = Cursor::new(data);
        let mut src = [0; 16];
        let mut dst = [0; 16];
        let mut proto = [0; 2];
        cursor
            .read_exact(&mut dst[..6])
            .and_then(|_| cursor.read_exact(&mut src[..6]))
            .and_then(|_| cursor.read_exact(&mut proto))
            .map_err(|_| Error::Parse("Frame is too short"))?;
        if proto == [0x81, 0x00] {
            src.copy_within(..6, 2);
            dst.copy_within(..6, 2);
            cursor.read_exact(&mut src[..2]).map_err(|_| Error::Parse("Vlan frame is too short"))?;
            src[0] &= 0x0f; // restrict vlan id to 12 bits
            dst[..2].copy_from_slice(&src[..2]);
            if src[0..1] == [0, 0] {
                // treat vlan id 0x000 as untagged
                src.copy_within(2..8, 0);
                dst.copy_within(2..8, 0);
                return Ok((Address { data: src, len: 6 }, Address { data: dst, len: 6 }));
            }
            Ok((Address { data: src, len: 8 }, Address { data: dst, len: 8 }))
        } else {
            Ok((Address { data: src, len: 6 }, Address { data: dst, len: 6 }))
        }
    }
}

#[test]
fn decode_frame_without_vlan() {
    let data = [6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address { data: [1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 6 });
    assert_eq!(dst, Address { data: [6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 6 });
}

#[test]
fn decode_frame_with_vlan() {
    let data = [6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 0x81, 0, 4, 210, 1, 2, 3, 4, 5, 6, 7, 8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address { data: [4, 210, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0], len: 8 });
    assert_eq!(dst, Address { data: [4, 210, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0], len: 8 });
}

#[test]
fn decode_invalid_frame() {
    assert!(Frame::parse(&[6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8]).is_ok());
    // truncated frame
    assert!(Frame::parse(&[]).is_err());
    // truncated vlan frame
    assert!(Frame::parse(&[6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 0x81, 0x00]).is_err());
}

/// An IP packet dissector
///
/// This dissector is able to extract the source and destination ip addresses of ipv4 packets and
/// ipv6 packets.
#[allow(dead_code)]
pub struct Packet;

impl Protocol for Packet {
    /// Parses an ip packet and extracts the source and destination addresses
    ///
    /// # Errors
    /// This method will fail when the given data is not a valid ipv4 and ipv6 packet.
    fn parse(data: &[u8]) -> Result<(Address, Address), Error> {
        // HOT PATH
        if data.is_empty() {
            return Err(Error::Parse("Empty header"));
        }
        let version = data[0] >> 4;
        match version {
            4 => {
                if data.len() < 20 {
                    return Err(Error::Parse("Truncated IPv4 header"));
                }
                let src = Address::read_from_fixed(&data[12..], 4)?;
                let dst = Address::read_from_fixed(&data[16..], 4)?;
                Ok((src, dst))
            }
            6 => {
                if data.len() < 40 {
                    return Err(Error::Parse("Truncated IPv6 header"));
                }
                let src = Address::read_from_fixed(&data[8..], 16)?;
                let dst = Address::read_from_fixed(&data[24..], 16)?;
                Ok((src, dst))
            }
            _ => Err(Error::Parse(
                "Invalid IP protocol version (check that every node uses the same device type: tun vs tap)"
            ))
        }
    }
}

#[test]
fn decode_ipv4_packet() {
    let data = [0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2];
    let (src, dst) = Packet::parse(&data).unwrap();
    assert_eq!(src, Address { data: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 4 });
    assert_eq!(dst, Address { data: [192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 4 });
}

#[test]
fn decode_ipv6_packet() {
    let data = [
        0x60, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5,
        4, 3, 2, 1
    ];
    let (src, dst) = Packet::parse(&data).unwrap();
    assert_eq!(src, Address { data: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6], len: 16 });
    assert_eq!(dst, Address { data: [0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5, 4, 3, 2, 1], len: 16 });
}

#[test]
fn decode_invalid_packet() {
    assert!(Packet::parse(&[0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2]).is_ok());
    assert!(Packet::parse(&[
        0x60, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5,
        4, 3, 2, 1
    ])
    .is_ok());
    // no data
    assert!(Packet::parse(&[]).is_err());
    // wrong version
    assert!(Packet::parse(&[0x20]).is_err());
    // truncated ipv4
    assert!(Packet::parse(&[0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1]).is_err());
    // truncated ipv6
    assert!(Packet::parse(&[
        0x60, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5,
        4, 3, 2
    ])
    .is_err());
}

/// Recompute IPv4 / L4 checksums so TAP/feth/BPF offload does not deliver packets the peer kernel drops.
pub fn fix_ethernet_ipv4_checksums(frame: &mut [u8]) {
    if frame.len() < 14 {
        return;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut payload_off = 14;
    if ethertype == 0x8100 {
        if frame.len() < 18 {
            return;
        }
        ethertype = u16::from_be_bytes([frame[16], frame[17]]);
        payload_off = 18;
    }
    if ethertype != 0x0800 {
        return;
    }
    if payload_off >= frame.len() {
        return;
    }
    fix_ipv4_checksums(&mut frame[payload_off..]);
}

pub fn fix_ipv4_checksums(pkt: &mut [u8]) {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return;
    }
    // Only fill checksums that look offloaded (zero). Recomputing a valid checksum in place
    // is fine, but UDP 0 means "disabled" and must be left alone.
    if pkt[10] == 0 && pkt[11] == 0 {
        let ip_sum = internet_checksum(&pkt[..ihl]);
        pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    }

    let proto = pkt[9];
    match proto {
        1 if pkt.len() >= ihl + 4 && pkt[ihl + 2] == 0 && pkt[ihl + 3] == 0 => fix_icmp_checksum(&mut pkt[ihl..]),
        6 if pkt.len() >= ihl + 18 && pkt[ihl + 16] == 0 && pkt[ihl + 17] == 0 => fix_transport_checksum(pkt, ihl, 16),
        17 if pkt.len() >= ihl + 8 && pkt[ihl + 6] == 0 && pkt[ihl + 7] == 0 => {
            // UDP checksum 0 is a legal "no checksum" marker; do not invent one.
        }
        _ => {}
    }
}

fn fix_icmp_checksum(icmp: &mut [u8]) {
    if icmp.len() < 8 {
        return;
    }
    icmp[2] = 0;
    icmp[3] = 0;
    let sum = internet_checksum(icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
}

fn fix_transport_checksum(pkt: &mut [u8], ihl: usize, check_off: usize) {
    if pkt.len() < ihl + check_off + 2 {
        return;
    }
    pkt[ihl + check_off] = 0;
    pkt[ihl + check_off + 1] = 0;
    let l4_len = pkt.len() - ihl;
    let mut sum = 0u32;
    sum += u16::from_be_bytes([pkt[12], pkt[13]]) as u32;
    sum += u16::from_be_bytes([pkt[14], pkt[15]]) as u32;
    sum += u16::from_be_bytes([pkt[16], pkt[17]]) as u32;
    sum += u16::from_be_bytes([pkt[18], pkt[19]]) as u32;
    sum += pkt[9] as u32;
    sum += l4_len as u32;
    let check = {
        let mut s = sum;
        let l4 = &pkt[ihl..];
        let mut i = 0;
        while i + 1 < l4.len() {
            s += u16::from_be_bytes([l4[i], l4[i + 1]]) as u32;
            i += 2;
        }
        if i < l4.len() {
            s += (l4[i] as u32) << 8;
        }
        fold_checksum(s)
    };
    pkt[ihl + check_off..ihl + check_off + 2].copy_from_slice(&check.to_be_bytes());
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    fold_checksum(sum)
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

#[test]
fn ipv4_header_checksum_is_recomputed() {
    // Minimal IPv4 header (20 bytes) + ICMP echo (8 bytes)
    let mut pkt = [
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 2, 10, 0, 0, 1, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x02
    ];
    fix_ipv4_checksums(&mut pkt);
    assert_ne!(&pkt[10..12], &[0, 0]);
    let saved = [pkt[10], pkt[11]];
    pkt[10] = 0;
    pkt[11] = 0;
    assert_eq!(internet_checksum(&pkt[..20]).to_be_bytes(), saved);
    pkt[10..12].copy_from_slice(&saved);
    assert_ne!(&pkt[22..24], &[0, 0]);
    let once = pkt;
    fix_ipv4_checksums(&mut pkt);
    assert_eq!(pkt, once, "checksum fix must be idempotent on valid packets");
}

#[test]
fn ethernet_frame_checksum_skips_non_ipv4() {
    let mut arp = [0u8; 42];
    arp[12] = 0x08;
    arp[13] = 0x06;
    fix_ethernet_ipv4_checksums(&mut arp);
}
