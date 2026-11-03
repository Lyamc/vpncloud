// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use crate::{
    error::Error,
    gso::{GsoMeta, GSO_UDP_L4, VIRTIO_F_NEEDS_CSUM},
    types::Address
};
#[cfg(test)] use std::str::FromStr;

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
        if data.len() < 14 {
            return Err(Error::Parse("Frame is too short"));
        }
        let mut src = [0; 16];
        let mut dst = [0; 16];
        dst[..6].copy_from_slice(&data[0..6]);
        src[..6].copy_from_slice(&data[6..12]);
        if data[12] == 0x81 && data[13] == 0x00 {
            if data.len() < 16 {
                return Err(Error::Parse("Vlan frame is too short"));
            }
            src.copy_within(..6, 2);
            dst.copy_within(..6, 2);
            src[..2].copy_from_slice(&data[14..16]);
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
            _ => {
                Err(Error::Parse(
                    "Invalid IP protocol version (check that every node uses the same device type: tun vs tap)"
                ))
            }
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

/// Overlay L4 fields used by ACLs (IP source, protocol, destination port).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OverlayL4 {
    pub ip_src: Option<Address>,
    pub proto: Option<u8>,
    pub dport: Option<u16>
}

/// Parse IP/L4 from a TUN packet or a TAP Ethernet frame.
pub fn overlay_l4(data: &[u8], tap: bool) -> OverlayL4 {
    let ip = if tap { ethernet_payload(data) } else { data };
    parse_ip_l4(ip)
}

fn ethernet_payload(frame: &[u8]) -> &[u8] {
    if frame.len() < 14 {
        return &[];
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut off = 14;
    if ethertype == 0x8100 {
        if frame.len() < 18 {
            return &[];
        }
        ethertype = u16::from_be_bytes([frame[16], frame[17]]);
        off = 18;
    }
    if ethertype != 0x0800 && ethertype != 0x86dd {
        return &[];
    }
    &frame[off..]
}

fn parse_ip_l4(pkt: &[u8]) -> OverlayL4 {
    if pkt.is_empty() {
        return OverlayL4::default();
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return OverlayL4::default();
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            let ip_src = Address::read_from_fixed(&pkt[12..], 4).ok();
            let proto = pkt[9];
            let dport = l4_dport(proto, pkt.get(ihl..).unwrap_or(&[]));
            OverlayL4 { ip_src, proto: Some(proto), dport }
        }
        6 => {
            if pkt.len() < 40 {
                return OverlayL4::default();
            }
            let ip_src = Address::read_from_fixed(&pkt[8..], 16).ok();
            let proto = pkt[6];
            let dport = l4_dport(proto, pkt.get(40..).unwrap_or(&[]));
            OverlayL4 { ip_src, proto: Some(proto), dport }
        }
        _ => OverlayL4::default()
    }
}

fn l4_dport(proto: u8, payload: &[u8]) -> Option<u16> {
    if proto != 6 && proto != 17 {
        return None;
    }
    if payload.len() < 4 {
        return None;
    }
    Some(u16::from_be_bytes([payload[2], payload[3]]))
}

#[test]
fn overlay_l4_ipv4_tcp() {
    let mut pkt = [0u8; 40];
    pkt[0] = 0x45;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    pkt[20..24].copy_from_slice(&[0x04, 0xd2, 0x00, 0x16]); // sport 1234, dport 22
    let l4 = overlay_l4(&pkt, false);
    assert_eq!(l4.proto, Some(6));
    assert_eq!(l4.dport, Some(22));
    assert_eq!(l4.ip_src, Some(Address::from_str("10.0.0.1").unwrap()));
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

/// Finish a virtio `NEEDS_CSUM` transport checksum.
///
/// The field at `csum_start + csum_offset` holds the unfolded pseudo-header sum.
/// The bytes from `csum_start` to the end of the packet are the L4 header and payload.
pub fn finish_virtio_l4_csum(pkt: &mut [u8], csum_start: u16, csum_offset: u16) {
    let start = csum_start as usize;
    let at = start + csum_offset as usize;
    if start > pkt.len() || at + 1 >= pkt.len() {
        return;
    }
    let initial = u16::from_be_bytes([pkt[at], pkt[at + 1]]) as u32;
    pkt[at] = 0;
    pkt[at + 1] = 0;
    let mut sum = initial;
    let data = &pkt[start..];
    let mut chunks = data.chunks_exact(2);
    for c in chunks.by_ref() {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    let sum = fold_checksum(sum);
    pkt[at..at + 2].copy_from_slice(&sum.to_be_bytes());
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
        let mut chunks = l4.chunks_exact(2);
        for c in chunks.by_ref() {
            s += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        if let [b] = chunks.remainder() {
            s += (*b as u32) << 8;
        }
        fold_checksum(s)
    };
    pkt[ihl + check_off..ihl + check_off + 2].copy_from_slice(&check.to_be_bytes());
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in chunks.by_ref() {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    fold_checksum(sum)
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn fold_sum(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// One ordinary UDP datagram that can be glued onto a UDP_L4 aggregate.
///
/// Returns `(header_len, payload_len)`. Header length is the IP header plus
/// the 8-byte UDP header. IPv4 options and IPv6 extension headers are rejected
/// because the kernel will not segment those.
pub fn udp_segment(pkt: &[u8]) -> Option<(usize, usize)> {
    if pkt.len() < 28 {
        return None;
    }
    let (iph, proto_at) = match pkt[0] >> 4 {
        4 => {
            let iph = ((pkt[0] & 0x0f) as usize) * 4;
            if iph != 20 || pkt.len() < iph + 8 {
                return None;
            }
            let frag = (((pkt[6] as u16) & 0x1f) << 8) | pkt[7] as u16;
            if frag != 0 || pkt[6] & 0x20 != 0 {
                return None;
            }
            let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            if total != pkt.len() {
                return None;
            }
            (iph, 9usize)
        }
        6 => {
            if pkt.len() < 48 {
                return None;
            }
            let payload = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            if payload != pkt.len() - 40 {
                return None;
            }
            (40usize, 6usize)
        }
        _ => return None
    };
    if pkt[proto_at] != 17 {
        return None;
    }
    let hdr = iph + 8;
    if pkt.len() <= hdr {
        return None;
    }
    Some((hdr, pkt.len() - hdr))
}

fn udp_same_flow(a: &[u8], b: &[u8]) -> bool {
    match a[0] >> 4 {
        4 => {
            a[1] == b[1]
                && a[6] >> 5 == b[6] >> 5
                && a[8] == b[8]
                && a[12..20] == b[12..20]
                && a[20..24] == b[20..24]
        }
        6 => a[0] == b[0] && a[1] >> 4 == b[1] >> 4 && a[7] == b[7] && a[8..44] == b[8..44],
        _ => false
    }
}

/// How many leading packets form one UDP GSO aggregate, or 0 when fewer than two match.
///
/// `max_len` is the largest IP packet that still fits in one outer UDP datagram.
/// A shorter final datagram is included. Anything after that shorter tail is not,
/// matching the kernel rule that a short segment ends the train.
pub fn udp_gso_span(pkts: &[&[u8]], max_len: usize) -> usize {
    if pkts.len() < 2 || max_len < 28 {
        return 0;
    }
    let Some((hdr, payload)) = udp_segment(pkts[0]) else {
        return 0;
    };
    if payload == 0 || payload > u16::MAX as usize {
        return 0;
    }
    let mut total = pkts[0].len();
    let mut n = 1usize;
    let mut short = false;
    for pkt in &pkts[1..] {
        let Some((hdr2, payload2)) = udp_segment(pkt) else {
            break;
        };
        if hdr2 != hdr || !udp_same_flow(pkts[0], pkt) || short || payload2 > payload {
            break;
        }
        let add = pkt.len() - hdr;
        if add != payload2 || total + add > max_len {
            break;
        }
        if payload2 < payload {
            short = true;
        }
        total += add;
        n += 1;
    }
    if n >= 2 {
        n
    } else {
        0
    }
}

/// Rewrite `pkt` as one UDP_L4 aggregate and return the virtio header for it.
///
/// `hdr` is the IP+UDP header length and `gso_size` is one segment's UDP payload.
/// The checksum field receives the unfolded-then-folded pseudo-header sum with
/// no final inversion. That is the `CHECKSUM_PARTIAL` value the kernel combines
/// with each segment, the same placement WireGuard's TUN GRO uses.
pub fn seal_udp_gso(pkt: &mut [u8], hdr: usize, gso_size: usize) -> Option<GsoMeta> {
    if hdr < 28 || gso_size == 0 || gso_size > u16::MAX as usize || pkt.len() < hdr + gso_size || pkt.len() > 65535 {
        return None;
    }
    let iph = hdr - 8;
    let udp_len = pkt.len() - iph;
    if udp_len > u16::MAX as usize {
        return None;
    }
    let v6 = match pkt[0] >> 4 {
        4 => false,
        6 => true,
        _ => return None
    };
    pkt[iph + 4..iph + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    let pseudo = if v6 {
        if iph != 40 {
            return None;
        }
        pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pseudo_sum(&pkt[8..24], &pkt[24..40], udp_len as u16)
    } else {
        if iph != 20 || pkt.len() > u16::MAX as usize {
            return None;
        }
        let total = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt[10] = 0;
        pkt[11] = 0;
        let ip_sum = internet_checksum(&pkt[..iph]);
        pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        pseudo_sum(&pkt[12..16], &pkt[16..20], udp_len as u16)
    };
    pkt[iph + 6..iph + 8].copy_from_slice(&pseudo.to_be_bytes());
    Some(GsoMeta {
        flags: VIRTIO_F_NEEDS_CSUM,
        gso_type: GSO_UDP_L4,
        hdr_len: hdr as u16,
        gso_size: gso_size as u16,
        csum_start: iph as u16,
        csum_offset: 6
    })
}

fn pseudo_sum(src: &[u8], dst: &[u8], udp_len: u16) -> u16 {
    let mut sum = 0u32;
    for chunk in src.chunks_exact(2).chain(dst.chunks_exact(2)) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += 17;
    sum += udp_len as u32;
    fold_sum(sum)
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

#[cfg(test)]
fn sample_udp(payload: usize, port: u16, fill: u8) -> Vec<u8> {
    let total = 28 + payload;
    let mut pkt = vec![fill; total];
    pkt[..28].fill(0);
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    pkt[20..22].copy_from_slice(&port.to_be_bytes());
    pkt[22..24].copy_from_slice(&9u16.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
    pkt
}

#[test]
fn udp_gso_span_groups_one_flow_and_stops_after_a_short_tail() {
    let a = sample_udp(100, 4000, 0xab);
    let b = sample_udp(100, 4000, 0xcd);
    let short = sample_udp(40, 4000, 0xef);
    let after = sample_udp(100, 4000, 0x11);
    let other = sample_udp(100, 4001, 0x22);
    let pkts = [&a[..], &b[..], &short[..], &after[..]];
    assert_eq!(udp_gso_span(&pkts, 60_000), 3);
    assert_eq!(udp_gso_span(&[&a[..], &other[..]], 60_000), 0);
    assert_eq!(udp_gso_span(&[&a[..], &b[..]], 28 + 100 + 50), 0);
    let mut joined = a.clone();
    joined.extend_from_slice(&b[28..]);
    let meta = seal_udp_gso(&mut joined, 28, 100).unwrap();
    assert_eq!(meta.gso_type, GSO_UDP_L4);
    assert_eq!(meta.gso_size, 100);
    assert_eq!(meta.hdr_len, 28);
    assert_eq!(meta.flags, VIRTIO_F_NEEDS_CSUM);
    assert_eq!(u16::from_be_bytes([joined[2], joined[3]]) as usize, joined.len());
    assert_eq!(&joined[28..128], &a[28..]);
    assert_eq!(&joined[128..], &b[28..]);
}
