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
    let initial = u16::from_be_bytes([pkt[at], pkt[at + 1]]) as u64;
    pkt[at] = 0;
    pkt[at + 1] = 0;
    let sum = fold_checksum_u64(accum_words(&pkt[start..]) + initial);
    pkt[at..at + 2].copy_from_slice(&sum.to_be_bytes());
}

/// Segments kept on one coalesced train. tun-rs keys a flow by ACK number,
/// so every member has to carry the same ACK or the train splits.
const TCP_GRO_RUN: usize = 64;

/// Make the next in-order TCP segment carry the anchor segment's TCP options
/// and the newest ACK in the run.
///
/// The userspace coalescer refuses unequal option bytes and treats a different
/// ACK number as a different flow. Copying the anchor options and stamping the
/// newest ACK is what lets a full-duplex train merge. The head buffer is the
/// one the coalescer keeps, so that ACK is written there too. An older ACK is
/// not stamped over a newer one. Only a sequence-adjacent segment of the same
/// header length is rewritten. A different header length would move the
/// payload. Pure ACKs are not written. PSH on the segment being extended is
/// cleared, because the coalescer will not append after PSH. The payload is
/// not written. The TCP checksum of a changed segment is cleared so
/// [`fix_ipv4_checksums`] fills it again.
pub fn share_tcp_timestamps_for_gro(pkts: &mut [crate::util::MsgBuffer]) {
    let mut anchors: [Option<TcpTsAnchor>; 4] = [None, None, None, None];
    for index in 0..pkts.len() {
        let Some(mut this) = TcpTsAnchor::parse(pkts[index].message()) else {
            continue;
        };
        this.index = index;
        if this.payload == 0 {
            continue;
        }
        let slot = anchors.iter().position(|a| a.is_some_and(|a| a.same_flow(&this)));
        let Some(slot) = slot else {
            if let Some(empty) = anchors.iter_mut().find(|a| a.is_none()) {
                this.begin_run();
                *empty = Some(this);
            }
            continue;
        };
        let stitch = anchors[slot].is_some_and(|a| {
            a.ihl == this.ihl
                && a.opt_len == this.opt_len
                && this.seq == a.seq.wrapping_add(a.payload as u32)
                && this.payload <= a.payload
                && (a.n_members as usize) < TCP_GRO_RUN
        });
        if !stitch {
            this.begin_run();
            anchors[slot] = Some(this);
            continue;
        }
        let mut run = anchors[slot].unwrap();
        {
            let msg = pkts[index].message_mut();
            let at = this.ihl + 20;
            msg[at..at + run.opt_len].copy_from_slice(&run.options[..run.opt_len]);
            msg[this.ihl + 16] = 0;
            msg[this.ihl + 17] = 0;
        }
        {
            let anchor = pkts[run.index].message_mut();
            let flags = run.ihl + 13;
            if anchor[flags] & 0x08 != 0 {
                anchor[flags] &= !0x08;
                anchor[run.ihl + 16] = 0;
                anchor[run.ihl + 17] = 0;
            }
        }
        run.members[run.n_members as usize] = index as u16;
        run.n_members += 1;
        // wrapping_sub < 2^31 means `this.ack` is equal or newer. An older
        // piggybacked ACK must not move the run backwards.
        if this.ack.wrapping_sub(run.ack) < 0x8000_0000 {
            run.ack = this.ack;
            run.window = this.window;
        }
        stamp_tcp_run(pkts, &run);
        if this.payload == run.payload {
            // `seq` stays the last segment's sequence. Adding the payload here
            // made the next check skip a segment, so a run never grew past two.
            run.seq = this.seq;
            run.index = index;
            anchors[slot] = Some(run);
        } else {
            // A short tail can join the run. Nothing may follow it.
            anchors[slot] = None;
        }
    }
}

/// Write the run's ACK onto every member. The head also takes the run's
/// window, because that is the header the coalescer keeps.
fn stamp_tcp_run(pkts: &mut [crate::util::MsgBuffer], run: &TcpTsAnchor) {
    let ack_b = run.ack.to_be_bytes();
    let win_b = run.window.to_be_bytes();
    let ihl = run.ihl;
    for i in 0..run.n_members as usize {
        let mi = run.members[i] as usize;
        let msg = pkts[mi].message_mut();
        let ack_same = msg[ihl + 8..ihl + 12] == ack_b;
        let win_same = mi != run.head || msg[ihl + 14..ihl + 16] == win_b;
        if ack_same && win_same {
            continue;
        }
        msg[ihl + 8..ihl + 12].copy_from_slice(&ack_b);
        if mi == run.head {
            msg[ihl + 14..ihl + 16].copy_from_slice(&win_b);
        }
        msg[ihl + 16] = 0;
        msg[ihl + 17] = 0;
    }
}

/// IPv4 TCP with a complete header. Pure ACKs are included.
pub fn ipv4_tcp_segment(msg: &[u8]) -> bool {
    if msg.len() < 40 || msg[0] >> 4 != 4 || msg[9] != 6 {
        return false;
    }
    let ihl = ((msg[0] & 0x0f) as usize) * 4;
    ihl >= 20 && msg.len() >= ihl + 20
}

/// IPv4 TCP that carries payload. GRO can merge these; a pure ACK cannot.
pub fn ipv4_tcp_data(msg: &[u8]) -> bool {
    if !ipv4_tcp_segment(msg) {
        return false;
    }
    let ihl = ((msg[0] & 0x0f) as usize) * 4;
    let tcph = ((msg[ihl + 12] >> 4) as usize) * 4;
    tcph >= 20 && msg.len() > ihl + tcph
}

#[derive(Copy, Clone)]
struct TcpTsAnchor {
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    window: u16,
    ihl: usize,
    payload: usize,
    options: [u8; 40],
    opt_len: usize,
    head: usize,
    members: [u16; TCP_GRO_RUN],
    n_members: u16,
    index: usize
}

impl TcpTsAnchor {
    fn parse(pkt: &[u8]) -> Option<Self> {
        if pkt.len() < 40 || pkt[0] >> 4 != 4 {
            return None;
        }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if ihl < 20 || pkt.len() < ihl + 20 || pkt[9] != 6 {
            return None;
        }
        let tcph = ((pkt[ihl + 12] >> 4) as usize) * 4;
        if tcph < 20 || pkt.len() < ihl + tcph {
            return None;
        }
        let mut options = [0u8; 40];
        let opt_len = tcph - 20;
        if opt_len > options.len() {
            return None;
        }
        options[..opt_len].copy_from_slice(&pkt[ihl + 20..ihl + tcph]);
        // A segment with no timestamp is left alone. Rewriting one is what
        // made a later TSval older than the peer's window.
        tcp_timestamp_at(&options[..opt_len])?;
        Some(Self {
            src: pkt[12..16].try_into().ok()?,
            dst: pkt[16..20].try_into().ok()?,
            sport: u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]),
            dport: u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
            seq: u32::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5], pkt[ihl + 6], pkt[ihl + 7]]),
            ack: u32::from_be_bytes([pkt[ihl + 8], pkt[ihl + 9], pkt[ihl + 10], pkt[ihl + 11]]),
            window: u16::from_be_bytes([pkt[ihl + 14], pkt[ihl + 15]]),
            ihl,
            payload: pkt.len() - ihl - tcph,
            options,
            opt_len,
            head: 0,
            members: [0; TCP_GRO_RUN],
            n_members: 0,
            index: 0
        })
    }

    fn begin_run(&mut self) {
        self.head = self.index;
        self.members[0] = self.index as u16;
        self.n_members = 1;
    }

    fn same_flow(&self, other: &Self) -> bool {
        self.src == other.src && self.dst == other.dst && self.sport == other.sport && self.dport == other.dport
    }
}

/// Offset of the 8 timestamp bytes within the TCP options, if the option is well formed.
fn tcp_timestamp_at(options: &[u8]) -> Option<usize> {
    let mut o = 0;
    while o < options.len() {
        let kind = options[o];
        if kind == 0 {
            return None;
        }
        if kind == 1 {
            o += 1;
            continue;
        }
        if o + 1 >= options.len() {
            return None;
        }
        let len = options[o + 1] as usize;
        if len < 2 || o + len > options.len() {
            return None;
        }
        if kind == 8 && len == 10 {
            return Some(o + 2);
        }
        o += len;
    }
    None
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
    let check = fold_checksum_u64(accum_words(&pkt[ihl..]) + sum as u64);
    pkt[ihl + check_off..ihl + check_off + 2].copy_from_slice(&check.to_be_bytes());
}

fn internet_checksum(data: &[u8]) -> u16 {
    fold_checksum_u64(accum_words(data))
}

/// Sum of big-endian 16-bit words. Odd trailing byte is the high byte, matching RFC 1071.
fn accum_words(data: &[u8]) -> u64 {
    let mut sum0 = 0u64;
    let mut sum1 = 0u64;
    let mut chunks = data.chunks_exact(4);
    for c in chunks.by_ref() {
        sum0 += u16::from_be_bytes([c[0], c[1]]) as u64;
        sum1 += u16::from_be_bytes([c[2], c[3]]) as u64;
    }
    let mut sum = sum0 + sum1;
    let rest = chunks.remainder();
    if rest.len() >= 2 {
        sum += u16::from_be_bytes([rest[0], rest[1]]) as u64;
    }
    if rest.len() % 2 == 1 {
        sum += (rest[rest.len() - 1] as u64) << 8;
    }
    sum
}

fn fold_checksum_u64(mut sum: u64) -> u16 {
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

/// The wide sum has to match a one-word-at-a-time RFC 1071 accumulation,
/// including the odd-byte tail and the unfolded pseudo-header the virtio
/// header leaves in the checksum field.
#[test]
fn wide_checksum_matches_a_word_at_a_time_sum() {
    fn naive_accum(data: &[u8]) -> u64 {
        let mut sum = 0u64;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u64;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u64) << 8;
        }
        sum
    }

    let mut state = 0x1234_5678u32;
    let mut next = || {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        (state >> 24) as u8
    };
    let mut buf = vec![0u8; 1430];
    for len in 0..=300 {
        for b in &mut buf[..len] {
            *b = next();
        }
        let slice = &buf[..len];
        assert_eq!(accum_words(slice), naive_accum(slice), "accum len {len}");
        assert_eq!(internet_checksum(slice), fold_checksum_u64(naive_accum(slice)), "csum len {len}");
    }
    for b in &mut buf {
        *b = next();
    }
    assert_eq!(accum_words(&buf), naive_accum(&buf));
    assert_eq!(internet_checksum(&buf), fold_checksum_u64(naive_accum(&buf)));
    buf.fill(0xff);
    assert_eq!(internet_checksum(&buf), fold_checksum_u64(naive_accum(&buf)), "all-ones fold");

    // csum_start sits on the TCP header. The field holds an unfolded pseudo-header sum.
    for (len, pseudo) in [(60usize, 0x1234u16), (1430, 0xabcd), (1431, 0xffff), (41, 0x00ff)] {
        let mut pkt = vec![0u8; len];
        for b in &mut pkt {
            *b = next();
        }
        let start = 20u16;
        let offset = 16u16;
        let at = (start + offset) as usize;
        pkt[at] = (pseudo >> 8) as u8;
        pkt[at + 1] = pseudo as u8;
        let mut expect = pkt.clone();
        expect[at] = 0;
        expect[at + 1] = 0;
        let folded = fold_checksum_u64(naive_accum(&expect[start as usize..]) + pseudo as u64);
        expect[at..at + 2].copy_from_slice(&folded.to_be_bytes());
        finish_virtio_l4_csum(&mut pkt, start, offset);
        assert_eq!(pkt, expect, "virtio finish len {len}");
    }
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
fn tcp_timestamp_share_matches_the_first_segment_and_keeps_the_payload() {
    fn seg(seq: u32, ts: u32, payload: &[u8]) -> crate::util::MsgBuffer {
        let total = 52 + payload.len();
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[20..22].copy_from_slice(&4000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&5201u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&seq.to_be_bytes());
        pkt[32] = 0x80;
        pkt[33] = 0x10;
        pkt[40] = 1;
        pkt[41] = 1;
        pkt[42] = 8;
        pkt[43] = 10;
        pkt[44..48].copy_from_slice(&ts.to_be_bytes());
        pkt[48..52].copy_from_slice(&7u32.to_be_bytes());
        pkt[52..].copy_from_slice(payload);
        let mut buf = crate::util::MsgBuffer::new(0);
        buf.clone_from(&pkt);
        buf
    }
    fn seg_flow(seq: u32, ts: u32, payload: &[u8], dst: u8) -> crate::util::MsgBuffer {
        let mut buf = seg(seq, ts, payload);
        buf.message_mut()[19] = dst;
        buf
    }
    // seq 1 then 5 are adjacent. seq 40 is a gap and must keep its own timestamp.
    // The second flow is interleaved and stitches on its own sequence.
    let mut pkts = [
        seg(1, 100, b"abcd"),
        seg_flow(10, 500, b"ijkl", 9),
        seg(5, 180, b"efgh"),
        seg(9, 999, b""),
        seg(40, 250, b"mnop"),
        seg_flow(14, 700, b"qrst", 9)
    ];
    let ack_ts = pkts[3].message()[44..48].to_vec();
    let gap_ts = pkts[4].message()[44..48].to_vec();
    // Same option length, different layout, and PSH on both data segments.
    // GRO keeps the anchor header and will not append onto PSH.
    {
        let m = pkts[2].message_mut();
        m[33] |= 0x08;
        m[36] = 0x11;
        m[37] = 0x22;
        m[40] = 1;
        m[41] = 8;
        m[42] = 10;
        m[43..47].copy_from_slice(&180u32.to_be_bytes());
        m[47..51].copy_from_slice(&9u32.to_be_bytes());
        m[51] = 1;
    }
    {
        let m = pkts[0].message_mut();
        m[33] |= 0x08;
        m[36] = 0xAB;
        m[37] = 0xCD;
        m[28..32].copy_from_slice(&50u32.to_be_bytes());
    }
    pkts[2].message_mut()[28..32].copy_from_slice(&80u32.to_be_bytes());
    let gap_ack = pkts[4].message()[28..32].to_vec();
    share_tcp_timestamps_for_gro(&mut pkts);
    assert_eq!(&pkts[0].message()[44..48], &100u32.to_be_bytes());
    assert_eq!(pkts[0].message()[33] & 0x08, 0);
    assert_eq!(&pkts[0].message()[36..38], &[0, 0]);
    assert_eq!(&pkts[2].message()[40..52], &pkts[0].message()[40..52]);
    // The coalescer keeps the head header, so the run shares the newer ACK.
    assert_eq!(&pkts[0].message()[28..32], &80u32.to_be_bytes());
    assert_eq!(&pkts[2].message()[28..32], &80u32.to_be_bytes());
    assert_eq!(&pkts[2].message()[44..48], &100u32.to_be_bytes());
    assert_eq!(&pkts[2].message()[52..], b"efgh");
    assert_eq!(&pkts[2].message()[36..38], &[0, 0]);
    assert_ne!(pkts[2].message()[33] & 0x08, 0);
    assert_eq!(&pkts[3].message()[44..48], ack_ts.as_slice());
    assert_eq!(&pkts[4].message()[44..48], gap_ts.as_slice());
    assert_eq!(&pkts[4].message()[28..32], gap_ack.as_slice());
    assert_eq!(&pkts[4].message()[52..], b"mnop");
    assert_eq!(&pkts[1].message()[44..48], &500u32.to_be_bytes());
    assert_eq!(&pkts[5].message()[44..48], &500u32.to_be_bytes());
    assert_eq!(&pkts[5].message()[52..], b"qrst");
    let udp = sample_udp(4, 9, 0);
    assert!(!ipv4_tcp_segment(&udp));
    assert!(!ipv4_tcp_data(&udp));
    assert!(ipv4_tcp_segment(pkts[3].message()));
    assert!(!ipv4_tcp_data(pkts[3].message()));
    assert!(ipv4_tcp_data(pkts[4].message()));
}

#[test]
fn tcp_timestamp_share_stamps_the_newest_ack_on_every_segment() {
    fn seg(seq: u32, ack: u32, window: u16, ts: u32, payload: &[u8], psh: bool) -> crate::util::MsgBuffer {
        let total = 52 + payload.len();
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[20..22].copy_from_slice(&4000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&5201u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&seq.to_be_bytes());
        pkt[28..32].copy_from_slice(&ack.to_be_bytes());
        pkt[32] = 0x80;
        pkt[33] = if psh { 0x18 } else { 0x10 };
        pkt[34..36].copy_from_slice(&window.to_be_bytes());
        pkt[40] = 1;
        pkt[41] = 1;
        pkt[42] = 8;
        pkt[43] = 10;
        pkt[44..48].copy_from_slice(&ts.to_be_bytes());
        pkt[48..52].copy_from_slice(&7u32.to_be_bytes());
        pkt[52..].copy_from_slice(payload);
        let mut buf = crate::util::MsgBuffer::new(0);
        buf.clone_from(&pkt);
        buf
    }
    let mut pkts = [
        seg(1, 10, 1000, 100, b"aaaa", true),
        seg(5, 20, 2000, 200, b"bbbb", true),
        seg(9, 40, 4000, 300, b"cccc", true)
    ];
    share_tcp_timestamps_for_gro(&mut pkts);
    for pkt in &pkts {
        assert_eq!(&pkt.message()[28..32], &40u32.to_be_bytes());
        assert_eq!(&pkt.message()[44..48], &100u32.to_be_bytes());
    }
    // The kept header is the head, so it advertises the newest window.
    assert_eq!(&pkts[0].message()[34..36], &4000u16.to_be_bytes());
    assert_eq!(pkts[0].message()[33] & 0x08, 0);
    assert_eq!(pkts[1].message()[33] & 0x08, 0);
    assert_ne!(pkts[2].message()[33] & 0x08, 0);
    assert_eq!(&pkts[0].message()[52..], b"aaaa");
    assert_eq!(&pkts[1].message()[52..], b"bbbb");
    assert_eq!(&pkts[2].message()[52..], b"cccc");
    // A reordered older ACK must not walk the run backwards.
    let mut older = [seg(100, 50, 1111, 1, b"xxxx", false), seg(104, 40, 2222, 2, b"yyyy", false)];
    share_tcp_timestamps_for_gro(&mut older);
    assert_eq!(&older[0].message()[28..32], &50u32.to_be_bytes());
    assert_eq!(&older[1].message()[28..32], &50u32.to_be_bytes());
    assert_eq!(&older[0].message()[34..36], &1111u16.to_be_bytes());
    assert_eq!(&older[0].message()[52..], b"xxxx");
    assert_eq!(&older[1].message()[52..], b"yyyy");
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
    // Two MTU-sized datagrams stop at an Ethernet budget; two small ones do not.
    let big = sample_udp(1320, 4000, 0x44);
    assert_eq!(big.len(), 1348);
    let v4_budget = crate::mtu::max_gso(1500, crate::mtu::Underlay::V4);
    let v6_budget = crate::mtu::max_gso(1500, crate::mtu::Underlay::V6);
    assert_eq!(udp_gso_span(&[&big[..], &big[..]], v4_budget), 0);
    assert_eq!(udp_gso_span(&[&big[..], &big[..]], v6_budget), 0);
    assert_eq!(udp_gso_span(&[&a[..], &b[..]], v4_budget), 2);
    assert_eq!(udp_gso_span(&[&a[..], &b[..]], v6_budget), 2);
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

#[cfg(test)]
fn sample_udp_v6(payload: usize) -> Vec<u8> {
    let total = 48 + payload;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x60;
    let udp_len = (8 + payload) as u16;
    pkt[4..6].copy_from_slice(&udp_len.to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64;
    pkt[8..24].fill(0x11);
    pkt[24..40].fill(0x22);
    pkt[40..42].copy_from_slice(&4000u16.to_be_bytes());
    pkt[42..44].copy_from_slice(&9u16.to_be_bytes());
    pkt[44..46].copy_from_slice(&udp_len.to_be_bytes());
    pkt
}

#[test]
fn udp_gso_span_ipv6_respects_underlay_budget() {
    let a = sample_udp_v6(100);
    let b = sample_udp_v6(100);
    let budget = crate::mtu::max_gso(1500, crate::mtu::Underlay::V6);
    assert_eq!(udp_gso_span(&[&a[..], &b[..]], budget), 2);
    // 700-byte payloads: 48+700 + 700 = 1448, which is over the 1400-byte IPv6 cap.
    let big = sample_udp_v6(700);
    assert_eq!(udp_gso_span(&[&big[..], &big[..]], budget), 0);
    assert!(big.len() <= crate::mtu::max_plain(1500, crate::mtu::Underlay::V6));
    let mut joined = a.clone();
    joined.extend_from_slice(&b[48..]);
    let meta = seal_udp_gso(&mut joined, 48, 100).unwrap();
    assert_eq!(meta.gso_type, GSO_UDP_L4);
    assert_eq!(meta.hdr_len, 48);
    assert_eq!(u16::from_be_bytes([joined[4], joined[5]]) as usize, joined.len() - 40);
}
