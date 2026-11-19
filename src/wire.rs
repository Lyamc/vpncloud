// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Wire-format negotiation and the L2/L3 compatibility shim.
//!
//! The mesh can carry either raw IP packets (TUN, layer 3) or Ethernet frames
//! (TAP, layer 2). `WireFormat` is the format used for a given DATA payload;
//! `WireCaps` is the set of formats a peer can receive, advertised in
//! `NodeInfo` so a mismatch is detected before a packet is misparsed.

use crate::{
    device::Type,
    error::Error,
    payload::{Frame, Packet, Protocol},
    types::{Address, RangeList}
};

/// The format of a DATA payload on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireFormat {
    Ethernet,
    Ip
}

impl WireFormat {
    /// The native format of a local interface type.
    pub const fn from_device_type(device: Type) -> Self {
        match device {
            Type::Tap => Self::Ethernet,
            Type::Tun => Self::Ip
        }
    }

    pub const fn is_ip(self) -> bool {
        matches!(self, Self::Ip)
    }

    /// Parse a payload, validating strictly so a frame of the wrong format is
    /// rejected instead of being learned as garbage addresses.
    pub fn parse(self, data: &[u8]) -> Result<(Address, Address), Error> {
        match self {
            Self::Ethernet => Frame::parse(data),
            Self::Ip => Packet::parse(data)
        }
    }
}

/// Capability bits advertised in the `PART_WIRE_FORMAT` NodeInfo part.
///
/// Bit 0: can receive Ethernet frames (L2). Bit 1: can receive raw IP (L3).
/// Bit 2: prefers IP when both are supported (used by L2/L3 bridge nodes).
/// Zero means "legacy peer that does not advertise capabilities".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireCaps(u8);

impl WireCaps {
    pub const ETHERNET: Self = Self(0x01);
    pub const IP: Self = Self(0x02);
    pub const PREFER_IP: Self = Self(0x04);
    /// Understands an optional hop-count byte in relay and flood headers.
    pub const TTL: Self = Self(0x08);

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & 0x0f)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn is_unknown(self) -> bool {
        self.0 == 0
    }

    pub const fn can_ethernet(self) -> bool {
        self.0 & Self::ETHERNET.0 != 0
    }

    pub const fn can_ip(self) -> bool {
        self.0 & Self::IP.0 != 0
    }

    pub const fn prefers_ip(self) -> bool {
        self.0 & Self::PREFER_IP.0 != 0
    }

    /// Whether this peer can receive the given format.
    pub const fn can(self, format: WireFormat) -> bool {
        match format {
            WireFormat::Ethernet => self.can_ethernet(),
            WireFormat::Ip => self.can_ip()
        }
    }

    /// Capabilities of an ordinary node: its native format plus hop counts.
    pub const fn for_device(device: Type) -> Self {
        match device {
            Type::Tap => Self(Self::ETHERNET.0 | Self::TTL.0),
            Type::Tun => Self(Self::IP.0 | Self::TTL.0)
        }
    }

    /// A TAP node with the L2/L3 bridge enabled can accept both formats.
    pub const fn for_bridge() -> Self {
        Self(Self::ETHERNET.0 | Self::IP.0 | Self::TTL.0)
    }

    pub const fn has_ttl(self) -> bool {
        self.0 & Self::TTL.0 != 0
    }

    /// Infer the format of a legacy peer from the length of its announced
    /// claims: 4/16-byte addresses are IP, 6/8-byte are MACs. Returns unknown
    /// when the claims are empty or mixed.
    pub fn infer_from_claims(claims: &RangeList) -> Self {
        let mut ip = false;
        let mut eth = false;
        for claim in claims {
            match claim.base.len {
                4 | 16 => ip = true,
                6 | 8 => eth = true,
                _ => {}
            }
        }
        match (ip, eth) {
            (true, false) => Self::IP,
            (false, true) => Self::ETHERNET,
            (true, true) => Self(Self::ETHERNET.0 | Self::IP.0),
            (false, false) => Self(0)
        }
    }

    /// Pick the format to use when sending to a peer. Prefers the peer's
    /// preference when we support it, then any mutually supported format.
    pub fn choose_format(self, peer: Self, peer_claims: &RangeList) -> WireFormat {
        let peer = if peer.is_unknown() { Self::infer_from_claims(peer_claims) } else { peer };
        if peer.can_ethernet() && self.can_ethernet() {
            if peer.prefers_ip() && self.can_ip() {
                return WireFormat::Ip;
            }
            return WireFormat::Ethernet;
        }
        if peer.can_ip() && self.can_ip() {
            return WireFormat::Ip;
        }
        // No overlap: use our native format. The send gate will drop the
        // packet with a clear warning rather than letting the peer misparse it.
        WireFormat::from_device_type(if self.can_ethernet() { Type::Tap } else { Type::Tun })
    }
}

/// Length of the Ethernet header of an IPv4/IPv6 frame (14, or 18 with one
/// VLAN tag). Returns `None` for non-IP frames which cannot cross a TUN link.
pub fn ethernet_header_len(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut off = 14;
    if ethertype == 0x8100 {
        if frame.len() < 18 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[16], frame[17]]);
        off = 18;
    }
    if ethertype != 0x0800 && ethertype != 0x86dd {
        return None;
    }
    Some(off)
}

/// Strip a valid IPv4/IPv6 Ethernet header, returning the inner IP packet.
/// Returns `None` for non-IP frames (ARP, unknown EtherTypes) which cannot be
/// carried on a TUN link.
pub fn strip_ethernet(frame: &[u8]) -> Option<&[u8]> {
    let off = ethernet_header_len(frame)?;
    Some(&frame[off..])
}

/// Prepend an Ethernet header with the given MACs to an IP packet.
pub fn wrap_ip(ip: &[u8], src_mac: [u8; 6], dst_mac: [u8; 6]) -> Option<Vec<u8>> {
    let ethertype = match ip.first()? >> 4 {
        4 => 0x0800u16,
        6 => 0x86ddu16,
        _ => return None
    };
    let mut out = Vec::with_capacity(ip.len() + 14);
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(ip);
    Some(out)
}

/// A stable, locally-administered unicast MAC for a node. Using the node id
/// keeps the same peer MAC across reconnects from a new address.
pub fn synthetic_mac(node_id: &[u8; 16]) -> [u8; 6] {
    let mut mac = [0u8; 6];
    mac[0] = 0x02;
    mac[1..].copy_from_slice(&node_id[..5]);
    mac
}

/// A distinct synthetic MAC for a specific (node, IPv4 address) pair. This is
/// what lets one node announce several overlay IPs, each with its own Ethernet
/// address, without needing multiple daemon instances.
pub fn synthetic_mac_for_ip(node_id: &[u8; 16], ip: [u8; 4]) -> [u8; 6] {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in node_id.iter().chain(ip.iter()) {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut mac = [0u8; 6];
    // Locally administered, unicast.
    mac[0] = 0x02;
    mac[1..].copy_from_slice(&hash.to_le_bytes()[..5]);
    mac
}

/// Build an ARP reply for `who has <ip>` using `mac`. Only IPv4 Ethernet
/// requests for the given target are answered.
pub fn arp_reply(request: &[u8], ip: [u8; 4], mac: [u8; 6]) -> Option<Vec<u8>> {
    if request.len() < 42 || u16::from_be_bytes([request[12], request[13]]) != 0x0806 {
        return None;
    }
    let arp = &request[14..];
    if u16::from_be_bytes([arp[0], arp[1]]) != 1
        || u16::from_be_bytes([arp[2], arp[3]]) != 0x0800
        || arp[4] != 6
        || arp[5] != 4
        || u16::from_be_bytes([arp[6], arp[7]]) != 1
        || [arp[24], arp[25], arp[26], arp[27]] != ip
    {
        return None;
    }
    let requester_mac = &arp[8..14];
    let requester_ip = &arp[14..18];
    let mut out = Vec::with_capacity(42);
    out.extend_from_slice(requester_mac);
    out.extend_from_slice(&mac);
    out.extend_from_slice(&[0x08, 0x06]);
    let mut reply = [0u8; 28];
    reply[..2].copy_from_slice(&1u16.to_be_bytes());
    reply[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    reply[4] = 6;
    reply[5] = 4;
    reply[6..8].copy_from_slice(&2u16.to_be_bytes());
    reply[8..14].copy_from_slice(&mac);
    reply[14..18].copy_from_slice(&ip);
    reply[18..24].copy_from_slice(requester_mac);
    reply[24..28].copy_from_slice(requester_ip);
    out.extend_from_slice(&reply);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Range};
    use std::str::FromStr;

    #[test]
    fn caps_roundtrip_bits() {
        let caps = WireCaps::for_bridge();
        assert!(caps.can_ethernet());
        assert!(caps.can_ip());
        assert!(WireCaps::from_bits(caps.bits()) == caps);
        assert!(WireCaps::for_device(Type::Tun).can_ip());
        assert!(!WireCaps::for_device(Type::Tun).can_ethernet());
        assert!(WireCaps(0).is_unknown());
    }

    #[test]
    fn infer_format_from_claims() {
        let mut claims = RangeList::new();
        claims.push(Range { base: Address::from_str("10.0.0.0").unwrap(), prefix_len: 8, metric: 0 });
        assert_eq!(WireCaps::infer_from_claims(&claims), WireCaps::IP);
        let mut claims = RangeList::new();
        claims.push(Range { base: Address::from_str("02:00:00:00:00:01").unwrap(), prefix_len: 48, metric: 0 });
        assert_eq!(WireCaps::infer_from_claims(&claims), WireCaps::ETHERNET);
    }

    #[test]
    fn per_ip_macs_are_distinct_and_stable() {
        let node = [7u8; 16];
        let a = synthetic_mac_for_ip(&node, [10, 0, 0, 1]);
        let b = synthetic_mac_for_ip(&node, [10, 0, 0, 2]);
        assert_ne!(a, b, "different local IPs must get different MACs");
        assert_eq!(a, synthetic_mac_for_ip(&node, [10, 0, 0, 1]));
        assert_eq!(a[0] & 0x03, 0x02, "locally administered unicast");
        assert_ne!(a, synthetic_mac_for_ip(&[8u8; 16], [10, 0, 0, 1]));
    }

    #[test]
    fn strip_and_wrap_ip_roundtrip() {
        let ip = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        let src = [2, 1, 2, 3, 4, 5];
        let dst = [2, 6, 7, 8, 9, 10];
        let frame = wrap_ip(&ip, src, dst).unwrap();
        assert_eq!(&frame[..6], &dst);
        assert_eq!(&frame[6..12], &src);
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert_eq!(strip_ethernet(&frame), Some(&ip[..]));
        // ARP must not be forwarded to a TUN peer.
        assert_eq!(strip_ethernet(&frame[..13]), None);
        let mut arp = frame.clone();
        arp[12] = 0x08;
        arp[13] = 0x06;
        assert_eq!(strip_ethernet(&arp), None);
    }

    #[test]
    fn arp_reply_for_known_ip() {
        let mut request = vec![0u8; 42];
        request[..6].fill(0xff);
        request[6..12].copy_from_slice(&[1, 1, 1, 1, 1, 1]);
        request[12..14].copy_from_slice(&[0x08, 0x06]);
        let arp = &mut request[14..];
        arp[..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&1u16.to_be_bytes());
        arp[8..14].copy_from_slice(&[1, 1, 1, 1, 1, 1]);
        arp[14..18].copy_from_slice(&[10, 0, 0, 9]);
        arp[24..28].copy_from_slice(&[10, 0, 0, 1]);
        let mac = [2, 9, 8, 7, 6, 5];
        let reply = arp_reply(&request, [10, 0, 0, 1], mac).unwrap();
        assert_eq!(reply.len(), 42);
        assert_eq!(&reply[..6], &[1, 1, 1, 1, 1, 1]);
        assert_eq!(&reply[6..12], &mac);
        assert_eq!(&reply[12..14], &[0x08, 0x06]);
        // A request for a different target is not answered.
        assert!(arp_reply(&request, [10, 0, 0, 2], mac).is_none());
    }

    #[test]
    fn choose_format_respects_peer_preference() {
        let local = WireCaps::for_bridge();
        let peer = WireCaps(WireCaps::IP.0 | WireCaps::PREFER_IP.0);
        assert_eq!(local.choose_format(peer, &RangeList::new()), WireFormat::Ip);
        let peer = WireCaps::ETHERNET;
        assert_eq!(local.choose_format(peer, &RangeList::new()), WireFormat::Ethernet);
        let local = WireCaps::for_device(Type::Tun);
        let peer = WireCaps::ETHERNET;
        assert_eq!(local.choose_format(peer, &RangeList::new()), WireFormat::Ip);
    }
}
