// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! How large an inner packet may be before the encrypted outer datagram
//! no longer fits in one underlay frame.
//!
//! A 60KB GSO aggregate on a 1500-byte path is IP-fragmented. Losing any
//! fragment drops the whole datagram, which is what collapsed UDP on a
//! real Ethernet link. These budgets keep every outer datagram inside the
//! path MTU for IPv4 and IPv6 underlays, including a VLAN-tagged Ethernet
//! frame from TAP.

use crate::{
    crypto::{EXTRA_LEN, TAG_LEN},
    gso::GSO_META_LEN
};

/// Message type byte, then the core AEAD header and tag.
/// Noise's on-wire overhead is smaller (type + tag only); this is the larger one.
pub const CRYPTO_OVERHEAD: usize = 1 + EXTRA_LEN + TAG_LEN;
/// Relayed messages prepend a 16-byte node id and the inner type before `send_msg`.
pub const RELAY_OVERHEAD: usize = 17;
pub const GSO_META: usize = GSO_META_LEN;
pub const ETH_HDR: usize = 14;
pub const VLAN_TAG: usize = 4;
pub const IPV4_HDR: usize = 20;
pub const IPV6_HDR: usize = 40;
pub const UDP_HDR: usize = 8;

/// Address family of the underlay UDP socket, not of the inner packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Underlay {
    V4,
    V6
}

const fn ip_hdr(underlay: Underlay) -> usize {
    match underlay {
        Underlay::V4 => IPV4_HDR,
        Underlay::V6 => IPV6_HDR
    }
}

/// UDP payload that fits in one underlay datagram. `l2_mtu` is the interface
/// MTU (maximum IP packet), not the Ethernet frame including its header.
pub const fn udp_payload(l2_mtu: usize, underlay: Underlay) -> usize {
    l2_mtu.saturating_sub(ip_hdr(underlay) + UDP_HDR)
}

/// Largest plain inner packet (IP packet, or a full Ethernet frame) that
/// still fits, leaving room for a relay header.
pub const fn max_plain(l2_mtu: usize, underlay: Underlay) -> usize {
    udp_payload(l2_mtu, underlay).saturating_sub(CRYPTO_OVERHEAD + RELAY_OVERHEAD)
}

/// Largest IP super-packet that fits once the 10-byte GSO prefix is added.
pub const fn max_gso(l2_mtu: usize, underlay: Underlay) -> usize {
    max_plain(l2_mtu, underlay).saturating_sub(GSO_META)
}

/// TAP device MTU. The kernel MTU is the Ethernet payload; the bytes we
/// encrypt include a 14-byte header and, when present, one 802.1Q tag.
pub const fn max_tap_mtu(l2_mtu: usize, underlay: Underlay) -> usize {
    max_plain(l2_mtu, underlay).saturating_sub(ETH_HDR + VLAN_TAG)
}

/// On-wire size of an outer datagram that carries `inner` bytes of plaintext
/// (the IP packet, or the IP packet plus the GSO prefix).
pub const fn wire_len(inner: usize, underlay: Underlay) -> usize {
    ip_hdr(underlay) + UDP_HDR + CRYPTO_OVERHEAD + RELAY_OVERHEAD + inner
}

/// Preamble + SFD + FCS + interframe gap. The 14-byte header is not in here;
/// [`wire_len`] does not include it either, so shapers add both.
pub const ETH_ON_WIRE_FRAMING: usize = 8 + 4 + 12;

/// Smaller of the two underlay MTUs. A missing or empty peer does not raise
/// `local`, and neither side is rewritten to 1500.
pub fn limiting_l2(local: usize, peer: Option<usize>) -> usize {
    match peer {
        Some(peer) if peer > 0 => {
            if local == 0 {
                peer
            } else {
                local.min(peer)
            }
        }
        _ => local
    }
}

/// Device MTU and GSO cap for one underlay path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathFit {
    pub l2_mtu: usize,
    pub device_mtu: usize,
    pub max_gso: usize
}

/// Inner sizes that keep one outer datagram inside the smaller underlay.
///
/// `requested` is the user's inner MTU. A value above the fit is lowered.
/// A value below it is kept. The result is never raised to 576, 1280, or 1500.
pub fn path_fit(local_l2: usize, peer_l2: Option<usize>, ipv6: bool, tap: bool, requested: Option<usize>) -> PathFit {
    let l2 = limiting_l2(local_l2, peer_l2).max(1);
    let underlay = if ipv6 { Underlay::V6 } else { Underlay::V4 };
    let fit = if tap { max_tap_mtu(l2, underlay) } else { max_plain(l2, underlay) }.max(1);
    let device_mtu = requested.map(|v| v.min(fit)).unwrap_or(fit).min(u16::MAX as usize);
    let max_gso = max_gso(l2, underlay).min(device_mtu).max(1);
    PathFit { l2_mtu: l2, device_mtu, max_gso }
}

/// Bytes added outside the tunnel packet: crypto, outer IP and UDP, and the
/// Ethernet frame around that datagram. Direct messages; the MTU itself
/// already reserved the larger relay header.
pub fn encapsulation_overhead(ipv6: bool) -> u64 {
    let underlay = if ipv6 { Underlay::V6 } else { Underlay::V4 };
    (CRYPTO_OVERHEAD + ip_hdr(underlay) + UDP_HDR + ETH_HDR + ETH_ON_WIRE_FRAMING) as u64
}

/// Share of the link the shaper may use, in per-mille.
///
/// 1000 fills the wire. The UDP socket then blocks, the first TCP direction
/// holds it, and the other direction drops to a fraction of the link. The
/// same setting also dropped more UDP than an unpaced tunnel. 995 keeps a
/// full packet near the wire and leaves room for the token burst to drain.
const SHAPER_PER_MILLE: u64 = 995;

/// Token bucket charged on `packet + overhead` bytes. Overhead keeps a
/// short packet from putting more bytes on the wire than the rate allows.
/// `rate_bps` is 0 when the link rate is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenBucket {
    pub rate_bps: u64,
    pub overhead: u64
}

pub fn token_bucket(link_bps: u64, ipv6: bool) -> TokenBucket {
    if link_bps == 0 {
        return TokenBucket { rate_bps: 0, overhead: 0 };
    }
    TokenBucket { rate_bps: link_bps.saturating_mul(SHAPER_PER_MILLE) / 1000, overhead: encapsulation_overhead(ipv6) }
}

/// Outer header family for one tunnel MTU.
///
/// A v4 listen is always the IPv4 budget. A v6 or dual-stack listen keeps
/// the IPv6 budget when any configured peer is real IPv6, or when no peer
/// was given, because an incoming peer may be IPv6. Peers that are all
/// IPv4 (including v4-mapped addresses) use the IPv4 budget: those
/// datagrams are IPv4 on the wire, and the larger inner MTU still fits.
pub fn ipv6_header_budget(listen_v6: bool, peer_is_ipv6: &[bool]) -> bool {
    listen_v6 && (peer_is_ipv6.is_empty() || peer_is_ipv6.iter().any(|v6| *v6))
}

/// Inner-byte rate for packets of `packet_len` at [`token_bucket`].
pub fn shaped_inner_bps(link_bps: u64, packet_len: u64, ipv6: bool) -> u64 {
    if link_bps == 0 || packet_len == 0 {
        return 0;
    }
    let bucket = token_bucket(link_bps, ipv6);
    packet_len.saturating_mul(bucket.rate_bps) / packet_len.saturating_add(bucket.overhead)
}

/// On-wire bit rate of `packet_len` byte tunnel packets shaped by [`token_bucket`].
pub fn implied_wire_bps(link_bps: u64, packet_len: u64, ipv6: bool) -> u64 {
    if packet_len == 0 {
        return 0;
    }
    let overhead = encapsulation_overhead(ipv6);
    shaped_inner_bps(link_bps, packet_len, ipv6).saturating_mul(packet_len.saturating_add(overhead)) / packet_len
}

/// Inner-byte rate of a full-MTU packet. `mtu` is that packet's length.
pub fn shaper_inner_bps(link_bps: u64, mtu: u64, ipv6: bool) -> u64 {
    shaped_inner_bps(link_bps, mtu, ipv6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_ipv4_budget() {
        assert_eq!(udp_payload(1500, Underlay::V4), 1472);
        assert_eq!(max_plain(1500, Underlay::V4), 1430);
        assert_eq!(max_gso(1500, Underlay::V4), 1420);
        assert_eq!(max_tap_mtu(1500, Underlay::V4), 1412);
        assert_eq!(wire_len(max_plain(1500, Underlay::V4), Underlay::V4), 1500);
        assert_eq!(wire_len(max_gso(1500, Underlay::V4) + GSO_META, Underlay::V4), 1500);
        assert_eq!(ETH_HDR + VLAN_TAG + max_tap_mtu(1500, Underlay::V4), max_plain(1500, Underlay::V4));
        assert!(wire_len(ETH_HDR + max_tap_mtu(1500, Underlay::V4), Underlay::V4) <= 1500);
    }

    #[test]
    fn ethernet_ipv6_budget() {
        assert_eq!(udp_payload(1500, Underlay::V6), 1452);
        assert_eq!(max_plain(1500, Underlay::V6), 1410);
        assert_eq!(max_gso(1500, Underlay::V6), 1400);
        assert_eq!(max_tap_mtu(1500, Underlay::V6), 1392);
        assert_eq!(wire_len(max_plain(1500, Underlay::V6), Underlay::V6), 1500);
        assert_eq!(wire_len(max_gso(1500, Underlay::V6) + GSO_META, Underlay::V6), 1500);
        assert_eq!(ETH_HDR + VLAN_TAG + max_tap_mtu(1500, Underlay::V6), max_plain(1500, Underlay::V6));
        // A 1500-byte underlay still leaves an inner MTU above the IPv6 minimum.
        assert!(max_plain(1500, Underlay::V4) >= 1280);
        assert!(max_plain(1500, Underlay::V6) >= 1280);
        assert!(max_tap_mtu(1500, Underlay::V4) >= 1280);
        assert!(max_tap_mtu(1500, Underlay::V6) >= 1280);
    }

    #[test]
    fn small_ipv6_underlay_is_not_rounded_up() {
        // Rounding up to 1280 would make the outer datagram larger than the path.
        assert_eq!(udp_payload(1280, Underlay::V6), 1232);
        assert_eq!(max_plain(1280, Underlay::V6), 1190);
        assert_eq!(max_gso(1280, Underlay::V6), 1180);
        assert_eq!(max_tap_mtu(1280, Underlay::V6), 1172);
        assert!(max_plain(1280, Underlay::V6) < 1280);
        assert_eq!(wire_len(max_plain(1280, Underlay::V6), Underlay::V6), 1280);
    }

    #[test]
    fn jumbo_underlay_still_rejects_a_60kb_aggregate() {
        assert!(max_gso(9000, Underlay::V4) < 60_000);
        assert!(max_gso(9000, Underlay::V6) < 60_000);
        assert!(wire_len(60_000, Underlay::V4) > 9000);
        assert!(wire_len(60_000 + GSO_META, Underlay::V6) > 9000);
        assert!(wire_len(max_gso(9000, Underlay::V4) + GSO_META, Underlay::V4) <= 9000);
    }

    #[test]
    fn shaper_stays_under_the_link_for_a_full_packet() {
        let mtu = 1410u64;
        let link = 1_000_000_000u64;
        let inner = shaper_inner_bps(link, mtu, false);
        let wire = implied_wire_bps(link, mtu, false);
        let rate = token_bucket(link, false).rate_bps;
        assert_eq!(rate, link * 995 / 1000);
        assert!(wire <= rate, "inner {inner} wire {wire}");
        // Integer division may drop a few bits below the shaper rate.
        let slack = (mtu + token_bucket(link, false).overhead) * 8;
        assert!(rate - wire <= slack, "inner {inner} wire {wire} slack {slack}");
        assert_eq!(shaper_inner_bps(0, mtu, false), 0);
        assert_eq!(implied_wire_bps(0, mtu, false), 0);
        assert!(shaper_inner_bps(link, mtu, true) < inner);
        assert!(token_bucket(link, true).rate_bps <= token_bucket(link, false).rate_bps);
        assert!(token_bucket(link, true).overhead > token_bucket(link, false).overhead);
    }

    #[test]
    fn rate_follows_packet_size_and_non_1500_mtus() {
        let link = 1_000_000_000u64;
        for mtu in [1280u64, 1410, 9000] {
            for ipv6 in [false, true] {
                let rate = token_bucket(link, ipv6).rate_bps;
                assert_eq!(rate, link * 995 / 1000);
                let full = implied_wire_bps(link, mtu, ipv6);
                assert!(full <= rate, "mtu {mtu} ipv6 {ipv6} wire {full}");
                let slack = (mtu + token_bucket(link, ipv6).overhead) * 8;
                assert!(rate - full <= slack, "mtu {mtu} ipv6 {ipv6} wire {full}");
                let small = implied_wire_bps(link, 64, ipv6);
                assert!(small <= link, "small packet wire {small}");
                assert!(shaped_inner_bps(link, mtu, true) <= shaped_inner_bps(link, mtu, false));
            }
        }
        assert_eq!(token_bucket(0, false).rate_bps, 0);
        assert_eq!(implied_wire_bps(link, 0, false), 0);
    }

    fn assert_outer_fits(local: usize, peer: Option<usize>, ipv6: bool) {
        let underlay = if ipv6 { Underlay::V6 } else { Underlay::V4 };
        let tun = path_fit(local, peer, ipv6, false, None);
        let tap = path_fit(local, peer, ipv6, true, None);
        let l2 = tun.l2_mtu;
        assert_eq!(tap.l2_mtu, l2);
        assert!(l2 == local || peer == Some(l2) || peer.map(|p| p == l2).unwrap_or(false));
        assert!(tun.device_mtu <= max_plain(l2, underlay));
        assert!(tun.max_gso < 60_000);
        assert!(tap.max_gso < 60_000);
        assert!(wire_len(tun.device_mtu, underlay) <= l2, "tun {} l2 {}", tun.device_mtu, l2);
        assert!(wire_len(tun.max_gso + GSO_META, underlay) <= l2);
        assert!(wire_len(ETH_HDR + VLAN_TAG + tap.device_mtu, underlay) <= l2, "tap {}", tap.device_mtu);
        assert!(wire_len(60_000, underlay) > l2);
        assert_ne!(l2, 0);
    }

    #[test]
    fn budgets_cover_1500_1280_jumbo_and_mismatched_peers() {
        for ipv6 in [false, true] {
            assert_outer_fits(1500, None, ipv6);
            assert_outer_fits(9000, None, ipv6);
        }
        assert_outer_fits(1280, None, true);
        // The smaller path wins in both directions. A shared non-1500 MTU stays.
        let down = path_fit(9000, Some(1500), false, false, None);
        let up = path_fit(1500, Some(9000), false, false, None);
        assert_eq!(down, up);
        assert_eq!(down.l2_mtu, 1500);
        let v6_down = path_fit(1500, Some(1280), true, false, None);
        let v6_up = path_fit(1280, Some(1500), true, false, None);
        assert_eq!(v6_down, v6_up);
        assert_eq!(v6_down.l2_mtu, 1280);
        assert!(v6_down.device_mtu < path_fit(1500, None, true, false, None).device_mtu);
        let shared = path_fit(1280, Some(1280), true, true, None);
        assert_eq!(shared.l2_mtu, 1280);
        assert_ne!(shared.l2_mtu, 1500);
        assert_eq!(shared.device_mtu, max_tap_mtu(1280, Underlay::V6));
        // An IPv4 packet and an IPv6 packet of the plain cap both fit.
        assert!(wire_len(v6_down.device_mtu, Underlay::V6) <= 1280);
        assert!(v6_down.device_mtu >= 40);
    }

    #[test]
    fn requested_mtu_is_kept_or_lowered_never_raised() {
        let kept = path_fit(1500, Some(1500), false, false, Some(1000));
        assert_eq!(kept.device_mtu, 1000);
        assert!(kept.max_gso <= 1000);
        let fit = path_fit(1500, None, false, false, None);
        let lowered = path_fit(1500, Some(9000), false, false, Some(8000));
        assert_eq!(lowered.device_mtu, fit.device_mtu);
        assert!(lowered.device_mtu < 8000);
        let small_path = path_fit(1280, None, true, false, None);
        assert!(small_path.device_mtu < 1280);
        assert_ne!(small_path.device_mtu, fit.device_mtu);
        assert_eq!(limiting_l2(1280, None), 1280);
        assert_eq!(limiting_l2(9000, Some(1500)), 1500);
    }

    #[test]
    fn ipv4_peers_use_the_larger_budget_that_still_fits_one_frame() {
        assert!(!ipv6_header_budget(true, &[false]));
        assert!(!ipv6_header_budget(true, &[false, false]));
        assert!(ipv6_header_budget(true, &[true]));
        assert!(ipv6_header_budget(true, &[false, true]));
        assert!(ipv6_header_budget(true, &[]));
        assert!(!ipv6_header_budget(false, &[true]));
        assert!(!ipv6_header_budget(false, &[]));
        let v4 = path_fit(1500, None, ipv6_header_budget(true, &[false]), false, None);
        let v6 = path_fit(1500, None, ipv6_header_budget(true, &[true]), false, None);
        assert_eq!(v4.device_mtu, max_plain(1500, Underlay::V4));
        assert_eq!(v6.device_mtu, max_plain(1500, Underlay::V6));
        assert!(v4.device_mtu > v6.device_mtu);
        assert!(wire_len(v4.device_mtu, Underlay::V4) <= 1500);
        assert!(wire_len(v6.device_mtu, Underlay::V6) <= 1500);
        // The IPv4 size does not fit an IPv6 header, so a v6 peer keeps the smaller one.
        assert!(wire_len(v4.device_mtu, Underlay::V6) > 1500);
        let bucket = token_bucket(1_000_000_000, false);
        assert_eq!(bucket.rate_bps, 995_000_000);
        assert!(bucket.overhead < token_bucket(1_000_000_000, true).overhead);
    }

    #[test]
    fn two_iperf_datagrams_do_not_fit_but_small_ones_do() {
        // The 1G run offered 1348-byte IP datagrams. Two of those are one
        // aggregate of 1348 + 1320 = 2668, which fits in neither family.
        let one = 1348usize;
        let aggregate = one + (one - 28);
        assert!(aggregate > max_gso(1500, Underlay::V4));
        assert!(aggregate > max_gso(1500, Underlay::V6));
        assert!(one <= max_plain(1500, Underlay::V4));
        assert!(one <= max_plain(1500, Underlay::V6));
        let two_small = 28 + 100 + 100;
        assert!(two_small <= max_gso(1500, Underlay::V4));
        assert!(two_small <= max_gso(1500, Underlay::V6));
    }

}
