// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::common::*;
use crate::{
    gso::{GsoMeta, GSO_TCPV4, GSO_UDP_L4, VIRTIO_F_NEEDS_CSUM},
    mtu::path_fit,
    payload::udp_gso_span,
    types::Mode
};

#[test]
fn switch_forwards_gso_aggregate() {
    let config = Config { device_type: Type::Tun, mode: Mode::Switch, ..Config::default() };
    let mut sim = TunSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);
    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));

    let mut ip = vec![0u8; 48];
    ip[0] = 0x45;
    ip[2] = 0;
    ip[3] = 48;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
    ip[20..].fill(0xab);
    let meta = GsoMeta {
        flags: VIRTIO_F_NEEDS_CSUM,
        gso_type: GSO_TCPV4,
        hdr_len: 40,
        gso_size: 1460,
        csum_start: 20,
        csum_offset: 16
    };
    sim.put_gso(node1, meta, ip.clone());
    sim.simulate_all_messages();
    assert_eq!(Some(meta), sim.pop_gso_meta(node2));
    assert_eq!(Some(ip), sim.pop_payload(node2));
}

fn udp_datagram(payload: usize, port: u16, fill: u8) -> Vec<u8> {
    let total = 28 + payload;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    pkt[20..22].copy_from_slice(&port.to_be_bytes());
    pkt[22..24].copy_from_slice(&9u16.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
    pkt[28..].fill(fill);
    pkt
}

#[test]
fn switch_coalesces_udp_datagrams_into_one_gso() {
    let config = Config { device_type: Type::Tun, mode: Mode::Switch, ..Config::default() };
    let mut sim = TunSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);
    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));

    let first = udp_datagram(100, 4000, 0xab);
    let second = udp_datagram(100, 4000, 0xcd);
    let mut expect = first.clone();
    expect.extend_from_slice(&second[28..]);
    sim.put_plains(node1, vec![(None, first), (None, second)]);
    sim.simulate_all_messages();

    let meta = sim.pop_gso_meta(node2).expect("udp datagrams forwarded as one aggregate");
    assert_eq!(meta.gso_type, GSO_UDP_L4);
    assert_eq!(meta.gso_size, 100);
    assert_eq!(meta.hdr_len, 28);
    assert_eq!(meta.csum_start, 20);
    assert_eq!(meta.csum_offset, 6);
    assert_eq!(meta.flags, VIRTIO_F_NEEDS_CSUM);
    let got = sim.pop_payload(node2).expect("aggregate payload");
    assert_eq!(got.len(), expect.len());
    assert_eq!(&got[28..], &expect[28..]);
    assert_eq!(u16::from_be_bytes([got[2], got[3]]) as usize, got.len());
    assert!(sim.pop_gso_meta(node2).is_none());
    assert!(sim.pop_payload(node2).is_none());
}

#[test]
fn switch_keeps_mtu_sized_udp_datagrams_separate() {
    let config = Config { device_type: Type::Tun, mode: Mode::Switch, ..Config::default() };
    let mut sim = TunSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);
    sim.connect(node1, node2);
    sim.simulate_all_messages();

    // 1348-byte IP datagrams are what iperf offered on the 1400-byte tunnel.
    // Two of them must not become one GSO message: that message does not fit
    // in a 1500-byte underlay datagram.
    let first = udp_datagram(1320, 4000, 0xab);
    let second = udp_datagram(1320, 4000, 0xcd);
    assert_eq!(first.len(), 1348);
    sim.put_plains(node1, vec![(None, first.clone()), (None, second.clone())]);
    sim.simulate_all_messages();
    assert!(sim.pop_gso_meta(node2).is_none());
    let got_a = sim.pop_payload(node2).expect("first datagram");
    let got_b = sim.pop_payload(node2).expect("second datagram");
    assert_eq!(got_a.len(), first.len());
    assert_eq!(got_b.len(), second.len());
    assert_eq!(&got_a[28..], &first[28..]);
    assert_eq!(&got_b[28..], &second[28..]);
    assert!(sim.pop_payload(node2).is_none());
}

fn udp_datagram_v6(total: usize) -> Vec<u8> {
    assert!(total >= 48, "ipv6 udp packet {total}");
    let udp_len = (total - 40) as u16;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x60;
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

fn assert_outer_fits(lens: &[usize], header: usize, l2: usize) {
    assert!(!lens.is_empty(), "forward path sent nothing");
    for len in lens {
        assert!(len + header <= l2, "outer udp payload {len} + {header} exceeds underlay {l2}");
    }
}

/// Both peers end on the smaller underlay. Full datagrams stay separate,
/// small ones still coalesce, and nothing larger than the fit is sent whole.
fn exercise_mismatched_forward(local_a: usize, local_b: usize, ipv6: bool) {
    let config = Config { device_type: Type::Tun, mode: Mode::Switch, ..Config::default() };
    let mut sim = TunSimulator::new();
    let node_a = sim.add_node(false, &config);
    let node_b = sim.add_node(false, &config);
    sim.set_underlay(node_a, local_a, ipv6);
    sim.set_underlay(node_b, local_b, ipv6);
    sim.connect(node_a, node_b);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node_a, node_b));

    let fit = path_fit(local_a, Some(local_b), ipv6, false, None);
    assert_eq!(path_fit(local_b, Some(local_a), ipv6, false, None), fit);
    let gso_a = sim.get_node(node_a).device().gso_limit();
    let plain_a = sim.get_node(node_a).device().plain_limit();
    let gso_b = sim.get_node(node_b).device().gso_limit();
    let plain_b = sim.get_node(node_b).device().plain_limit();
    assert_eq!(gso_a, fit.max_gso, "local {local_a} vs {local_b}");
    assert_eq!(gso_b, fit.max_gso, "local {local_b} vs {local_a}");
    assert_eq!(plain_a, fit.device_mtu);
    assert_eq!(plain_b, fit.device_mtu);
    assert!(fit.max_gso < 60_000);

    let header = if ipv6 { 48 } else { 28 };
    let full = udp_datagram(fit.device_mtu - 28, 4000, 0xab);
    let full_b = udp_datagram(fit.device_mtu - 28, 4000, 0xcd);
    assert_eq!(full.len(), fit.device_mtu);
    assert_eq!(udp_gso_span(&[&full, &full_b], fit.max_gso), 0);
    let small = udp_datagram(100, 4000, 0x11);
    let small_b = udp_datagram(100, 4000, 0x22);
    assert_eq!(udp_gso_span(&[&small, &small_b], fit.max_gso), 2);
    let v6 = udp_datagram_v6(fit.device_mtu);
    let v6_b = udp_datagram_v6(fit.device_mtu);
    assert_eq!(udp_gso_span(&[&v6, &v6_b], fit.max_gso), 0);
    let v6_small = udp_datagram_v6(48 + 100);
    assert_eq!(udp_gso_span(&[&v6_small, &v6_small], fit.max_gso), 2);

    // The side with the larger NIC must not emit a datagram the smaller path cannot carry.
    let sender = if local_a >= local_b { node_a } else { node_b };
    let receiver = if sender == node_a { node_b } else { node_a };
    sim.put_plains(sender, vec![(None, full.clone()), (None, full_b.clone())]);
    assert_eq!(sim.pending_payload_lens().len(), 2, "mtu-sized datagrams were coalesced");
    assert_outer_fits(&sim.pending_payload_lens(), header, fit.l2_mtu);
    sim.simulate_all_messages();
    assert!(sim.pop_gso_meta(receiver).is_none());
    assert_eq!(sim.pop_payload(receiver).expect("first").len(), full.len());
    assert_eq!(sim.pop_payload(receiver).expect("second").len(), full_b.len());

    sim.put_plains(sender, vec![(None, small), (None, small_b)]);
    assert_eq!(sim.pending_payload_lens().len(), 1, "small datagrams were not coalesced");
    assert_outer_fits(&sim.pending_payload_lens(), header, fit.l2_mtu);
    sim.simulate_all_messages();
    let meta = sim.pop_gso_meta(receiver).expect("small udp coalesced");
    assert_eq!(meta.gso_type, GSO_UDP_L4);
    assert!(sim.pop_payload(receiver).is_some());

    sim.put_plains(sender, vec![(None, v6.clone())]);
    assert_outer_fits(&sim.pending_payload_lens(), header, fit.l2_mtu);
    sim.simulate_all_messages();
    assert_eq!(sim.pop_payload(receiver).expect("inner ipv6").len(), v6.len());

    let v6_small_b = v6_small.clone();
    sim.put_plains(sender, vec![(None, v6_small), (None, v6_small_b)]);
    assert_eq!(sim.pending_payload_lens().len(), 1, "small inner ipv6 datagrams were not coalesced");
    assert_outer_fits(&sim.pending_payload_lens(), header, fit.l2_mtu);
    sim.simulate_all_messages();
    assert_eq!(sim.pop_gso_meta(receiver).expect("small ipv6 udp coalesced").gso_type, GSO_UDP_L4);
    assert!(sim.pop_payload(receiver).is_some());

    sim.put_plains(sender, vec![(None, vec![0u8; 60_000])]);
    assert!(sim.pending_payload_lens().is_empty(), "a 60KB inner packet was sent whole on underlay {}", fit.l2_mtu);
}

#[test]
fn mismatched_underlays_cap_both_directions_and_keep_small_coalesce() {
    exercise_mismatched_forward(9000, 1500, false);
    exercise_mismatched_forward(1500, 1280, true);
    exercise_mismatched_forward(1280, 1280, true);
    exercise_mismatched_forward(1500, 1500, false);
}

#[test]
fn requested_inner_mtu_is_kept_when_smaller_and_lowered_when_larger() {
    let low = Config { device_type: Type::Tun, mode: Mode::Switch, mtu: Some(1000), ..Config::default() };
    let high = Config { device_type: Type::Tun, mode: Mode::Switch, mtu: Some(8000), ..Config::default() };
    let mut sim = TunSimulator::new();
    let node_low = sim.add_node(false, &low);
    let node_high = sim.add_node(false, &high);
    sim.set_underlay(node_low, 1500, false);
    sim.set_underlay(node_high, 1500, false);
    let kept = path_fit(1500, None, false, false, Some(1000));
    let lowered = path_fit(1500, None, false, false, Some(8000));
    let natural = path_fit(1500, None, false, false, None);
    assert_eq!(sim.get_node(node_low).device().plain_limit(), kept.device_mtu);
    assert_eq!(kept.device_mtu, 1000);
    assert_eq!(sim.get_node(node_high).device().plain_limit(), lowered.device_mtu);
    assert_eq!(lowered.device_mtu, natural.device_mtu);
    assert!(lowered.device_mtu < 8000);
}

#[test]
fn switch_keeps_distinct_udp_flows_separate() {
    let config = Config { device_type: Type::Tun, mode: Mode::Switch, ..Config::default() };
    let mut sim = TunSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);
    sim.connect(node1, node2);
    sim.simulate_all_messages();

    let a = udp_datagram(80, 4000, 0x11);
    let b = udp_datagram(80, 4001, 0x22);
    sim.put_plains(node1, vec![(None, a.clone()), (None, b.clone())]);
    sim.simulate_all_messages();
    assert!(sim.pop_gso_meta(node2).is_none());
    let got_a = sim.pop_payload(node2).expect("first flow");
    let got_b = sim.pop_payload(node2).expect("second flow");
    assert_eq!(&got_a[20..24], &a[20..24]);
    assert_eq!(&got_a[28..], &a[28..]);
    assert_eq!(&got_b[20..24], &b[20..24]);
    assert_eq!(&got_b[28..], &b[28..]);
    assert_ne!(&got_a[10..12], &[0, 0], "ipv4 header checksum must be filled");
}

#[test]
fn switch_delivers_crypto_pool() {
    let config = Config { device_type: Type::Tap, crypto_threads: 2, ..Config::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];

    sim.put_payload(node1, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload), sim.pop_payload(node2));
}

#[test]
fn switch_delivers() {
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];

    sim.put_payload(node1, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload), sim.pop_payload(node2));
}

#[test]
fn switch_learns() {
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);
    let node3 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.connect(node1, node3);
    sim.connect(node2, node3);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];

    // Nothing learnt so far, node1 broadcasts

    sim.put_payload(node1, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload.clone()), sim.pop_payload(node2));
    assert_eq!(Some(payload), sim.pop_payload(node3));

    let payload = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 5, 4, 3, 2, 1];

    // Node 2 learned the address by receiving it, does not broadcast

    sim.put_payload(node2, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload), sim.pop_payload(node1));
    assert_eq!(None, sim.pop_payload(node3));
}

#[test]
fn switch_honours_vlans() {
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);
    let node3 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.connect(node1, node3);
    sim.connect(node2, node3);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 0x81, 0, 0, 0x67, 1, 2, 3, 4, 5];

    // Nothing learnt so far, node1 broadcasts

    sim.put_payload(node1, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload.clone()), sim.pop_payload(node2));
    assert_eq!(Some(payload), sim.pop_payload(node3));

    let payload = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 0x81, 0, 0, 0x67, 5, 4, 3, 2, 1];

    // Node 2 learned the address by receiving it, does not broadcast

    sim.put_payload(node2, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload), sim.pop_payload(node1));
    assert_eq!(None, sim.pop_payload(node3));

    let payload = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 0x81, 0, 0, 0x68, 5, 4, 3, 2, 1];

    // Different VLANs, node 2 does not learn, still broadcasts

    sim.put_payload(node2, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload.clone()), sim.pop_payload(node1));
    assert_eq!(Some(payload), sim.pop_payload(node3));
}

#[test]
#[ignore]
fn switch_forgets() {
    // TODO Test
    unimplemented!()
}

#[test]
fn router_delivers() {
    let config1 = Config {
        device_type: Type::Tun,
        auto_claim: false,
        claims: vec!["1.1.1.1/32".to_string()],
        ..Config::default()
    };
    let config2 = Config {
        device_type: Type::Tun,
        auto_claim: false,
        claims: vec!["2.2.2.2/32".to_string()],
        ..Config::default()
    };
    let mut sim = TunSimulator::new();
    let node1 = sim.add_node(false, &config1);
    let node2 = sim.add_node(false, &config2);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    let payload = vec![0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2];

    sim.put_payload(node1, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload), sim.pop_payload(node2));
}

#[test]
fn router_drops_unknown_dest() {
    let config1 = Config {
        device_type: Type::Tun,
        auto_claim: false,
        claims: vec!["1.1.1.1/32".to_string()],
        ..Config::default()
    };
    let config2 = Config {
        device_type: Type::Tun,
        auto_claim: false,
        claims: vec!["2.2.2.2/32".to_string()],
        ..Config::default()
    };
    let mut sim = TunSimulator::new();
    let node1 = sim.add_node(false, &config1);
    let node2 = sim.add_node(false, &config2);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    let payload = vec![0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 3, 3, 3, 3];

    sim.put_payload(node1, payload);
    sim.simulate_all_messages();

    assert_eq!(None, sim.pop_payload(node2));
}
