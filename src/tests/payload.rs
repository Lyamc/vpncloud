// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::common::*;
use crate::{
    gso::{GsoMeta, GSO_TCPV4, GSO_UDP_L4, VIRTIO_F_NEEDS_CSUM},
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
