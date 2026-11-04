// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Multi-hop delivery through `GenericCloud::handle_interface_data`.
//! The underlay between non-adjacent nodes is dropped, so the only way a
//! payload reaches the far TUN is a sealed `MESSAGE_TYPE_RELAY`.

use std::net::SocketAddr;

use super::common::*;
use crate::{
    messages::{MESSAGE_TYPE_DATA, MESSAGE_TYPE_RELAY},
    policy::SEAL_MARK,
    types::Mode
};

const SECRET: &[u8] = b"overlay-secret-9f3a-not-for-hops";

fn router(claim: &str, plain: bool) -> Config {
    Config {
        mode: Mode::Router,
        device_type: Type::Tun,
        auto_claim: false,
        claims: vec![claim.to_string()],
        crypto: if plain {
            CryptoConfig { algorithms: vec!["plain".to_string()], ..CryptoConfig::default() }
        } else {
            CryptoConfig::default()
        },
        ..Config::default()
    }
}

fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + payload.len()];
    pkt[0] = 0x45;
    let len = pkt.len();
    pkt[2] = (len >> 8) as u8;
    pkt[3] = len as u8;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..].copy_from_slice(payload);
    pkt
}

fn contains_secret(bytes: &[u8]) -> bool {
    bytes.windows(SECRET.len()).any(|window| window == SECRET)
}

fn assert_sealed_relay(frame: &[u8]) {
    assert!(frame.len() > 18, "relay frame too short: {}", frame.len());
    assert_eq!(frame[0], MESSAGE_TYPE_RELAY);
    assert_eq!(frame[17], MESSAGE_TYPE_DATA);
    assert_eq!(frame[18], SEAL_MARK);
    assert!(!contains_secret(frame), "relay wrapper carries the overlay payload");
}

/// Deliver queued datagrams. Record every `MESSAGE_TYPE_RELAY` before it is consumed.
fn drive(sim: &mut TunSimulator) -> Vec<(SocketAddr, SocketAddr, Vec<u8>)> {
    let mut relays = Vec::new();
    for _ in 0..80 {
        match sim.front_message() {
            Some((src, dst, data)) if data.first() == Some(&MESSAGE_TYPE_RELAY) => {
                assert_sealed_relay(&data);
                relays.push((src, dst, data));
                sim.simulate_next_message();
            }
            Some(_) => sim.simulate_next_message(),
            None => break
        }
    }
    assert_eq!(sim.message_count(), 0, "undelivered underlay messages");
    relays
}

fn drain(sim: &mut TunSimulator, addr: SocketAddr) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(pkt) = sim.pop_payload(addr) {
        out.push(pkt);
    }
    out
}

fn bring_up(sim: &mut TunSimulator, src: SocketAddr, dst: SocketAddr) {
    sim.connect(src, dst);
    sim.simulate_all_messages();
    assert!(sim.is_connected(src, dst), "{src} -> {dst}");
    assert!(sim.is_connected(dst, src), "{dst} -> {src}");
}

#[test]
fn one_and_two_hops_deliver_a_sealed_relay() {
    let mut sim = TunSimulator::new();
    sim.set_time(10);
    let a = sim.add_node(false, &router("10.1.0.0/24", true));
    let b = sim.add_node(false, &router("10.2.0.0/24", true));
    let c = sim.add_node(false, &router("10.3.0.0/24", true));

    bring_up(&mut sim, b, c);
    sim.block_pair(a, c);
    bring_up(&mut sim, a, b);
    assert!(!sim.is_connected(a, c));
    assert!(!sim.is_connected(c, a));

    let direct = ipv4([10, 1, 0, 9], [10, 2, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, direct.clone());
    let front = sim.front_message().expect("direct send");
    assert_eq!(front.0, a);
    assert_eq!(front.1, b);
    assert_eq!(front.2[0], MESSAGE_TYPE_DATA);
    assert_eq!(&front.2[1..], direct.as_slice());
    assert_ne!(front.2[0], MESSAGE_TYPE_RELAY);
    sim.simulate_all_messages();
    assert_eq!(drain(&mut sim, b), vec![direct]);
    assert!(drain(&mut sim, c).is_empty());

    let far = ipv4([10, 1, 0, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, far.clone());
    let relays = drive(&mut sim);
    assert!(relays.len() >= 2, "expected a relay toward B and from B to C, got {relays:?}");
    assert_eq!(relays[0].0, a);
    assert_eq!(relays[0].1, b);
    assert!(relays.iter().any(|(src, dst, _)| *src == b && *dst == c));
    let body = &relays[0].2[18..];
    assert!(relays.iter().all(|(_, _, frame)| &frame[18..] == body));
    assert!(drain(&mut sim, b).is_empty());
    assert_eq!(drain(&mut sim, c), vec![far]);

    // A second chain: A—B—D—C, with the shortcuts removed.
    let mut sim = TunSimulator::new();
    sim.set_time(10);
    let a = sim.add_node(false, &router("10.1.0.0/24", true));
    let b = sim.add_node(false, &router("10.2.0.0/24", true));
    let d = sim.add_node(false, &router("10.4.0.0/24", true));
    let c = sim.add_node(false, &router("10.3.0.0/24", true));
    bring_up(&mut sim, d, c);
    sim.block_pair(a, c);
    sim.block_pair(a, d);
    sim.block_pair(b, c);
    bring_up(&mut sim, b, d);
    bring_up(&mut sim, a, b);
    assert!(!sim.is_connected(a, c));
    assert!(!sim.is_connected(a, d));
    assert!(!sim.is_connected(b, c));
    assert!(sim.is_connected(d, c));

    let far = ipv4([10, 1, 0, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, far.clone());
    let relays = drive(&mut sim);
    assert_eq!(relays.len(), 3, "one frame per hop, got {relays:?}");
    assert_eq!((relays[0].0, relays[0].1), (a, b));
    assert_eq!((relays[1].0, relays[1].1), (b, d));
    assert_eq!((relays[2].0, relays[2].1), (d, c));
    assert_eq!(&relays[0].2[18..], &relays[1].2[18..]);
    assert_eq!(&relays[1].2[18..], &relays[2].2[18..]);
    assert!(drain(&mut sim, b).is_empty());
    assert!(drain(&mut sim, d).is_empty());
    assert_eq!(drain(&mut sim, c), vec![far]);
}

#[test]
fn default_crypto_one_hop_delivers_the_inner_only_at_the_dest() {
    let mut sim = TunSimulator::new();
    sim.set_time(10);
    let a = sim.add_node(false, &router("10.1.0.0/24", false));
    let b = sim.add_node(false, &router("10.2.0.0/24", false));
    let c = sim.add_node(false, &router("10.3.0.0/24", false));
    bring_up(&mut sim, b, c);
    sim.block_pair(a, c);
    bring_up(&mut sim, a, b);
    assert!(!sim.is_connected(a, c));

    let far = ipv4([10, 1, 0, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, far.clone());
    // Outer crypto hides the type byte. The destination TUN is the proof the
    // shipped route delivered, and the intermediate TUN stays empty.
    sim.simulate_all_messages();
    assert!(drain(&mut sim, b).is_empty());
    assert_eq!(drain(&mut sim, c), vec![far.clone()]);

    let (plain, _, _) = crate::crypto::Crypto::parse_algorithms(&[]).unwrap();
    assert!(!plain);
    let _ = far;
}

#[test]
fn lowest_rtt_relay_fails_over_when_that_hop_disappears() {
    let mut sim = TunSimulator::new();
    sim.set_time(10);
    let a = sim.add_node(false, &router("10.1.0.0/24", true));
    let b = sim.add_node(false, &router("10.2.0.0/24", true));
    let e = sim.add_node(false, &router("10.5.0.0/24", true));
    let c = sim.add_node(false, &router("10.3.0.0/24", true));
    bring_up(&mut sim, b, c);
    bring_up(&mut sim, e, c);
    sim.block_pair(a, c);
    bring_up(&mut sim, a, b);
    bring_up(&mut sim, a, e);
    assert!(!sim.is_connected(a, c));
    assert!(sim.is_connected(a, b));
    assert!(sim.is_connected(a, e));

    let rb = sim.get_node(a).test_peer_rtt(&b).unwrap();
    let re = sim.get_node(a).test_peer_rtt(&e).unwrap();
    let expected = if (rb, b) <= (re, e) { b } else { e };
    let other = if expected == b { e } else { b };

    let far = ipv4([10, 1, 0, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, far.clone());
    let first = sim.front_message().expect("first relay");
    assert_eq!(first.0, a);
    assert_eq!(first.1, expected);
    assert_sealed_relay(&first.2);
    sim.simulate_all_messages();
    assert_eq!(drain(&mut sim, c), vec![far]);

    sim.get_node(a).test_fail_peer_crypto(&expected);
    sim.clear_messages();
    sim.trigger_node_housekeep(a);
    assert!(!sim.is_connected(a, expected));
    assert!(sim.is_connected(a, other));
    sim.clear_messages();

    let again = ipv4([10, 1, 0, 9], [10, 3, 0, 8], SECRET);
    sim.put_payload(a, again.clone());
    let second = sim.front_message().expect("failover relay");
    assert_eq!(second.1, other);
    assert_sealed_relay(&second.2);
    sim.simulate_all_messages();
    assert_eq!(drain(&mut sim, c), vec![again]);
}

#[test]
fn missing_e2e_key_drops_instead_of_forwarding_plaintext() {
    let mut sim = TunSimulator::new();
    sim.set_time(10);
    let a = sim.add_node(false, &router("10.1.0.0/24", true));
    let b = sim.add_node(false, &router("10.2.0.0/24", true));
    let c = sim.add_node(false, &router("10.3.0.0/24", true));
    bring_up(&mut sim, b, c);
    sim.block_pair(a, c);
    bring_up(&mut sim, a, b);

    let dest = sim.get_node(c).test_node_id();
    sim.get_node(a).test_forget_e2e(&dest);
    let far = ipv4([10, 1, 0, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, far);
    for _ in 0..8 {
        let Some((_, _, data)) = sim.front_message() else { break };
        assert_ne!(data.first().copied(), Some(MESSAGE_TYPE_RELAY));
        assert!(!contains_secret(&data));
        sim.simulate_next_message();
    }
    sim.simulate_all_messages();
    assert!(drain(&mut sim, b).is_empty());
    assert!(drain(&mut sim, c).is_empty());
}

#[test]
fn crypto_housekeep_forgets_claims_for_the_dead_peer() {
    let mut sim = TunSimulator::new();
    sim.set_time(10);
    let a = sim.add_node(false, &router("10.1.0.0/24", true));
    let b = sim.add_node(false, &router("10.2.0.0/24", true));
    let e = sim.add_node(false, &router("10.5.0.0/24", true));
    bring_up(&mut sim, a, b);
    bring_up(&mut sim, a, e);
    sim.get_node(a).test_fail_peer_crypto(&b);
    sim.clear_messages();
    sim.trigger_node_housekeep(a);
    assert!(!sim.is_connected(a, b));
    assert!(sim.is_connected(a, e));
    sim.clear_messages();

    let to_b = ipv4([10, 1, 0, 9], [10, 2, 0, 9], SECRET);
    sim.put_payload(a, to_b);
    let mut queued = Vec::new();
    while let Some(msg) = sim.front_message() {
        queued.push(msg);
        sim.simulate_next_message();
        if queued.len() > 8 {
            break;
        }
    }
    assert!(queued.iter().all(|(_, _, data)| data.first() != Some(&MESSAGE_TYPE_RELAY)));
    assert!(queued.iter().all(|(_, _, data)| !contains_secret(data)));
    assert!(drain(&mut sim, e).is_empty());
    assert!(drain(&mut sim, b).is_empty());
}

fn router_grants(claim: &str, grants: &[&str]) -> Config {
    let mut config = router(claim, true);
    config.grants = grants.iter().map(|line| (*line).to_string()).collect();
    config
}

#[test]
fn higher_transit_metric_loses_to_the_direct_claim() {
    let mut sim = TunSimulator::new();
    sim.set_time(10);
    let a = sim.add_node(false, &router("10.1.0.0/24", true));
    let b = sim.add_node(false, &router("10.2.0.0/24", true));
    let e = sim.add_node(false, &router("10.9.0.0/16@10", true));
    let c = sim.add_node(false, &router("10.9.0.0/16@40", true));
    bring_up(&mut sim, b, c);
    bring_up(&mut sim, a, e);
    sim.block_pair(a, c);
    bring_up(&mut sim, a, b);
    assert!(sim.is_connected(a, e));
    assert!(!sim.is_connected(a, c));

    let pkt = ipv4([10, 1, 0, 9], [10, 9, 1, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, pkt.clone());
    let front = sim.front_message().expect("direct preferred over transit");
    assert_eq!(front.0, a);
    assert_eq!(front.1, e);
    assert_eq!(front.2[0], MESSAGE_TYPE_DATA);
    assert_ne!(front.2[0], MESSAGE_TYPE_RELAY);
    assert_eq!(&front.2[1..], pkt.as_slice());
    sim.simulate_all_messages();
    assert_eq!(drain(&mut sim, e), vec![pkt]);
    assert!(drain(&mut sim, b).is_empty());
    assert!(drain(&mut sim, c).is_empty());
}

#[test]
fn relay_delivery_authorizes_the_origin_not_the_hop() {
    let mut sim = TunSimulator::new();
    sim.set_time(10);
    let a = sim.add_node(false, &router_grants("10.1.0.0/24", &["prefix:10.3.0.0/24", "prefix:10.1.0.0/24"]));
    let b = sim.add_node(false, &router_grants("10.2.0.0/24", &["prefix:10.1.0.0/24", "prefix:10.3.0.0/24"]));
    let c = sim.add_node(false, &router_grants("10.3.0.0/24", &["prefix:10.1.0.0/24", "prefix:10.2.0.0/24"]));
    bring_up(&mut sim, a, b);
    sim.block_pair(a, c);
    bring_up(&mut sim, b, c);
    assert!(!sim.is_connected(a, c));
    sim.trigger_node_housekeep(b);
    sim.simulate_all_messages();
    assert!(!sim.is_connected(a, c));
    assert!(sim.is_connected(b, c));

    let pkt = ipv4([10, 1, 0, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, pkt.clone());
    let relays = drive(&mut sim);
    assert!(relays.iter().any(|(src, dst, _)| *src == b && *dst == c), "hop did not forward: {relays:?}");
    assert!(drain(&mut sim, b).is_empty());
    assert_eq!(drain(&mut sim, c), vec![pkt]);

    let foreign = ipv4([192, 168, 9, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, foreign);
    sim.simulate_all_messages();
    assert!(drain(&mut sim, c).is_empty());
    assert!(drain(&mut sim, b).is_empty());

    // 10.2.0.9 is B's granted prefix. A's seal must not be accepted for it.
    let spoof = ipv4([10, 2, 0, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, spoof);
    let relays = drive(&mut sim);
    assert!(relays.iter().any(|(src, dst, _)| *src == b && *dst == c), "spoof was not relayed: {relays:?}");
    assert!(drain(&mut sim, c).is_empty());
    assert!(drain(&mut sim, b).is_empty());
}

#[test]
fn unauthorized_group_is_dropped_on_relay_delivery() {
    let mut sim = TunSimulator::new();
    sim.set_time(10);
    let mut a_cfg = router("10.1.0.0/24", true);
    a_cfg.announce_group = Some("finance".to_string());
    let a = sim.add_node(false, &a_cfg);
    let b = sim.add_node(false, &{
        let mut config = router_grants("10.2.0.0/24", &["group:eng", "prefix:10.1.0.0/24", "prefix:10.3.0.0/24"]);
        config.announce_group = Some("eng".to_string());
        config
    });
    let c = sim.add_node(false, &{
        let mut config = router_grants("10.3.0.0/24", &["group:eng", "prefix:10.1.0.0/24"]);
        config.announce_group = Some("eng".to_string());
        config
    });
    bring_up(&mut sim, b, c);
    sim.block_pair(a, c);
    bring_up(&mut sim, a, b);
    assert!(!sim.is_connected(a, c));
    assert!(sim.is_connected(b, c));
    sim.trigger_node_housekeep(b);
    sim.simulate_all_messages();
    assert!(!sim.is_connected(a, c));

    let pkt = ipv4([10, 1, 0, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, pkt);
    let relays = drive(&mut sim);
    assert!(relays.iter().any(|(src, dst, _)| *src == b && *dst == c), "group reject never reached C: {relays:?}");
    assert!(drain(&mut sim, c).is_empty());
    assert!(drain(&mut sim, b).is_empty());
}

#[test]
fn authorized_group_is_delivered_on_relay() {
    let mut sim = TunSimulator::new();
    sim.set_time(10);
    let mut a_cfg = router_grants("10.1.0.0/24", &["group:eng", "prefix:10.3.0.0/24", "prefix:10.2.0.0/24"]);
    a_cfg.announce_group = Some("eng".to_string());
    let a = sim.add_node(false, &a_cfg);
    let b = sim.add_node(false, &{
        let mut config = router_grants("10.2.0.0/24", &["group:eng", "prefix:10.1.0.0/24", "prefix:10.3.0.0/24"]);
        config.announce_group = Some("eng".to_string());
        config
    });
    let c = sim.add_node(false, &{
        let mut config = router_grants("10.3.0.0/24", &["group:eng", "prefix:10.1.0.0/24", "prefix:10.2.0.0/24"]);
        config.announce_group = Some("eng".to_string());
        config
    });
    bring_up(&mut sim, b, c);
    sim.block_pair(a, c);
    bring_up(&mut sim, a, b);
    assert!(!sim.is_connected(a, c));
    sim.trigger_node_housekeep(b);
    sim.simulate_all_messages();
    assert!(!sim.is_connected(a, c));
    assert!(sim.is_connected(b, c));

    let pkt = ipv4([10, 1, 0, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, pkt.clone());
    let relays = drive(&mut sim);
    assert!(relays.iter().any(|(src, dst, _)| *src == b && *dst == c), "eng relay did not reach C: {relays:?}");
    assert!(drain(&mut sim, b).is_empty());
    assert_eq!(drain(&mut sim, c), vec![pkt]);
}
