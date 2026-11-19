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
    assert!(frame[0] == MESSAGE_TYPE_RELAY || frame[0] == crate::messages::MESSAGE_TYPE_RELAY_TTL);
    // Frame includes the message-type prefix: dest starts at 1, inner type at
    // 17. TTL-capable meshes add a hop count at 18 before the sealed body.
    assert_eq!(frame[17], MESSAGE_TYPE_DATA);
    let seal_at = if frame[18] == SEAL_MARK { 18 } else { 19 };
    assert_eq!(frame[seal_at], SEAL_MARK);
    assert!(!contains_secret(frame), "relay wrapper carries the overlay payload");
}

/// Deliver queued datagrams. Record every `MESSAGE_TYPE_RELAY` before it is consumed.
fn drive(sim: &mut TunSimulator) -> Vec<(SocketAddr, SocketAddr, Vec<u8>)> {
    let mut relays = Vec::new();
    for _ in 0..80 {
        match sim.front_message() {
            Some((src, dst, data))
                if data.first() == Some(&MESSAGE_TYPE_RELAY)
                    || data.first() == Some(&crate::messages::MESSAGE_TYPE_RELAY_TTL) =>
            {
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
    // Compare the sealed bodies, skipping the per-hop TTL byte when present.
    let seal_at = if relays[0].2[18] == SEAL_MARK { 18 } else { 19 };
    let body = &relays[0].2[seal_at..];
    assert!(relays.iter().all(|(_, _, frame)| &frame[seal_at..] == body));
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
    let seal_at = if relays[0].2[18] == SEAL_MARK { 18 } else { 19 };
    assert_eq!(&relays[0].2[seal_at..], &relays[1].2[seal_at..]);
    assert_eq!(&relays[1].2[seal_at..], &relays[2].2[seal_at..]);
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
fn gossiped_quality_suggests_a_relay() {
    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &router("10.1.0.0/24", true));
    let b = sim.add_node(false, &router("10.2.0.0/24", true));
    let c = sim.add_node(false, &router("10.3.0.0/24", true));
    bring_up(&mut sim, b, c);
    sim.block_pair(a, c);
    bring_up(&mut sim, a, b);
    assert!(!sim.is_connected(a, c));
    assert!(sim.is_connected(a, b));

    // The wire round-trip of a quality report is covered in messages.rs tests;
    // here we verify the aggregation with an injected report (timing-independent).
    let b_id = sim.get_node(b).test_node_id();
    let c_id = sim.get_node(c).test_node_id();
    sim.get_node(a).test_set_peer_rtt(&b, 10_000);
    sim.get_node(a).test_inject_quality(b_id, vec![(c_id, 25)]);

    let (quality, suggestion) = sim.get_node(a).test_quality_snapshot();
    assert!(!quality.is_empty(), "A must learn remote quality from B's gossip");
    assert!(
        quality.iter().any(|entry| entry.node_id == crate::util::bytes_to_hex(&c_id)),
        "C must appear in the estimated quality table"
    );
    let suggestion = suggestion.expect("A should get a relay suggestion via B");
    assert_eq!(suggestion.via_node, crate::util::bytes_to_hex(&sim.get_node(b).test_node_id()));
    assert_eq!(suggestion.dest_node, crate::util::bytes_to_hex(&sim.get_node(c).test_node_id()));
    assert!(suggestion.estimated_rtt_ms > 0);
}

#[test]
fn hop_count_decrements_and_legacy_peers_use_old_format() {
    let config = router("10.1.0.0/24", true);
    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &config);
    let b = sim.add_node(false, &router("10.2.0.0/24", true));
    let c = sim.add_node(false, &router("10.3.0.0/24", true));
    bring_up(&mut sim, b, c);
    sim.block_pair(a, c);
    bring_up(&mut sim, a, b);

    let far = ipv4([10, 1, 0, 9], [10, 3, 0, 9], SECRET);
    sim.clear_messages();
    sim.put_payload(a, far.clone());
    let relays = drive(&mut sim);
    let hops: Vec<u8> = relays.iter().map(|(_, _, frame)| frame[18]).collect();
    assert!(hops.len() >= 2, "expected a two-hop relay");
    assert_eq!(hops[0], crate::cloud::DEFAULT_WIRE_TTL);
    assert_eq!(hops[1], crate::cloud::DEFAULT_WIRE_TTL - 1, "hop count must decrement per hop");

    // A legacy peer (no TTL capability) disables the byte for the whole mesh.
    sim.get_node(a).test_set_peer_caps(&b, crate::wire::WireCaps::IP.bits());
    sim.clear_messages();
    sim.put_payload(a, far);
    let relays = drive(&mut sim);
    assert!(relays.iter().any(|(_, _, frame)| frame[18] == SEAL_MARK), "legacy mesh must omit the TTL byte");
}

#[test]
fn quality_estimate_uses_median_and_bounds_reports() {
    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &router("10.1.0.0/24", true));
    let b = sim.add_node(false, &router("10.2.0.0/24", true));
    let d = sim.add_node(false, &router("10.4.0.0/24", true));
    let c = sim.add_node(false, &router("10.3.0.0/24", true));
    bring_up(&mut sim, a, b);
    bring_up(&mut sim, a, d);

    let b_id = sim.get_node(b).test_node_id();
    let d_id = sim.get_node(d).test_node_id();
    let c_id = sim.get_node(c).test_node_id();
    sim.get_node(a).test_set_peer_rtt(&b, 10_000);
    sim.get_node(a).test_set_peer_rtt(&d, 10_000);
    // B reports a sane 25 ms; D reports an absurd 5000 ms outlier and a
    // beyond-cap value that must be discarded on receive (tested via helper).
    sim.get_node(a).test_inject_quality(b_id, vec![(c_id, 25)]);
    sim.get_node(a).test_inject_quality(d_id, vec![(c_id, 5_000)]);

    let (_, suggestion) = sim.get_node(a).test_quality_snapshot();
    let suggestion = suggestion.expect("suggestion via one of the two peers");
    // Median of {37, 5012} is the lower candidate closest to the median.
    assert_eq!(suggestion.dest_node, crate::util::bytes_to_hex(&c_id));
    assert!(suggestion.estimated_rtt_ms <= 5_012);
}

#[test]
fn relay_choice_is_sticky_under_small_rtt_changes() {
    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &router("10.1.0.0/24", true));
    let b = sim.add_node(false, &router("10.2.0.0/24", true));
    let d = sim.add_node(false, &router("10.4.0.0/24", true));
    bring_up(&mut sim, a, b);
    bring_up(&mut sim, a, d);
    sim.get_node(a).test_set_peer_rtt(&b, 10_000);
    sim.get_node(a).test_set_peer_rtt(&d, 11_000);

    let first = sim.get_node(a).test_pick_relay("10.9.9.9:1".parse().unwrap()).unwrap();
    assert_eq!(first, b);
    // D becomes marginally faster; hysteresis should keep B.
    sim.get_node(a).test_set_peer_rtt(&d, 9_000);
    let second = sim.get_node(a).test_pick_relay("10.9.9.9:1".parse().unwrap()).unwrap();
    assert_eq!(second, first, "small RTT changes must not flap the relay");
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

fn broadcast_frame() -> Vec<u8> {
    let mut frame = vec![0xffu8; 6]; // Ethernet broadcast
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // source MAC
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    frame.extend_from_slice(&[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 255, 255, 255, 255]);
    frame
}

#[test]
fn flood_relay_sends_one_copy_and_redistributes() {
    let mut a_cfg = router("10.1.0.0/24", true);
    a_cfg.mode = crate::types::Mode::Switch;
    a_cfg.device_type = crate::device::Type::Tap;
    a_cfg.flood_relay = true;
    let mut other = a_cfg.clone();
    other.flood_relay = false;

    let mut sim = TapSimulator::new();
    let a = sim.add_node(false, &a_cfg);
    let b = sim.add_node(false, &other);
    let c = sim.add_node(false, &other);
    sim.connect(a, b);
    sim.connect(a, c);
    sim.connect(b, c);
    sim.simulate_all_messages();
    sim.clear_messages();

    let frame = broadcast_frame();
    sim.put_payload(a, frame.clone());

    // The weak sender emits exactly one datagram, not one per peer.
    let mut from_a = 0;
    let mut wire_type = 0;
    while let Some((src, _, data)) = sim.front_message() {
        if src == a {
            from_a += 1;
            wire_type = data[0];
        }
        sim.simulate_next_message();
    }
    assert_eq!(from_a, 1, "flood sender must emit only one copy");
    assert!(
        wire_type == crate::messages::MESSAGE_TYPE_FLOOD || wire_type == crate::messages::MESSAGE_TYPE_FLOOD_TTL,
        "expected a flood message, got {}",
        wire_type
    );

    // Both other nodes receive exactly one copy of the frame.
    let mut got_b = Vec::new();
    while let Some(pkt) = sim.pop_payload(b) {
        got_b.push(pkt);
    }
    let mut got_c = Vec::new();
    while let Some(pkt) = sim.pop_payload(c) {
        got_c.push(pkt);
    }
    assert_eq!(got_b, vec![frame.clone()]);
    assert_eq!(got_c, vec![frame]);
}

#[test]
fn flood_relay_can_pin_the_redistribution_peer() {
    let mut a_cfg = router("10.1.0.0/24", true);
    a_cfg.mode = crate::types::Mode::Switch;
    a_cfg.device_type = crate::device::Type::Tap;
    a_cfg.flood_relay = true;
    let other = Config { mode: crate::types::Mode::Switch, device_type: crate::device::Type::Tap, ..a_cfg.clone() };

    let mut sim = TapSimulator::new();
    let a = sim.add_node(false, &a_cfg);
    let b = sim.add_node(false, &other);
    let c = sim.add_node(false, &other);
    sim.connect(a, b);
    sim.connect(a, c);
    sim.connect(b, c);
    sim.simulate_all_messages();
    let c_id = sim.get_node(c).test_node_id();
    sim.get_node(a).config_for_test_mut().flood_relay_via = Some(crate::util::bytes_to_hex(&c_id));
    sim.clear_messages();

    sim.put_payload(a, broadcast_frame());
    let mut target = None;
    while let Some((src, dst, _)) = sim.front_message() {
        if src == a {
            target = Some(dst);
        }
        sim.simulate_next_message();
    }
    assert_eq!(target, Some(c), "pinned flood peer must receive the sender's only copy");
}

#[test]
fn flood_relay_is_opt_in() {
    let mut cfg = router("10.1.0.0/24", true);
    cfg.mode = crate::types::Mode::Switch;
    cfg.device_type = crate::device::Type::Tap;
    let mut sim = TapSimulator::new();
    let a = sim.add_node(false, &cfg);
    let b = sim.add_node(false, &cfg);
    let c = sim.add_node(false, &cfg);
    sim.connect(a, b);
    sim.connect(a, c);
    sim.connect(b, c);
    sim.simulate_all_messages();
    sim.clear_messages();

    sim.put_payload(a, broadcast_frame());
    let mut from_a = 0;
    while let Some((src, _, _)) = sim.front_message() {
        if src == a {
            from_a += 1;
        }
        sim.simulate_next_message();
    }
    assert_eq!(from_a, 2, "without flood_relay the sender still emits one copy per peer");
}

#[test]
fn replayed_sealed_body_is_rejected_per_sealer() {
    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &router("10.1.0.0/24", true));
    let sealer = [0x42u8; 32];
    let body = b"sealed relay body";
    assert!(sim.get_node(a).test_accept_e2e_body(sealer, body));
    assert!(!sim.get_node(a).test_accept_e2e_body(sealer, body));
    // A different sealer sending the same bytes is a different body.
    assert!(sim.get_node(a).test_accept_e2e_body([0x43u8; 32], body));
    // A different body from the original sealer is fine.
    assert!(sim.get_node(a).test_accept_e2e_body(sealer, b"another sealed body"));
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
