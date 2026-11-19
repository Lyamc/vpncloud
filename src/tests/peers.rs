// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::common::*;

/// Reload tests share process-global state (config path and signature keys),
/// so they must not run concurrently with each other.
static RELOAD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn direct_connect() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn direct_connect_unencrypted() {
    let config = Config {
        crypto: CryptoConfig { algorithms: vec!["plain".to_string()], ..CryptoConfig::default() },
        ..Config::default()
    };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn per_node_identity_rejects_unsigned_announcements() {
    use crate::{
        crypto::{Crypto, Ed25519KeyPair},
        messages::NodeInfo,
        types::NODE_ID_BYTES
    };

    let (priv_b62, pub_b62) = Crypto::generate_keypair(None);
    let node_id = [7u8; NODE_ID_BYTES];
    let mapping = format!("{}={}", crate::util::bytes_to_hex(&node_id), pub_b62);

    let mut config = Config::default();
    config.trusted_node_keys = vec![mapping];
    let mut sim = TunSimulator::new();
    let node = sim.add_node(false, &config);
    let receiver = sim.get_node(node);

    let mut info = NodeInfo {
        node_id,
        peers: smallvec::smallvec![],
        claims: smallvec::smallvec![],
        peer_timeout: None,
        addrs: smallvec::smallvec![],
        underlay_mtu: None,
        group: None,
        e2e_public: Some([1u8; 32]),
        peer_e2e: Vec::new(),
        transit: Vec::new(),
        compression: false,
        wire_caps: 0,
        peer_rtts: Vec::new(),
        node_signature: None
    };
    assert!(!receiver.test_verify_node_identity(&info));
    let seed = crate::util::from_base62_fixed::<32>(&priv_b62).unwrap();
    let pair = Ed25519KeyPair::from_seed(&seed).unwrap();
    info.node_signature = Some(pair.sign(&info.identity_bytes()));
    assert!(receiver.test_verify_node_identity(&info));
    info.e2e_public = Some([2u8; 32]);
    assert!(!receiver.test_verify_node_identity(&info));
}

#[test]
fn sighup_reload_applies_policy_without_restart() {
    use std::io::Write;

    let _guard = RELOAD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    crate::config_verify::set_reload_verify_keys(crate::config_verify::VerifyKeys::none());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("net.net");
    std::fs::write(&path, "listen: 3210\ncrypto:\n  password: secret\n").unwrap();
    crate::util::CtrlC::set_reload_path(path.clone());

    let config = Config::default();
    let mut sim = TunSimulator::new();
    let node = sim.add_node(false, &config);
    // Mutate the config on disk; a SIGHUP reload should pick up new ACL rules.
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "listen: 3210\ncrypto:\n  password: secret\nacl:\n  - deny:10.0.0.0/8").unwrap();
    drop(f);
    assert!(sim.get_node(node).test_acl_allows("10.1.2.3"));
    sim.get_node(node).test_reload_config();
    assert!(!sim.get_node(node).test_acl_allows("10.1.2.3"));
    assert!(sim.get_node(node).test_acl_allows("192.0.2.1"));
}

#[test]
fn reload_exit_node_reparses_node_ids() {
    let _guard = RELOAD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    crate::config_verify::set_reload_verify_keys(crate::config_verify::VerifyKeys::none());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("net.net");
    let id1 = "0102030405060708090a0b0c0d0e0f10";
    let id2 = "1112131415161718191a1b1c1d1e1f20";
    let expected1: [u8; 16] = crate::util::from_hex(id1).unwrap().try_into().unwrap();
    let expected2: [u8; 16] = crate::util::from_hex(id2).unwrap().try_into().unwrap();

    std::fs::write(&path, format!("listen: 3210\ncrypto:\n  password: secret\nexit-node: {}\n", id1)).unwrap();
    crate::util::CtrlC::set_reload_path(path.clone());

    let config = Config::default();
    let mut sim = TunSimulator::new();
    let node = sim.add_node(false, &config);
    assert_eq!(sim.get_node(node).test_exit_target(), (None, vec![]));

    // Change exit node and add an allow-list: the parsed NodeIds must follow.
    std::fs::write(
        &path,
        format!("listen: 3210\ncrypto:\n  password: secret\nexit-node: {}\nexit-allow: [{}]\n", id2, id1)
    )
    .unwrap();
    sim.get_node(node).test_reload_config();
    assert_eq!(sim.get_node(node).test_exit_target(), (Some(expected2), vec![expected1]));

    // Removing the allow-list falls back to allowing only the exit node.
    std::fs::write(&path, format!("listen: 3210\ncrypto:\n  password: secret\nexit-node: {}\n", id2)).unwrap();
    sim.get_node(node).test_reload_config();
    assert_eq!(sim.get_node(node).test_exit_target(), (Some(expected2), vec![expected2]));
}

#[test]
fn sighup_reload_verifies_signatures() {
    use crate::{
        config_verify::{set_reload_verify_keys, VerifyKeys},
        crypto::Crypto,
        sign
    };

    let _guard = RELOAD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (privk, pubk) = Crypto::generate_keypair(None);

    let signed = |acl: &str| -> String {
        let raw = format!("listen: 3210\ncrypto:\n  password: secret\nacl:\n  - {}\n", acl);
        let body = sign::body_for_signing(&raw);
        let sig = sign::sign_body(&body, &privk).unwrap();
        sign::append_signature_line(&raw, &sig, false)
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("net.net");
    std::fs::write(&path, signed("deny:10.0.0.0/8")).unwrap();
    crate::util::CtrlC::set_reload_path(path.clone());
    set_reload_verify_keys(VerifyKeys { keys: vec![pubk], provided: true });

    let config = Config::default();
    let mut sim = TunSimulator::new();
    let node = sim.add_node(false, &config);

    // A correctly signed config is accepted.
    std::fs::write(&path, signed("deny:10.1.0.0/16")).unwrap();
    sim.get_node(node).test_reload_config();
    assert!(!sim.get_node(node).test_acl_allows("10.1.2.3"), "signed reload must be applied");

    // An unsigned config is rejected; the previous ACL stays in effect.
    std::fs::write(&path, "listen: 3210\ncrypto:\n  password: secret\nacl:\n  - deny:192.0.2.0/24\n").unwrap();
    sim.get_node(node).test_reload_config();
    assert!(sim.get_node(node).test_acl_allows("192.0.2.1"), "unsigned reload must be rejected");
    assert!(!sim.get_node(node).test_acl_allows("10.1.2.3"), "old ACL must remain after rejection");

    // A tampered signature is rejected too.
    let mut tampered = signed("deny:198.51.100.0/24");
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    std::fs::write(&path, &tampered).unwrap();
    sim.get_node(node).test_reload_config();
    assert!(sim.get_node(node).test_acl_allows("198.51.100.1"), "tampered reload must be rejected");

    set_reload_verify_keys(VerifyKeys::none());
}

#[test]
fn sighup_reload_updates_claims() {
    use std::str::FromStr;

    let _guard = RELOAD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    crate::config_verify::set_reload_verify_keys(crate::config_verify::VerifyKeys::none());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("net.net");
    std::fs::write(&path, "crypto:\n  password: secret\nauto-claim: false\nclaims: [10.0.0.0/24]\n").unwrap();
    crate::util::CtrlC::set_reload_path(path.clone());
    let config = Config { claims: vec!["10.0.0.0/24".into()], auto_claim: false, ..Config::default() };
    let mut sim = TunSimulator::new();
    let node = sim.add_node(false, &config);
    assert!(sim
        .get_node(node)
        .test_claims()
        .iter()
        .any(|c| c.base == crate::types::Address::from_str("10.0.0.0").unwrap()));

    std::fs::write(&path, "crypto:\n  password: secret\nauto-claim: false\nclaims: [10.5.0.0/24, 10.6.0.0/24]\n")
        .unwrap();
    sim.get_node(node).test_reload_config();
    let claims = sim.get_node(node).test_claims();
    assert!(claims.iter().any(|c| c.base == crate::types::Address::from_str("10.5.0.0").unwrap()));
    assert!(claims.iter().any(|c| c.base == crate::types::Address::from_str("10.6.0.0").unwrap()));
    assert!(!claims.iter().any(|c| c.base == crate::types::Address::from_str("10.0.0.0").unwrap()));
}

#[test]
fn local_addresses_are_claimed_and_get_distinct_arps() {
    use std::str::FromStr;
    let config = Config {
        device_type: Type::Tap,
        local_addresses: vec!["10.9.0.10".into(), "10.9.0.11".into()],
        l2_l3_bridge: true,
        ..Config::default()
    };
    let mut sim = TapSimulator::new();
    let node = sim.add_node(false, &config);
    let cloud = sim.get_node(node);
    let claims = cloud.test_claims();
    for ip in ["10.9.0.10", "10.9.0.11"] {
        assert!(
            claims.iter().any(|c| c.base == crate::types::Address::from_str(ip).unwrap() && c.prefix_len == 32),
            "{ip} must be announced as a host claim"
        );
    }

    fn arp_request(ip: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![0xffu8; 6];
        frame.extend_from_slice(&[1, 1, 1, 1, 1, 1]);
        frame.extend_from_slice(&[0x08, 0x06]);
        let mut arp = vec![0u8; 28];
        arp[..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&1u16.to_be_bytes());
        arp[8..14].copy_from_slice(&[1, 1, 1, 1, 1, 1]);
        arp[14..18].copy_from_slice(&[10, 0, 0, 9]);
        arp[24..28].copy_from_slice(&ip);
        frame.extend_from_slice(&arp);
        frame
    }

    let reply10 = cloud.test_arp_reply(&arp_request([10, 9, 0, 10])).expect("ARP for first local IP");
    let reply11 = cloud.test_arp_reply(&arp_request([10, 9, 0, 11])).expect("ARP for second local IP");
    assert_ne!(&reply10[6..12], &reply11[6..12], "each local IP must resolve to a distinct MAC");
}

#[test]
fn noisy_peer_is_throttled() {
    let config = Config {
        // 100-byte bucket; each 50-byte packet consumes half.
        per_peer_rate_limit: 100,
        jitter_ms: Some(0),
        claims: vec!["10.0.0.2/32".into()],
        ..Config::default()
    };
    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &config);
    let b = sim.add_node(false, &config);
    sim.connect(a, b);
    sim.simulate_all_messages();
    assert!(sim.is_connected(a, b));

    let mut pkt = vec![0u8; 50];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&50u16.to_be_bytes());
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    sim.put_payload(a, pkt.clone());
    sim.simulate_all_messages();
    sim.put_payload(a, pkt.clone());
    sim.simulate_all_messages();
    sim.put_payload(a, pkt);
    sim.simulate_all_messages();
    assert!(sim.pop_payload(b).is_some(), "first packet below bucket limit");
    assert!(sim.pop_payload(b).is_some(), "second packet exhausts bucket");

    let before = sim.pop_payload(b);
    assert!(before.is_none(), "third packet must be throttled");
    // The peer is marked penalised in status.
    let node = sim.get_node(b);
    assert!(node.test_peer_throttled(&a) > 0, "throttle event must be recorded");
}

#[test]
fn tap_bridge_exchanges_ip_with_tun_peer() {
    use crate::types::Mode;

    let tap_config = Config {
        device_type: Type::Tap,
        l2_l3_bridge: true,
        mode: Mode::Switch,
        // Advertise the IP the TUN peer sends to so it can route to us.
        claims: vec!["10.0.0.2/32".into()],
        ..Config::default()
    };
    let tun_config = Config { device_type: Type::Tun, ..Config::default() };
    let mut sim = TapSimulator::new();
    let tap = sim.add_node(false, &tap_config);
    let tun = sim.add_node(false, &tun_config);
    sim.connect(tap, tun);
    sim.simulate_all_messages();
    assert!(sim.is_connected(tap, tun), "mixed TAP/TUN handshake must succeed");

    // Ethernet frame from the TAP bridge arrives as a raw IP packet at TUN.
    let ip = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
    let mut frame = crate::wire::wrap_ip(&ip, [2, 1, 2, 3, 4, 5], [2, 6, 7, 8, 9, 10]).unwrap();
    sim.put_payload(tap, frame.clone());
    sim.simulate_all_messages();
    let received = sim.pop_payload(tun).expect("TUN peer must receive the IP packet");
    assert_eq!(received, ip.to_vec(), "Ethernet header must be stripped for the TUN peer");

    // Raw IP from the TUN peer arrives as an Ethernet frame at the TAP node.
    sim.put_payload(tun, ip.to_vec());
    sim.simulate_all_messages();
    let received = sim.pop_payload(tap).expect("TAP bridge must receive an Ethernet frame");
    assert_eq!(&received[12..14], &[0x08, 0x00], "IPv4 EtherType expected");
    assert_eq!(crate::wire::strip_ethernet(&received), Some(&ip[..]));
    // Keep the mutable binding used so the compiler does not warn.
    frame.clear();
}

#[test]
fn per_node_keys_require_unique_keys_and_bindings() {
    let (privk, pubk) = crate::crypto::Crypto::generate_keypair(None);
    let mut cfg = Config::default();
    cfg.per_node_keys = true;
    cfg.crypto.password = None;
    assert!(cfg.validate().is_err(), "password-only config must be rejected");
    cfg.crypto.private_key = Some(privk);
    assert!(cfg.validate().is_err(), "missing bindings must be rejected");
    cfg.trusted_node_keys = vec![format!("{}={}", crate::util::bytes_to_hex(&[1u8; 16]), pubk)];
    assert!(cfg.validate().is_ok());
}

#[test]
fn per_node_keys_handshake_binds_peer_identity() {
    let (priv_a, pub_a) = crate::crypto::Crypto::generate_keypair(None);
    let (priv_b, pub_b) = crate::crypto::Crypto::generate_keypair(None);
    let id_a = [1u8; 16];
    let id_b = [2u8; 16];

    let mut cfg_a = Config::default();
    cfg_a.per_node_keys = true;
    cfg_a.crypto.private_key = Some(priv_a);
    cfg_a.node_id = Some(crate::util::bytes_to_hex(&id_a));
    cfg_a.trusted_node_keys = vec![format!("{}={}", crate::util::bytes_to_hex(&id_b), pub_b)];

    let mut cfg_b = Config::default();
    cfg_b.per_node_keys = true;
    cfg_b.crypto.private_key = Some(priv_b);
    cfg_b.node_id = Some(crate::util::bytes_to_hex(&id_b));
    cfg_b.trusted_node_keys = vec![format!("{}={}", crate::util::bytes_to_hex(&id_a), pub_a)];

    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &cfg_a);
    let b = sim.add_node(false, &cfg_b);
    sim.connect(a, b);
    sim.simulate_all_messages();
    assert!(sim.is_connected(a, b), "per-node-key handshake must succeed");
    assert!(sim.is_connected(b, a));
}

#[test]
fn per_node_keys_reject_a_key_bound_to_another_node() {
    let (priv_a, pub_a) = crate::crypto::Crypto::generate_keypair(None);
    let (priv_b, pub_b) = crate::crypto::Crypto::generate_keypair(None);
    let id_a = [1u8; 16];
    let id_b = [2u8; 16];

    let mut cfg_a = Config::default();
    cfg_a.per_node_keys = true;
    cfg_a.crypto.private_key = Some(priv_a);
    cfg_a.node_id = Some(crate::util::bytes_to_hex(&id_a));
    // B's real key is bound to the WRONG node id (id_a), so B's handshake
    // claims id_b and must be rejected.
    cfg_a.trusted_node_keys = vec![format!("{}={}", crate::util::bytes_to_hex(&id_a), pub_b)];

    let mut cfg_b = Config::default();
    cfg_b.per_node_keys = true;
    cfg_b.crypto.private_key = Some(priv_b);
    cfg_b.node_id = Some(crate::util::bytes_to_hex(&id_b));
    cfg_b.trusted_node_keys = vec![format!("{}={}", crate::util::bytes_to_hex(&id_a), pub_a)];

    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &cfg_a);
    let b = sim.add_node(false, &cfg_b);
    sim.connect(a, b);
    sim.simulate_all_messages();
    assert!(!sim.is_connected(a, b), "mismatched identity binding must fail");
}

#[test]
fn node_id_is_stable_when_derived_from_the_signing_key() {
    let (privk, _) = crate::crypto::Crypto::generate_keypair(None);
    let mut cfg = Config::default();
    cfg.node_key = Some(privk.clone());
    let mut sim1 = TunSimulator::new();
    let a = sim1.add_node(false, &cfg);
    let id1 = sim1.get_node(a).test_own_node_id();

    // A fresh process with the same key derives the same id.
    let mut cfg2 = Config::default();
    cfg2.node_key = Some(privk);
    let mut sim2 = TunSimulator::new();
    let b = sim2.add_node(false, &cfg2);
    let id2 = sim2.get_node(b).test_own_node_id();
    assert_eq!(id1, id2, "same key must derive the same stable node id");
}

#[test]
fn peer_migrates_when_the_same_node_reconnects_from_a_new_address() {
    let cfg = Config::default();
    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &cfg);
    let b = sim.add_node(false, &cfg);
    sim.connect(a, b);
    sim.simulate_all_messages();
    assert!(sim.is_connected(a, b));
    let b_id = sim.get_node(a).test_peer_node_id(&b).expect("B's node id as seen by A");

    // A third node announces the SAME node id from a different address — this
    // models the phone reappearing on 4G with a stable node id.
    let mut moved = cfg.clone();
    moved.node_id = Some(crate::util::bytes_to_hex(&b_id));
    let b2 = sim.add_node(false, &moved);
    sim.connect(a, b2);
    sim.simulate_all_messages();

    assert!(!sim.is_connected(a, b), "old address must be dropped immediately");
    assert!(sim.is_connected(a, b2), "new address must be connected");
}

#[test]
fn underlay_mtu_recovers_when_the_limiting_peer_leaves() {
    let cfg = Config::default();
    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &cfg);
    let b = sim.add_node(false, &cfg);
    sim.connect(a, b);
    sim.simulate_all_messages();

    sim.set_underlay(a, 1500, false);
    let full = sim.get_node(a).device().plain_limit();
    sim.set_underlay(b, 600, false);
    sim.get_node(a).test_note_peer_underlay(&b, Some(600));
    let limited = sim.get_node(a).device().plain_limit();
    assert!(limited < full, "low-MTU peer must lower the tunnel MTU: {} -> {}", full, limited);

    // With the constrained peer gone, the MTU must recover (the old code
    // ratcheted down permanently).
    sim.get_node(a).test_remove_peer_mtu(&b);
    let recovered = sim.get_node(a).device().plain_limit();
    assert_eq!(recovered, full, "tunnel MTU must recover after the peer leaves");
}

#[test]
fn consistency_profile_buffers_frames_until_their_delay_elapses() {
    let mut cfg = Config::default();
    cfg.profile = crate::types::NetworkProfile::Consistency;
    cfg.jitter_ms = Some(50);
    cfg.mode = crate::types::Mode::Switch;
    let mut sim = TunSimulator::new();
    let a = sim.add_node(false, &cfg);
    let b = sim.add_node(false, &cfg);
    sim.connect(a, b);
    sim.simulate_all_messages();
    sim.clear_messages();

    let mut pkt = vec![0x45u8; 40];
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    sim.put_payload(a, pkt.clone());
    sim.simulate_all_messages();
    // Frame is held in the jitter buffer, not yet delivered to the TUN.
    assert_eq!(sim.pop_payload(b), None);

    crate::util::MockTimeSource::set_time(crate::util::MockTimeSource::now() + 60);
    sim.trigger_node_housekeep(b);
    assert_eq!(sim.pop_payload(b), Some(pkt));
}

#[test]
fn status_file_is_written_on_housekeep() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let config = Config { status_file: Some(path.display().to_string()), ..Config::default() };
    let mut sim = TunSimulator::new();
    let node = sim.add_node(false, &config);
    sim.trigger_node_housekeep(node);
    let raw = std::fs::read_to_string(&path).expect("status file written by housekeep");
    let status: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(status["device"].is_string());
    assert_eq!(status["peer_count"], 0);
    assert!(status["uptime_secs"].is_number());
}

#[test]
fn cross_connect() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);
    let node3 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.connect(node1, node3);
    sim.simulate_all_messages();

    sim.simulate_time(120);

    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));
}

#[test]
fn connect_via_beacons() {
    let mut sim = TapSimulator::new();
    let beacon_path = "target/.vpncloud_test";
    let config1 = Config { beacon_store: Some(beacon_path.to_string()), ..Default::default() };
    let node1 = sim.add_node(false, &config1);
    let config2 = Config { beacon_load: Some(beacon_path.to_string()), ..Default::default() };
    let node2 = sim.add_node(false, &config2);

    sim.set_time(100);
    sim.trigger_node_housekeep(node1);
    sim.trigger_node_housekeep(node2);
    sim.simulate_all_messages();

    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn reconnect_after_timeout() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    sim.set_time(5000);
    sim.trigger_housekeep();
    assert!(!sim.is_connected(node1, node2));
    assert!(!sim.is_connected(node2, node1));

    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn lost_init_ping() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.drop_message(); // drop init ping

    sim.simulate_time(120);
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn lost_init_pong() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_next_message(); // init ping
    sim.drop_message(); // drop init pong

    sim.simulate_time(120);
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn lost_init_peng() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_next_message(); // init ping
    sim.simulate_next_message(); // init pong
    sim.drop_message(); // drop init peng

    sim.simulate_time(120);
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
#[ignore]
fn peer_exchange() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
fn lost_peer_exchange() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
fn remove_dead_peers() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
fn update_primary_address() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
fn automatic_peer_timeout() {
    // TODO Test
    unimplemented!()
}
