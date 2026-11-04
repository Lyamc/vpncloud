// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Relay, claim, filter, and tunnel decisions used by the mesh path.
//! Lib tests call these functions directly. The cloud calls the same ones.

use std::{collections::HashSet, net::SocketAddr, str::FromStr};

use crate::crypto_ring::rand::SecureRandom;

use crate::types::{Address, NodeId, Range};

pub const SEAL_MARK: u8 = 0xE2;

#[derive(Clone, Debug)]
pub struct RelayHop {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub rtt_us: u64,
    pub alive: bool
}

/// Lowest RTT wins. Dead hops and excluded underlay addresses are skipped.
pub fn select_relay<'a>(hops: &'a [RelayHop], exclude: &[SocketAddr]) -> Option<&'a RelayHop> {
    hops.iter().filter(|h| h.alive && !exclude.contains(&h.addr)).min_by_key(|h| (h.rtt_us, h.addr))
}

pub fn encode_relay(dest: &NodeId, inner_type: u8, inner: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(17 + inner.len());
    frame.extend_from_slice(dest);
    frame.push(inner_type);
    frame.extend_from_slice(inner);
    frame
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayDecision {
    Deliver { inner_type: u8, inner: Vec<u8> },
    Forward { via: SocketAddr, dest: NodeId, inner_type: u8, inner: Vec<u8> },
    Drop
}

/// One relay step. The inner bytes are not decrypted here.
pub fn decide_relay(self_id: &NodeId, frame: &[u8], hops: &[RelayHop], inbound: Option<SocketAddr>) -> RelayDecision {
    if frame.len() < 17 {
        return RelayDecision::Drop;
    }
    let mut dest = [0u8; 16];
    dest.copy_from_slice(&frame[..16]);
    let inner_type = frame[16];
    let inner = frame[17..].to_vec();
    if dest == *self_id {
        return RelayDecision::Deliver { inner_type, inner };
    }
    if let Some(hop) = hops.iter().find(|h| h.alive && h.node_id == dest) {
        return RelayDecision::Forward { via: hop.addr, dest, inner_type, inner };
    }
    let mut exclude = Vec::new();
    if let Some(addr) = inbound {
        exclude.push(addr);
    }
    match select_relay(hops, &exclude) {
        Some(hop) => RelayDecision::Forward { via: hop.addr, dest, inner_type, inner },
        None => RelayDecision::Drop
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Direct,
    Relay(SocketAddr),
    Drop
}

/// Direct peers get the original datagram type. Everyone else is a relay hop.
pub fn choose_delivery(dest_connected: bool, hops: &[RelayHop], exclude: SocketAddr) -> Delivery {
    if dest_connected {
        return Delivery::Direct;
    }
    match select_relay(hops, &[exclude]) {
        Some(hop) => Delivery::Relay(hop.addr),
        None => Delivery::Drop
    }
}

pub fn generate_e2e_keypair() -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    crate::crypto_ring::rand::SystemRandom::new().fill(&mut secret).expect("e2e key");
    #[cfg(feature = "noise")]
    {
        let sk = x25519_dalek::StaticSecret::from(secret);
        let pk = x25519_dalek::PublicKey::from(&sk);
        (secret, *pk.as_bytes())
    }
    #[cfg(not(feature = "noise"))]
    {
        (secret, secret)
    }
}

/// Seal `plain` to `dest_public`. `None` when the seal cannot be built.
/// Callers drop the packet. The plaintext is never returned.
pub fn seal_relay_body(secret: &[u8; 32], my_public: &[u8; 32], dest_public: &[u8; 32], plain: &[u8]) -> Option<Vec<u8>> {
    #[cfg(feature = "noise")]
    {
        let me = x25519_dalek::StaticSecret::from(*secret);
        let them = x25519_dalek::PublicKey::from(*dest_public);
        let shared = me.diffie_hellman(&them);
        let mut key = [0u8; 16];
        key.copy_from_slice(&shared.as_bytes()[..16]);
        let ct = crate::crypto::seal_raw(&key, true, plain).ok()?;
        let mut out = Vec::with_capacity(1 + 32 + ct.len());
        out.push(SEAL_MARK);
        out.extend_from_slice(my_public);
        out.extend_from_slice(&ct);
        return Some(out);
    }
    #[cfg(not(feature = "noise"))]
    {
        let _ = (secret, my_public, dest_public, plain);
        None
    }
}

/// Open a body produced by [`seal_relay_body`]. Returns `None` when the mark is absent or the MAC fails.
pub fn open_relay_body(secret: &[u8; 32], inner: &[u8]) -> Option<Vec<u8>> {
    if inner.first() != Some(&SEAL_MARK) || inner.len() < 1 + 32 {
        return None;
    }
    #[cfg(feature = "noise")]
    {
        let mut their = [0u8; 32];
        their.copy_from_slice(&inner[1..33]);
        let me = x25519_dalek::StaticSecret::from(*secret);
        let them = x25519_dalek::PublicKey::from(their);
        let shared = me.diffie_hellman(&them);
        let mut key = [0u8; 16];
        key.copy_from_slice(&shared.as_bytes()[..16]);
        return crate::crypto::open_raw(&key, false, &inner[33..]).ok();
    }
    #[cfg(not(feature = "noise"))]
    {
        let _ = secret;
        None
    }
}

#[derive(Clone, Debug)]
pub struct Grants {
    pub enforcing: bool,
    pub prefixes: Vec<Range>,
    pub groups: Vec<String>
}

pub fn parse_grants(lines: &[String]) -> Result<Grants, &'static str> {
    let mut prefixes = Vec::new();
    let mut groups = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("prefix:") {
            prefixes.push(Range::from_str(rest.trim()).map_err(|_| "invalid grant prefix")?);
        } else if let Some(rest) = line.strip_prefix("group:") {
            let name = rest.trim();
            if name.is_empty() {
                return Err("empty grant group");
            }
            groups.push(name.to_string());
        } else {
            return Err("grant must start with prefix: or group:");
        }
    }
    let enforcing = !prefixes.is_empty() || !groups.is_empty();
    Ok(Grants { enforcing, prefixes, groups })
}

#[derive(Clone, Debug)]
pub struct Announcement {
    pub claims: Vec<Range>,
    pub group: Option<String>
}

#[derive(Clone, Debug)]
pub struct FilteredAnnouncement {
    pub claims: Vec<Range>,
    pub group_ok: bool
}

fn prefix_covered(allow: &[Range], claim: &Range) -> bool {
    allow.iter().any(|grant| {
        grant.base.len == claim.base.len && grant.matches(claim.base) && claim.prefix_len >= grant.prefix_len
    })
}

/// Unauthorized prefixes are left out of `claims`. An unauthorized group sets `group_ok` false.
pub fn filter_announcement(grants: &Grants, ann: &Announcement) -> FilteredAnnouncement {
    if !grants.enforcing {
        return FilteredAnnouncement { claims: ann.claims.clone(), group_ok: true };
    }
    let claims = ann.claims.iter().copied().filter(|c| prefix_covered(&grants.prefixes, c)).collect();
    let group_ok = match &ann.group {
        None => true,
        Some(group) => grants.groups.iter().any(|allowed| allowed == group)
    };
    FilteredAnnouncement { claims, group_ok }
}

pub fn source_allowed(enforcing: bool, group_ok: bool, installed: &[Range], src: Address) -> bool {
    if !enforcing {
        return true;
    }
    group_ok && installed.iter().any(|claim| claim.matches(src))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: Address,
    pub dst: Address,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16
}

#[derive(Clone, Debug, Default)]
pub struct FlowTable {
    seen: HashSet<FlowKey>
}

impl FlowTable {
    pub fn note_outbound(&mut self, flow: FlowKey) {
        self.seen.insert(flow);
    }

    pub fn allow_inbound(&self, flow: &FlowKey) -> bool {
        let rev = FlowKey { src: flow.dst, dst: flow.src, proto: flow.proto, sport: flow.dport, dport: flow.sport };
        self.seen.contains(&rev)
    }
}

pub fn ipv4_flow(pkt: &[u8]) -> Option<FlowKey> {
    if pkt.first().map(|b| b >> 4) != Some(4) || pkt.len() < 20 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 4 {
        return None;
    }
    let proto = pkt[9];
    if proto != 6 && proto != 17 {
        return None;
    }
    let src = Address::from_ipv4(std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
    let dst = Address::from_ipv4(std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    Some(FlowKey { src, dst, proto, sport, dport })
}

pub fn split_forwards(prefixes: &[Range], dest: Address) -> bool {
    prefixes.iter().any(|prefix| prefix.matches(dest))
}

pub fn full_tunnel_target(allow: &[NodeId], requested: Option<NodeId>) -> Option<NodeId> {
    let id = requested?;
    if allow.iter().any(|allowed| *allowed == id) {
        Some(id)
    } else {
        None
    }
}

pub fn parse_peer_names(lines: &[String]) -> Vec<(String, Address)> {
    let mut out = Vec::new();
    for line in lines {
        let Some((name, addr)) = line.split_once('=') else { continue };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        if let Ok(addr) = Address::from_str(addr.trim()) {
            out.push((name.to_string(), addr));
        }
    }
    out
}

pub fn resolve_peer_name(records: &[(String, Address)], name: &str) -> Option<Address> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    records.iter().find(|(record, _)| record.eq_ignore_ascii_case(&name)).map(|(_, addr)| *addr)
}

fn read_dns_name(pkt: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    for _ in 0..32 {
        if i >= pkt.len() {
            return None;
        }
        let len = pkt[i] as usize;
        if len == 0 {
            return Some((labels.join("."), i + 1));
        }
        if len > 63 || i + 1 + len > pkt.len() {
            return None;
        }
        i += 1;
        labels.push(String::from_utf8_lossy(&pkt[i..i + len]).into_owned());
        i += len;
    }
    None
}

/// Answer an IPv4 UDP query to port 53 from the configured table. No external resolver.
pub fn answer_dns(pkt: &[u8], records: &[(String, Address)]) -> Option<Vec<u8>> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 || pkt[9] != 17 {
        return None;
    }
    let udp = &pkt[ihl..];
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    if dport != 53 || udp.len() < 8 + 12 {
        return None;
    }
    let dns = &udp[8..];
    let (qname, after_name) = read_dns_name(dns, 12)?;
    if after_name + 4 > dns.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([dns[after_name], dns[after_name + 1]]);
    let addr = resolve_peer_name(records, &qname)?;
    let (rtype, rdata): (u16, Vec<u8>) = if addr.len == 4 && (qtype == 1 || qtype == 255) {
        (1, addr.data[..4].to_vec())
    } else if addr.len == 16 && (qtype == 28 || qtype == 255) {
        (28, addr.data.to_vec())
    } else {
        return None;
    };
    let question = &dns[12..after_name + 4];
    let mut dns_out = Vec::with_capacity(12 + question.len() + 12 + rdata.len());
    dns_out.extend_from_slice(&dns[..2]);
    dns_out.extend_from_slice(&[0x84, 0x00]);
    dns_out.extend_from_slice(&1u16.to_be_bytes());
    dns_out.extend_from_slice(&1u16.to_be_bytes());
    dns_out.extend_from_slice(&[0, 0, 0, 0]);
    dns_out.extend_from_slice(question);
    dns_out.extend_from_slice(&[0xc0, 0x0c]);
    dns_out.extend_from_slice(&rtype.to_be_bytes());
    dns_out.extend_from_slice(&1u16.to_be_bytes());
    dns_out.extend_from_slice(&60u32.to_be_bytes());
    dns_out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    dns_out.extend_from_slice(&rdata);

    let udp_len = 8 + dns_out.len();
    let total = ihl + udp_len;
    let mut out = vec![0u8; total];
    out[..ihl].copy_from_slice(&pkt[..ihl]);
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[10] = 0;
    out[11] = 0;
    out[12..16].copy_from_slice(&pkt[16..20]);
    out[16..20].copy_from_slice(&pkt[12..16]);
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    out[ihl..ihl + 2].copy_from_slice(&53u16.to_be_bytes());
    out[ihl + 2..ihl + 4].copy_from_slice(&sport.to_be_bytes());
    out[ihl + 4..ihl + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[ihl + 6] = 0;
    out[ihl + 7] = 0;
    out[ihl + 8..].copy_from_slice(&dns_out);
    Some(out)
}

pub fn parse_node_id(text: &str) -> Option<NodeId> {
    let text = text.trim();
    if text.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for i in 0..16 {
        id[i] = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{MESSAGE_TYPE_DATA, MESSAGE_TYPE_RELAY};
    use std::net::{Ipv4Addr, SocketAddr};

    fn hop(id: u8, port: u16, rtt: u64) -> RelayHop {
        RelayHop {
            node_id: [id; 16],
            addr: SocketAddr::from((Ipv4Addr::new(10, 0, 0, id), port)),
            rtt_us: rtt,
            alive: true
        }
    }

    #[test]
    fn latency_selects_lowest_rtt_and_skips_a_dead_relay() {
        let hops = vec![hop(1, 1, 50), hop(2, 2, 10), hop(3, 3, 20)];
        assert_eq!(select_relay(&hops, &[]).unwrap().addr, hops[1].addr);
        let mut lost = hops.clone();
        lost[1].alive = false;
        assert_eq!(select_relay(&lost, &[]).unwrap().addr, hops[2].addr);
        assert!(select_relay(&lost, &[hops[2].addr, hops[0].addr]).is_none());
    }

    #[test]
    fn one_and_two_intermediates_forward_opaque_inner() {
        let (secret_a, pub_a) = generate_e2e_keypair();
        let (secret_b, pub_b) = generate_e2e_keypair();
        let (secret_r, _) = generate_e2e_keypair();
        let payload = b"end-to-end-secret";
        let sealed = seal_relay_body(&secret_a, &pub_a, &pub_b, payload).expect("seal");
        assert_ne!(&sealed[..], payload);
        assert!(open_relay_body(&secret_r, &sealed).is_none());
        assert_eq!(open_relay_body(&secret_b, &sealed).as_deref(), Some(payload.as_slice()));

        let dest = [9u8; 16];
        let frame = encode_relay(&dest, MESSAGE_TYPE_DATA, &sealed);
        let r1 = [4u8; 16];
        let r2 = [5u8; 16];
        let from_a = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 1));
        let step1 = decide_relay(&r1, &frame, &[hop(5, 5, 30)], Some(from_a));
        let RelayDecision::Forward { via, inner, inner_type, dest: d1 } = step1 else { panic!("hop1") };
        assert_eq!(via.port(), 5);
        assert_eq!(inner, sealed);
        assert_eq!(inner_type, MESSAGE_TYPE_DATA);
        assert_eq!(d1, dest);
        let frame2 = encode_relay(&d1, inner_type, &inner);
        let step2 = decide_relay(&r2, &frame2, &[hop(9, 9, 5)], Some(hops_addr(5)));
        let RelayDecision::Forward { via, inner, .. } = step2 else { panic!("hop2") };
        assert_eq!(via.port(), 9);
        assert_eq!(inner, sealed);
        let frame3 = encode_relay(&dest, MESSAGE_TYPE_DATA, &inner);
        let RelayDecision::Deliver { inner, .. } = decide_relay(&dest, &frame3, &[], Some(hops_addr(9))) else {
            panic!("dest")
        };
        assert_eq!(inner, sealed);
        assert_eq!(open_relay_body(&secret_b, &inner).as_deref(), Some(payload.as_slice()));
    }

    fn hops_addr(id: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, id), id as u16))
    }

    #[test]
    fn direct_delivery_has_no_relay_wrapper_and_is_not_plain() {
        let body = b"\x45direct-datagram";
        let dest = [2u8; 16];
        let exclude = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        assert_eq!(choose_delivery(true, &[hop(3, 3, 1)], exclude), Delivery::Direct);
        let wrapped = encode_relay(&dest, MESSAGE_TYPE_RELAY, body);
        assert_ne!(body.as_slice(), wrapped.as_slice());
        assert_eq!(body[0] >> 4, 4);
        let (plain, _, algos) = crate::crypto::Crypto::parse_algorithms(&[]).unwrap();
        assert!(!plain);
        assert!(!algos.is_empty());
    }

    #[test]
    fn unauthorized_prefix_and_group_are_rejected() {
        let grants = parse_grants(&["prefix:10.0.0.0/8".into(), "group:eng".into()]).unwrap();
        let ok_claim = Range::from_str("10.1.2.0/24").unwrap();
        let bad_claim = Range::from_str("192.168.0.0/24").unwrap();
        let kept = filter_announcement(&grants, &Announcement {
            claims: vec![ok_claim, bad_claim],
            group: Some("eng".into())
        });
        assert_eq!(kept.claims, vec![ok_claim]);
        assert!(kept.group_ok);
        let src = Address::from_str("10.1.2.9").unwrap();
        assert!(source_allowed(true, kept.group_ok, &kept.claims, src));
        let outsider = Address::from_str("192.168.0.9").unwrap();
        assert!(!source_allowed(true, kept.group_ok, &kept.claims, outsider));

        let bad_group = filter_announcement(&grants, &Announcement {
            claims: vec![ok_claim],
            group: Some("finance".into())
        });
        assert!(bad_group.claims.is_empty() || !bad_group.group_ok);
        assert!(!bad_group.group_ok);
        assert!(!source_allowed(true, bad_group.group_ok, &bad_group.claims, src));

        let open = parse_grants(&[]).unwrap();
        assert!(!open.enforcing);
        let all = filter_announcement(&open, &Announcement { claims: vec![bad_claim], group: Some("finance".into()) });
        assert_eq!(all.claims, vec![bad_claim]);
        assert!(source_allowed(false, true, &[], outsider));
    }

    #[test]
    fn stateful_filter_allows_the_reply_and_drops_the_reverse() {
        let mut flows = FlowTable::default();
        let src = Address::from_str("10.0.0.1").unwrap();
        let dst = Address::from_str("10.0.0.2").unwrap();
        let out = FlowKey { src, dst, proto: 6, sport: 40000, dport: 80 };
        flows.note_outbound(out);
        let reply = FlowKey { src: dst, dst: src, proto: 6, sport: 80, dport: 40000 };
        assert!(flows.allow_inbound(&reply));
        let unsolicited = FlowKey { src: dst, dst: src, proto: 6, sport: 40000, dport: 80 };
        assert!(!flows.allow_inbound(&unsolicited));
    }

    #[test]
    fn split_full_and_dns_use_configured_tables() {
        let prefixes = vec![Range::from_str("10.8.0.0/16").unwrap()];
        assert!(split_forwards(&prefixes, Address::from_str("10.8.1.4").unwrap()));
        assert!(!split_forwards(&prefixes, Address::from_str("1.1.1.1").unwrap()));
        let allow = [[7u8; 16]];
        assert_eq!(full_tunnel_target(&allow, Some([7u8; 16])), Some([7u8; 16]));
        assert_eq!(full_tunnel_target(&allow, Some([8u8; 16])), None);
        let names = parse_peer_names(&["Alice=10.9.0.4".into()]);
        assert_eq!(resolve_peer_name(&names, "alice."), Some(Address::from_str("10.9.0.4").unwrap()));
        assert!(resolve_peer_name(&names, "bob").is_none());

        let mut query = vec![0u8; 20];
        query[0] = 0x45;
        query[9] = 17;
        query[12..16].copy_from_slice(&[10, 0, 0, 2]);
        query[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        dns.extend_from_slice(&[5, b'a', b'l', b'i', b'c', b'e', 0, 0x00, 0x01, 0x00, 0x01]);
        let udp_len = 8 + dns.len();
        query.extend_from_slice(&1234u16.to_be_bytes());
        query.extend_from_slice(&53u16.to_be_bytes());
        query.extend_from_slice(&(udp_len as u16).to_be_bytes());
        query.extend_from_slice(&[0, 0]);
        query.extend_from_slice(&dns);
        let total = query.len() as u16;
        query[2..4].copy_from_slice(&total.to_be_bytes());
        let answer = answer_dns(&query, &names).unwrap();
        assert!(answer.windows(4).any(|w| w == [10, 9, 0, 4]));
        assert!(answer_dns(&query, &[]).is_none());
    }
}
