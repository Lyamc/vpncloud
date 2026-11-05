// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Enrollment checks that stay local: a CA certificate, an HS256 token,
//! a scripted login, an opt-in approval gate, an exact group rule, and
//! removal of ephemeral nodes.

use std::{
    collections::BTreeSet,
    io::{self, BufRead, ErrorKind}
};

use crate::crypto::{pbkdf2_hmac_sha256, Ed25519KeyPair};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCert {
    pub node_id: [u8; 16],
    pub pubkey: [u8; 32],
    pub expiry: u64,
    pub signature: [u8; 64]
}

fn cert_message(node_id: &[u8; 16], pubkey: &[u8; 32], expiry: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(56);
    msg.extend_from_slice(node_id);
    msg.extend_from_slice(pubkey);
    msg.extend_from_slice(&expiry.to_be_bytes());
    msg
}

pub fn issue_cert(ca: &Ed25519KeyPair, node_id: [u8; 16], pubkey: [u8; 32], expiry: u64) -> SignedCert {
    let signature = ca.sign(&cert_message(&node_id, &pubkey, expiry));
    SignedCert { node_id, pubkey, expiry, signature }
}

pub fn accept_cert(ca_public: &[u8], cert: &SignedCert, now: u64) -> bool {
    if cert.expiry <= now {
        return false;
    }
    let msg = cert_message(&cert.node_id, &cert.pubkey, cert.expiry);
    Ed25519KeyPair::verify(ca_public, &msg, &cert.signature).is_ok()
}

fn b64url(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    if i < data.len() {
        let mut n = (data[i] as u32) << 16;
        if i + 1 < data.len() {
            n |= (data[i + 1] as u32) << 8;
        }
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if i + 1 < data.len() {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
    }
    out
}

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None
        }
    }
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = val(bytes[i])? as u32;
        let b = val(bytes[i + 1])? as u32;
        let c = val(bytes[i + 2])? as u32;
        let d = val(bytes[i + 3])? as u32;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    let rem = bytes.len() - i;
    if rem == 2 {
        let a = val(bytes[i])? as u32;
        let b = val(bytes[i + 1])? as u32;
        let n = (a << 18) | (b << 12);
        out.push((n >> 16) as u8);
    } else if rem == 3 {
        let a = val(bytes[i])? as u32;
        let b = val(bytes[i + 1])? as u32;
        let c = val(bytes[i + 2])? as u32;
        let n = (a << 18) | (b << 12) | (c << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    } else if rem != 0 {
        return None;
    }
    Some(out)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn json_string(json: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let start = json.find(&pat)? + pat.len();
    let end = json[start..].find('"')? + start;
    Some(json[start..end].to_string())
}

fn json_u64(json: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\":");
    let start = json.find(&pat)? + pat.len();
    let digits: String = json[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

pub fn issue_token(secret: &[u8], sub: &str, exp: u64) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64url(format!(r#"{{"sub":"{sub}","exp":{exp}}}"#).as_bytes());
    let signing = format!("{header}.{payload}");
    let sig = hmac_sha256(secret, signing.as_bytes());
    format!("{signing}.{}", b64url(&sig))
}

/// Local HS256 check. No identity provider is contacted.
pub fn accept_token(secret: &[u8], token: &str, now: u64) -> Result<String, ()> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or(())?;
    let payload_b64 = parts.next().ok_or(())?;
    let sig_b64 = parts.next().ok_or(())?;
    if parts.next().is_some() {
        return Err(());
    }
    let header = b64url_decode(header_b64).ok_or(())?;
    let header_text = std::str::from_utf8(&header).map_err(|_| ())?;
    if !header_text.contains("HS256") {
        return Err(());
    }
    let expect = hmac_sha256(secret, format!("{header_b64}.{payload_b64}").as_bytes());
    let got = b64url_decode(sig_b64).ok_or(())?;
    if got.as_slice() != expect.as_slice() {
        return Err(());
    }
    let payload = b64url_decode(payload_b64).ok_or(())?;
    let text = std::str::from_utf8(&payload).map_err(|_| ())?;
    let exp = json_u64(text, "exp").ok_or(())?;
    if now >= exp {
        return Err(());
    }
    json_string(text, "sub").ok_or(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub username: String,
    pub hash: [u8; 32]
}

/// Read `username\npassword\n` and return a PBKDF2-HMAC-SHA256 credential.
pub fn scripted_login<R: BufRead>(mut reader: R) -> io::Result<Credential> {
    let mut username = String::new();
    let mut password = String::new();
    reader.read_line(&mut username)?;
    reader.read_line(&mut password)?;
    let username = username.trim().to_string();
    let password = password.trim().to_string();
    if username.is_empty() || password.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "username and password"));
    }
    let mut hash = [0u8; 32];
    pbkdf2_hmac_sha256(password.as_bytes(), username.as_bytes(), 1000, &mut hash);
    Ok(Credential { username, hash })
}

#[derive(Clone, Debug)]
pub struct ApprovalGate {
    pub required: bool,
    approved: BTreeSet<[u8; 16]>
}

impl ApprovalGate {
    pub fn default_open() -> Self {
        Self { required: false, approved: BTreeSet::new() }
    }

    pub fn enforcing() -> Self {
        Self { required: true, approved: BTreeSet::new() }
    }

    pub fn approve(&mut self, id: [u8; 16]) {
        self.approved.insert(id);
    }

    pub fn forward<'a>(&self, id: &[u8; 16], packet: &'a [u8]) -> Option<&'a [u8]> {
        if !self.required || self.approved.contains(id) {
            Some(packet)
        } else {
            None
        }
    }
}

/// Exact group name. A longer name with the same prefix is refused.
pub fn admit(allowed: &str, presented: &str) -> bool {
    !allowed.is_empty() && allowed == presented
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRecord {
    pub id: [u8; 16],
    pub ephemeral: bool,
    pub expiry: u64,
    pub connected: bool
}

pub fn reload_stable(nodes: &[NodeRecord], now: u64) -> Vec<[u8; 16]> {
    nodes.iter().filter(|node| !node.ephemeral && node.expiry > now).map(|node| node.id).collect()
}

pub fn on_disconnect(nodes: &mut Vec<NodeRecord>, id: &[u8; 16]) {
    if let Some(node) = nodes.iter_mut().find(|node| node.id == *id) {
        node.connected = false;
    }
    nodes.retain(|node| !(node.ephemeral && node.id == *id));
}

pub fn drop_expired(nodes: &mut Vec<NodeRecord>, now: u64) {
    nodes.retain(|node| !(node.ephemeral && node.expiry <= now));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn certificate_based_enrollment() {
        println!("row: certificate-based enrollment");
        let ca = Ed25519KeyPair::from_seed(&[7u8; 32]).unwrap();
        let node = Ed25519KeyPair::from_seed(&[9u8; 32]).unwrap();
        let id = [3u8; 16];
        let cert = issue_cert(&ca, id, *node.public_key(), 1_700_000_000);
        assert!(accept_cert(ca.public_key(), &cert, 1_600_000_000));
        let mut tampered = cert.clone();
        tampered.signature[0] ^= 0x01;
        assert!(!accept_cert(ca.public_key(), &tampered, 1_600_000_000));
        let mut body = cert.clone();
        body.node_id[0] ^= 0x01;
        assert!(!accept_cert(ca.public_key(), &body, 1_600_000_000));
    }

    #[test]
    fn oauth_oidc() {
        println!("row: OAuth/OIDC");
        let secret = b"local-oidc-secret";
        let token = issue_token(secret, "node-7", 5000);
        assert_eq!(accept_token(secret, &token, 1000).unwrap(), "node-7");
        let mut chars: Vec<u8> = token.into_bytes();
        let last = chars.len() - 1;
        chars[last] ^= 0x01;
        let bad = String::from_utf8(chars).unwrap();
        assert!(accept_token(secret, &bad, 1000).is_err());
        let expired = issue_token(secret, "node-7", 50);
        assert!(accept_token(secret, &expired, 50).is_err());
    }

    #[test]
    fn interactive_login() {
        println!("row: interactive login");
        let first = scripted_login(Cursor::new("alice\nhunter2\n")).unwrap();
        let again = scripted_login(Cursor::new("alice\nhunter2\n")).unwrap();
        let other = scripted_login(Cursor::new("alice\nother-secret\n")).unwrap();
        assert_eq!(first.username, "alice");
        assert_eq!(first, again);
        assert_ne!(first.hash, other.hash);
        assert_ne!(first.hash, [0u8; 32]);
        assert!(scripted_login(Cursor::new("\n\n")).is_err());
    }

    #[test]
    fn admin_approval_workflow() {
        println!("row: admin approval workflow");
        let id = [4u8; 16];
        let packet = b"overlay";
        let open = ApprovalGate::default_open();
        assert!(!open.required);
        assert_eq!(open.forward(&id, packet), Some(packet.as_slice()));
        let mut gate = ApprovalGate::enforcing();
        assert!(gate.forward(&id, packet).is_none());
        gate.approve(id);
        assert_eq!(gate.forward(&id, packet), Some(packet.as_slice()));
    }

    #[test]
    fn automated_enrollment_rules() {
        println!("row: automated enrollment rules");
        assert!(admit("edge", "edge"));
        assert!(!admit("edge", "edge-extra"));
        assert!(!admit("edge", "edg"));
        assert!(!admit("edge", ""));
    }

    #[test]
    fn ephemeral_nodes() {
        println!("row: ephemeral nodes");
        let stable = NodeRecord { id: [1u8; 16], ephemeral: false, expiry: 100, connected: true };
        let guest = NodeRecord { id: [2u8; 16], ephemeral: true, expiry: 100, connected: true };
        let mut nodes = vec![stable.clone(), guest.clone()];
        assert_eq!(reload_stable(&nodes, 10), vec![stable.id]);
        on_disconnect(&mut nodes, &guest.id);
        assert!(!nodes.iter().any(|node| node.id == guest.id));
        assert!(nodes.iter().any(|node| node.id == stable.id));
        assert_eq!(reload_stable(&nodes, 10), vec![stable.id]);
        nodes.push(NodeRecord { id: [3u8; 16], ephemeral: true, expiry: 20, connected: true });
        drop_expired(&mut nodes, 20);
        assert!(!nodes.iter().any(|node| node.id == [3u8; 16]));
        assert_eq!(reload_stable(&nodes, 20), vec![stable.id]);
        assert_eq!(reload_stable(&nodes, 100), Vec::<[u8; 16]>::new());
    }
}
