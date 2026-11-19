// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Stable node identity and loop/replay identifiers for relay frames.
//! Extracted from `cloud.rs` so routing code stays focused on forwarding.

use crate::{config::Config, crypto::Ed25519KeyPair, types::NodeId, util::bytes_to_hex};

use rand::random;

/// Bound on the loop-break set for relay frames.
pub const MAX_RELAY_SEEN: usize = 8192;
/// Per-sealer bound on remembered e2e-sealed bodies.
pub const MAX_E2E_SEEN: usize = 8192;

/// Resolve a stable node id from config, else derive it from the signing key,
/// else generate a random one. A stable id lets peers recognise a node that
/// reconnects from a new address (WiFi -> cellular).
pub fn resolve_node_id(config: &Config) -> NodeId {
    if let Some(ref id) = config.node_id {
        if let Ok(bytes) = crate::util::from_hex(id) {
            if let Ok(id) = <[u8; 16]>::try_from(bytes.as_slice()) {
                info!("Using configured node id {}", bytes_to_hex(&id));
                return id;
            }
        }
        warn!("Invalid node-id in config; falling back to derived/random id");
    }
    if let Some(ref key) = config.node_key {
        if let Ok(seed) = crate::util::from_base62_fixed::<32>(key) {
            if let Ok(pair) = Ed25519KeyPair::from_seed(&seed) {
                let digest = crate::crypto::sha256(pair.public_key());
                let mut id = [0u8; 16];
                id.copy_from_slice(&digest[..16]);
                info!("Derived stable node id {}", bytes_to_hex(&id));
                return id;
            }
        }
    }
    random()
}

pub fn stable_hash(data: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

/// Stable identity of a relay frame: destination plus a hash of the envelope
/// body (inner type + sealed payload). Identical across every hop.
pub fn relay_frame_key(frame: &[u8]) -> (NodeId, u64) {
    let mut dest = [0u8; 16];
    dest.copy_from_slice(&frame[..16]);
    (dest, stable_hash(&frame[16..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_frame_key_is_stable_and_content_sensitive() {
        let dest = [7u8; 16];
        let mut frame = dest.to_vec();
        frame.push(crate::messages::MESSAGE_TYPE_DATA);
        frame.extend_from_slice(b"payload");
        assert_eq!(relay_frame_key(&frame), relay_frame_key(&frame));
        let mut other = frame.clone();
        other[17] = b'X';
        assert_ne!(relay_frame_key(&frame), relay_frame_key(&other));
    }

    #[test]
    fn node_id_is_configurable_hex() {
        let mut cfg = Config::default();
        cfg.node_id = Some("aabbccddeeff00112233445566778899".into());
        assert_eq!(resolve_node_id(&cfg), [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
        ]);
    }
}
