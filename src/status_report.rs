// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Builds the status snapshot and its Prometheus/JSON representations.
//! Extracted from the datapath so the wire loop stays focused on forwarding.

use std::{io, path::Path};

use crate::runtime_status::{FullStatus, PeerStatus};

/// Prometheus text exposition from a snapshot.
pub fn prometheus(status: &FullStatus) -> String {
    let mut out = String::new();
    out.push_str("# HELP vpncloud_up Whether the node is running.\n# TYPE vpncloud_up gauge\nvpncloud_up 1\n");
    out.push_str(&format!("# TYPE vpncloud_sent_bytes counter\nvpncloud_sent_bytes {}\n", status.sent_bytes));
    out.push_str(&format!("# TYPE vpncloud_recv_bytes counter\nvpncloud_recv_bytes {}\n", status.recv_bytes));
    out.push_str(&format!("# TYPE vpncloud_uptime_seconds gauge\nvpncloud_uptime_seconds {}\n", status.uptime_secs));
    out.push_str(&format!("# TYPE vpncloud_peers gauge\nvpncloud_peers {}\n", status.peer_count));
    out.push_str("# TYPE vpncloud_peer_rtt_ms gauge\n");
    for peer in &status.peers {
        if let Some(rtt) = peer.rtt_ms {
            out.push_str(&format!(
                "vpncloud_peer_rtt_ms{{addr=\"{}\",node=\"{}\"}} {}\n",
                peer.addr, peer.node_id, rtt
            ));
        }
    }
    out.push_str("# TYPE vpncloud_peer_throttled_total counter\n");
    for peer in &status.peers {
        out.push_str(&format!(
            "vpncloud_peer_throttled_total{{addr=\"{}\",node=\"{}\"}} {}\n",
            peer.addr, peer.node_id, peer.throttled
        ));
    }
    out.push_str("# TYPE vpncloud_peer_penalty gauge\n");
    for peer in &status.peers {
        out.push_str(&format!(
            "vpncloud_peer_penalty{{addr=\"{}\",node=\"{}\"}} {}\n",
            peer.addr, peer.node_id, peer.penalty
        ));
    }
    out.push_str("# TYPE vpncloud_estimated_rtt_ms gauge\n");
    for entry in &status.quality {
        out.push_str(&format!("vpncloud_estimated_rtt_ms{{node=\"{}\"}} {}\n", entry.node_id, entry.estimated_rtt_ms));
    }
    if let Some(ref relay) = status.suggested_relay {
        out.push_str(&format!(
            "# TYPE vpncloud_suggested_relay_rtt_ms gauge\nvpncloud_suggested_relay_rtt_ms{{via=\"{}\",dest=\"{}\"}} {}\n",
            relay.via_node, relay.dest_node, relay.estimated_rtt_ms
        ));
    }
    if status.last_handshake_unix > 0 {
        out.push_str(&format!(
            "# TYPE vpncloud_last_handshake_timestamp_seconds gauge\nvpncloud_last_handshake_timestamp_seconds {}\n",
            status.last_handshake_unix
        ));
    }
    out
}

/// Write the JSON snapshot to `path` with private permissions.
pub fn write_json(path: &Path, status: &FullStatus) -> io::Result<()> {
    let json = serde_json::to_string(status).map_err(|e| io::Error::other(e.to_string()))?;
    let mut file = crate::config::create_private_file(path)?;
    use std::io::Write;
    file.write_all(json.as_bytes())
}

/// Build a snapshot from the current peer table and process counters.
pub fn build(device: &str, peers: Vec<PeerStatus>) -> FullStatus {
    let snap = crate::runtime_status::snapshot();
    FullStatus {
        device: device.to_string(),
        sent_bytes: snap.sent_bytes,
        recv_bytes: snap.recv_bytes,
        last_handshake_unix: snap.last_handshake_unix,
        uptime_secs: crate::runtime_status::uptime_secs(),
        peer_count: peers.len(),
        peers,
        quality: Vec::new(),
        suggested_relay: None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_includes_counters_and_peer_rtt() {
        let status = FullStatus {
            device: "vpncloud0".into(),
            sent_bytes: 10,
            recv_bytes: 20,
            last_handshake_unix: 100,
            uptime_secs: 5,
            peer_count: 1,
            peers: vec![PeerStatus {
                addr: "192.0.2.1:3210".into(),
                node_id: "ab".into(),
                rtt_ms: Some(7),
                throttled: 3,
                penalty: 1
            }],
            quality: vec![crate::runtime_status::QualityEntry { node_id: "cd".into(), estimated_rtt_ms: 25 }],
            suggested_relay: Some(crate::runtime_status::RelaySuggestion {
                via_addr: "192.0.2.1:3210".into(),
                via_node: "ab".into(),
                dest_node: "cd".into(),
                estimated_rtt_ms: 25
            })
        };
        let text = prometheus(&status);
        assert!(text.contains("vpncloud_sent_bytes 10"));
        assert!(text.contains("vpncloud_recv_bytes 20"));
        assert!(text.contains("vpncloud_peer_rtt_ms{addr=\"192.0.2.1:3210\",node=\"ab\"} 7"));
        assert!(text.contains("vpncloud_estimated_rtt_ms{node=\"cd\"} 25"));
        assert!(text.contains("vpncloud_suggested_relay_rtt_ms"));
    }
}
