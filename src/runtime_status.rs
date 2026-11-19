// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Process-wide sent/received counters and last handshake time for the GUI.

use std::{
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Mutex, OnceLock
    },
    time::{Instant, SystemTime, UNIX_EPOCH}
};

use serde::{Deserialize, Serialize};

static START: OnceLock<Instant> = OnceLock::new();
static PROMETHEUS: Mutex<String> = Mutex::new(String::new());
static PEERS: Mutex<Vec<PeerStatus>> = Mutex::new(Vec::new());

static SENT: AtomicU64 = AtomicU64::new(0);
static RECV: AtomicU64 = AtomicU64::new(0);
static LAST_HANDSHAKE: AtomicI64 = AtomicI64::new(0);

#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot {
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    /// Unix seconds of last completed peer handshake, or 0.
    pub last_handshake_unix: i64
}

pub fn reset() {
    SENT.store(0, Ordering::Relaxed);
    RECV.store(0, Ordering::Relaxed);
    LAST_HANDSHAKE.store(0, Ordering::Relaxed);
}

#[inline]
pub fn add_sent(bytes: usize) {
    SENT.fetch_add(bytes as u64, Ordering::Relaxed);
}

#[inline]
pub fn add_recv(bytes: usize) {
    RECV.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn note_handshake() {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    LAST_HANDSHAKE.store(t, Ordering::Relaxed);
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        sent_bytes: SENT.load(Ordering::Relaxed),
        recv_bytes: RECV.load(Ordering::Relaxed),
        last_handshake_unix: LAST_HANDSHAKE.load(Ordering::Relaxed)
    }
}

/// A suggested relay path derived from gossiped peer quality.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelaySuggestion {
    pub via_addr: String,
    pub via_node: String,
    pub dest_node: String,
    pub estimated_rtt_ms: u32
}

/// Estimated quality of a remote node (first-hand or relayed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QualityEntry {
    pub node_id: String,
    pub estimated_rtt_ms: u32
}

/// Serialized form written to `status_file` and read by `vpncloud status`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub addr: String,
    pub node_id: String,
    pub rtt_ms: Option<u64>,
    /// Number of payloads dropped by the per-peer rate limiter.
    #[serde(default)]
    pub throttled: u64,
    /// Current rate penalty (0 = none, higher = stricter), if enabled.
    #[serde(default)]
    pub penalty: u8
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullStatus {
    pub device: String,
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub last_handshake_unix: i64,
    pub uptime_secs: u64,
    pub peer_count: usize,
    pub peers: Vec<PeerStatus>,
    /// Estimated RTT to every known node, best path first.
    #[serde(default)]
    pub quality: Vec<QualityEntry>,
    /// Best relayed path found from gossiped quality, if any.
    #[serde(default)]
    pub suggested_relay: Option<RelaySuggestion>
}

/// Replace the Prometheus exposition text served by the metrics endpoint.
pub fn set_prometheus(text: String) {
    if let Ok(mut guard) = PROMETHEUS.lock() {
        *guard = text;
    }
}

pub fn prometheus() -> String {
    PROMETHEUS.lock().map(|guard| guard.clone()).unwrap_or_default()
}

/// Replace the peer list shown by the desktop GUI.
pub fn set_peers(peers: Vec<PeerStatus>) {
    if let Ok(mut guard) = PEERS.lock() {
        *guard = peers;
    }
}

pub fn peers() -> Vec<PeerStatus> {
    PEERS.lock().map(|guard| guard.clone()).unwrap_or_default()
}

/// Seconds since the process started (first call initializes the clock).
pub fn uptime_secs() -> u64 {
    START.get_or_init(Instant::now).elapsed().as_secs()
}
