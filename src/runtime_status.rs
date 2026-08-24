// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Process-wide sent/received counters and last handshake time for the GUI.

use std::{
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH}
};

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
