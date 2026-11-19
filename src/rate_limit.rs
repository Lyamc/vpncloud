// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr}
};

use crate::util::Time;

/// Per-peer token bucket for overlay DATA traffic. A peer that repeatedly
/// drains its bucket has its effective rate penalised, which both contains a
/// flood and marks the peer as problematic in status/metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerRateState {
    pub tokens: u64,
    pub last: Time,
    pub penalty: u8,
    pub throttled: u64
}

/// Token bucket keyed by underlay peer address. `rate` is bytes per second;
/// `burst` is the bucket capacity in bytes. A zero rate disables limiting.
pub struct PeerRateLimit {
    buckets: HashMap<SocketAddr, PeerRateState>,
    rate: u64,
    burst: u64
}

impl PeerRateLimit {
    pub fn new(rate: u64, burst: u64) -> Self {
        Self { buckets: HashMap::new(), rate, burst: burst.max(1) }
    }

    pub fn enabled(&self) -> bool {
        self.rate > 0
    }

    /// Charge `bytes` to a peer. Returns true if allowed. Exhausting the
    /// bucket halves the effective rate (down to 1/16) and counts a throttle
    /// event; the penalty recovers one step per `recover` call.
    pub fn allow(&mut self, peer: SocketAddr, bytes: usize, now: Time) -> bool {
        if self.rate == 0 {
            return true;
        }
        let entry = self.buckets.entry(peer).or_insert(PeerRateState {
            tokens: self.burst,
            last: now,
            penalty: 0,
            throttled: 0
        });
        let elapsed = now.saturating_sub(entry.last).max(0) as u64;
        let effective = self.rate >> entry.penalty.min(4);
        entry.tokens = entry.tokens.saturating_add(elapsed.saturating_mul(effective.max(1))).min(self.burst);
        entry.last = now;
        let cost = bytes as u64;
        if entry.tokens >= cost {
            entry.tokens -= cost;
            true
        } else {
            entry.throttled = entry.throttled.saturating_add(1);
            entry.penalty = entry.penalty.saturating_add(1).min(4);
            false
        }
    }

    /// Gradually restore peers that have behaved since their last offence.
    pub fn recover(&mut self, now: Time) {
        if self.rate == 0 {
            return;
        }
        for entry in self.buckets.values_mut() {
            let elapsed = now.saturating_sub(entry.last).max(0) as u64;
            let effective = self.rate >> entry.penalty.min(4);
            entry.tokens = entry.tokens.saturating_add(elapsed.saturating_mul(effective.max(1))).min(self.burst);
            entry.last = now;
            if entry.tokens >= self.burst / 2 {
                entry.penalty = entry.penalty.saturating_sub(1);
            }
        }
    }

    pub fn state(&self, peer: SocketAddr) -> PeerRateState {
        self.buckets.get(&peer).copied().unwrap_or(PeerRateState {
            tokens: self.burst,
            last: 0,
            penalty: 0,
            throttled: 0
        })
    }

    pub fn remove(&mut self, peer: SocketAddr) {
        self.buckets.remove(&peer);
    }

    pub fn housekeep(&mut self, now: Time) {
        self.recover(now);
        let rate = self.rate;
        self.buckets.retain(|_, entry| {
            rate == 0 || entry.penalty > 0 || entry.throttled > 0 || now.saturating_sub(entry.last) < 3_600
        });
    }
}

/// Per-IP token bucket for crypto-init (handshake) packets.
pub struct InitRateLimit {
    hits: HashMap<IpAddr, (u32, Time)>,
    max: u32,
    window: Time
}

impl InitRateLimit {
    pub fn new(max: u32, window: Time) -> Self {
        Self { hits: HashMap::new(), max: max.max(1), window: window.max(1) }
    }

    /// Returns true if this handshake is allowed.
    pub fn allow(&mut self, ip: IpAddr, now: Time) -> bool {
        match self.hits.get(&ip).copied() {
            Some((count, start)) if now.saturating_sub(start) < self.window => {
                if count >= self.max {
                    return false;
                }
                self.hits.insert(ip, (count + 1, start));
                true
            }
            _ => {
                self.hits.insert(ip, (1, now));
                true
            }
        }
    }

    pub fn housekeep(&mut self, now: Time) {
        let window = self.window;
        self.hits.retain(|_, (_, start)| now.saturating_sub(*start) < window * 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn blocks_after_max() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let mut rl = InitRateLimit::new(3, 10);
        assert!(rl.allow(ip, 100));
        assert!(rl.allow(ip, 101));
        assert!(rl.allow(ip, 102));
        assert!(!rl.allow(ip, 103));
        assert!(rl.allow(ip, 111));
    }

    #[test]
    fn peer_bucket_drains_and_penalises() {
        let peer: SocketAddr = "10.0.0.1:3210".parse().unwrap();
        let mut rl = PeerRateLimit::new(1_000_000, 1_000);
        assert!(rl.allow(peer, 600, 0));
        assert!(rl.allow(peer, 400, 0));
        assert!(!rl.allow(peer, 1, 0));
        let state = rl.state(peer);
        assert_eq!(state.penalty, 1);
        assert_eq!(state.throttled, 1);
        // No refill without elapsed time.
        assert!(!rl.allow(peer, 1, 0));
        // 1 s at the penalised rate (500 kB/s) partially refills.
        assert!(rl.allow(peer, 1, 1));
    }

    #[test]
    fn peer_bucket_recovers_and_disabled() {
        let peer: SocketAddr = "10.0.0.1:3210".parse().unwrap();
        let mut rl = PeerRateLimit::new(0, 1000);
        assert!(!rl.enabled());
        for _ in 0..10 {
            assert!(rl.allow(peer, 100_000, 0));
        }
        let mut rl = PeerRateLimit::new(1_000_000, 1_000);
        assert!(rl.allow(peer, 1_000, 0));
        assert!(!rl.allow(peer, 1, 0));
        assert_eq!(rl.state(peer).penalty, 1);
        // With a full bucket, recovery decays the penalty one step.
        rl.recover(10);
        assert_eq!(rl.state(peer).penalty, 0);
    }
}
