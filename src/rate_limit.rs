// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{collections::HashMap, net::IpAddr};

use crate::util::Time;

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
}
